/* ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

#include <stdlib.h>

#include <apr.h>
#include <apr_uri.h>
#include <apr_strings.h>
#include <apr_atomic.h>
#include <apr_base64.h>
#include <apr_getopt.h>
#include <apr_version.h>

#include "serf.h"

/* Add Connection: close header to each request. */
/* #define CONNECTION_CLOSE_HDR */

typedef struct app_baton_t {
    const char *hostinfo;
    int using_ssl;
    int head_request;
    int negotiate_http2;
    int use_h2direct;
    const char *pem_path;
    const char *pem_pwd;
    serf_bucket_alloc_t *bkt_alloc;
    serf_context_t *serf_ctx;
} app_baton_t;

typedef struct conn_baton_t {
    app_baton_t *app;
    serf_ssl_context_t *ssl_ctx;
    serf_connection_t *conn;
} conn_baton_t;

static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    conn_baton_t *conn_ctx = closed_baton;

    conn_ctx->ssl_ctx = NULL;

    if (why) {
        abort();
    }
}

static apr_status_t client_cert_cb(void *data, const char **cert_path)
{
    app_baton_t *ctx = data;

    *cert_path = ctx->pem_path;

    return APR_SUCCESS;
}

static apr_status_t client_cert_pw_cb(void *data,
                                      const char *cert_path,
                                      const char **password)
{
    app_baton_t *ctx = data;

    if (strcmp(cert_path, ctx->pem_path) == 0)
    {
        *password = ctx->pem_pwd;
        return APR_SUCCESS;
    }

    return APR_EGENERAL;
}

static void print_ssl_cert_errors(int failures)
{
    if (failures) {
        fprintf(stderr, "INVALID CERTIFICATE:\n");
        if (failures & SERF_SSL_CERT_NOTYETVALID)
            fprintf(stderr, "* The certificate is not yet valid.\n");
        if (failures & SERF_SSL_CERT_EXPIRED)
            fprintf(stderr, "* The certificate expired.\n");
        if (failures & SERF_SSL_CERT_SELF_SIGNED)
            fprintf(stderr, "* The certificate is self-signed.\n");
        if (failures & SERF_SSL_CERT_UNKNOWNCA)
            fprintf(stderr, "* The CA is unknown.\n");
        if (failures & SERF_SSL_CERT_UNKNOWN_FAILURE)
            fprintf(stderr, "* Unknown failure.\n");
        if (failures & SERF_SSL_CERT_REVOKED)
            fprintf(stderr, "* The certificate is revoked.\n");
    }
}

static apr_status_t ignore_all_cert_errors(void *data, int failures,
                                           const serf_ssl_certificate_t *cert)
{
    print_ssl_cert_errors(failures);

     /* In a real application, you would normally would not want to do this */
    return APR_SUCCESS;
}

static char *
convert_organisation_to_str(apr_hash_t *org, apr_pool_t *pool)
{
    return apr_psprintf(pool, "%s, %s, %s, %s, %s (%s)",
                        (char*)apr_hash_get(org, "OU", APR_HASH_KEY_STRING),
                        (char*)apr_hash_get(org, "O", APR_HASH_KEY_STRING),
                        (char*)apr_hash_get(org, "L", APR_HASH_KEY_STRING),
                        (char*)apr_hash_get(org, "ST", APR_HASH_KEY_STRING),
                        (char*)apr_hash_get(org, "C", APR_HASH_KEY_STRING),
                        (char*)apr_hash_get(org, "E", APR_HASH_KEY_STRING));
}

static apr_status_t print_certs(void *data, int failures, int error_depth,
                                const serf_ssl_certificate_t * const * certs,
                                apr_size_t certs_len)
{
    apr_pool_t *pool;
    const serf_ssl_certificate_t *current;

    apr_pool_create(&pool, NULL);

    fprintf(stderr, "Received certificate chain with length %d\n",
            (int)certs_len);
    print_ssl_cert_errors(failures);
    if (failures)
        fprintf(stderr, "Error at depth=%d\n", error_depth);
    else
        fprintf(stderr, "Chain provided with depth=%d\n", error_depth);

    while ((current = *certs) != NULL)
    {
        apr_hash_t *issuer, *subject, *serf_cert;
        apr_array_header_t *san;

        subject = serf_ssl_cert_subject(current, pool);
        issuer = serf_ssl_cert_issuer(current, pool);
        serf_cert = serf_ssl_cert_certificate(current, pool);

        fprintf(stderr, "\n-----BEGIN CERTIFICATE-----\n");
        fprintf(stderr, "Hostname: %s\n",
                (const char *)apr_hash_get(subject, "CN", APR_HASH_KEY_STRING));
        fprintf(stderr, "Sha1: %s\n",
                (const char *)apr_hash_get(serf_cert, "sha1", APR_HASH_KEY_STRING));
        fprintf(stderr, "Valid from: %s\n",
                (const char *)apr_hash_get(serf_cert, "notBefore", APR_HASH_KEY_STRING));
        fprintf(stderr, "Valid until: %s\n",
                (const char *)apr_hash_get(serf_cert, "notAfter", APR_HASH_KEY_STRING));
        fprintf(stderr, "Issuer: %s\n", convert_organisation_to_str(issuer, pool));

        san = apr_hash_get(serf_cert, "subjectAltName", APR_HASH_KEY_STRING);
        if (san) {
            int i;
            for (i = 0; i < san->nelts; i++) {
                char *s = APR_ARRAY_IDX(san, i, char*);
                fprintf(stderr, "SubjectAltName: %s\n", s);
            }
        }

        fprintf(stderr, "%s\n", serf_ssl_cert_export(current, pool));
        fprintf(stderr, "-----END CERTIFICATE-----\n");
        ++certs;
    }

    apr_pool_destroy(pool);
    return APR_SUCCESS;
}

/* Implements serf_ssl_protocol_result_cb_t for conn_setup */
static apr_status_t conn_set_protocol(void *baton,
                                      const char *protocol)
{
    conn_baton_t *conn_ctx = baton;

    if (!strcmp(protocol, "h2")) {
        serf_connection_set_framing_type(
                  conn_ctx->conn,
                  SERF_CONNECTION_FRAMING_TYPE_HTTP2);
    } else /* "http/1.1" or "" */ {
        serf_connection_set_framing_type(
                  conn_ctx->conn,
                  SERF_CONNECTION_FRAMING_TYPE_HTTP1);
    }

    return APR_SUCCESS;
}

static apr_status_t conn_setup(apr_socket_t *skt,
                               serf_bucket_t **input_bkt,
                               serf_bucket_t **output_bkt,
                               void *setup_baton,
                               apr_pool_t *pool)
{
    serf_bucket_t *c;
    conn_baton_t *conn_ctx = setup_baton;
    app_baton_t *ctx = conn_ctx->app;

    c = serf_context_bucket_socket_create(ctx->serf_ctx, skt,
                                          ctx->bkt_alloc);
    if (ctx->using_ssl) {
        c = serf_bucket_ssl_decrypt_create(c, conn_ctx->ssl_ctx, ctx->bkt_alloc);
        if (!conn_ctx->ssl_ctx) {
            conn_ctx->ssl_ctx = serf_bucket_ssl_decrypt_context_get(c);
        }
        serf_ssl_server_cert_chain_callback_set(conn_ctx->ssl_ctx, 
                                                ignore_all_cert_errors, 
                                                print_certs, NULL);
        serf_ssl_set_hostname(conn_ctx->ssl_ctx, ctx->hostinfo);

        *output_bkt = serf_bucket_ssl_encrypt_create(*output_bkt,
                                                     conn_ctx->ssl_ctx,
                                                     ctx->bkt_alloc);
        if (ctx->pem_path) {
            serf_ssl_client_cert_provider_set(conn_ctx->ssl_ctx,
                                              client_cert_cb,
                                              ctx,
                                              pool);
        }

        if (ctx->pem_pwd) {
            serf_ssl_client_cert_password_set(conn_ctx->ssl_ctx,
                                              client_cert_pw_cb,
                                              ctx,
                                              pool);
        }

        if (ctx->negotiate_http2) {
            if (!serf_ssl_negotiate_protocol(conn_ctx->ssl_ctx,
                                             "h2,http/1.1",
                                             conn_set_protocol, conn_ctx))
            {
                serf_bucket_t *bkt;

                /* Disable sending initial data until negotiate is done */
                serf_connection_set_framing_type(
                              conn_ctx->conn,
                              SERF_CONNECTION_FRAMING_TYPE_NONE);
            }
        }
    }
    else if (ctx->use_h2direct) {
      serf_connection_set_framing_type(
                              conn_ctx->conn,
                              SERF_CONNECTION_FRAMING_TYPE_HTTP2);
    }


    *input_bkt = c;

    return APR_SUCCESS;
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      serf_bucket_t *stream,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_t *response;
    serf_bucket_alloc_t *bkt_alloc;
    app_baton_t *app_ctx = acceptor_baton;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    response = serf_bucket_response_create(c, bkt_alloc);

    if (app_ctx->head_request)
      serf_bucket_response_set_head(response);

    return response;
}

typedef struct handler_baton_t {
#if APR_MAJOR_VERSION > 0
    apr_uint32_t completed_requests;
#else
    apr_atomic_t completed_requests;
#endif
    int print_headers;
    apr_file_t *output_file;

    serf_response_acceptor_t acceptor;
    app_baton_t *acceptor_baton;

    serf_response_handler_t handler;

    const char *host;
    const char *method;
    const char *path;
    const char *req_body_path;
    const char *username;
    const char *password;
    int auth_attempts;
    serf_bucket_t *req_hdrs;
} handler_baton_t;

/* Kludges for APR 0.9 support. */
#if APR_MAJOR_VERSION == 0
#define apr_atomic_inc32 apr_atomic_inc
#define apr_atomic_dec32 apr_atomic_dec
#define apr_atomic_read32 apr_atomic_read
#endif


static int append_request_headers(void *baton,
                                  const char *key,
                                  const char *value)
{
    serf_bucket_t *hdrs_bkt = baton;
    serf_bucket_headers_setc(hdrs_bkt, key, value);
    return 0;
}

static apr_status_t setup_request(serf_request_t *request,
                                  void *setup_baton,
                                  serf_bucket_t **req_bkt,
                                  serf_response_acceptor_t *acceptor,
                                  void **acceptor_baton,
                                  serf_response_handler_t *handler,
                                  void **handler_baton,
                                  apr_pool_t *pool)
{
    handler_baton_t *ctx = setup_baton;
    serf_bucket_t *hdrs_bkt;
    serf_bucket_t *body_bkt;

    if (ctx->req_body_path) {
        apr_file_t *file;
        apr_status_t status;

        status = apr_file_open(&file, ctx->req_body_path, APR_READ,
                               APR_OS_DEFAULT, pool);

        if (status) {
            printf("Error opening file (%s)\n", ctx->req_body_path);
            return status;
        }

        body_bkt = serf_bucket_file_create(file,
                                           serf_request_get_alloc(request));
    }
    else {
        body_bkt = NULL;
    }

    *req_bkt = serf_request_bucket_request_create(request, ctx->method,
                                                  ctx->path, body_bkt,
                                                  serf_request_get_alloc(request));

    hdrs_bkt = serf_bucket_request_get_headers(*req_bkt);

    serf_bucket_headers_setn(hdrs_bkt, "User-Agent",
                             "Serf/" SERF_VERSION_STRING);
    /* Shouldn't serf do this for us? */
    serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");
#ifdef CONNECTION_CLOSE_HDR
    serf_bucket_headers_setn(hdrs_bkt, "Connection", "close");
#endif

    /* Add the extra headers from the command line */
    if (ctx->req_hdrs != NULL) {
        serf_bucket_headers_do(ctx->req_hdrs, append_request_headers, hdrs_bkt);
    }

    *acceptor = ctx->acceptor;
    *acceptor_baton = ctx->acceptor_baton;
    *handler = ctx->handler;
    *handler_baton = ctx;
    
    return APR_SUCCESS;
}

static apr_status_t handle_response(serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    serf_status_line sl;
    apr_status_t status;
    handler_baton_t *ctx = handler_baton;

    if (!response) {
        /* A NULL response probably means that the connection was closed while
           this request was already written. Just requeue it. */
        serf_connection_t *conn = serf_request_get_conn(request);

        serf_connection_request_create(conn, setup_request, handler_baton);
        return APR_SUCCESS;
    }

    status = serf_bucket_response_status(response, &sl);
    if (status) {
        return status;
    }

    while (1) {
        struct iovec vecs[64];
        int vecs_read;
        apr_size_t bytes_written;

        status = serf_bucket_read_iovec(response, 8000, 64, vecs, &vecs_read);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* got some data. print it out. */
        if (vecs_read) {
            apr_file_writev(ctx->output_file, vecs, vecs_read, &bytes_written);
        }

        /* are we done yet? */
        if (APR_STATUS_IS_EOF(status)) {
            if (ctx->print_headers) {
                serf_bucket_t *hdrs;
                hdrs = serf_bucket_response_get_headers(response);
                while (1) {
                    status = serf_bucket_read_iovec(hdrs, 8000, 64, vecs,
                                                    &vecs_read);

                    if (SERF_BUCKET_READ_ERROR(status))
                        return status;

                    if (vecs_read) {
                        apr_file_writev(ctx->output_file, vecs, vecs_read,
                                        &bytes_written);
                    }
                    if (APR_STATUS_IS_EOF(status)) {
                        break;
                    }
                }
            }

            apr_atomic_inc32(&ctx->completed_requests);
            return APR_EOF;
        }

        /* have we drained the response so far? */
        if (APR_STATUS_IS_EAGAIN(status))
            return status;

        /* loop to read some more. */
    }
    /* NOTREACHED */
}

static apr_status_t
credentials_callback(char **username,
                     char **password,
                     serf_request_t *request, void *baton,
                     int code, const char *authn_type,
                     const char *realm,
                     apr_pool_t *pool)
{
    handler_baton_t *ctx = baton;

    if (ctx->auth_attempts > 0)
    {
        return SERF_ERROR_AUTHN_FAILED;
    }
    else
    {
        *username = (char*)ctx->username;
        *password = (char*)ctx->password;
        ctx->auth_attempts++;

        return APR_SUCCESS;
    }
}

/* Value for 'no short code' should be > 255 */
#define CERTFILE 256
#define CERTPWD  257
#define HTTP2FLAG 258
#define H2DIRECT 259

static const apr_getopt_option_t options[] =
{

    {"help",    'h', 0, "Display this help"},
    {NULL,      'v', 0, "Display version"},
    {NULL,      'H', 0, "Print response headers"},
    {NULL,      'n', 1, "<count> Fetch URL <count> times"},
    {NULL,      'c', 1, "<count> Use <count> concurrent connections"},
    {NULL,   'x', 1, "<count> Number of maximum outstanding requests inflight"},
    {"user",    'U', 1, "<user> Username for Basic/Digest authentication"},
    {"pwd",     'P', 1, "<password> Password for Basic/Digest authentication"},
    {NULL,      'm', 1, "<method> Use the <method> HTTP Method"},
    {NULL,      'f', 1, "<file> Use the <file> as the request body"},
    {NULL,      'p', 1, "<hostname:port> Use the <host:port> as proxy server"},
    {"cert",    CERTFILE, 1, "<file> Use SSL client certificate <file>"},
    {"certpwd", CERTPWD, 1, "<password> Password for the SSL client certificate"},
    {NULL,      'r', 1, "<header:value> Use <header:value> as request header"},
    {"debug",   'd', 0, "Enable debugging"},
    {"http2",   HTTP2FLAG, 0, "Enable http2 (https only) (Experimental)"},
    {"h2direct",H2DIRECT, 0, "Enable h2direct (Experimental)"},

    { NULL, 0 }
};

static void print_usage(apr_pool_t *pool)
{
    int i = 0;

    puts("serf_get [options] URL\n");
    puts("Options:");

    while (options[i].optch > 0) {
        const apr_getopt_option_t* o = &options[i];

        if (o->optch <= 255) {
            printf(" -%c", o->optch);
            if (o->name)
                printf(", ");
        } else {
            printf("     ");
        }

        printf("%s%s\t%s\n",
               o->name ? "--" : "\t",
               o->name ? o->name : "",
               o->description);

        i++;
    }
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *pool;
    serf_bucket_alloc_t *bkt_alloc;
    serf_context_t *context;
    serf_connection_t **connections;
    app_baton_t app_ctx;
    handler_baton_t handler_ctx;
    serf_bucket_t *req_hdrs = NULL;
    apr_uri_t url;
    const char *proxy = NULL;
    const char *raw_url, *method, *req_body_path = NULL;
    int count, inflight, conn_count;
    int i;
    int print_headers, debug, negotiate_http2, use_h2direct;
    const char *username = NULL;
    const char *password = "";
    const char *pem_path = NULL, *pem_pwd = NULL;
    apr_getopt_t *opt;
    int opt_c;
    const char *opt_arg;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    /* serf_initialize(); */
    bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);

    /* Default to one round of fetching with no limit to max inflight reqs. */
    count = 1;
    inflight = 0;
    conn_count = 1;
    /* Default to GET. */
    method = "GET";
    /* Do not print headers by default. */
    print_headers = 0;
    /* Do not debug by default. */
    debug = 0;
    negotiate_http2 = 0;
    use_h2direct = 0;

    apr_getopt_init(&opt, pool, argc, argv);
    while ((status = apr_getopt_long(opt, options, &opt_c, &opt_arg)) ==
           APR_SUCCESS) {

        switch (opt_c) {
        case 'U':
            username = opt_arg;
            break;
        case 'P':
            password = opt_arg;
            break;
        case 'd':
            debug = 1;
            break;
        case 'f':
            req_body_path = opt_arg;
            break;
        case 'h':
            print_usage(pool);
            exit(0);
            break;
        case 'H':
            print_headers = 1;
            break;
        case 'm':
            method = opt_arg;
            break;
        case 'n':
            errno = 0;
            count = apr_strtoi64(opt_arg, NULL, 10);
            if (errno) {
                printf("Problem converting number of times to fetch URL (%d)\n",
                       errno);
                return errno;
            }
            break;
        case 'c':
            errno = 0;
            conn_count = apr_strtoi64(opt_arg, NULL, 10);
            if (errno) {
                printf("Problem converting number of concurrent connections to use (%d)\n",
                       errno);
                return errno;
            }

            if (conn_count <= 0) {
                printf("Invalid number of concurrent connections to use (%d)\n",
                       conn_count);
                return 1;
            }
            break;
        case 'x':
            errno = 0;
            inflight = apr_strtoi64(opt_arg, NULL, 10);
            if (errno) {
                printf("Problem converting number of requests to have outstanding (%d)\n",
                       errno);
                return errno;
            }
            break;
        case 'p':
            proxy = opt_arg;
            break;
        case 'r':
            {
                char *sep;
                char *hdr_val;

                if (req_hdrs == NULL) {
                    /* first request header, allocate bucket */
                    req_hdrs = serf_bucket_headers_create(bkt_alloc);
                }
                sep = strchr(opt_arg, ':');
                if ((sep == NULL) || (sep == opt_arg) || (strlen(sep) <= 1)) {
                    printf("Invalid request header string (%s)\n", opt_arg);
                    return EINVAL;
                }
                hdr_val = sep + 1;
                while (*hdr_val == ' ') {
                    hdr_val++;
                }
                serf_bucket_headers_setx(req_hdrs, opt_arg, (sep - opt_arg), 1,
                                         hdr_val, strlen(hdr_val), 1);
            }
            break;
        case CERTFILE:
            pem_path = opt_arg;
            break;
        case CERTPWD:
            pem_pwd = opt_arg;
            break;
        case HTTP2FLAG:
            negotiate_http2 = 1;
            break;
        case H2DIRECT:
            use_h2direct = 1;
            break;
        case 'v':
            puts("Serf version: " SERF_VERSION_STRING);
            exit(0);
        default:
            break;
        }
    }

    if (opt->ind != opt->argc - 1) {
        print_usage(pool);
        exit(-1);
    }

    raw_url = argv[opt->ind];

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_port_of_scheme(url.scheme);
    }
    if (!url.path) {
        url.path = "/";
    }

    if (strcasecmp(url.scheme, "https") == 0) {
        app_ctx.using_ssl = 1;

        app_ctx.negotiate_http2 = negotiate_http2;
        app_ctx.use_h2direct = FALSE;
    }
    else {
        app_ctx.using_ssl = 0;
        app_ctx.negotiate_http2 = FALSE;
        app_ctx.use_h2direct = use_h2direct;
    }

    if (strcasecmp(method, "HEAD") == 0) {
        app_ctx.head_request = 1;
    }
    else {
        app_ctx.head_request = 0;
    }

    app_ctx.hostinfo = url.hostinfo;
    app_ctx.pem_path = pem_path;
    app_ctx.pem_pwd = pem_pwd;

    context = serf_context_create(pool);
    app_ctx.serf_ctx = context;

    if (proxy)
    {
        apr_sockaddr_t *proxy_address = NULL;
        apr_port_t proxy_port;
        char *proxy_host;
        char *proxy_scope;

        status = apr_parse_addr_port(&proxy_host, &proxy_scope, &proxy_port, proxy, pool);
        if (status)
        {
            printf("Cannot parse proxy hostname/port: %d\n", status);
            apr_pool_destroy(pool);
            exit(1);
        }

        if (!proxy_host)
        {
            printf("Proxy hostname must be specified\n");
            apr_pool_destroy(pool);
            exit(1);
        }

        if (!proxy_port)
        {
            printf("Proxy port must be specified\n");
            apr_pool_destroy(pool);
            exit(1);
        }

        status = apr_sockaddr_info_get(&proxy_address, proxy_host, APR_UNSPEC,
                                       proxy_port, 0, pool);

        if (status)
        {
            printf("Cannot resolve proxy address '%s': %d\n", proxy_host, status);
            apr_pool_destroy(pool);
            exit(1);
        }

        serf_config_proxy(context, proxy_address);
    }

    if (username)
    {
        serf_config_authn_types(context, SERF_AUTHN_ALL);
    }
    else
    {
        serf_config_authn_types(context, SERF_AUTHN_NTLM | SERF_AUTHN_NEGOTIATE);
    }

    serf_config_credentials_callback(context, credentials_callback);

    /* Setup debug logging */
    if (debug)
    {
        serf_log_output_t *output;
        apr_status_t status;

        status = serf_logging_create_stream_output(&output,
                                                   context,
                                                   SERF_LOG_DEBUG,
                                                   SERF_LOGCOMP_ALL_MSG,
                                                   SERF_LOG_DEFAULT_LAYOUT,
                                                   stderr,
                                                   pool);

        if (!status)
            serf_logging_add_output(context, output);
    }

    /* ### Connection or Context should have an allocator? */
    app_ctx.bkt_alloc = bkt_alloc;

    connections = apr_pcalloc(pool, conn_count * sizeof(serf_connection_t*));
    for (i = 0; i < conn_count; i++)
    {
        conn_baton_t *conn_ctx = apr_pcalloc(pool, sizeof(*conn_ctx));
        conn_ctx->app = &app_ctx;
        conn_ctx->ssl_ctx = NULL;

        status = serf_connection_create2(&connections[i], context, url,
                                         conn_setup, conn_ctx,
                                         closed_connection, conn_ctx,
                                         pool);
        if (status) {
            printf("Error creating connection: %d\n", status);
            apr_pool_destroy(pool);
            exit(1);
        }

        conn_ctx->conn = connections[i];

        serf_connection_set_max_outstanding_requests(connections[i], inflight);
    }

    handler_ctx.completed_requests = 0;
    handler_ctx.print_headers = print_headers;

#if APR_VERSION_AT_LEAST(1, 3, 0)
    apr_file_open_flags_stdout(&handler_ctx.output_file, APR_BUFFERED, pool);
#else
    apr_file_open_stdout(&handler_ctx.output_file, pool);
#endif

    handler_ctx.host = url.hostinfo;
    handler_ctx.method = method;
    handler_ctx.path = apr_pstrcat(pool,
                                   url.path,
                                   url.query ? "?" : "",
                                   url.query ? url.query : "",
                                   NULL);
    handler_ctx.username = username;
    handler_ctx.password = password;
    handler_ctx.auth_attempts = 0;

    handler_ctx.req_body_path = req_body_path;

    handler_ctx.acceptor = accept_response;
    handler_ctx.acceptor_baton = &app_ctx;
    handler_ctx.handler = handle_response;
    handler_ctx.req_hdrs = req_hdrs;

    for (i = 0; i < count; i++) {
        /* We don't need the returned request here. */
        serf_connection_request_create(connections[i % conn_count],
                                       setup_request, &handler_ctx);
    }

    while (1) {
        status = serf_context_run(context, SERF_DURATION_FOREVER, pool);
        if (APR_STATUS_IS_TIMEUP(status))
            continue;
        if (status) {
            char buf[200];
            const char *err_string;
            err_string = serf_error_string(status);
            if (!err_string) {
                err_string = apr_strerror(status, buf, sizeof(buf));
            }

            printf("Error running context: (%d) %s\n", status, err_string);
            apr_pool_destroy(pool);
            exit(1);
        }
        if (apr_atomic_read32(&handler_ctx.completed_requests) >= count) {
            break;
        }
        /* Debugging purposes only! */
        serf_debug__closed_conn(app_ctx.bkt_alloc);
    }

    apr_file_close(handler_ctx.output_file);

    for (i = 0; i < conn_count; i++)
    {
        serf_connection_close(connections[i]);
    }

    apr_pool_destroy(pool);
    return 0;
}
