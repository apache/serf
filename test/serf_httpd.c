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

typedef struct app_ctx_t {
    int foo;
    apr_pool_t *pool;
} app_ctx_t;

typedef struct listener_ctx_t {
    app_ctx_t *app;
    const char *proto;

} listener_ctx_t;

typedef struct client_ctx_t {
    listener_ctx_t *listener;
    apr_pool_t *pool;
    serf_bucket_alloc_t *alloc;
} client_ctx_t;

typedef struct request_ctx_t {
    client_ctx_t *client;
    apr_pool_t *pool;
    serf_bucket_t *headers;
    const char *method;
    const char *path;
    int http_version;
} request_ctx_t;

static apr_status_t client_setup(apr_socket_t *skt,
                                 serf_bucket_t **read_bkt,
                                 serf_bucket_t **write_bkt,
                                 void *setup_baton,
                                 apr_pool_t *pool)
{
    client_ctx_t *cctx = setup_baton;
    if (cctx->alloc == NULL)
        cctx->alloc = serf_bucket_allocator_create(cctx->pool, NULL, NULL);

    *read_bkt = serf_bucket_socket_create(skt, cctx->alloc);
    return APR_SUCCESS;
}

static apr_status_t client_closed(serf_incoming_t *incoming,
                                  void *closed_baton,
                                  apr_status_t why,
                                  apr_pool_t *pool)
{
    client_ctx_t *cctx = closed_baton;
    apr_pool_destroy(cctx->pool);
    return APR_SUCCESS;
}

static apr_status_t request_handler(serf_incoming_request_t *req,
                                    serf_bucket_t *request,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    request_ctx_t *rctx = handler_baton;
    apr_status_t status;

    if (!rctx->method) {
        status = serf_bucket_incoming_request_read(&rctx->headers,
                                                   &rctx->method,
                                                   &rctx->path,
                                                   &rctx->http_version,
                                                   request);
        if (status) {
            rctx->method = NULL;
            return status;
        }
    }

    status = serf_bucket_incoming_request_wait_for_headers(request);
    if (status)
        return status;

    status = serf_incoming_response_create(req);
    if (status)
        return status;

    do
    {
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(request, SERF_READ_ALL_AVAIL, &data, &len);
    } while (status == APR_SUCCESS);

    return status;
}

static apr_status_t request_generate_response(serf_bucket_t **resp_bkt,
                                              serf_incoming_request_t *req,
                                              void *setup_baton,
                                              serf_bucket_alloc_t *alloc,
                                              apr_pool_t *pool)
{
    request_ctx_t *rctx = setup_baton;
    serf_bucket_t *agg = serf_bucket_aggregate_create(alloc);
    serf_bucket_t *body;
    serf_bucket_t *tmp;
#define CRLF "\r\n"

    tmp = SERF_BUCKET_SIMPLE_STRING("HTTP/1.1 200 OK" CRLF, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    tmp = SERF_BUCKET_SIMPLE_STRING("Transfer-Encoding: chunked" CRLF, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    tmp = SERF_BUCKET_SIMPLE_STRING("Content-Type: text/plain" CRLF, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    tmp = SERF_BUCKET_SIMPLE_STRING(CRLF, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    body = serf_bucket_aggregate_create(alloc);

    if (rctx->method)
    {
        tmp = SERF_BUCKET_SIMPLE_STRING("Method: ", alloc);
        serf_bucket_aggregate_append(body, tmp);

        tmp = serf_bucket_simple_copy_create(rctx->method, strlen(rctx->method), alloc);
        serf_bucket_aggregate_append(body, tmp);

        tmp = SERF_BUCKET_SIMPLE_STRING(CRLF "Path: ", alloc);
        serf_bucket_aggregate_append(body, tmp);

        tmp = serf_bucket_simple_copy_create(rctx->path, strlen(rctx->path), alloc);
        serf_bucket_aggregate_append(body, tmp);

        tmp = SERF_BUCKET_SIMPLE_STRING(CRLF, alloc);
        serf_bucket_aggregate_append(body, tmp);
    }

    tmp = SERF_BUCKET_SIMPLE_STRING(CRLF, alloc);
    serf_bucket_aggregate_append(body, tmp);

    tmp = serf_bucket_chunk_create(body, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    tmp = SERF_BUCKET_SIMPLE_STRING(CRLF, alloc);
    serf_bucket_aggregate_append(agg, tmp);

    *resp_bkt = agg;
    return APR_SUCCESS;
}

static apr_status_t client_request_acceptor(serf_bucket_t **req_bkt,
                                            serf_bucket_t *stream,
                                            serf_incoming_request_t *req,
                                            void *request_baton,
                                            serf_incoming_request_handler_t *handler,
                                            void **handler_baton,
                                            serf_incoming_response_setup_t *response_setup,
                                            void **response_setup_baton,
                                            apr_pool_t *pool)
{
    client_ctx_t *cctx = request_baton;
    apr_pool_t *request_pool;
    request_ctx_t *rctx;

    *req_bkt = serf_bucket_incoming_request_create(stream, stream->allocator);

    apr_pool_create(&request_pool, cctx->pool);

    rctx = apr_pcalloc(request_pool, sizeof(*rctx));
    rctx->client = cctx;

    *handler = request_handler;
    *handler_baton = rctx;

    *response_setup = request_generate_response;
    *response_setup_baton = rctx;

    return APR_SUCCESS;
}


static apr_status_t client_accept(serf_context_t *ctx,
                                  serf_listener_t *l,
                                  void *accept_baton,
                                  apr_socket_t *insock,
                                  apr_pool_t *pool)
{
    serf_incoming_t *incoming;
    listener_ctx_t *lctx = accept_baton;
    apr_pool_t *cctx_pool;
    client_ctx_t *cctx;

    apr_pool_create(&cctx_pool, pool);
    cctx = apr_pcalloc(cctx_pool, sizeof(*cctx));
    cctx->pool = cctx_pool;
    cctx->listener = lctx;

    return serf_incoming_create2(&incoming, ctx, insock,
                                 client_setup, cctx,
                                 client_closed, cctx,
                                 client_request_acceptor, cctx,
                                 pool);
}


/* Value for 'no short code' should be > 255 */
#define CERTFILE 256
#define CERTPWD  257
#define HTTP2FLAG 258
#define H2DIRECT 259

static const apr_getopt_option_t options[] =
{

    { "help",    'h', 0, "Display this help" },
    { NULL,      'v', 0, "Display version" },
    { "listen",  'l', 1, "<[protocol,][host:]port> Configure listener"},
/*    { NULL,      'H', 0, "Print response headers" },
    { NULL,      'n', 1, "<count> Fetch URL <count> times" },
    { NULL,      'c', 1, "<count> Use <count> concurrent connections" },
    { NULL,   'x', 1, "<count> Number of maximum outstanding requests inflight" },
    { "user",    'U', 1, "<user> Username for Basic/Digest authentication" },
    { "pwd",     'P', 1, "<password> Password for Basic/Digest authentication" },
    { NULL,      'm', 1, "<method> Use the <method> HTTP Method" },
    { NULL,      'f', 1, "<file> Use the <file> as the request body" },
    { NULL,      'p', 1, "<hostname:port> Use the <host:port> as proxy server" },
    { "cert",    CERTFILE, 1, "<file> Use SSL client certificate <file>" },
    { "certpwd", CERTPWD, 1, "<password> Password for the SSL client certificate" },
    { NULL,      'r', 1, "<header:value> Use <header:value> as request header" },
    { "debug",   'd', 0, "Enable debugging" },
    { "http2",   HTTP2FLAG, 0, "Enable http2 (https only) (Experimental)" },
    { "h2direct",H2DIRECT, 0, "Enable h2direct (Experimental)" },*/

    { NULL, 0 }
};

static void print_usage(apr_pool_t *pool)
{
    int i = 0;

    puts("serf_httpd [options] directory\n");
    puts("Options:");

    while (options[i].optch > 0) {
        const apr_getopt_option_t* o = &options[i];

        if (o->optch <= 255) {
            printf(" -%c", o->optch);
            if (o->name)
                printf(", ");
        }
        else {
            printf("     ");
        }

        printf("%s%s\t%s\n",
               o->name ? "--" : "\t",
               o->name ? o->name : "",
               o->description);

        i++;
    }
}

void configure_listener(serf_context_t *ctx,
                        app_ctx_t *app,
                        const char *arg,
                        apr_pool_t *pool)
{
    const char *listen_spec;
    char *addr = NULL;
    char *scope_id = NULL;
    apr_port_t port;
    apr_status_t status;
    listener_ctx_t *lctx;
    serf_listener_t *listener;

    char *comma = strchr(arg, ',');

    listen_spec = comma ? comma + 1 : arg;

    status = apr_parse_addr_port(&addr, &scope_id, &port, listen_spec, pool);
    if (status) {
        printf("Error parsing listen address: %s\n", listen_spec);
        exit(1);
    }

    if (!addr) {
        addr = "0.0.0.0";
    }

    if (port == 0) {
        port = 8080;
    }

    lctx = apr_pcalloc(pool, sizeof(*lctx));
    lctx->app = app;

    if (comma)
        lctx->proto = apr_pstrmemdup(pool, arg, comma - arg);

    status = serf_listener_create(&listener, ctx, addr, port, lctx,
                                  client_accept, pool);
    if (status) {
        printf("Error creating listener '%s': %d", listen_spec, status);
        exit(1);
    }
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *app_pool;
    apr_pool_t *scratch_pool;
    serf_context_t *context;
    app_ctx_t app_ctx;
    apr_getopt_t *opt;
    int opt_c;
    const char *opt_arg;
    const char *root_dir;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&app_pool, NULL);
    apr_pool_create(&scratch_pool, app_pool);

    apr_getopt_init(&opt, scratch_pool, argc, argv);
    context = serf_context_create(app_pool);

    apr_getopt_init(&opt, scratch_pool, argc, argv);
    while ((status = apr_getopt_long(opt, options, &opt_c, &opt_arg)) ==
           APR_SUCCESS) {
        switch (opt_c) {
            case 'h':
                print_usage(scratch_pool);
                exit(0);
                break;
            case 'v':
                puts("Serf version: " SERF_VERSION_STRING);
                exit(0);
            case 'l':
                configure_listener(context, &app_ctx, opt_arg, app_pool);
                break;
            default:
                break;
        }
    }

    if (opt->ind != opt->argc - 1) {
        print_usage(scratch_pool);
        exit(-1);
    }

    root_dir = argv[opt->ind];

    while (1) {
        apr_pool_clear(scratch_pool);
        status = serf_context_run(context, SERF_DURATION_FOREVER, scratch_pool);
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
            apr_pool_destroy(app_pool);
            exit(1);
        }
    }

    apr_pool_destroy(app_pool);
    return 0;
}
