/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <apr.h>
#include <apr_uri.h>
#include <apr_strings.h>
#include <apr_atomic.h>

#include "serf.h"

#define SERF_VERSION_STRING "0.01"

#if 0

#include "serf_filters.h"
#include "serf_version.h"

#define CRLF "\r\n"

/* Yes, it'd be nice if these were command-line options... */
/* Define this to 1 to print out header information. */
#define SERF_GET_DEBUG 0
/* httpd-2.0 is cute WRT chunking and will only do it on a keep-alive.
 * Define this to 1 to test serf's ability to handle chunking.
 */
#define SERF_GET_TEST_CHUNKING 0 

static apr_status_t print_bucket(apr_bucket *bucket, apr_file_t *file)
{
    const char *buf;
    apr_size_t length, written;
    apr_status_t status;
        
    status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

    if (status) {
        return status;
    }

    return apr_file_write_full(file, buf, length, &written);
}

static apr_status_t http_source(apr_bucket_brigade *brigade,
                                serf_request_t *request,
                                apr_pool_t *pool)
{
    apr_bucket *bucket;

    bucket = serf_bucket_request_line_create(request->method,
                                             request->uri->path,
                                             "HTTP/1.1", pool,
                                             brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_HEAD(brigade, bucket);

#if !SERF_GET_TEST_CHUNKING
    bucket = serf_bucket_header_create("Connection",
                                       "Close",
                                       pool, brigade->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
#endif

    return APR_SUCCESS;
}

static apr_status_t host_header_filter(apr_bucket_brigade *brigade,
                                       serf_filter_t *filter,
                                       apr_pool_t *pool)
{
    apr_bucket *bucket;
    serf_request_t *request = filter->ctx;

    bucket = serf_bucket_header_create("Host",
                                       request->uri->hostname,
                                       pool, brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t user_agent_filter(apr_bucket_brigade *brigade,
                                      serf_filter_t *filter,
                                      apr_pool_t *pool)
{
    apr_bucket *bucket;

    bucket = serf_bucket_header_create("User-Agent",
                                       "Serf " SERF_VERSION_STRING,
                                       pool, brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t http_headers_filter(apr_bucket_brigade *brigade,
                                        serf_filter_t *filter,
                                        apr_pool_t *pool)
{
    apr_bucket *bucket;

    /* All we do here is stick CRLFs in the right places. */
    bucket = APR_BRIGADE_FIRST(brigade);
    while (bucket != APR_BRIGADE_SENTINEL(brigade)) {
        if (SERF_BUCKET_IS_REQUEST_LINE(bucket) ||
            SERF_BUCKET_IS_HEADER(bucket)) {
            apr_bucket *eol;

            eol = apr_bucket_immortal_create(CRLF, sizeof(CRLF)-1,
                                             brigade->bucket_alloc);

            APR_BUCKET_INSERT_AFTER(bucket, eol);
       }

        bucket = APR_BUCKET_NEXT(bucket);
    }

    /* FIXME: We need a way to indicate we are EOH. */
    bucket = apr_bucket_immortal_create(CRLF, sizeof(CRLF)-1,
                                        brigade->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t debug_request(apr_bucket_brigade *brigade,
                                  serf_filter_t *filter,
                                  apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {

        status = print_bucket(bucket, out_file);
        if (status) {
            return status;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t debug_response(apr_bucket_brigade *brigade,
                                   serf_filter_t *filter,
                                   apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    /* Print the STATUS bucket first. */ 
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (SERF_BUCKET_IS_STATUS(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
            status = apr_file_putc('\n', out_file);
            if (status) {
                return status;
            }
        } 
    }

    /* Now, print all headers.  */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (SERF_BUCKET_IS_HEADER(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
            status = apr_file_putc('\n', out_file);
            if (status) {
                return status;
            }
        } 
    }

    /* Print a separator line. */
    status = apr_file_putc('\n', out_file);
    if (status) {
        return status;
    }

    return APR_SUCCESS;
}

static apr_status_t http_handler(serf_response_t *response, apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    /* Print anything that isn't metadata. */
    for (bucket = APR_BRIGADE_FIRST(response->entity);
         bucket != APR_BRIGADE_SENTINEL(response->entity);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (!APR_BUCKET_IS_METADATA(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
        }
    }

    apr_brigade_cleanup(response->entity);

    return APR_SUCCESS;
}

#endif /* 0 */


static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    abort();
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      apr_socket_t *socket,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;

    bkt_alloc = serf_request_get_alloc(request);

    c = serf_bucket_socket_create(socket, bkt_alloc);

    return serf_bucket_response_create(c, bkt_alloc);
}

typedef struct {
    apr_uint32_t requests_outstanding;
} handler_baton_t;

static apr_status_t handle_response(serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    const char *data;
    apr_size_t len;
    serf_status_line sl;
    apr_status_t status;
    handler_baton_t *ctx = handler_baton;

    status = serf_bucket_response_status(response, &sl);
    if (status) {
        if (APR_STATUS_IS_EAGAIN(status)) {
            return APR_SUCCESS;
        }
        abort();
    }

    while (1) {
        status = serf_bucket_read(response, 2048, &data, &len);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* got some data. print it out. */
        fwrite(data, 1, len, stdout);

        /* are we done yet? */
        if (APR_STATUS_IS_EOF(status)) {
            apr_atomic_dec32(&ctx->requests_outstanding);
            return APR_EOF;
        }

        /* have we drained the response so far? */
        if (APR_STATUS_IS_EAGAIN(status))
            return APR_SUCCESS;

        /* loop to read some more. */
    }
    /* NOTREACHED */
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *pool;
    apr_sockaddr_t *address;
    serf_context_t *context;
    serf_connection_t *connection;
    serf_request_t *request;
    serf_bucket_t *req_bkt;
    serf_bucket_t *hdrs_bkt;
    handler_baton_t handler_ctx;
#if 0
    serf_filter_t *filter;
#endif /* 0 */
    apr_uri_t url;
    const char *raw_url;
#if 0
    int using_ssl = 0;
#endif /* 0 */

    if (argc != 2) {
        puts("Gimme a URL, stupid!");
        exit(-1);
    }
    raw_url = argv[1];

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    apr_atomic_init(pool);
    /* serf_initialize(); */

#if 0
    serf_register_filter("SOCKET_WRITE", serf_socket_write, pool);
    serf_register_filter("SOCKET_READ", serf_socket_read, pool);

#if SERF_HAS_OPENSSL
    serf_register_filter("SSL_WRITE", serf_ssl_write, pool);
    serf_register_filter("SSL_READ", serf_ssl_read, pool);
#endif

    serf_register_filter("USER_AGENT", user_agent_filter, pool);
    serf_register_filter("HOST_HEADER", host_header_filter, pool);
    serf_register_filter("HTTP_HEADERS_OUT", http_headers_filter, pool);

    serf_register_filter("HTTP_STATUS_IN", serf_http_status_read, pool);
    serf_register_filter("HTTP_HEADERS_IN", serf_http_header_read, pool);
    serf_register_filter("HTTP_DECHUNK", serf_http_dechunk, pool);

    serf_register_filter("DEFLATE_SEND_HEADER", serf_deflate_send_header, pool);
    serf_register_filter("DEFLATE_READ", serf_deflate_read, pool);

    serf_register_filter("DEBUG_REQUEST", debug_request, pool);
    serf_register_filter("DEBUG_RESPONSE", debug_response, pool);

    /*
    serf_register_filter("DEFLATE_READ", serf_deflate_read, pool);
    */
#endif /* 0 */

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_port_of_scheme(url.scheme);
    }
#if SERF_HAS_OPENSSL
    if (strcasecmp(url.scheme, "https") == 0) {
        using_ssl = 1;
    }
#endif

    status = apr_sockaddr_info_get(&address,
                                   url.hostname, APR_UNSPEC, url.port, 0,
                                   pool);
    if (status) {
        printf("Error creating address: %d\n", status);
        exit(1);
    }

    context = serf_context_create(pool);

    connection = serf_connection_create(context, address,
                                        closed_connection, NULL, pool);
    request = serf_connection_request_create(connection);

    req_bkt = serf_bucket_request_create("GET", url.path, NULL,
                                         serf_request_get_alloc(request));

    hdrs_bkt = serf_bucket_request_get_headers(req_bkt);

    /* FIXME: Shouldn't we be able to figure out the host ourselves? */
    serf_bucket_headers_setn(hdrs_bkt, "Host", url.hostinfo);
    serf_bucket_headers_setn(hdrs_bkt, "User-Agent",
                             "Serf/" SERF_VERSION_STRING);

    handler_ctx.requests_outstanding = 0;
    apr_atomic_inc32(&handler_ctx.requests_outstanding);
    serf_request_deliver(request, req_bkt,
                         accept_response, NULL,
                         handle_response, &handler_ctx);

    while (1) {
        status = serf_context_run(context, SERF_DURATION_FOREVER, pool);
        if (APR_STATUS_IS_TIMEUP(status))
            continue;
        if (status) {
            char buf[200];

            printf("Error running context: (%d) %s\n", status,
                   apr_strerror(status, buf, sizeof(buf)));
            exit(1);
        }
        if (!apr_atomic_read32(&handler_ctx.requests_outstanding)) {
            break;
        }
    }

    apr_pool_destroy(pool);
#if 0
    status = serf_open_uri(url, &connection, &request, pool);

    if (status) {
        printf("Error opening uri: %d\n", status);
        exit(1);
    }

    request->source = http_source;
    request->handler = http_handler;

    request->method = "GET";
    request->uri = url;

    /* FIXME: Get serf to install an endpoint which has access to the conn. */
    if (using_ssl) {
        filter = serf_add_filter(connection->request_filters, 
                                 "SSL_WRITE", pool);
        filter->ctx = connection;

        filter = serf_add_filter(connection->response_filters, 
                                 "SSL_READ", pool);
        filter->ctx = connection;
    }
    else {
        filter = serf_add_filter(connection->request_filters, 
                                 "SOCKET_WRITE",
                                 pool);
        filter->ctx = connection;

        filter = serf_add_filter(connection->response_filters, 
                                 "SOCKET_READ", pool);
        filter->ctx = connection;
    }
#if SERF_GET_DEBUG
    filter = serf_add_filter(connection->request_filters, "DEBUG_REQUEST", pool);
#endif

    filter = serf_add_filter(request->request_filters, "USER_AGENT", pool);
    filter = serf_add_filter(request->request_filters, "HOST_HEADER", pool);
    filter->ctx = request;
    filter = serf_add_filter(request->request_filters, "DEFLATE_SEND_HEADER",
                             pool);
    filter = serf_add_filter(request->request_filters, "HTTP_HEADERS_OUT",
                             pool);

    /* Now add the response filters. */
    filter = serf_add_filter(request->response_filters, "HTTP_STATUS_IN",
                             pool);
    filter = serf_add_filter(request->response_filters, "HTTP_HEADERS_IN",
                             pool);
    filter = serf_add_filter(request->response_filters, "HTTP_DECHUNK",
                             pool);
    filter = serf_add_filter(request->response_filters, "DEFLATE_READ",
                             pool);
#if SERF_GET_DEBUG
    filter = serf_add_filter(request->response_filters, "DEBUG_RESPONSE",
                             pool);
#endif

    status = serf_open_connection(connection);
    if (status) {
        printf("Error opening connection: %d\n", status);
        exit(1);
    }

    status = serf_write_request(request, connection);

    if (status) {
        printf("Error writing request: %d\n", status);
        exit(1);
    }

    status = serf_read_response(&response, connection, pool);

    if (status) {
        printf("Error reading response: %d\n", status);
        exit(1);
    }
#endif /* 0 */

    return 0;
}
