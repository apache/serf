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

static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    abort();
}

typedef struct {
    const char *resp_file;
} accept_baton_t;

static serf_bucket_t* accept_response(serf_request_t *request,
                                      void *write_baton,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    accept_baton_t *ctx = acceptor_baton;
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;
    apr_file_t *file;
    apr_pool_t *req_pool;
    apr_status_t status;

    req_pool = serf_request_get_pool(request);
    bkt_alloc = serf_request_get_alloc(request);

    status = apr_file_open(&file, ctx->resp_file,
                           APR_READ, APR_OS_DEFAULT, req_pool);
    if (status) {
        return NULL;
    }

    c = serf_bucket_file_create(file, bkt_alloc);

    return serf_bucket_response_create(c, bkt_alloc);
}

typedef struct {
    apr_uint32_t requests_outstanding;
} handler_baton_t;

static apr_status_t handle_response(serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    const char *data, *s;
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

    status = serf_bucket_read(response, 2048, &data, &len);

    if (!status || APR_STATUS_IS_EOF(status)) {
        s = apr_pstrmemdup(pool, data, len);
        printf("%s", s);
    }
    else if (APR_STATUS_IS_EAGAIN(status)) {
        status = APR_SUCCESS;
    }
    if (APR_STATUS_IS_EOF(status)) {
        apr_atomic_dec32(&ctx->requests_outstanding);
    }

    return status;
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *pool;
    apr_file_t *file;
    serf_context_t *context;
    serf_connection_t *connection;
    serf_request_t *request;
    serf_bucket_t *req_bkt;
    accept_baton_t accept_ctx;
    handler_baton_t handler_ctx;
    apr_uri_t url;
    const char *raw_url;
    const char *req_file;
    const char *resp_file;

    if (argc != 4) {
        printf("%s: [URL] [Req. File] [Resp. File]\n", argv[0]);
        exit(-1);
    }
    raw_url = argv[1];
    req_file = argv[2];
    accept_ctx.resp_file = argv[3];

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    apr_atomic_init(pool);
    /* serf_initialize(); */

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_port_of_scheme(url.scheme);
    }

    status = apr_file_open(&file, req_file,
                           APR_WRITE|APR_CREATE|APR_DELONCLOSE,
                           APR_OS_DEFAULT, pool);

    if (status) {
        printf("Error creating file: %s %d\n", req_file, status);
        exit(1);
    }

    context = serf_context_create(pool);

    connection =
        serf_connection_create_ex(context, 
                                  (serf_connection_write_t)apr_file_write,
                                  file, closed_connection, NULL, pool);
    request = serf_connection_request_create(connection);

    req_bkt = serf_bucket_request_create("GET", url.path, NULL,
                                         serf_request_get_alloc(request));

    /* FIXME: Shouldn't we be able to figure out the host ourselves? */
    serf_bucket_set_metadata(req_bkt, SERF_REQUEST_HEADERS, "Host",
                             url.hostinfo);
    serf_bucket_set_metadata(req_bkt, SERF_REQUEST_HEADERS, "User-Agent",
                             "Serf/" SERF_VERSION_STRING);

    handler_ctx.requests_outstanding = 0;
    apr_atomic_inc32(&handler_ctx.requests_outstanding);
    serf_request_deliver(request, req_bkt,
                         accept_response, &accept_ctx,
                         handle_response, &handler_ctx);

    while (1) {
        status = serf_context_run(context, SERF_DURATION_FOREVER, pool);
        if (APR_STATUS_IS_TIMEUP(status))
            continue;
        if (status) {
            printf("Error running context: %d\n", status);
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
