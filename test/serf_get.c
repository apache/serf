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
    int using_ssl;
    serf_ssl_context_t *ssl_ctx;
} accept_baton_t;

static serf_bucket_t* accept_response(serf_request_t *request,
                                      apr_socket_t *socket,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;
    accept_baton_t *ctx = acceptor_baton;

    bkt_alloc = serf_request_get_alloc(request);

    c = serf_bucket_socket_create(socket, bkt_alloc);
    if (ctx->using_ssl) {
        c = serf_bucket_ssl_decrypt_create(c, ctx->ssl_ctx, bkt_alloc);
    }

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
    accept_baton_t accept_ctx;
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

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_port_of_scheme(url.scheme);
    }

    if (strcasecmp(url.scheme, "https") == 0) {
        accept_ctx.using_ssl = 1;
    }
    else {
        accept_ctx.using_ssl = 0;
    }

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
    /* Shouldn't serf do this for us? */
    serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");

    handler_ctx.requests_outstanding = 0;
    apr_atomic_inc32(&handler_ctx.requests_outstanding);

    if (accept_ctx.using_ssl) {
        req_bkt =
            serf_bucket_ssl_encrypt_create(req_bkt, NULL,
                                           serf_request_get_alloc(request));
        accept_ctx.ssl_ctx = serf_bucket_ssl_encrypt_context_get(req_bkt);
    }
    serf_request_deliver(request, req_bkt,
                         accept_response, &accept_ctx,
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
    return 0;
}
