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

/*#define PRINT_HEADERS*/

typedef struct {
    int using_ssl;
    serf_ssl_context_t *ssl_ctx;
    serf_bucket_t *bkt;
    serf_bucket_alloc_t *bkt_alloc;
} accept_baton_t;

static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    accept_baton_t *ctx = closed_baton;

    if (why) {
        abort();
    }

    if (ctx->bkt != NULL) {
        serf_bucket_destroy(ctx->bkt);
    }

}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      apr_socket_t *socket,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;
    accept_baton_t *ctx = acceptor_baton;

    bkt_alloc = serf_request_get_alloc(request);

    if (ctx->bkt == NULL) {
        c = serf_bucket_socket_create(socket, ctx->bkt_alloc);
        if (ctx->using_ssl) {
            c = serf_bucket_ssl_decrypt_create(c, ctx->ssl_ctx, ctx->bkt_alloc);
        }
        ctx->bkt = c;
    }
    else {
        c = ctx->bkt;
    }

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(c, bkt_alloc);

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
#ifdef PRINT_HEADERS
            serf_bucket_t *hdrs;
            hdrs = serf_bucket_response_get_headers(response);
            while (1) {
                status = serf_bucket_read(hdrs, 2048, &data, &len);
                if (SERF_BUCKET_READ_ERROR(status))
                    return status;

                fwrite(data, 1, len, stdout);
                if (APR_STATUS_IS_EOF(status)) {
                    break;
                }
            }
#endif
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
    apr_uri_t url;
    const char *raw_url;
    int count, i;

    if (argc < 2) {
        puts("Gimme a URL, stupid!");
        exit(-1);
    }
    raw_url = argv[1];

    if (argc >= 3) {
        errno = 0;
        count = apr_strtoi64(argv[2], NULL, 10);
        if (errno) {
            printf("Problem converting number of times to fetch URL (%d)\n",
                   errno);
            return errno;
        }
    }
    else {
        count = 1;
    }

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

    /* ### Connection or Context should have an allocator? */
    accept_ctx.bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    accept_ctx.bkt = NULL;
    accept_ctx.ssl_ctx = NULL;

    connection = serf_connection_create(context, address,
                                        closed_connection, &accept_ctx, pool);

    handler_ctx.requests_outstanding = 0;
    for (i = 0; i < count; i++) {
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

        apr_atomic_inc32(&handler_ctx.requests_outstanding);

        if (accept_ctx.using_ssl) {
            serf_bucket_alloc_t *req_alloc;

            req_alloc = serf_request_get_alloc(request);

            if (accept_ctx.ssl_ctx == NULL) {
                req_bkt =
                    serf_bucket_ssl_encrypt_create(req_bkt, NULL,
                                                   accept_ctx.bkt_alloc);
                accept_ctx.ssl_ctx =
                    serf_bucket_ssl_encrypt_context_get(req_bkt);
            }
            else {
                req_bkt =
                    serf_bucket_ssl_encrypt_create(req_bkt, accept_ctx.ssl_ctx,
                                                   accept_ctx.bkt_alloc);
            }
        }

        serf_request_deliver(request, req_bkt,
                             accept_response, &accept_ctx,
                             handle_response, &handler_ctx);
    }

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
        /* Debugging purposes only! */
        serf_debug__closed_conn(accept_ctx.bkt_alloc);
    }

    serf_connection_close(connection);

    apr_pool_destroy(pool);
    return 0;
}
