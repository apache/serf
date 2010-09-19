/* Copyright 2010 Justin Erenkrantz and Greg Stein
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

#include "serf.h"
#include "serf_bucket_util.h"

#include <apr_version.h>

typedef struct {
    /* Temporary store of (pointers to) data that's read from the
       output stream but not yet send over the socket. */
    struct iovec vec[IOV_MAX];
    int vec_len;

    /* Address of the destination server */
    apr_sockaddr_t *serv_addr;

    /* Address of a proxy server, NULL if not used. */
    apr_sockaddr_t *proxy_addr;

    /* client socket pointer */
    apr_socket_t *skt;

    /* Pool in which the socket is allocated. */
    apr_pool_t *skt_pool;

    /* Output stream, we read data from this bucket to send over the
       socket. */
    serf_bucket_t *ostream;
    /* Input stream, provided by the user, wraps a socket.
       (normally *skt, but that's not guaranteed. */
    serf_bucket_t *stream;
} httpconn_context_t;

/**
 * httpconn buckets manage a socket.
 *
 * Users should set a stream (probably a socket_bucket, or an ssl_bucket that
 * wraps the socket_bucket) that's used to read from the socket.
 *
 * This bucket can read from an output stream and write that data on the socket.
 */
serf_bucket_t *serf_bucket_httpconn_create(serf_bucket_alloc_t *allocator,
                                           apr_sockaddr_t *serv_addr,
                                           apr_sockaddr_t *proxy_addr,
                                           apr_pool_t *pool)
{
    httpconn_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));

    ctx->vec_len = 0;
    ctx->serv_addr = serv_addr;
    ctx->proxy_addr = proxy_addr;
    apr_pool_create(&ctx->skt_pool, pool);

    return serf_bucket_create(&serf_bucket_type_httpconn, allocator, ctx);
}

void serf_httpconn_set_streams(serf_bucket_t *bucket,
                               serf_bucket_t *stream,
                               serf_bucket_t *ostream)
{
    httpconn_context_t *ctx = bucket->data;

    ctx->stream = stream;
    ctx->ostream = ostream;
}

/* cleanup handler for the socket */
static apr_status_t clean_skt(void* data)
{
    serf_bucket_t *bucket = data;
    httpconn_context_t *ctx = bucket->data;
    apr_status_t status;

    if (ctx->skt) {
        status = apr_socket_close(ctx->skt);
        ctx->skt = NULL;
        return status;
    }

    return APR_SUCCESS;
}

apr_status_t serf_httpconn_connect(serf_bucket_t* bucket)
{
    httpconn_context_t *ctx = bucket->data;
    apr_status_t status;
    apr_sockaddr_t *serv_addr;

    if (ctx->proxy_addr)
        serv_addr = ctx->proxy_addr;
    else
        serv_addr = ctx->serv_addr;

    if ((status = apr_socket_create(&ctx->skt, serv_addr->family,
                                    SOCK_STREAM,
#if APR_MAJOR_VERSION > 0
                                    APR_PROTO_TCP,
#endif
                                    ctx->skt_pool)) != APR_SUCCESS)
        return status;

    apr_pool_cleanup_register(ctx->skt_pool, bucket, clean_skt, clean_skt);

    /* Set the socket to be non-blocking */
    if ((status = apr_socket_timeout_set(ctx->skt, 0)) != APR_SUCCESS)
        return status;

    /* Disable Nagle's algorithm */
    if ((status = apr_socket_opt_set(ctx->skt,
                                     APR_TCP_NODELAY, 0)) != APR_SUCCESS)
        return status;

    /* Now that the socket is set up, let's connect it. This should
     * return immediately.
     */
    if ((status = apr_socket_connect(ctx->skt,
                                     serv_addr)) != APR_SUCCESS) {
        if (!APR_STATUS_IS_EINPROGRESS(status))
            return status;
    }

    return APR_SUCCESS;
}

apr_status_t serf_httpconn_close(serf_bucket_t *bucket)
{
    httpconn_context_t *ctx = bucket->data;
    apr_status_t status;

    if (ctx->skt) {
        status = apr_socket_close(ctx->skt);
        ctx->skt = NULL;
        apr_pool_clear(ctx->skt_pool);
        return status;
    }

    return APR_SUCCESS;
}

/* Writes any pointer/length pairs currently stored in the bucket over the socket. */
static apr_status_t socket_writev(serf_bucket_t *bucket, apr_size_t *written)
{
    httpconn_context_t *ctx = bucket->data;
    apr_status_t status;

    status = apr_socket_sendv(ctx->skt, ctx->vec,
                              ctx->vec_len, written);

    /* did we write everything? */
    if (*written) {
        apr_size_t len = 0;
        int i;

        for (i = 0; i < ctx->vec_len; i++) {
            len += ctx->vec[i].iov_len;
            if (*written < len) {
                if (i) {
                    memmove(ctx->vec, &ctx->vec[i],
                            sizeof(struct iovec) * (ctx->vec_len - i));
                    ctx->vec_len -= i;
                }
                ctx->vec[0].iov_base = (char *)ctx->vec[0].iov_base + (ctx->vec[0].iov_len - (len - *written));
                ctx->vec[0].iov_len = len - *written;
                break;
            }
        }
        if (len == *written) {
            ctx->vec_len = 0;
        }
    }

    return status;
}

void serf_httpconn_clear_state(serf_bucket_t *bucket)
{
    httpconn_context_t *ctx = bucket->data;

    ctx->vec_len = 0;
}

int serf_httpconn_unwritten_data(serf_bucket_t *bucket)
{
    httpconn_context_t *ctx = bucket->data;

    return ctx->vec_len > 0;
}

apr_socket_t *serf_httpconn_socket(serf_bucket_t *bucket)
{
    httpconn_context_t *ctx = bucket->data;

    return ctx->skt;
}

apr_status_t serf_httpconn_write_iovec(serf_bucket_t *bucket,
                                       apr_status_t *read_status,
                                       apr_size_t *written)
{
    apr_status_t status = 0;
    httpconn_context_t *ctx = bucket->data;

    if (!ctx->ostream)
        return APR_EGENERAL;

    /* ### optimize at some point by using read_for_sendfile */
    if (ctx->vec_len == 0) {
        *read_status = serf_bucket_read_iovec(ctx->ostream,
                                              SERF_READ_ALL_AVAIL,
                                              IOV_MAX,
                                              ctx->vec,
                                              &ctx->vec_len);
        if (SERF_BUCKET_READ_ERROR(*read_status))
            return *read_status;
    }

    /* If we got some data, then deliver it. */
    if (ctx->vec_len > 0)
        return socket_writev(bucket, written);

    return APR_SUCCESS;
}

static apr_status_t serf_httpconn_read(serf_bucket_t *bucket,
                                       apr_size_t requested,
                                       const char **data, apr_size_t *len)
{
    httpconn_context_t *ctx = bucket->data;

    return serf_bucket_read(ctx->stream, requested, data, len);
}

static apr_status_t serf_httpconn_read_iovec(serf_bucket_t *bucket,
                                             apr_size_t requested,
                                             int vecs_size, struct iovec *vecs,
                                             int *vecs_used)
{
    httpconn_context_t *ctx = bucket->data;

    return serf_bucket_read_iovec(ctx->stream, requested, vecs_size, vecs,
                                  vecs_used);
}

static apr_status_t serf_httpconn_readline(serf_bucket_t *bucket,
                                           int acceptable, int *found,
                                           const char **data, apr_size_t *len)
{
    httpconn_context_t *ctx = bucket->data;

    return serf_bucket_readline(ctx->stream, acceptable, found, data, len);
}

static apr_status_t serf_httpconn_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    httpconn_context_t *ctx = bucket->data;

    return serf_bucket_peek(ctx->stream, data, len);
}

static void serf_httpconn_destroy_and_data(serf_bucket_t *bucket)
{
    httpconn_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->stream);
    serf_bucket_destroy(ctx->ostream);

    serf_default_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_httpconn = {
    "HTTPCONN",
    serf_httpconn_read,
    serf_httpconn_readline,
    serf_httpconn_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_httpconn_peek,
    serf_httpconn_destroy_and_data,
    serf_default_snapshot,
    serf_default_restore_snapshot,
    serf_default_is_snapshot_set,
};
