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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"

typedef struct prefix_context_t {
    serf_bucket_t *stream;
    apr_size_t prefix_len;
    apr_size_t read_len;

    serf_bucket_prefix_handler_t handler;
    void *handler_baton;

    char *buffer;
} prefix_context_t;


serf_bucket_t *serf_bucket_prefix_create(serf_bucket_t *stream,
                                         apr_size_t prefix_len,
                                         serf_bucket_prefix_handler_t handler,
                                         void *handler_baton,
                                         serf_bucket_alloc_t *allocator)
{
    prefix_context_t *ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));

    ctx->stream = stream;
    ctx->prefix_len = prefix_len;
    ctx->read_len = 0;

    ctx->handler = handler;
    ctx->handler_baton = handler_baton;

    ctx->buffer = NULL;

    return serf_bucket_create(&serf_bucket_type_prefix, allocator, ctx);
}

static apr_status_t read_prefix(serf_bucket_t *bucket)
{
    prefix_context_t *ctx = bucket->data;
    const char *data;
    apr_size_t len;
    apr_status_t status;

    if (!ctx->read_len) {

        /* Perhaps we can handle this without copying any data? */
        status = serf_bucket_read(ctx->stream, ctx->prefix_len, &data,
                                  &len);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        if (APR_STATUS_IS_EOF(status) || (len == ctx->prefix_len)) {
            apr_status_t cb_status;

            /* Prefix reading is done */
            ctx->prefix_len = 0;

            cb_status = ctx->handler(ctx->handler_baton, ctx->stream,
                                     data, len);

            if (SERF_BUCKET_READ_ERROR(cb_status))
                return cb_status;

            return status;
        }
        else if (len == 0) {
            /* Nothing read at all. Try again later */
            return APR_EAGAIN;
        }

        /* Create a buffer to hold what we already read */
        ctx->buffer = serf_bucket_mem_alloc(bucket->allocator, ctx->prefix_len);
        memcpy(ctx->buffer, data, len);
        ctx->read_len = len;

        if (status)
            return status;

        /* Else: Try filling the rest of the buffer */
    }

    while (TRUE) {

        status = serf_bucket_read(ctx->stream, ctx->prefix_len - ctx->read_len,
                                  &data, &len);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        memcpy(ctx->buffer + ctx->read_len, data, len);
        ctx->read_len += len;

        if (APR_STATUS_IS_EOF(status) || (ctx->prefix_len == ctx->read_len)) {
            apr_status_t cb_status;

            /* Prefix reading is done */
            ctx->prefix_len = 0;

            cb_status = ctx->handler(ctx->handler_baton, ctx->stream,
                                     ctx->buffer, ctx->read_len);

            serf_bucket_mem_free(bucket->allocator, ctx->buffer);
            ctx->buffer = NULL;

            if (SERF_BUCKET_READ_ERROR(cb_status))
              return cb_status;

            return status;
        }
        else if (status)
            return status;
    }
}

static apr_status_t serf_prefix_read(serf_bucket_t *bucket,
                                     apr_size_t requested,
                                     const char **data,
                                     apr_size_t *len)
{
    prefix_context_t *ctx = bucket->data;

    if (ctx->prefix_len) {
        apr_status_t status = read_prefix(bucket);

        if (status) {
            *len = 0;
            return status;
        }
    }

    return serf_bucket_read(ctx->stream, requested, data, len);
}

static apr_status_t serf_prefix_read_iovec(serf_bucket_t *bucket,
                                           apr_size_t requested,
                                           int vecs_size,
                                           struct iovec *vecs,
                                           int *vecs_used)
{
    prefix_context_t *ctx = bucket->data;

    if (ctx->prefix_len) {
        apr_status_t status = read_prefix(bucket);

        if (status) {
            *vecs_used = 0;
            return status;
        }
    }

    return serf_bucket_read_iovec(ctx->stream, requested, vecs_size,
                                  vecs, vecs_used);
}

static apr_status_t serf_prefix_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    prefix_context_t *ctx = bucket->data;

    if (ctx->prefix_len) {
        apr_status_t status = read_prefix(bucket);

        if (status) {
            *len = 0;
            return status;
        }
    }

    return serf_bucket_peek(ctx->stream, data, len);
}

static apr_uint64_t serf_prefix_get_remaining(serf_bucket_t *bucket)
{
    prefix_context_t *ctx = bucket->data;
    apr_uint64_t remaining;

    remaining = serf_bucket_get_remaining(ctx->stream);

    if (remaining != SERF_LENGTH_UNKNOWN && ctx->prefix_len) {
        remaining -= (ctx->prefix_len - ctx->read_len);
    }

    return remaining;
}

static apr_status_t serf_prefix_set_config(serf_bucket_t *bucket,
                                           serf_config_t *config)
{
    prefix_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

static void serf_prefix_destroy(serf_bucket_t *bucket)
{
    prefix_context_t *ctx = bucket->data;

    if (ctx->buffer)
        serf_bucket_mem_free(bucket->allocator, ctx->buffer);

    serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_prefix = {
    "prefix",
    serf_prefix_read,
    serf_default_readline,
    serf_prefix_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_prefix_peek,
    serf_prefix_destroy,
    serf_default_read_bucket,
    serf_default_readline2,
    serf_prefix_get_remaining,
    serf_prefix_set_config
};


