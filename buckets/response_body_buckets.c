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

/* Older versions of APR do not have this macro.  */
#ifdef APR_SIZE_MAX
#define REQUESTED_MAX APR_SIZE_MAX
#else
#define REQUESTED_MAX (~((apr_size_t)0))
#endif


typedef struct body_context_t {
    serf_bucket_t *stream;
    apr_uint64_t remaining;
} body_context_t;

serf_bucket_t *serf_bucket_response_body_create(
    serf_bucket_t *stream, apr_uint64_t len, serf_bucket_alloc_t *allocator)
{
    body_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->remaining = len;

    return serf_bucket_create(&serf_bucket_type_response_body, allocator, ctx);
}

static apr_status_t serf_response_body_read(serf_bucket_t *bucket,
                                            apr_size_t requested,
                                            const char **data,
                                            apr_size_t *len)
{
    body_context_t *ctx = bucket->data;
    apr_status_t status;

    if (!ctx->remaining) {
        *len = 0;
        return APR_EOF;
    }

    if (requested == SERF_READ_ALL_AVAIL || requested > ctx->remaining) {
        if (ctx->remaining <= REQUESTED_MAX) {
            requested = (apr_size_t) ctx->remaining;
        } else {
            requested = REQUESTED_MAX;
        }
    }

    status = serf_bucket_read(ctx->stream, requested, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        ctx->remaining -= *len;

        if (!ctx->remaining)
            status = APR_EOF;
        else if (APR_STATUS_IS_EOF(status) && ctx->remaining > 0) {
            /* The server sent less data than expected. */
            status = SERF_ERROR_TRUNCATED_HTTP_RESPONSE;
        }
    }

    return status;
}

static apr_status_t serf_response_body_read_iovec(serf_bucket_t *bucket,
                                                  apr_size_t requested,
                                                  int vecs_size,
                                                  struct iovec *vecs,
                                                  int *vecs_used)
{
    body_context_t *ctx = bucket->data;
    apr_status_t status;

    if (!ctx->remaining) {
        *vecs_used = 0;
        return APR_EOF;
    }

    if (requested == SERF_READ_ALL_AVAIL || requested > ctx->remaining) {
        if (ctx->remaining <= REQUESTED_MAX) {
            requested = (apr_size_t) ctx->remaining;
        } else {
            requested = REQUESTED_MAX;
        }
    }

    status = serf_bucket_read_iovec(ctx->stream, requested, vecs_size, vecs,
                                    vecs_used);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        int i;

        for (i = 0; i < *vecs_used; i++)
            ctx->remaining -= vecs[i].iov_len;

        if (!ctx->remaining)
            status = APR_EOF;
        else if (APR_STATUS_IS_EOF(status) && ctx->remaining > 0) {
            /* The server sent less data than expected. */
            status = SERF_ERROR_TRUNCATED_HTTP_RESPONSE;
        }
    }

    return status;
}

static apr_status_t serf_response_body_readline2(serf_bucket_t *bucket,
                                                int acceptable,
                                                apr_size_t requested,
                                                int *found,
                                                const char **data,
                                                apr_size_t *len)
{
    body_context_t *ctx = bucket->data;
    apr_status_t status;

    if (!ctx->remaining) {
        *len = 0;
        *found = SERF_NEWLINE_NONE;
        return APR_EOF;
    }

    if (requested > ctx->remaining)
        requested = (apr_size_t)ctx->remaining;

    status = serf_bucket_readline2(ctx->stream, acceptable, requested,
                                   found, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        ctx->remaining -= *len;

        if (!ctx->remaining)
            status = APR_EOF;
        else if (APR_STATUS_IS_EOF(status) && ctx->remaining > 0) {
            /* The server sent less data than expected. */
            status = SERF_ERROR_TRUNCATED_HTTP_RESPONSE;
        }
    }

    return status;
}

static apr_status_t serf_response_body_readline(serf_bucket_t *bucket,
                                                int acceptable,
                                                int *found,
                                                const char **data,
                                                apr_size_t *len)
{
  return serf_response_body_readline2(bucket, acceptable,
                                      SERF_READ_ALL_AVAIL,
                                      found, data, len);
}


static apr_status_t serf_response_body_peek(serf_bucket_t *bucket,
                                            const char **data,
                                            apr_size_t *len)
{
    body_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_bucket_peek(ctx->stream, data, len);

    if (!SERF_BUCKET_READ_ERROR(status) && *len > ctx->remaining) {
        *len = (apr_size_t)ctx->remaining;
    }

    return status;
}

static void serf_response_body_destroy(serf_bucket_t *bucket)
{
    body_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

static apr_uint64_t serf_response_body_get_remaining(serf_bucket_t *bucket)
{
    body_context_t *ctx = bucket->data;

    return ctx->remaining;
}

static apr_status_t serf_response_body_set_config(serf_bucket_t *bucket,
                                                  serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
     it along to our wrapped bucket. */
    body_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

const serf_bucket_type_t serf_bucket_type_response_body = {
    "RESPONSE_BODY",
    serf_response_body_read,
    serf_response_body_readline,
    serf_response_body_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_response_body_peek,
    serf_response_body_destroy,
    serf_default_read_bucket,
    serf_response_body_readline2,
    serf_response_body_get_remaining,
    serf_response_body_set_config,
};
