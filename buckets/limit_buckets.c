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
#include "serf_private.h"

typedef struct limit_context_t {
    serf_bucket_t *stream;
    apr_uint64_t remaining;
} limit_context_t;


serf_bucket_t *serf_bucket_limit_create(
    serf_bucket_t *stream, apr_uint64_t len, serf_bucket_alloc_t *allocator)
{
    limit_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->remaining = len;

    return serf_bucket_create(&serf_bucket_type_limit, allocator, ctx);
}

static apr_status_t serf_limit_read(serf_bucket_t *bucket,
                                    apr_size_t requested,
                                    const char **data, apr_size_t *len)
{
    limit_context_t *ctx = bucket->data;
    apr_status_t status;

    if (!ctx->remaining) {
        *len = 0;
        return APR_EOF;
    }

    if (requested > ctx->remaining) {
        requested = (apr_size_t) ctx->remaining;
    }

    status = serf_bucket_read(ctx->stream, requested, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        ctx->remaining -= *len;

        /* If we have met our limit and don't have a status, return EOF. */
        if (!ctx->remaining && !status) {
            status = APR_EOF;
        }
        else if (APR_STATUS_IS_EOF(status) && ctx->remaining) {
            status = SERF_ERROR_TRUNCATED_STREAM;
        }
    }

    return status;
}

static apr_status_t serf_limit_readline(serf_bucket_t *bucket,
                                        int accepted,
                                        int *found,
                                        const char **data,
                                        apr_size_t *len)
{
    limit_context_t *ctx = bucket->data;
    apr_status_t status;
    apr_size_t requested;

    if (!ctx->remaining) {
        *len = 0;
        return APR_EOF;
    }

    if (ctx->remaining >= APR_SIZE_MAX)
        requested = APR_SIZE_MAX;
    else
        requested = (apr_size_t) ctx->remaining;

    status = serf_bucket_limited_readline(ctx->stream, accepted,
                                          requested, found, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        ctx->remaining -= *len;

        /* If we have met our limit and don't have a status, return EOF. */
        if (!ctx->remaining && !status) {
            status = APR_EOF;
        }
        else if (APR_STATUS_IS_EOF(status) && ctx->remaining) {
            status = SERF_ERROR_TRUNCATED_STREAM;
        }
    }

    return status;
}

static apr_status_t serf_limit_read_iovec(serf_bucket_t *bucket,
                                          apr_size_t requested,
                                          int vecs_size,
                                          struct iovec *vecs,
                                          int *vecs_used)
{
    limit_context_t *ctx = bucket->data;
    apr_status_t status;

    if (!ctx->remaining) {
        *vecs_used = 0;
        return APR_EOF;
    }

    if (requested > ctx->remaining) {
        requested = (apr_size_t) ctx->remaining;
    }

  status = serf_bucket_read_iovec(ctx->stream, requested,
                                  vecs_size, vecs, vecs_used);
  if (!SERF_BUCKET_READ_ERROR(status)) {
      int i;
      apr_size_t len = 0;

      for (i = 0; i < *vecs_used; i++)
        len += vecs[i].iov_len;

      ctx->remaining -= len;

      /* If we have met our limit and don't have a status, return EOF. */
      if (!ctx->remaining && !status) {
          status = APR_EOF;
      }
      else if (APR_STATUS_IS_EOF(status) && ctx->remaining) {
          status = SERF_ERROR_TRUNCATED_STREAM;
      }
  }

  return status;
}

static apr_status_t serf_limit_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    limit_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_bucket_peek(ctx->stream, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        if (*len > ctx->remaining)
            *len = (apr_size_t)ctx->remaining;
    }
    return status;
}

static void serf_limit_destroy(serf_bucket_t *bucket)
{
    limit_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

static apr_uint64_t serf_limit_get_remaining(serf_bucket_t *bucket)
{
    limit_context_t *ctx = bucket->data;

    return ctx->remaining;
}

static apr_status_t serf_limit_set_config(serf_bucket_t *bucket,
                                          serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
     it along to our wrapped bucket. */
    limit_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

const serf_bucket_type_t serf_bucket_type_limit = {
    "LIMIT",
    serf_limit_read,
    serf_limit_readline,
    serf_limit_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_limit_peek,
    serf_limit_destroy,
    serf_default_read_bucket,
    serf_limit_get_remaining,
    serf_limit_set_config,
};
