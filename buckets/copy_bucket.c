/* Copyright 2013 Justin Erenkrantz and Greg Stein
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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"


typedef struct {
    serf_bucket_t *wrapped;

    int min_size;

    /* ### copied iovec  */

} copy_context_t;



serf_bucket_t *serf_bucket_copy_create(
    serf_bucket_t *wrapped,
    int min_size,
    serf_bucket_alloc_t *allocator)
{
    copy_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->wrapped = wrapped;
    ctx->min_size = min_size;

    return serf_bucket_create(&serf_bucket_type_copy, allocator, ctx);
}

static apr_status_t serf_copy_read(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    if (requested == SERF_READ_ALL_AVAIL || requested > ctx->remaining)
        requested = ctx->remaining;

    *data = ctx->current;
    *len = requested;

    ctx->current += requested;
    ctx->remaining -= requested;

    return ctx->remaining ? APR_SUCCESS : APR_EOF;
}

#if 0
static apr_status_t serf_simple_readline(serf_bucket_t *bucket,
                                         int acceptable, int *found,
                                         const char **data, apr_size_t *len)
{
    simple_context_t *ctx = bucket->data;

    /* Returned data will be from current position. */
    *data = ctx->current;
    serf_util_readline(&ctx->current, &ctx->remaining, acceptable, found);

    /* See how much ctx->current moved forward. */
    *len = ctx->current - *data;

    return ctx->remaining ? APR_SUCCESS : APR_EOF;
}
#endif


static apr_status_t serf_copy_read_iovec(serf_bucket_t *bucket,
                                         apr_size_t requested,
                                         int vecs_size,
                                         struct iovec *vecs,
                                         int *vecs_used)
{
    copy_context_t *ctx = bucket->data;

    /* ### fill buffer  */
}


static apr_status_t serf_copy_peek(serf_bucket_t *bucket,
                                   const char **data,
                                   apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    return serf_bucket_peek(ctx->wrapped, data, len);
}


static void serf_copy_destroy(serf_bucket_t *bucket)
{
    copy_context_t *ctx = bucket->data;

    /* ### kill the holding iovec  */

    serf_default_destroy_and_data(bucket);
}


const serf_bucket_type_t serf_bucket_type_simple = {
    "COPY",
    serf_copy_read,
    serf_copy_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_copy_peek,
    serf_copy_destroy,
};
