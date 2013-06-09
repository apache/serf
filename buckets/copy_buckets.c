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


#define IOVEC_HOLD_COUNT 16

typedef struct {
    serf_bucket_t *wrapped;

    /* When reading, this defines the amount of data that we should grab
       from the wrapped bucket.  */
    apr_size_t min_size;

    /* We try to use read_iovec() on the wrapped bucket. Sometimes, the
       vecs are NOT completely used, so we need to hold onto the unused
       iovec structures.

       There is pending data if VECS_COUNT > 0.  */
    struct iovec vecs[IOVEC_HOLD_COUNT];
    int vecs_count;

    /* In order to reach MIN_SIZE, we may sometimes make copies of the
       data to reach that size. HOLD_BUF (if not NULL) is a buffer of
       MIN_SIZE length to hold/concatenate that data.

       HOLD_BUF remains NULL until the buffer is actually required.  */
    char *hold_buf;

} copy_context_t;


serf_bucket_t *serf_bucket_copy_create(
    serf_bucket_t *wrapped,
    apr_size_t min_size,
    serf_bucket_alloc_t *allocator)
{
    copy_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->wrapped = wrapped;
    ctx->min_size = min_size;
    ctx->vecs_count = 0;
    ctx->hold_buf = NULL;

    return serf_bucket_create(&serf_bucket_type_copy, allocator, ctx);
}

static apr_status_t serf_copy_read(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    if (ctx->vecs_count > 0)
    {
        /* ### return held data  */
    }

    /* ### peek to see how much is easily available. if it is MIN_SIZE,
       ### then a read() would (likely) get that same amount. otherwise,
       ### we should read an iovec and concatenate the result.  */

    /* ### fix this return code  */
    return APR_SUCCESS;
}


static apr_status_t serf_copy_readline(serf_bucket_t *bucket,
                                       int acceptable, int *found,
                                       const char **data, apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    if (ctx->vecs_count > 0)
    {
        /* ### return held data  */
    }

    /* Disregard MIN_SIZE. a "line" could very well be shorter. Just
       delegate this to the wrapped bucket.  */

    return serf_bucket_readline(ctx->wrapped, acceptable, found, data, len);
}


static apr_status_t serf_copy_read_iovec(serf_bucket_t *bucket,
                                         apr_size_t requested,
                                         int vecs_size,
                                         struct iovec *vecs,
                                         int *vecs_used)
{
    copy_context_t *ctx = bucket->data;
    apr_status_t status;
    apr_size_t total;
    int i;

    if (ctx->vecs_count > 0)
    {
        /* ### return held data  */
    }

    status = serf_bucket_read_iovec(bucket, requested,
                                    vecs_size, vecs, vecs_used);

    /* The wrapped bucket is (temporarily) done, or is depleted. Return
       the final data, because there is nothing we can do (if the data
       meets/not the MIN_SIZE requirement).  */
    if (APR_STATUS_IS_EOF(status) || APR_STATUS_IS_EAGAIN(status))
        return status;

    for (total = 0, i = *vecs_used; i-- > 0; )
        total += vecs[i].iov_len;

    /* The IOVEC holds at least MIN_SIZE data, so we're good. Or, it
       holds the amount requested, so we shouldn't try to
       gather/accumulate more data.  */
    if (total >= ctx->min_size || total == requested)
        return status;

    /* Use our buffer to get at least MIN_SIZE or REQUESTED bytes of data.  */

    /* ### copy into HOLD_BUF. then read/append some more.  */

    return status;
}


static apr_status_t serf_copy_read_for_sendfile(
    serf_bucket_t *bucket,
    apr_size_t requested,
    apr_hdtr_t *hdtr,
    apr_file_t **file,
    apr_off_t *offset,
    apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    /* Any held data means we cannot provide a source for sendfile().  */
    if (ctx->vecs_count > 0)
    {
        /* ### return the held data  */
    }

    return serf_bucket_read_for_sendfile(ctx->wrapped, requested,
                                         hdtr, file, offset, len);
}


static serf_bucket_t *serf_copy_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    copy_context_t *ctx = bucket->data;

    /* If there is some held data (at the front of the read stream), then
       we definitely don't have the requested bucket type.  */
    if (ctx->vecs_count > 0)
        return NULL;

    return serf_bucket_read_bucket(ctx->wrapped, type);
}


static apr_status_t serf_copy_peek(serf_bucket_t *bucket,
                                   const char **data,
                                   apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;

    if (ctx->vecs_count > 0)
    {
        *data = ctx->vecs[0].iov_base;
        *len = ctx->vecs[0].iov_len;
        return APR_SUCCESS;
    }

    return serf_bucket_peek(ctx->wrapped, data, len);
}


static void serf_copy_destroy(serf_bucket_t *bucket)
{
/*    copy_context_t *ctx = bucket->data;*/

    /* ### kill the HOLD_BUF  */

    serf_default_destroy_and_data(bucket);
}


const serf_bucket_type_t serf_bucket_type_copy = {
    "COPY",
    serf_copy_read,
    serf_copy_readline,
    serf_copy_read_iovec,
    serf_copy_read_for_sendfile,
    serf_copy_read_bucket,
    serf_copy_peek,
    serf_copy_destroy,
};
