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

typedef struct copy_context_t {
    serf_bucket_t *wrapped;

    /* When reading, this defines the amount of data that we should grab
       from the wrapped bucket.  */
    apr_size_t min_size;

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
    ctx->hold_buf = NULL;

    return serf_bucket_create(&serf_bucket_type_copy, allocator, ctx);
}

static apr_status_t serf_copy_read(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
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

    status = serf_bucket_read_iovec(bucket, requested,
                                    vecs_size, vecs, vecs_used);

    /* There are four possible results:

       EOF: if the wrapped bucket is done, then we must be done, too. it is
            quite possible we'll return less than MIN_SIZE, but with EOF, there
            is no way we'll be able to return that.
       EAGAIN: we cannot possibly read more (right now), so return. whatever
               was read, it is all we have, whether we met MIN_SIZE or not.
       error: any other error will prevent us from further work; return it.
       SUCCESS: we read a portion, and the bucket says we can read more.

       For all but SUCCESS, we simply return the status. We're done now.  */
    if (status)
        return status;

    /* How much was read on this pass?  */
    for (total = 0, i = *vecs_used; i-- > 0; )
        total += vecs[i].iov_len;

    /* The IOVEC holds at least MIN_SIZE data, so we're good. Or, it
       holds precisely the amount requested, so we shouldn't try to
       gather/accumulate more data.  */
    if (total >= ctx->min_size || total == requested)
        return APR_SUCCESS;
    /* TOTAL < REQUESTED. TOTAL < MIN_SIZE. We should try and fetch more.  */

    /* Copy what we have into our buffer. Then continue reading to get at
       least MIN_SIZE or REQUESTED bytes of data.  */

    /* ### copy into HOLD_BUF. then read/append some more.  */

    /* ### point vecs[0] at HOLD_BUF.  */

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

    return serf_bucket_read_for_sendfile(ctx->wrapped, requested,
                                         hdtr, file, offset, len);
}


static serf_bucket_t *serf_copy_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    copy_context_t *ctx = bucket->data;

    return serf_bucket_read_bucket(ctx->wrapped, type);
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
/*    copy_context_t *ctx = bucket->data;*/

    /* ### kill the HOLD_BUF  */

    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_copy_set_config(serf_bucket_t *bucket,
                                         serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
     it along to our wrapped bucket. */
    copy_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->wrapped, config);
}

const serf_bucket_type_t serf_bucket_type_copy = {
    "COPY",
    serf_copy_read,
    serf_copy_readline,
    serf_copy_read_iovec,
    serf_copy_read_for_sendfile,
    serf_buckets_are_v2,
    serf_copy_peek,
    serf_copy_destroy,
    serf_copy_read_bucket,
    NULL,
    serf_copy_set_config,
};
