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

static void serf__copy_iovec(char *data,
                             apr_size_t *copied,
                             struct iovec *vecs,
                             int vecs_used)
{
    int i;
    apr_size_t sz = 0;

    for (i = 0; i < vecs_used; i++) {
        memcpy(data, vecs[i].iov_base, vecs[i].iov_len);
        data += vecs[i].iov_len;
        sz += vecs[i].iov_len;
    }

    if (copied)
      *copied = sz;
}

static apr_status_t serf_copy_read(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    copy_context_t *ctx = bucket->data;
    apr_status_t status;
    const char *wdata;
    apr_size_t peek_len;
    apr_size_t fetched;

    status = serf_bucket_peek(ctx->wrapped, &wdata, &peek_len);

    if (SERF_BUCKET_READ_ERROR(status)) {
        *len = 0;
        return status;
    }

    /* Can we just return the peeked result? */
    if (status || requested <= peek_len || ctx->min_size <= peek_len) {

        return serf_bucket_read(ctx->wrapped, requested, data, len);
    }

    /* Reduce requested to fit in our buffer */
    if (requested > ctx->min_size)
        requested = ctx->min_size;

    fetched = 0;
    while (fetched < requested) {
        struct iovec vecs[16];
        int vecs_used;
        apr_size_t read;

        status = serf_bucket_read_iovec(ctx->wrapped, requested - fetched,
                                        16, vecs, &vecs_used);

        if (SERF_BUCKET_READ_ERROR(status)) {
            if (fetched > 0)
                status = APR_EAGAIN;
            break;
        }
        else if (!fetched && vecs_used == 1
                 && (status || (vecs[0].iov_len == requested))) {

            /* Easy out
                * We don't have anything stashed
                * We only have one buffer to return
                * And either
                    - We can't read any further at this time
                    - Or the buffer is already filled
             */

            *data = vecs[0].iov_base;
            *len = vecs[0].iov_len;
            return status;
        }
        else if (!ctx->hold_buf && vecs_used > 0) {
            /* We have something that we want to store */

            ctx->hold_buf = serf_bucket_mem_alloc(bucket->allocator,
                                                  ctx->min_size);
        }

        serf__copy_iovec(ctx->hold_buf + fetched, &read, vecs, vecs_used);
        fetched += read;

        if (status)
            break;
    }

    *data = ctx->hold_buf;
    *len = fetched;

    return status;
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
    apr_size_t fetched;
    int i;

    /* If somebody really wants to call us for 1 iovec, call the function
       that already implements the copying for this */
    if (vecs_size == 1) {
        const char *data;
        apr_size_t len;

        *vecs_used = 1;

        status = serf_copy_read(bucket, requested, &data, &len);

        vecs[0].iov_base = (void*)data;
        vecs[0].iov_len = len;
        *vecs_used = 1;

        return status;
    }

    status = serf_bucket_read_iovec(ctx->wrapped, requested,
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
    if (! ctx->hold_buf)
        ctx->hold_buf = serf_bucket_mem_alloc(bucket->allocator,
                                              ctx->min_size);

    /* ### copy into HOLD_BUF. then read/append some more.  */
    fetched = total;
    serf__copy_iovec(ctx->hold_buf, NULL, vecs, *vecs_used);

    /* ### point vecs[0] at HOLD_BUF.  */
    vecs[0].iov_base = ctx->hold_buf;
    vecs[0].iov_len = fetched;

    while (TRUE) {
        int v_used;

        status = serf_bucket_read_iovec(ctx->wrapped, requested - fetched,
                                      vecs_size - 1, &vecs[1], &v_used);

        if (SERF_BUCKET_READ_ERROR(status)) {
            *vecs_used = 1;
            return APR_EAGAIN;
        }

        for (i = 1; i <= v_used; i++)
            total += vecs[i].iov_len;

        if (status || total >= ctx->min_size || total == requested) {
            *vecs_used = v_used + 1;
            return status;
        }

        serf__copy_iovec(ctx->hold_buf + fetched, NULL, &vecs[1], v_used);

        fetched += total;
        vecs[0].iov_len = fetched;
    }
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

static apr_uint64_t serf_copy_get_remaining(serf_bucket_t *bucket)
{
    copy_context_t *ctx = bucket->data;

    return serf_bucket_get_remaining(ctx->wrapped);
}


static void serf_copy_destroy(serf_bucket_t *bucket)
{
    copy_context_t *ctx = bucket->data;

    if (ctx->hold_buf)
        serf_bucket_mem_free(bucket->allocator, ctx->hold_buf);

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
    serf_copy_get_remaining,
    serf_copy_set_config,
};
