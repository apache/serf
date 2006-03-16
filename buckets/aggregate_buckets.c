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

#include "serf.h"
#include "serf_bucket_util.h"


/* Should be an APR_RING? */
typedef struct bucket_list {
    serf_bucket_t *bucket;
    struct bucket_list *next;
} bucket_list_t;

typedef struct {
    bucket_list_t *list; /* active buckets */
    bucket_list_t *done; /* we finished reading this; now pending a destroy */
} aggregate_context_t;


static void cleanup_aggregate(aggregate_context_t *ctx,
                              serf_bucket_alloc_t *allocator)
{
    bucket_list_t *next_list;

    /* If we finished reading a bucket during the previous read, then
     * we can now toss that bucket.
     */
    while (ctx->done != NULL) {
        next_list = ctx->done->next;

        serf_bucket_destroy(ctx->done->bucket);
        serf_bucket_mem_free(allocator, ctx->done);

        ctx->done = next_list;
    }
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_aggregate_create(
    serf_bucket_alloc_t *allocator)
{
    aggregate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->list = NULL;
    ctx->done = NULL;

    return serf_bucket_create(&serf_bucket_type_aggregate, allocator, ctx);
}

static void serf_aggregate_destroy_and_data(serf_bucket_t *bucket)
{
    aggregate_context_t *ctx = bucket->data;
    bucket_list_t *next_ctx;

    while (ctx->list) {
        serf_bucket_destroy(ctx->list->bucket);
        next_ctx = ctx->list->next;
        serf_bucket_mem_free(bucket->allocator, ctx->list);
        ctx->list = next_ctx;
    }
    cleanup_aggregate(ctx, bucket->allocator);

    serf_default_destroy_and_data(bucket);
}

SERF_DECLARE(void) serf_bucket_aggregate_become(serf_bucket_t *bucket)
{
    aggregate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(bucket->allocator, sizeof(*ctx));
    ctx->list = NULL;
    ctx->done = NULL;

    bucket->type = &serf_bucket_type_aggregate;
    bucket->data = ctx;

    /* The allocator remains the same. */
}


SERF_DECLARE(void) serf_bucket_aggregate_prepend(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *prepend_bucket)
{
    aggregate_context_t *ctx = aggregate_bucket->data;
    bucket_list_t *new_list;

    new_list = serf_bucket_mem_alloc(aggregate_bucket->allocator,
                                     sizeof(*new_list));
    new_list->bucket = prepend_bucket;
    new_list->next = ctx->list;

    ctx->list = new_list;
}

SERF_DECLARE(void) serf_bucket_aggregate_append(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *append_bucket)
{
    aggregate_context_t *ctx = aggregate_bucket->data;
    bucket_list_t *new_list;

    new_list = serf_bucket_mem_alloc(aggregate_bucket->allocator,
                                     sizeof(*new_list));
    new_list->bucket = append_bucket;
    new_list->next = NULL;

    /* If we use APR_RING, this is trivial.  So, wait. 
    new_list->next = ctx->list;
    ctx->list = new_list;
    */
    if (ctx->list == NULL) {
        ctx->list = new_list;
    }
    else {
        bucket_list_t *scan = ctx->list;

        while (scan->next != NULL)
            scan = scan->next;
        scan->next = new_list;
    }
}

SERF_DECLARE(void) serf_bucket_aggregate_prepend_iovec(
    serf_bucket_t *aggregate_bucket,
    struct iovec *vecs,
    int vecs_count)
{
    int i;
    bucket_list_t *new_list;

    /* Add in reverse order. */
    for (i = vecs_count - 1; i > 0; i--) {
        serf_bucket_t *new_bucket;

        new_bucket = serf_bucket_simple_create(vecs[i].iov_base,
                                               vecs[i].iov_len,
                                               NULL, NULL,
                                               aggregate_bucket->allocator);

        serf_bucket_aggregate_prepend(aggregate_bucket, new_bucket);

    }
}

SERF_DECLARE(void) serf_bucket_aggregate_append_iovec(
    serf_bucket_t *aggregate_bucket,
    struct iovec *vecs,
    int vecs_count)
{
    int i;
    bucket_list_t *new_list;

    for (i = 0; i < vecs_count; i++) {
        serf_bucket_t *new_bucket;

        new_bucket = serf_bucket_simple_create(vecs[i].iov_base,
                                               vecs[i].iov_len,
                                               NULL, NULL,
                                               aggregate_bucket->allocator);

        serf_bucket_aggregate_append(aggregate_bucket, new_bucket);

    }
}

static apr_status_t read_aggregate(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   int vecs_size, struct iovec *vecs,
                                   int *vecs_used)
{
    aggregate_context_t *ctx = bucket->data;
    int cur_vecs_used;

    *vecs_used = 0;

    if (!ctx->list) {
        return APR_EOF;
    }

    while (1) {
        serf_bucket_t *head = ctx->list->bucket;
        apr_status_t status;

        status = serf_bucket_read_iovec(head, requested, vecs_size, vecs,
                                        &cur_vecs_used);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* Add the number of vecs we read to our running total. */
        *vecs_used += cur_vecs_used;

        if (cur_vecs_used > 0 || status) {
            bucket_list_t *next_list;

            /* If we got SUCCESS (w/bytes) or EAGAIN, we want to return now
             * as it isn't safe to read more without returning to our caller.
             */
            if (!status || APR_STATUS_IS_EAGAIN(status)) {
                return status;
            }

            /* However, if we read EOF, we can stash this bucket in a
             * to-be-freed list and move on to the next bucket.  This ensures
             * that the bucket stays alive (so as not to violate our read
             * semantics).  We'll destroy this list of buckets the next time
             * we are asked to perform a read operation - thus ensuring the
             * proper read lifetime.
             */
            next_list = ctx->list->next;
            ctx->list->next = ctx->done;
            ctx->done = ctx->list;
            ctx->list = next_list;

            /* If we have no more in our list, return EOF. */
            if (!ctx->list) {
                return status;
            }

            /* At this point, it safe to read the next bucket - if we can. */

            /* If the caller doesn't want ALL_AVAIL, decrement the size
             * of the items we just read from the list.
             */
            if (requested != SERF_READ_ALL_AVAIL) {
                int i;

                for (i = 0; i < cur_vecs_used; i++)
                    requested -= vecs[i].iov_len;
            }

            /* Adjust our vecs to account for what we just read. */
            vecs_size -= cur_vecs_used;
            vecs += cur_vecs_used;

            /* We reached our max.  Oh well. */
            if (!requested || !vecs_size) {
                return APR_SUCCESS;
            }
        }
    }
    /* NOTREACHED */
}

static apr_status_t serf_aggregate_read(serf_bucket_t *bucket,
                                        apr_size_t requested,
                                        const char **data, apr_size_t *len)
{
    aggregate_context_t *ctx = bucket->data;
    struct iovec vec;
    int vecs_used;
    apr_status_t status;

    cleanup_aggregate(ctx, bucket->allocator);

    status = read_aggregate(bucket, requested, 1, &vec, &vecs_used);

    if (!vecs_used) {
        *len = 0;
    }
    else {
        *data = vec.iov_base;
        *len = vec.iov_len;
    }

    return status;
}

static apr_status_t serf_aggregate_read_iovec(serf_bucket_t *bucket,
                                              apr_size_t requested,
                                              int vecs_size,
                                              struct iovec *vecs,
                                              int *vecs_used)
{
    aggregate_context_t *ctx = bucket->data;

    cleanup_aggregate(ctx, bucket->allocator);

    return read_aggregate(bucket, requested, vecs_size, vecs, vecs_used);
}

static apr_status_t serf_aggregate_readline(serf_bucket_t *bucket,
                                            int acceptable, int *found,
                                            const char **data, apr_size_t *len)
{
    /* Follow pattern from serf_aggregate_read. */
    return APR_ENOTIMPL;
}

static apr_status_t serf_aggregate_peek(serf_bucket_t *bucket,
                                        const char **data,
                                        apr_size_t *len)
{
    /* Follow pattern from serf_aggregate_read. */
    return APR_ENOTIMPL;
}

static serf_bucket_t * serf_aggregate_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    aggregate_context_t *ctx = bucket->data;
    serf_bucket_t *found_bucket;

    if (!ctx->list) {
        return NULL;
    }

    if (ctx->list->bucket->type == type) {
        /* Got the bucket. Consume it from our list. */
        found_bucket = ctx->list->bucket;
        ctx->list = ctx->list->next;
        return found_bucket;
    }

    /* Call read_bucket on first one in our list. */
    return serf_bucket_read_bucket(ctx->list->bucket, type);
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_aggregate = {
    "AGGREGATE",
    serf_aggregate_read,
    serf_aggregate_readline,
    serf_aggregate_read_iovec,
    serf_default_read_for_sendfile,
    serf_aggregate_read_bucket,
    serf_aggregate_peek,
    serf_aggregate_destroy_and_data,
};
