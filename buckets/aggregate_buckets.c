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
    serf_bucket_t *done; /* we finished reading this; now pending a destroy */
} aggregate_context_t;


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
    if (ctx->done) {
        serf_bucket_destroy(ctx->done);
    }

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

    /* ### leave the metadata? */
    /* bucket->metadata = NULL; */

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

static apr_status_t serf_aggregate_read(serf_bucket_t *bucket,
                                        apr_size_t requested,
                                        const char **data, apr_size_t *len)
{
    aggregate_context_t *ctx = bucket->data;
    bucket_list_t *next_list;

    /* If we finished reading a bucket during the previous read, then
     * we can now toss that bucket.
     */
    if (ctx->done != NULL) {
        serf_bucket_destroy(ctx->done);
        ctx->done = NULL;
    }

    if (!ctx->list) {
        *len = 0;
        /* ### can we leave *data unassigned given *len == 0? */
        return APR_EOF;
    }

    while (1) {
        serf_bucket_t *head = ctx->list->bucket;
        apr_status_t status;

        status = serf_bucket_read(head, requested, data, len);
        if (*len > 0) {
            if (APR_STATUS_IS_EOF(status)) {
                /* We finished reading this bucket. It must stay alive,
                 * though, so that we can return its data. Destroy it the
                 * next time we perform a read operation.
                 */
                next_list = ctx->list->next;
                serf_bucket_mem_free(bucket->allocator, ctx->list);
                ctx->list = next_list;
                ctx->done = head;
            }
            return status;
        }

        /* If we just read no data, then let's try again after destroying
         * this bucket.
         */
        serf_bucket_destroy(head);
        next_list = ctx->list->next;
        serf_bucket_mem_free(bucket->allocator, ctx->list);
        ctx->list = next_list;
    }
    /* NOTREACHED */
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
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_aggregate_read_bucket,
    serf_aggregate_peek,
    serf_default_get_metadata,
    serf_default_set_metadata,
    serf_aggregate_destroy_and_data,
};
