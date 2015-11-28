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

typedef struct split_context_t {
    serf_bucket_t *stream;
    struct split_stream_ctx_t *head, *tail;

    bool want_size;
} split_context_t;

typedef struct split_stream_ctx_t {
    split_context_t *ctx;

    apr_size_t read_size;
    apr_size_t fixed_size;
    apr_size_t min_size;
    apr_size_t max_size;
    apr_uint64_t tail_size;

    struct split_stream_ctx_t *prev, *next;

    bool at_eof, cant_read;
} split_stream_ctx_t;

static void split_detach_head(split_stream_ctx_t *sctx)
{
    split_context_t *ctx = sctx->ctx;

    if (!ctx || ctx->head != sctx)
        return;

    if (ctx->tail != sctx) {
        /* We can detach now */
        ctx->head = sctx->next;
        sctx->next->prev = NULL;

        /* Did somebody ask for the size while it wasn't possible?
           Perhaps we can retrieve and store it now */
        if (ctx->want_size) {
            ctx->want_size = false;
            ctx->head->tail_size = serf_bucket_get_remaining(ctx->stream);

            if (ctx->head->tail_size != SERF_LENGTH_UNKNOWN)
                ctx->head->tail_size -= ctx->head->read_size;
        }
        else if (sctx->tail_size != SERF_LENGTH_UNKNOWN) {

            /* If we have a cached total size, move it to the new head */
            ctx->head->tail_size = sctx->tail_size - sctx->read_size
                                                   + ctx->head->read_size;
        }
    }
    else {
        serf_bucket_t *stream = ctx->stream;

        serf_bucket_mem_free(stream->allocator, ctx);
        serf_bucket_destroy(stream);
    }

    sctx->prev = sctx->next = NULL;
    sctx->ctx = NULL;
}

static apr_status_t serf_split_read(serf_bucket_t *bucket,
                                    apr_size_t requested,
                                    const char **data,
                                    apr_size_t *len)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;
    apr_status_t status;

    if (! ctx || sctx->at_eof) {
        split_detach_head(sctx);
        *data = NULL;
        *len = 0;
        return APR_EOF;
    }
    else if (sctx->prev) {
        /* Not the current head */
        *data = NULL;
        *len = 0;
        if (sctx->prev->prev || !sctx->prev->at_eof)
            return APR_EAGAIN; /* Not ready soon */

        return APR_SUCCESS; /* Most likely ready at next read */
    }

    if (sctx->max_size != SERF_READ_ALL_AVAIL
        && requested > (sctx->max_size - sctx->read_size))
    {
      requested = (sctx->max_size - sctx->read_size);
    }

    status = serf_bucket_read(ctx->stream, requested, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        sctx->cant_read = (*len != 0);
        sctx->read_size += *len;

        if (sctx->min_size != SERF_READ_ALL_AVAIL
            && sctx->read_size >= sctx->min_size) {
            /* We read enough. Fix the final length now */
            sctx->at_eof = true;
            sctx->fixed_size = sctx->max_size = sctx->read_size;
            status = APR_EOF;
        }
        else if (APR_STATUS_IS_EOF(status)) {
            sctx->at_eof = true;

            if (sctx->fixed_size && sctx->read_size != sctx->fixed_size) {
                /* We promised more data via get_remaining() than we can
                   deliver. -> BAD get_remaining()  */
                status = SERF_ERROR_TRUNCATED_STREAM;
            }
            else {
                /* Ok, then this is our size */
                sctx->max_size = sctx->fixed_size = sctx->read_size;
            }
        }
    }
    else
      sctx->cant_read = false;

    return status;
}

static apr_status_t serf_split_read_iovec(serf_bucket_t *bucket,
                                          apr_size_t requested,
                                          int vecs_size,
                                          struct iovec *vecs,
                                          int *vecs_used)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;
    apr_status_t status;

    if (! ctx || sctx->at_eof) {
        split_detach_head(sctx);
        *vecs_used = 0;
        return APR_EOF;
    }
    else if (sctx->prev) {
        /* Not the current head */
        *vecs_used = 0;
        if (sctx->prev->prev || !sctx->prev->at_eof)
            return APR_EAGAIN; /* Not ready soon */

        return APR_SUCCESS; /* Most likely ready at next read */
    }

    if (sctx->max_size != SERF_READ_ALL_AVAIL
        && requested > (sctx->max_size - sctx->read_size))
    {
        requested = (sctx->max_size - sctx->read_size);
    }

    status = serf_bucket_read_iovec(ctx->stream, requested, vecs_size,
                                    vecs, vecs_used);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        apr_size_t len = 0;
        int i;

        for (i = 0; i < *vecs_used; i++)
            len += vecs[i].iov_len;

        sctx->cant_read = (len != 0);
        sctx->read_size += len;

        if (sctx->min_size != SERF_READ_ALL_AVAIL
            && sctx->read_size >= sctx->min_size) {
            /* We read enough. Fix the final length now */
            sctx->at_eof = true;
            sctx->fixed_size = sctx->max_size = sctx->read_size;
            status = APR_EOF;
        }
        else if (APR_STATUS_IS_EOF(status)) {
            sctx->at_eof = TRUE;

            if (sctx->fixed_size && sctx->read_size != sctx->fixed_size) {
                /* We promised more data via get_remaining() than we can
                   deliver. -> BAD get_remaining()  */
                status = SERF_ERROR_TRUNCATED_STREAM;
            }
            else {
                /* Ok, then this is our size */
                sctx->max_size = sctx->fixed_size = sctx->read_size;
            }
        }
    }
    else
      sctx->cant_read = false;

    return status;
}

static apr_status_t serf_split_peek(serf_bucket_t *bucket,
                                    const char **data,
                                    apr_size_t *len)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;
    apr_status_t status;

    if (! ctx || sctx->at_eof) {
        split_detach_head(sctx);
        *data = "";
        *len = 0;
        return APR_EOF;
    }
    else if (sctx->prev) {
        /* Not the current head */
        *data = "";
        *len = 0;
        if (sctx->prev->prev || !sctx->prev->at_eof)
            return APR_EAGAIN; /* Not ready soon */

        return APR_SUCCESS; /* Most likely ready at next read */
    }

    status = serf_bucket_peek(ctx->stream, data, len);

    if (!SERF_BUCKET_READ_ERROR(status)) {

        if (sctx->min_size != SERF_READ_ALL_AVAIL
            && *len >= (sctx->min_size - sctx->read_size)) {
            /* We peeked more data than we need to continue
               to the next bucket. We have to be careful that
               we don't promise data and not deliver later.
             */

            if (! sctx->fixed_size) {
                /* Determine the maximum size to what we can deliver now */
                sctx->fixed_size = MIN(sctx->max_size, sctx->read_size + *len);
                sctx->min_size = sctx->max_size = sctx->fixed_size;
            }

            *len = sctx->fixed_size - sctx->read_size;
            status = APR_EOF;
        }

        sctx->cant_read = (*len > 0);
    }
    else
        sctx->cant_read = false;

    return status;
}

static apr_uint64_t serf_split_get_remaining(serf_bucket_t *bucket)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;
    split_stream_ctx_t *head;
    apr_uint64_t remaining;

    if (!ctx || sctx->at_eof) {
        return 0; /* at eof */
    }
    else if (ctx->head == sctx) {
        /* We are HEAD. We hereby unlock the data to allow reading the size */
        sctx->cant_read = false;
    }

    if (sctx->fixed_size) {
        return sctx->fixed_size - sctx->read_size; /* already calculated */
    }

    /* Do we know the total size? */
    head = ctx->head;

    if (head->tail_size == SERF_LENGTH_UNKNOWN) {
        if (head->cant_read) {
            /* Can't obtain the size without unlocking data*/
            ctx->want_size = true;

            return SERF_LENGTH_UNKNOWN;
        }
        head->tail_size = serf_bucket_get_remaining(ctx->stream);

        if (head->tail_size == SERF_LENGTH_UNKNOWN)
            return SERF_LENGTH_UNKNOWN;

        /* Add what we already have to avoid updating on every read */
        head->tail_size += head->read_size;
    }

    remaining = head->tail_size;
    /* And now we fix the sizes of the buckets until we get to
       the one we're interested in */
    while (head) {

        if (!head->fixed_size) {
            /* Size not decided yet. Let's make this chunk as big
               as allowed */
            head->fixed_size = (remaining < head->max_size)
                                ? (apr_size_t)remaining
                                : head->max_size;

            /* Disable dynamic sizing now */
            head->min_size = head->max_size = head->fixed_size;
        }

        if (head == sctx) {
            /* We got the information we need. Exit now to avoid
               fixing the length of more buckets than needed */
            return sctx->fixed_size - sctx->read_size;
        }

        remaining -= head->fixed_size;
        head = head->next;
    }

    return SERF_LENGTH_UNKNOWN; /* Hit NULL before our bucket??? */
}

static void serf_split_destroy(serf_bucket_t *bucket)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;

    /* Are we the current read bucket */
    if (!sctx->prev) {
        if (!sctx->at_eof && sctx->fixed_size) {
            /* Auch, we promised to read a specific amount and
                then didn't keep our promise...*/
            serf__bucket_drain(bucket);
        }

        split_detach_head(sctx);
    }
    else {
        /* We are destroyed before being read... should never happen,
           unless the entire chain is destroyed */

        split_stream_ctx_t *h = sctx->next;

        /* We didn't read what we assumed to read. Fix calculations
           if we can. All data will shift to tail. Let's hope nobody
           tried to call get_remaining() on the final tail... */

        while (h) {
            h->tail_size = SERF_LENGTH_UNKNOWN;
            h = h->next;
        }

        /* Remove ourself from list */
        sctx->prev->next = sctx->next;
        if (sctx->next)
            sctx->next->prev = sctx->prev;
        else
            ctx->tail = sctx->prev;
    }

    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_split_set_config(serf_bucket_t *bucket,
                                          serf_config_t *config)
{
    split_stream_ctx_t *sctx = bucket->data;
    split_context_t *ctx = sctx->ctx;

    if (ctx && !sctx->prev)
        return serf_bucket_set_config(ctx->stream, config);

    return APR_SUCCESS;
}

#define SERF_BUCKET_IS__SPLIT(b) SERF_BUCKET_CHECK((b), _split)
static const serf_bucket_type_t serf_bucket_type__split =
{
  "SPLIT",
  serf_split_read,
  serf_default_readline,
  serf_split_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_split_peek,
  serf_split_destroy,
  serf_default_read_bucket,
  serf_split_get_remaining,
  serf_split_set_config
};

void serf_bucket_split_create(serf_bucket_t **head,
                              serf_bucket_t **tail,
                              serf_bucket_t *stream,
                              apr_size_t min_chunk_size,
                              apr_size_t max_chunk_size)
{
    split_stream_ctx_t *tail_ctx, *head_ctx;
    split_context_t *ctx;
    serf_bucket_alloc_t *allocator = stream->allocator;

    tail_ctx = serf_bucket_mem_calloc(allocator, sizeof(*tail_ctx));
    tail_ctx->tail_size = SERF_LENGTH_UNKNOWN;

    if (SERF_BUCKET_IS__SPLIT(stream)) {
        head_ctx = stream->data;
        ctx = head_ctx->ctx;
        *head = stream;

        head_ctx = tail_ctx->prev = ctx->tail;
        ctx->tail->next = tail_ctx;
        ctx->tail = tail_ctx;
    }
    else {
        ctx = serf_bucket_mem_calloc(allocator, sizeof(*ctx));
        ctx->stream = stream;

        head_ctx = serf_bucket_mem_calloc(allocator, sizeof(*head_ctx));
        head_ctx->ctx = ctx;
        head_ctx->tail_size = SERF_LENGTH_UNKNOWN;

        ctx->tail = head_ctx->next = tail_ctx;
        ctx->head = tail_ctx->prev = head_ctx;

        *head = serf_bucket_create(&serf_bucket_type__split, allocator,
                                   head_ctx);
    }

    *tail = serf_bucket_create(&serf_bucket_type__split, allocator, tail_ctx);

    tail_ctx->ctx = ctx;
    head_ctx->fixed_size = 0; /* Not fixed yet. This might change an existing
                                 tail bucket that we received as stream! */
    head_ctx->min_size = MAX(1, min_chunk_size);
    head_ctx->max_size = MAX(head_ctx->min_size, max_chunk_size);

    /* tail_ctx->fixed_size = 0; // Unknown */
    tail_ctx->min_size = SERF_READ_ALL_AVAIL;
    tail_ctx->max_size = SERF_READ_ALL_AVAIL;
}
