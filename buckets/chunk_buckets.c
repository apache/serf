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
 * chunkations under the License.
 */

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"


typedef struct {
    enum {
        STATE_FETCH,
        STATE_CHUNK,
        STATE_EOF
    } state;

    serf_bucket_t *chunk;
    serf_bucket_t *stream;

    char chunk_hdr[20];
} chunk_context_t;


SERF_DECLARE(serf_bucket_t *) serf_bucket_chunk_create(
    serf_bucket_t *stream, serf_bucket_alloc_t *allocator)
{
    chunk_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->state = STATE_FETCH;
    ctx->chunk = serf_bucket_aggregate_create(allocator);
    ctx->stream = stream;

    return serf_bucket_create(&serf_bucket_type_chunk, allocator, ctx);
}

#define CRLF "\r\n"

static apr_status_t serf_chunk_read(serf_bucket_t *bucket,
                                    apr_size_t requested,
                                    const char **data, apr_size_t *len)
{
    chunk_context_t *ctx = bucket->data;
    apr_status_t status;

    /* Before proceeding, we need to fetch some data from the stream. */
    if (ctx->state == STATE_FETCH) {
        const char *stream_data;
        apr_size_t stream_len;
        serf_bucket_t *simple_bkt;
        apr_size_t chunk_len;

        status = serf_bucket_read(ctx->stream, 8000, &stream_data, &stream_len);

        if (SERF_BUCKET_READ_ERROR(status)) {
            /* Uh-oh. */
            return status;
        }

        /* assert: stream_len in hex < sizeof(ctx->chunk_hdr) */

        /* Build the chunk header. */
        chunk_len = apr_snprintf(ctx->chunk_hdr, sizeof(ctx->chunk_hdr),
                                 "%" APR_UINT64_T_HEX_FMT CRLF,
                                 (apr_uint64_t)stream_len);

        simple_bkt = SERF_BUCKET_SIMPLE_STRING_LEN(ctx->chunk_hdr, chunk_len,
                                                   bucket->allocator);
        serf_bucket_aggregate_append(ctx->chunk, simple_bkt);

        /* Insert the chunk data. */
        simple_bkt = SERF_BUCKET_SIMPLE_STRING_LEN(stream_data, stream_len,
                                                   bucket->allocator);

        serf_bucket_aggregate_append(ctx->chunk, simple_bkt);

        /* Insert the chunk footer. */
        simple_bkt = SERF_BUCKET_SIMPLE_STRING(CRLF, bucket->allocator);
        serf_bucket_aggregate_append(ctx->chunk, simple_bkt);

        /* We've reached the end of the line for the stream. */
        if (APR_STATUS_IS_EOF(status)) {
            /* Insert the chunk footer. */
            simple_bkt = SERF_BUCKET_SIMPLE_STRING("0" CRLF CRLF,
                                                   bucket->allocator);
            serf_bucket_aggregate_append(ctx->chunk, simple_bkt);

            ctx->state = STATE_EOF;
        }
        else {
            /* Okay, we can return data.  */
            ctx->state = STATE_CHUNK;
        }
    }

    status = serf_bucket_read(ctx->chunk, requested, data, len);

    /* Mask EOF from aggregate bucket. */
    if (APR_STATUS_IS_EOF(status) && ctx->state == STATE_CHUNK) {
        status = APR_EAGAIN;
        ctx->state = STATE_FETCH;
    }

    return status;
}

static apr_status_t serf_chunk_readline(serf_bucket_t *bucket,
                                         int acceptable, int *found,
                                         const char **data, apr_size_t *len)
{
    chunk_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_bucket_readline(ctx->chunk, acceptable, found, data, len);

    /* Mask EOF from aggregate bucket. */
    if (APR_STATUS_IS_EOF(status) && ctx->state == STATE_CHUNK) {
        status = APR_EAGAIN;
        ctx->state = STATE_FETCH;
    }

    return status;
}

static apr_status_t serf_chunk_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    chunk_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_bucket_peek(ctx->chunk, data, len);

    /* Mask EOF from aggregate bucket. */
    if (APR_STATUS_IS_EOF(status) && ctx->state == STATE_CHUNK) {
        status = APR_EAGAIN;
    }

    return status;
}

static void serf_chunk_destroy(serf_bucket_t *bucket)
{
    chunk_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->stream);
    serf_bucket_destroy(ctx->chunk);

    serf_default_destroy_and_data(bucket);
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_chunk = {
    "CHUNK",
    serf_chunk_read,
    serf_chunk_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_chunk_peek,
    serf_chunk_destroy,
};
