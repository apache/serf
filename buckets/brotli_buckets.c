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

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

#ifdef SERF_HAVE_BROTLI

#include <brotli/decode.h>

int serf_bucket_is_brotli_supported()
{
    return TRUE;
}

typedef struct brotli_decompress_context_t {
    BrotliDecoderState *state;
    serf_bucket_t *input;
    serf_bucket_t *output;
    const char *pending_data;
    apr_size_t pending_len;
    /* Did we see an APR_EOF for the input stream? */
    int hit_eof;
    /* Did the decoder report the end of the compressed data? */
    int done;
} brotli_decompress_context_t;

static void *alloc_func(void *opaque, size_t size)
{
    serf_bucket_alloc_t *alloc = opaque;

    return serf_bucket_mem_alloc(alloc, size);
}

static void free_func(void *opaque, void *block)
{
    serf_bucket_alloc_t *alloc = opaque;

    if (block)
        serf_bucket_mem_free(alloc, block);
}

/* Implements serf_bucket_aggregate_eof_t */
static apr_status_t refill_output(void *baton, serf_bucket_t *aggregate_bkt)
{
    brotli_decompress_context_t *ctx = baton;

    while (1) {
        if (ctx->pending_len == 0 && !ctx->hit_eof) {
            apr_status_t status;

            status = serf_bucket_read(ctx->input, SERF_READ_ALL_AVAIL,
                                      &ctx->pending_data, &ctx->pending_len);
            if (APR_STATUS_IS_EOF(status))
                ctx->hit_eof = TRUE;
            else if (status)
                return status;
        }

        if (ctx->done && ctx->hit_eof && ctx->pending_len == 0) {
            return APR_EOF;
        }
        else if (ctx->done) {
            /* Finished with some input still there in the bucket, that's
             * an error. */
            return SERF_ERROR_DECOMPRESSION_FAILED;
        }
        else {
            BrotliDecoderResult result;
            apr_size_t avail_out = 0;

            result = BrotliDecoderDecompressStream(
                         ctx->state, &ctx->pending_len,
                         (const uint8_t **)&ctx->pending_data, &avail_out,
                         NULL, NULL);

            if (result == BROTLI_DECODER_RESULT_ERROR) {
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
                     && ctx->hit_eof) {
                /* The decoder says it requires more data, but we don't have
                 * it.  This could happen either if the input is truncated or
                 * corrupted, but as we don't know for sure, return a generic
                 * error. */
                return SERF_ERROR_DECOMPRESSION_FAILED;
            }
            else if (result == BROTLI_DECODER_RESULT_SUCCESS
                     && !BrotliDecoderHasMoreOutput(ctx->state)) {
                ctx->done = TRUE;
            }

            if (BrotliDecoderHasMoreOutput(ctx->state)) {
                serf_bucket_t *output_bkt;
                const uint8_t *output;
                apr_size_t output_len = 0;

                /* There is some output for us.  Place it into the aggregate
                 * bucket, and avoid making a copy by wrapping a pointer to
                 * the internal output buffer.  This data is valid until the
                 * next call to BrotliDecoderDecompressStream(), which won't
                 * happen until this bucket is read. */
                output = BrotliDecoderTakeOutput(ctx->state, &output_len);
                output_bkt = serf_bucket_simple_create((const char *)output,
                                                       output_len, NULL, NULL,
                                                       aggregate_bkt->allocator);
                serf_bucket_aggregate_append(aggregate_bkt, output_bkt);

                return APR_SUCCESS;
            }
        }
    }
}

serf_bucket_t *
serf_bucket_brotli_decompress_create(serf_bucket_t *stream,
                                     serf_bucket_alloc_t *alloc)
{
    brotli_decompress_context_t *ctx =
        serf_bucket_mem_calloc(alloc, sizeof(*ctx));

    ctx->state = BrotliDecoderCreateInstance(alloc_func, free_func, alloc);
    ctx->input = stream;
    ctx->output = serf_bucket_aggregate_create(alloc);
    ctx->pending_data = NULL;
    ctx->pending_len = 0;
    ctx->hit_eof = FALSE;
    ctx->done = FALSE;

    serf_bucket_aggregate_hold_open(ctx->output, refill_output, ctx);

    return serf_bucket_create(&serf_bucket_type_brotli_decompress, alloc, ctx);
}

static apr_status_t serf_brotli_decompress_read(serf_bucket_t *bucket,
                                                apr_size_t requested,
                                                const char **data,
                                                apr_size_t *len)
{
    brotli_decompress_context_t *ctx = bucket->data;

    return serf_bucket_read(ctx->output, requested, data, len);
}

static apr_status_t serf_brotli_decompress_readline(serf_bucket_t *bucket,
                                                    int acceptable, int *found,
                                                    const char **data,
                                                    apr_size_t *len)
{
    brotli_decompress_context_t *ctx = bucket->data;

    return serf_bucket_readline(ctx->output, acceptable, found, data, len);
}

static apr_status_t serf_brotli_decompress_peek(serf_bucket_t *bucket,
                                                const char **data,
                                                apr_size_t *len)
{
    brotli_decompress_context_t *ctx = bucket->data;

    return serf_bucket_peek(ctx->output, data, len);
}

static void serf_brotli_decompress_destroy_and_data(serf_bucket_t *bucket)
{
    brotli_decompress_context_t *ctx = bucket->data;

    BrotliDecoderDestroyInstance(ctx->state);
    serf_bucket_destroy(ctx->input);
    serf_bucket_destroy(ctx->output);
    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_brotli_decompress_set_config(serf_bucket_t *bucket,
                                                      serf_config_t *config)
{
    brotli_decompress_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_bucket_set_config(ctx->input, config);
    if (status)
        return status;

    return serf_bucket_set_config(ctx->output, config);
}

const serf_bucket_type_t serf_bucket_type_brotli_decompress = {
    "BROTLI-DECOMPRESS",
    serf_brotli_decompress_read,
    serf_brotli_decompress_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_brotli_decompress_peek,
    serf_brotli_decompress_destroy_and_data,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_brotli_decompress_set_config,
};

#else /* SERF_HAVE_BROTLI */

int serf_bucket_is_brotli_supported()
{
    return FALSE;
}

serf_bucket_t *
serf_bucket_brotli_decompress_create(serf_bucket_t *stream,
                                     serf_bucket_alloc_t *alloc)
{
    return NULL;
}

const serf_bucket_type_t serf_bucket_type_brotli_decompress = { 0 };

#endif /* SERF_HAVE_BROTLI */
