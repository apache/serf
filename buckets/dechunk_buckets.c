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

#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"

typedef struct dechunk_context_t {
    serf_bucket_t *stream;

    enum {
        STATE_SIZE,     /* reading the chunk size */
        STATE_CHUNK,    /* reading the chunk */
        STATE_TERM,     /* reading the chunk terminator */
        STATE_DONE      /* body is done; we've returned EOF */
    } state;

    /* How much of the chunk, or the terminator, do we have left to read? */
    apr_int64_t body_left;

    /* Buffer for accumulating a chunk size. */
    serf_linebuf_t linebuf;
} dechunk_context_t;


serf_bucket_t *serf_bucket_dechunk_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator)
{
    dechunk_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->state = STATE_SIZE;

    serf_linebuf_init(&ctx->linebuf);

    return serf_bucket_create(&serf_bucket_type_dechunk, allocator, ctx);
}

static void serf_dechunk_destroy_and_data(serf_bucket_t *bucket)
{
    dechunk_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

static apr_status_t wait_for_chunk(serf_bucket_t *bucket)
{
    dechunk_context_t *ctx = bucket->data;
    apr_status_t status;

    while (1) {
        switch (ctx->state) {
        case STATE_SIZE:

            /* fetch a line terminated by CRLF */
            status = serf_linebuf_fetch(&ctx->linebuf, ctx->stream,
                                        SERF_NEWLINE_CRLF);
            if (SERF_BUCKET_READ_ERROR(status))
                return status;

            /* if a line was read, then parse it. */
            if (ctx->linebuf.state == SERF_LINEBUF_READY) {
                /* NUL-terminate the line. if it filled the entire buffer,
                   then just assume the thing is too large. */
                if (ctx->linebuf.used == sizeof(ctx->linebuf.line))
                    return APR_FROM_OS_ERROR(ERANGE);
                ctx->linebuf.line[ctx->linebuf.used] = '\0';

                /* convert from HEX digits. */
                ctx->body_left = apr_strtoi64(ctx->linebuf.line, NULL, 16);
                if (errno == ERANGE) {
                    return APR_FROM_OS_ERROR(ERANGE);
                }

                if (ctx->body_left == 0) {
                    /* Just read the last-chunk marker. We're DONE. */
                    ctx->state = STATE_DONE;
                    status = APR_EOF;
                }
                else {
                    /* Got a size, so we'll start reading the chunk now. */
                    ctx->state = STATE_CHUNK;
                }

                /* If we can read more, then go do so. */
                if (!status)
                    continue;
            }
            /* assert: status != 0 */

            return status;

        case STATE_CHUNK:
            return APR_SUCCESS;

        case STATE_TERM:
          {
            /* Delegate to the stream bucket to do the read. */
            const char *data;
            apr_size_t len;

            status = serf_bucket_read(ctx->stream,
                                      (apr_size_t)ctx->body_left /* 2 or 1 */,
                                      &data, &len);
            if (SERF_BUCKET_READ_ERROR(status))
                return status;

            /* Some data was read, so decrement the amount left and see
             * if we're done reading the chunk terminator.
             */
            ctx->body_left -= len;

            /* We need more data but there is no more available. */
            if (ctx->body_left && APR_STATUS_IS_EOF(status))
                return SERF_ERROR_TRUNCATED_HTTP_RESPONSE;

            if (!ctx->body_left) {
                ctx->state = STATE_SIZE;
            }

            /* Don't return the CR of CRLF to the caller! */
            if (status)
                return status;

            break;
          }
        case STATE_DONE:
            /* Just keep returning EOF */
            return APR_EOF;

        default:
            /* Not reachable */
            return APR_EGENERAL;
        }
    }
    /* NOTREACHED */
}

static apr_status_t serf_dechunk_read(serf_bucket_t *bucket,
                                      apr_size_t requested,
                                      const char **data, apr_size_t *len)
{
    dechunk_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_chunk(bucket);
    if (status || ctx->state != STATE_CHUNK) {
        *len = 0;
        return status;
    }

    /* Don't overshoot */
    if (requested > ctx->body_left) {
        requested = (apr_size_t)ctx->body_left;
    }

    /* ### If requested is now ctx->body_left we might want to try
           reading 2 extra bytes in an attempt to skip STATE_TERM
           directly */

    /* Delegate to the stream bucket to do the read. */
    status = serf_bucket_read(ctx->stream, requested, data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    /* Some data was read, so decrement the amount left and see
     * if we're done reading this chunk. */
    ctx->body_left -= *len;
    if (!ctx->body_left) {
        ctx->state = STATE_TERM;
        ctx->body_left = 2;     /* CRLF */
    }

    /* We need more data but there is no more available. */
    if (ctx->body_left && APR_STATUS_IS_EOF(status)) {
        return SERF_ERROR_TRUNCATED_HTTP_RESPONSE;
    }

    /* Return the data we just read. */
    return status;
}

static apr_status_t serf_dechunk_readline2(serf_bucket_t *bucket,
                                           int accepted,
                                           apr_size_t requested,
                                           int *found,
                                           const char **data,
                                           apr_size_t *len)
{
    dechunk_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_chunk(bucket);
    if (status || ctx->state != STATE_CHUNK) {
        *len = 0;
        return status;
    }

    /* Don't overshoot */
    if (requested > ctx->body_left) {
        requested = (apr_size_t)ctx->body_left;
    }

    /* Delegate to the stream bucket to do the read. */
    status = serf_bucket_readline2(ctx->stream, accepted, requested,
                                   found, data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    /* Some data was read, so decrement the amount left and see
     * if we're done reading this chunk. */
    ctx->body_left -= *len;
    if (!ctx->body_left) {
        ctx->state = STATE_TERM;
        ctx->body_left = 2;     /* CRLF */
    }

    /* We need more data but there is no more available. */
    if (ctx->body_left && APR_STATUS_IS_EOF(status)) {
        return SERF_ERROR_TRUNCATED_HTTP_RESPONSE;
    }

    /* Return the data we just read. */
    return status;
}

static apr_status_t serf_dechunk_readline(serf_bucket_t *bucket,
                                          int accepted,
                                          int *found,
                                          const char **data,
                                          apr_size_t *len)
{
    return serf_dechunk_readline2(bucket, accepted, SERF_READ_ALL_AVAIL,
                                  found, data, len);
}

static apr_status_t serf_dechunk_peek(serf_bucket_t *bucket,
                                      const char **data,
                                      apr_size_t *len)
{
    dechunk_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_chunk(bucket);
    if (status) {
        *len = 0;
        return SERF_BUCKET_READ_ERROR(status) ? status : APR_SUCCESS;
    }

    status = serf_bucket_peek(ctx->stream, data, len);
    if (!SERF_BUCKET_READ_ERROR(status) && *len > ctx->body_left)
    {
        *len = (apr_size_t)ctx->body_left;
    }
    return status;
}

static apr_status_t serf_dechunk_set_config(serf_bucket_t *bucket,
                                            serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
     it along to our wrapped bucket. */
    dechunk_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

const serf_bucket_type_t serf_bucket_type_dechunk = {
    "DECHUNK",
    serf_dechunk_read,
    serf_dechunk_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_dechunk_peek,
    serf_dechunk_destroy_and_data,
    serf_default_read_bucket,
    serf_dechunk_readline2,
    serf_default_get_remaining,
    serf_dechunk_set_config,
};
