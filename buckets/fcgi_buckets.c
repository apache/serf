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

#include <stdlib.h>

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

#include "protocols/fcgi_buckets.h"

#define FCGI_RECORD_SIZE 8

typedef struct fcgi_unframe_ctx_t
{
    serf_bucket_t *stream;

    serf_bucket_end_of_frame_t end_of_frame;
    void *end_of_frame_baton;

    apr_size_t record_remaining;
    apr_size_t payload_remaining;
    apr_size_t pad_remaining;

    apr_uint16_t frame_type;
    apr_uint16_t streamid;

    unsigned char buffer[FCGI_RECORD_SIZE];
} fcgi_unframe_ctx_t;

serf_bucket_t * serf__bucket_fcgi_unframe_create(serf_bucket_t *stream,
                                                 serf_bucket_alloc_t *allocator)
{
    fcgi_unframe_ctx_t *ctx;

    ctx = serf_bucket_mem_calloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->record_remaining = FCGI_RECORD_SIZE;

    return serf_bucket_create(&serf_bucket_type__fcgi_unframe, allocator, ctx);
}

void serf__bucket_fcgi_unframe_set_eof(serf_bucket_t *bucket,
                                       serf_bucket_end_of_frame_t end_of_frame,
                                       void *end_of_frame_baton)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;

    ctx->end_of_frame = end_of_frame;
    ctx->end_of_frame_baton = end_of_frame_baton;
}

apr_status_t serf__bucket_fcgi_unframe_read_info(serf_bucket_t *bucket,
                                                 apr_uint16_t *stream_id,
                                                 apr_uint16_t *frame_type)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;
    const char *data;
    apr_size_t len;
    apr_status_t status;

    if (ctx->record_remaining == 0)
    {
        if (stream_id)
            *stream_id = ctx->streamid;
        if (frame_type)
            *frame_type = ctx->frame_type;

        return APR_SUCCESS;
    }

    status = serf_bucket_read(ctx->stream, ctx->record_remaining, &data, &len);
    if (!SERF_BUCKET_READ_ERROR(status))
    {
        const unsigned char *header;

        if (len < FCGI_RECORD_SIZE)
        {
            memcpy(ctx->buffer + FCGI_RECORD_SIZE - ctx->record_remaining,
                   data, len);

            ctx->record_remaining -= len;
            header = ctx->buffer;
        }
        else
        {
            header = (const void *)data;
            ctx->record_remaining = 0;
        }

        if (ctx->record_remaining == 0)
        {
            /* We combine version and frametype in a single value */
            ctx->frame_type = (header[0] << 8) | header[1];
            ctx->streamid = (header[2] << 8) | header[3];
            ctx->payload_remaining = (header[4] << 8) | header[5];
            /* header[6] is reserved */
            ctx->pad_remaining = header[7];

            /* Fill output arguments if necessary */
            if (stream_id)
                *stream_id = ctx->streamid;
            if (frame_type)
                *frame_type = ctx->frame_type;

            status = (ctx->payload_remaining == 0) ? APR_EOF
                : APR_SUCCESS;

            /* If we hava a zero-length frame we have to call the eof callback
            now, as the read operations will just shortcut to APR_EOF */
            if (ctx->payload_remaining == 0 && ctx->end_of_frame)
            {
                apr_status_t cb_status;

                cb_status = (*ctx->end_of_frame)(ctx->end_of_frame_baton,
                                                 bucket);

                ctx->end_of_frame = NULL;

                if (SERF_BUCKET_READ_ERROR(cb_status))
                    status = cb_status;
            }
        }
        else if (APR_STATUS_IS_EOF(status))
        {
            /* Reading frame failed because we couldn't read the header. Report
               a read failure instead of semi-success */
            status = SERF_ERROR_TRUNCATED_STREAM;
        }
        else if (!status)
            status = APR_EAGAIN;

    }
    return status;
}

static apr_status_t serf_fcgi_unframe_read(serf_bucket_t *bucket,
                                           apr_size_t requested,
                                           const char **data,
                                           apr_size_t *len)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;
    apr_status_t status;

    status = serf__bucket_fcgi_unframe_read_info(bucket, NULL, NULL);
    if (status)
    {
        *len = 0;
        return status;
    }

    if (requested > ctx->payload_remaining)
        requested = ctx->payload_remaining;

    if (requested == ctx->payload_remaining && ctx->pad_remaining)
        requested += ctx->pad_remaining;

    status = serf_bucket_read(ctx->stream, requested, data, len);
    if (!SERF_BUCKET_READ_ERROR(status)) {
        if (*len >= ctx->payload_remaining) {
            ctx->pad_remaining -= (*len - ctx->payload_remaining);
            *len = ctx->payload_remaining;
            ctx->payload_remaining = 0;
        }
        else {
            ctx->payload_remaining -= *len;
        }

        if (!ctx->payload_remaining && !ctx->pad_remaining) {
            if (ctx->end_of_frame) {
                status = (*ctx->end_of_frame)(ctx->end_of_frame_baton,
                                              bucket);
                ctx->end_of_frame = NULL;
            }

            if (!SERF_BUCKET_READ_ERROR(status))
                status = APR_EOF;
        }
        else if (APR_STATUS_IS_EOF(status))
            status = SERF_ERROR_TRUNCATED_STREAM;
    }

    return status;
}

static apr_status_t serf_fcgi_unframe_peek(serf_bucket_t *bucket,
                                           const char **data,
                                           apr_size_t *len)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;
    apr_status_t status;

    status = serf__bucket_fcgi_unframe_read_info(bucket, NULL, NULL);

    if (status)
    {
        *len = 0;
        return status;
    }

    status = serf_bucket_peek(ctx->stream, data, len);
    if (!SERF_BUCKET_READ_ERROR(status))
    {
        if (*len > ctx->payload_remaining)
            *len = ctx->payload_remaining;
    }

    return status;
}

static apr_uint64_t serf_fcgi_unframe_get_remaining(serf_bucket_t *bucket)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;

    if (ctx->record_remaining)
        return SERF_LENGTH_UNKNOWN;
    else
        return ctx->payload_remaining;
}

static apr_status_t serf_fcgi_unframe_set_config(serf_bucket_t *bucket,
                                                 serf_config_t *config)
{
    fcgi_unframe_ctx_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

extern const serf_bucket_type_t serf_bucket_type__fcgi_unframe =
{
    "FCGI-UNFRAME",
    serf_fcgi_unframe_read,
    serf_default_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_fcgi_unframe_peek,
    serf_default_destroy_and_data,
    serf_default_read_bucket,
    serf_fcgi_unframe_get_remaining,
    serf_fcgi_unframe_set_config
};


/* ==================================================================== */

serf_bucket_t *
serf__bucket_fcgi_frame_create(serf_bucket_t *stream,
                               apr_uint16_t stream_id,
                               apr_uint16_t frame_type,
                               serf_bucket_alloc_t *alloc)
{
    return NULL;
}


static apr_status_t serf_fcgi_frame_read(serf_bucket_t *bucket,
                                         apr_size_t requested,
                                         const char **data,
                                         apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static apr_status_t serf_fcgi_frame_read_iovec(serf_bucket_t *bucket,
                                               apr_size_t requested,
                                               int vecs_size,
                                               struct iovec *vecs,
                                               int *vecs_used)
{
    return APR_ENOTIMPL;
}

static apr_status_t serf_fcgi_frame_peek(serf_bucket_t *bucket,
                                         const char **data,
                                         apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static void serf_fcgi_frame_destroy(serf_bucket_t *bucket)
{
    serf_default_destroy_and_data(bucket);
}

static apr_uint64_t serf_fcgi_frame_get_remaining(serf_bucket_t *bucket)
{
    return APR_ENOTIMPL;
}

static apr_status_t serf_fcgi_frame_set_config(serf_bucket_t *bucket,
                                                 serf_config_t *config)
{
    return APR_ENOTIMPL;
}

extern const serf_bucket_type_t serf_bucket_type__fcgi_frame =
{
    "FCGI-FRAME",
    serf_fcgi_frame_read,
    serf_default_readline,
    serf_fcgi_frame_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_fcgi_frame_peek,
    serf_fcgi_frame_destroy,
    serf_default_read_bucket,
    serf_fcgi_frame_get_remaining,
    serf_fcgi_frame_set_config
};
