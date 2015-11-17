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

typedef struct fcgi_params_decode_ctx_t
{
    serf_bucket_t *stream;

    const char *last_data;
    apr_size_t last_len;

    apr_size_t key_sz;
    apr_size_t val_sz;

    enum fcgi_param_decode_status_t
    {
        DS_SIZES = 0,
        DS_KEY,
        DS_VALUE,
    } state;

    char size_buffer[8];
    apr_size_t tmp_size;

    char *key;
    char *val;

    const char *method;
    const char *path;

    serf_bucket_t *headers;

} fcgi_params_decode_ctx_t;

serf_bucket_t *
serf__bucket_fcgi_params_decode_create(serf_bucket_t *stream,
                                       serf_bucket_alloc_t *alloc)
{
    fcgi_params_decode_ctx_t *ctx;

    ctx = serf_bucket_mem_calloc(alloc, sizeof(*ctx));
    ctx->stream = stream;

    return serf_bucket_create(&serf_bucket_type__fcgi_params_decode, alloc,
                              ctx);
}

static apr_size_t size_data_requested(fcgi_params_decode_ctx_t *ctx)
{
    apr_size_t requested;

    if (ctx->tmp_size < 1)
        requested = 2;
    else if (ctx->size_buffer[0] & 0x80) {
        requested = 5;

        if (ctx->tmp_size > 4
            && ctx->size_buffer[4] & 0x80) {
            requested = 8;
        }
    }
    else if (ctx->tmp_size >= 2
             && ctx->size_buffer[1] & 0x80) {
        requested = 5;
    }
    else
        requested = 2;

    return requested;
}

void fcgi_handle_keypair(serf_bucket_t *bucket)
{
    fcgi_params_decode_ctx_t *ctx = bucket->data;
    char *key = ctx->key;
    char *val = ctx->val;

    ctx->key = NULL;
    ctx->val = NULL;

    if (!ctx->headers)
        ctx->headers = serf_bucket_headers_create(bucket->allocator);

    if (strncasecmp(key, "HTTP_", 5) == 0
        && strncasecmp(key + 5, "_FCGI_", 6) != 0)
    {
        apr_size_t i;
        memmove(key, key + 5, ctx->key_sz - 5 + 1);
        for (i = 0; i < ctx->key_sz; i++) {
            if (key[i] == '_')
                key[i] = '-';
        }
        ctx->key_sz -= 5;
    }
    else if (ctx->key_sz == 6 && !strcasecmp(key, "METHOD"))
    {
        ctx->method = val;
        serf_bucket_mem_free(bucket->allocator, key);
        return;
    }
    else if (ctx->key_sz == 11 && !strcasecmp(key, "REQUEST_URI"))
    {
        ctx->path = val;
        serf_bucket_mem_free(bucket->allocator, key);
        return;
    }
    else
    {
        memmove(key + 6, key, ctx->key_sz + 1);
        memcpy(key, "_FCGI_", 6);
        ctx->key_sz += 6;
    }

    serf_bucket_headers_setx(ctx->headers,
                             key, ctx->key_sz, TRUE,
                             val, ctx->val_sz, TRUE);
    serf_bucket_mem_free(bucket->allocator, key);
    serf_bucket_mem_free(bucket->allocator, val);
}

apr_status_t fcgi_params_decode(serf_bucket_t *bucket)
{
    fcgi_params_decode_ctx_t *ctx = bucket->data;
    apr_status_t status = APR_SUCCESS;

    while (status == APR_SUCCESS) {
        apr_size_t requested;
        const char *data;
        const unsigned char *udata;
        apr_size_t len;

        switch (ctx->state) {
            case DS_SIZES:
                requested = size_data_requested(ctx);
                status = serf_bucket_read(ctx->stream,
                                          requested - ctx->tmp_size,
                                          &data, &len);
                if (SERF_BUCKET_READ_ERROR(status))
                    return status;

                if (len < requested) {
                    memcpy(ctx->size_buffer + ctx->tmp_size, data, len);
                    ctx->tmp_size += len;

                    len = ctx->tmp_size;
                    data = ctx->size_buffer;
                }

                if (size_data_requested(ctx) < len) {
                    /* Read again. More bytes needed for
                       determining lengths */
                    if (data != ctx->size_buffer) {
                        memcpy(ctx->size_buffer, data, len);
                        ctx->tmp_size = len;
                    }
                    break;
                }

                udata = (const unsigned char*)data;

                if (udata[0] & 0x80) {
                    ctx->key_sz = (udata[0] & 0x7F) << 24 | (udata[1] << 16)
                                        | (udata[2] << 8) | (udata[3]);
                    udata += 4;
                }
                else {
                    ctx->key_sz = udata[0] & 0x7F;
                    udata += 1;
                }

                if (udata[0] & 0x80) {
                    ctx->val_sz = (udata[0] & 0x7F) << 24 | (udata[1] << 16)
                                        | (udata[2] << 8) | (udata[3]);
                    udata += 4;
                }
                else {
                    ctx->val_sz = udata[0] & 0x7F;
                    udata += 1;
                }

                ctx->tmp_size = 0;
                ctx->state++;
                break;
            case DS_KEY:
                status = serf_bucket_read(ctx->stream, ctx->key_sz,
                                          &data, &len);
                if (SERF_BUCKET_READ_ERROR(status))
                    break;

                if (!ctx->key) {
                    ctx->key = serf_bucket_mem_alloc(bucket->allocator,
                                                     ctx->key_sz + 1 + 6);
                    ctx->key[ctx->key_sz] = 0;
                }

                memcpy(ctx->key + ctx->tmp_size, data, len);
                ctx->tmp_size += len;

                if (ctx->tmp_size == ctx->key_sz) {
                    ctx->state++;
                    ctx->tmp_size = 0;
                }
                break;
            case DS_VALUE:
                status = serf_bucket_read(ctx->stream, ctx->val_sz,
                                          &data, &len);
                if (SERF_BUCKET_READ_ERROR(status))
                    break;
                if (!ctx->val) {
                    ctx->val = serf_bucket_mem_alloc(bucket->allocator,
                                                     ctx->val_sz + 1);
                    ctx->val[ctx->val_sz] = 0;
                }

                if (len == ctx->val_sz)
                    ctx->state++;

                memcpy(ctx->val + ctx->tmp_size, data, len);
                ctx->tmp_size += len;

                if (ctx->tmp_size == ctx->val_sz) {

                    fcgi_handle_keypair(bucket);
                    ctx->state = DS_SIZES;
                    ctx->tmp_size = 0;
                }
                break;
        }
    }

    if (APR_STATUS_IS_EOF(status)) {
        if (ctx->state == DS_SIZES && !ctx->tmp_size
            || (ctx->state == DS_KEY && !ctx->key_sz && !ctx->val_sz))
        {
            return APR_SUCCESS;
        }

        return SERF_ERROR_TRUNCATED_STREAM;
    }

    return status;
}

static void fcgi_serialize(serf_bucket_t *bucket)
{
    fcgi_params_decode_ctx_t *ctx = bucket->data;
    serf_bucket_t *tmp;

    serf_bucket_aggregate_become(bucket);

    if (ctx->method || ctx->path) {
        if (ctx->method) {
            tmp = serf_bucket_simple_own_create(ctx->method, strlen(ctx->method),
                                                bucket->allocator);
        }
        else
            tmp = SERF_BUCKET_SIMPLE_STRING("GET", bucket->allocator);
        serf_bucket_aggregate_append(bucket, tmp);

        tmp = SERF_BUCKET_SIMPLE_STRING(" ", bucket->allocator);
        serf_bucket_aggregate_append(bucket, tmp);

        if (ctx->path) {
            tmp = serf_bucket_simple_own_create(ctx->path, strlen(ctx->path),
                                                bucket->allocator);
        }
        else
            tmp = SERF_BUCKET_SIMPLE_STRING("/", bucket->allocator);
        serf_bucket_aggregate_append(bucket, tmp);

        tmp = SERF_BUCKET_SIMPLE_STRING(" HTTP/2.0\r\n", bucket->allocator);
        serf_bucket_aggregate_append(bucket, tmp);
    }

    if (ctx->headers)
        serf_bucket_aggregate_append(bucket, ctx->headers);

    if (ctx->key)
        serf_bucket_mem_free(bucket->allocator, ctx->key);
    if (ctx->val)
        serf_bucket_mem_free(bucket->allocator, ctx->val);

    serf_bucket_mem_free(bucket->allocator, ctx);
}

static apr_status_t fcgi_params_decode_read(serf_bucket_t *bucket,
                                            apr_size_t requested,
                                            const char **data,
                                            apr_size_t *len)
{
    apr_status_t status;

    status = fcgi_params_decode(bucket);

    if (status) {
        *len = 0;
        return status;
    }

    fcgi_serialize(bucket);
    return bucket->type->read(bucket, requested, data, len);
}

static apr_status_t fcgi_params_decode_peek(serf_bucket_t *bucket,
                                            const char **data,
                                            apr_size_t *len)
{
    apr_status_t status;

    status = fcgi_params_decode(bucket);

    if (status) {
        *len = 0;
        return status;
    }

    fcgi_serialize(bucket);
    return bucket->type->peek(bucket, data, len);
}

static void fcgi_params_decode_destroy(serf_bucket_t *bucket)
{
    fcgi_serialize(bucket);

    bucket->type->destroy(bucket);
}


extern const serf_bucket_type_t serf_bucket_type__fcgi_params_decode =
{
    "FCGI-PARAMS_DECODE",
    fcgi_params_decode_read,
    serf_default_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    fcgi_params_decode_peek,
    fcgi_params_decode_destroy,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_default_ignore_config
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

