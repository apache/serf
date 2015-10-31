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

#include "protocols/http2_buckets.h"

/* https://tools.ietf.org/html/rfc7540#section-4.1 */
#define FRAME_PREFIX_SIZE 9 

typedef struct http2_unframe_context_t
{
  serf_bucket_t *stream;
  apr_size_t max_payload_size;

  apr_size_t prefix_remaining;

  apr_status_t (*eof_callback)(void *baton,
                               serf_bucket_t *bucket);
  void *eof_callback_baton;

  /* These fields are only set after prefix_remaining is 0 */
  apr_size_t payload_remaining;  /* 0 <= payload_length < 2^24 */
  apr_int32_t stream_id;         /* 0 <= stream_id < 2^31 */
  unsigned char frame_type;
  unsigned char flags;

  unsigned char buffer[FRAME_PREFIX_SIZE];
  char destroy_stream;
} http2_unframe_context_t;

serf_bucket_t *
serf__bucket_http2_unframe_create(serf_bucket_t *stream,
                                  int destroy_stream,
                                  apr_size_t max_payload_size,
                                  serf_bucket_alloc_t *allocator)
{
  http2_unframe_context_t *ctx;

  ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
  ctx->stream = stream;
  ctx->max_payload_size = max_payload_size;
  ctx->prefix_remaining = sizeof(ctx->buffer);
  ctx->eof_callback = NULL;

  ctx->destroy_stream = (destroy_stream != 0);

  return serf_bucket_create(&serf_bucket_type__http2_unframe, allocator, ctx);
}

void
serf__bucket_http2_unframe_set_eof(serf_bucket_t *bucket,
                                   apr_status_t (*eof_callback)(
                                                    void *baton,
                                                    serf_bucket_t *bucket),
                                   void *eof_callback_baton)
{
  http2_unframe_context_t *ctx = bucket->data;

  ctx->eof_callback = eof_callback;
  ctx->eof_callback_baton = eof_callback_baton;
}

apr_status_t
serf__bucket_http2_unframe_read_info(serf_bucket_t *bucket,
                                     apr_int32_t *stream_id,
                                     unsigned char *frame_type,
                                     unsigned char *flags)
{
  http2_unframe_context_t *ctx = bucket->data;
  const char *data;
  apr_size_t len;
  apr_status_t status;

  if (ctx->prefix_remaining == 0)
    {
      if (stream_id)
        *stream_id = ctx->stream_id;
      if (frame_type)
        *frame_type = ctx->frame_type;
      if (flags)
        *flags = ctx->flags;

      return APR_SUCCESS;
    }

  status = serf_bucket_read(ctx->stream, ctx->prefix_remaining, &data, &len);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      const unsigned char *header;

      if (len < FRAME_PREFIX_SIZE)
        {
          memcpy(ctx->buffer + FRAME_PREFIX_SIZE - ctx->prefix_remaining,
                 data, len);

          ctx->prefix_remaining -= len;
          header = ctx->buffer;
        }
      else
        {
          header = (const void *)data;
          ctx->prefix_remaining = 0;
        }

      if (ctx->prefix_remaining == 0)
        {
          apr_size_t payload_length = (header[0] << 16)
                                    | (header[1] << 8)
                                    | (header[2]);
          ctx->frame_type = header[3];
          ctx->flags = header[4];
          /* Highest bit of stream_id MUST be ignored */
          ctx->stream_id = ((header[5] & 0x7F) << 24)
                           | (header[6] << 16)
                           | (header[7] << 8)
                           | (header[8]);

          ctx->payload_remaining = payload_length;

          /* Fill output arguments if necessary */
          if (stream_id)
            *stream_id = ctx->stream_id;
          if (frame_type)
            *frame_type = ctx->frame_type;
          if (flags)
            *flags = ctx->flags;

          /* https://tools.ietf.org/html/rfc7540#section-4.2
            An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame
            exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any
            limit defined for the frame type, or is too small to contain
            mandatory frame data.
          */
          if (ctx->max_payload_size < payload_length)
              return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

          status = (ctx->payload_remaining == 0) ? APR_EOF
                                                 : APR_SUCCESS;

          /* If we hava a zero-length frame we have to call the eof callback
             now, as the read operations will just shortcut to APR_EOF */
          if (ctx->payload_remaining == 0 && ctx->eof_callback)
            {
              apr_status_t cb_status;

              cb_status = ctx->eof_callback(ctx->eof_callback_baton,
                                            bucket);

              if (SERF_BUCKET_READ_ERROR(cb_status))
                status = cb_status;
            }
        }
      else if (APR_STATUS_IS_EOF(status))
        {
          /* Reading frame failed because we couldn't read the header. Report
             a read failure instead of semi-success */
          status = SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
      else if (!status)
        status = APR_EAGAIN;

    }
  return status;
}

static apr_status_t
serf_http2_unframe_read(serf_bucket_t *bucket,
                        apr_size_t requested,
                        const char **data,
                        apr_size_t *len)
{
  http2_unframe_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf__bucket_http2_unframe_read_info(bucket, NULL, NULL, NULL);

  if (status)
    {
      *len = 0;
      return status;
    }

  if (ctx->payload_remaining == 0)
    {
      *len = 0;
      return APR_EOF;
    }

  if (requested > ctx->payload_remaining)
    requested = ctx->payload_remaining;

  status = serf_bucket_read(ctx->stream, requested, data, len);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      ctx->payload_remaining -= *len;

      if (ctx->payload_remaining == 0)
        {
          if (ctx->eof_callback)
            status = ctx->eof_callback(ctx->eof_callback_baton,
                                       bucket);

          if (!SERF_BUCKET_READ_ERROR(status))
            status = APR_EOF;
        }
      else if (APR_STATUS_IS_EOF(status))
        return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
    }

  return status;
}

static apr_status_t
serf_http2_unframe_read_iovec(serf_bucket_t *bucket,
                              apr_size_t requested,
                              int vecs_size,
                              struct iovec *vecs,
                              int *vecs_used)
{
  http2_unframe_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf__bucket_http2_unframe_read_info(bucket, NULL, NULL, NULL);

  if (status)
    {
      *vecs_used = 0;
      return status;
    }

  if (ctx->payload_remaining == 0)
    {
      *vecs_used = 0;
      return APR_EOF;
    }

  if (requested > ctx->payload_remaining)
    requested = ctx->payload_remaining;

  status = serf_bucket_read_iovec(ctx->stream, requested,
                                  vecs_size, vecs, vecs_used);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      int i;
      apr_size_t len = 0;

      for (i = 0; i < *vecs_used; i++)
        len += vecs[i].iov_len;

      ctx->payload_remaining -= len;

      if (ctx->payload_remaining == 0)
        {
          if (ctx->eof_callback)
            status = ctx->eof_callback(ctx->eof_callback_baton,
                                       bucket);

          if (!SERF_BUCKET_READ_ERROR(status))
            status = APR_EOF;
        }
      else if (APR_STATUS_IS_EOF(status))
        return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
    }

  return status;
}

static apr_status_t
serf_http2_unframe_peek(serf_bucket_t *bucket,
                        const char **data,
                        apr_size_t *len)
{
  http2_unframe_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf__bucket_http2_unframe_read_info(bucket, NULL, NULL, NULL);

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

static void
serf_http2_unframe_destroy(serf_bucket_t *bucket)
{
  http2_unframe_context_t *ctx = bucket->data;

  if (ctx->destroy_stream)
    serf_bucket_destroy(ctx->stream);

  serf_default_destroy_and_data(bucket);
}

static apr_uint64_t
serf_http2_unframe_get_remaining(serf_bucket_t *bucket)
{
  http2_unframe_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf__bucket_http2_unframe_read_info(bucket, NULL, NULL, NULL);

  if (status)
    return SERF_LENGTH_UNKNOWN;

  return ctx->payload_remaining;
}

/* ### need to implement */
#define serf_http2_unframe_readline NULL

const serf_bucket_type_t serf_bucket_type__http2_unframe = {
  "H2-UNFRAME",
  serf_http2_unframe_read,
  serf_http2_unframe_readline /* ### TODO */,
  serf_http2_unframe_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_unframe_peek,
  serf_http2_unframe_destroy,
  serf_default_read_bucket,
  serf_http2_unframe_get_remaining,
  serf_default_ignore_config
};

typedef struct http2_unpad_context_t
{
  serf_bucket_t *stream;
  apr_size_t payload_remaining;
  apr_size_t pad_remaining;
  apr_size_t pad_length;
  int padsize_read;
  int destroy_stream;
} http2_unpad_context_t;

serf_bucket_t *
serf__bucket_http2_unpad_create(serf_bucket_t *stream,
                                int destroy_stream,
                                serf_bucket_alloc_t *allocator)
{
  http2_unpad_context_t *ctx;

  ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
  ctx->stream = stream;
  ctx->padsize_read = FALSE;
  ctx->destroy_stream = destroy_stream;

  return serf_bucket_create(&serf_bucket_type__http2_unpad, allocator, ctx);
}

static apr_status_t
serf_http2_unpad_read_padsize(serf_bucket_t *bucket)
{
  http2_unpad_context_t *ctx = bucket->data;
  apr_status_t status;
  const char *data;
  apr_size_t len;

  if (ctx->padsize_read)
    return APR_SUCCESS;

  status = serf_bucket_read(ctx->stream, 1, &data, &len);
  if (! SERF_BUCKET_READ_ERROR(status) && len > 0)
    {
      apr_int64_t remaining;

      ctx->pad_length = *(unsigned char *)data;
      ctx->pad_remaining = ctx->pad_length;
      ctx->padsize_read = TRUE;

      /* We call get_remaining() *after* reading from ctx->stream,
         to allow the framing above us to be read before we call this */
      remaining = serf_bucket_get_remaining(ctx->stream);

      if (remaining == SERF_LENGTH_UNKNOWN
          || remaining > APR_SIZE_MAX)
        return APR_EGENERAL; /* Can't calculate padding size */

      /* http://tools.ietf.org/html/rfc7540#section-6.1
         If the length of the padding is the length of the
         frame payload or greater, the recipient MUST treat this as a
         connection error (Section 5.4.1) of type PROTOCOL_ERROR.

         The frame payload includes the length byte, so when remaining
         is 0, that isn't a protocol error */
      if (remaining < ctx->pad_length)
        return SERF_ERROR_HTTP2_PROTOCOL_ERROR;

      ctx->payload_remaining = (apr_size_t)remaining - ctx->pad_length;
    }
  else if (APR_STATUS_IS_EOF(status))
    status = SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
  else if (!status)
    status = APR_EAGAIN;

  return status;
}

static apr_status_t
serf_http2_unpad_read_padding(serf_bucket_t *bucket)
{
  http2_unpad_context_t *ctx = bucket->data;
  apr_status_t status;

  /* ### What is the most efficient way to skip data?
         Should we use serf_bucket_read_iovec()? */

  while (ctx->pad_remaining > 0)
    {
      apr_size_t pad_read;
      const char *pad_data;

      status = serf_bucket_read(ctx->stream, ctx->pad_remaining,
                                &pad_data, &pad_read);

      if (! SERF_BUCKET_READ_ERROR(status))
        ctx->pad_remaining -= pad_read;

      if (status)
        return status;
    }

  return APR_EOF;
}

static apr_status_t
serf_http2_unpad_read(serf_bucket_t *bucket,
                      apr_size_t requested,
                      const char **data,
                      apr_size_t *len)
{
  http2_unpad_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf_http2_unpad_read_padsize(bucket);

  if (status)
    {
      *len = 0;
      return status;
    }
  else if (ctx->payload_remaining == 0
           && ctx->pad_remaining == 0)
    {
      *len = 0;
      return APR_EOF;
    }


  if (requested >= ctx->payload_remaining)
    requested = ctx->payload_remaining + ctx->pad_remaining;

  status = serf_bucket_read(ctx->stream, requested, data, len);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      if (*len < ctx->payload_remaining)
        ctx->payload_remaining -= *len;
      else
        {
          ctx->pad_remaining -= (*len - ctx->payload_remaining);
          *len = ctx->payload_remaining;
          ctx->payload_remaining = 0;

          if (ctx->pad_remaining == 0)
            status = APR_EOF;
        }

      if (APR_STATUS_IS_EOF(status)
          && (ctx->pad_remaining != 0 || ctx->payload_remaining != 0))
        {
          status = SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
    }

  return status;
}

static apr_status_t
serf_http2_unpad_read_iovec(serf_bucket_t *bucket,
                            apr_size_t requested,
                            int vecs_size,
                            struct iovec *vecs,
                            int *vecs_used)
{
  http2_unpad_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf_http2_unpad_read_padsize(bucket);

  if (status)
    {
      *vecs_used = 0;
      return status;
    }
  else if (ctx->payload_remaining == 0)
    {
      *vecs_used = 0;
      return serf_http2_unpad_read_padding(bucket);
    }

  /* ### Can we read data and padding in one go? */
  if (requested > ctx->payload_remaining)
    requested = ctx->payload_remaining;

  status = serf_bucket_read_iovec(ctx->stream, requested,
                                  vecs_size, vecs, vecs_used);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      int i;
      apr_size_t len = 0;

      for (i = 0; i < *vecs_used; i++)
        len += vecs[i].iov_len;

      ctx->payload_remaining -= len;

      if (APR_STATUS_IS_EOF(status)
          && (ctx->pad_remaining != 0 || ctx->payload_remaining != 0))
        {
          status = SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
    }

  return status;
}

static apr_status_t
serf_http2_unpad_peek(serf_bucket_t *bucket,
                      const char **data,
                      apr_size_t *len)
{
  http2_unpad_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf_http2_unpad_read_padsize(bucket);

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

static void
serf_http2_unpad_destroy(serf_bucket_t *bucket)
{
  http2_unpad_context_t *ctx = bucket->data;

  if (ctx->destroy_stream)
    serf_bucket_destroy(ctx->stream);

  serf_default_destroy_and_data(bucket);
}

static apr_uint64_t
serf_http2_unpad_get_remaining(serf_bucket_t *bucket)
{
  http2_unframe_context_t *ctx = bucket->data;
  apr_status_t status;

  status = serf_http2_unpad_read_padsize(bucket);

  if (status)
    return SERF_LENGTH_UNKNOWN;

  return ctx->payload_remaining;
}

/* ### need to implement */
#define serf_h2_dechunk_readline NULL

const serf_bucket_type_t serf_bucket_type__http2_unpad = {
  "H2-UNPAD",
  serf_http2_unpad_read,
  serf_h2_dechunk_readline /* ### TODO */,
  serf_http2_unpad_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_unpad_peek,
  serf_http2_unpad_destroy,
  serf_default_read_bucket,
  serf_http2_unpad_get_remaining,
  serf_default_ignore_config
};

/* ==================================================================== */

typedef struct serf_http2_frame_context_t {
  serf_bucket_t *stream;
  serf_bucket_alloc_t *alloc;
  serf_bucket_t *chunk;
  apr_status_t stream_status;
  apr_size_t max_payload_size;
  apr_int32_t stream_id;

  unsigned char frametype;
  unsigned char flags;
  char end_of_stream;
  char end_of_headers;
  char created_frame;

  apr_int32_t *p_stream_id;
  void *stream_id_baton;
  void (*stream_id_alloc)(void *baton, apr_int32_t *stream_id);

  apr_size_t current_window;
  void *alloc_window_baton;
  apr_int32_t (*alloc_window)(void *baton,
                              unsigned char frametype,
                              apr_int32_t stream_id,
                              apr_size_t requested,
                              int peek);

} serf_http2_frame_context_t;

serf_bucket_t *
serf__bucket_http2_frame_create(serf_bucket_t *stream,
                                unsigned char frame_type,
                                unsigned char flags,
                                apr_int32_t *stream_id,
                                void (*stream_id_alloc)(
                                                   void *baton,
                                                   apr_int32_t *stream_id),
                                void *stream_id_baton,
                                apr_size_t max_payload_size,
                                apr_int32_t (*alloc_window)(
                                                   void *baton,
                                                   unsigned char frametype,
                                                   apr_int32_t stream_id,
                                                   apr_size_t requested,
                                                   int peek),
                                void *alloc_window_baton,
                                serf_bucket_alloc_t *alloc)
{
  serf_http2_frame_context_t *ctx = serf_bucket_mem_alloc(alloc, sizeof(*ctx));

  ctx->alloc = alloc;
  ctx->stream = stream;
  ctx->chunk = serf_bucket_aggregate_create(alloc);
  ctx->stream_status = APR_SUCCESS;
  ctx->max_payload_size = max_payload_size;
  ctx->frametype = frame_type;
  ctx->flags = flags;

  if (max_payload_size > 0xFFFFFF)
    max_payload_size = 0xFFFFFF;

  if (!stream_id_alloc || (stream_id && *stream_id >= 0))
    {
      /* Avoid all alloc handling; we know the final id */
      ctx->stream_id = stream_id ? *stream_id : 0;
      ctx->p_stream_id = &ctx->stream_id;
      ctx->stream_id_alloc = NULL;
      ctx->stream_id_baton = NULL;
    }
  else
    {
      /* Delay creating the id until we really need it.

         Using a higher stream number before a lower version in communication
         closes the lower number directly (as 'unused') */

      ctx->stream_id = -1;
      ctx->p_stream_id = stream_id;
      ctx->stream_id_alloc = stream_id_alloc;
      ctx->stream_id_baton = stream_id_baton;
    }

  ctx->current_window = 0;
  ctx->alloc_window = alloc_window;
  ctx->alloc_window_baton = alloc_window_baton;

  ctx->end_of_stream = ctx->end_of_headers = ctx->created_frame = FALSE;

  return serf_bucket_create(&serf_bucket_type__http2_frame, alloc, ctx);
}


int
serf_bucket_http2_frame_within_frame(serf_bucket_t *bucket)
{
  const char *data;
  apr_size_t len;
  apr_status_t status = serf_bucket_peek(bucket, &data, &len);

  return APR_STATUS_IS_EOF(status);
}

static apr_status_t
http2_prepare_frame(serf_bucket_t *bucket)
{
  serf_http2_frame_context_t *ctx = bucket->data;
  struct iovec vecs[512];
  int vecs_used;
  apr_size_t len;
  unsigned char frame[FRAME_PREFIX_SIZE];
  int i;

  if (ctx->created_frame)
    return APR_SUCCESS;

  ctx->created_frame = TRUE;

  if (ctx->stream)
    {
      ctx->stream_status = serf_bucket_read_iovec(ctx->stream,
                                                  ctx->max_payload_size,
                                                  512, vecs, &vecs_used);

      if (SERF_BUCKET_READ_ERROR(ctx->stream_status))
        return ctx->stream_status;
    }
  else
    {
      vecs_used = 0;
      ctx->stream_status = APR_EOF;
    }

  /* For this first version assume that everything fits in a single frame */
  if (! APR_STATUS_IS_EOF(ctx->stream_status))
    abort(); /* Not implemented yet */

  if (ctx->stream_id < 0 && ctx->stream_id_alloc)
    {
      ctx->stream_id_alloc(ctx->stream_id_baton, ctx->p_stream_id);
      ctx->stream_id = *ctx->p_stream_id;
    }

  len = 0;
  for (i = 0; i < vecs_used; i++)
    len += vecs[i].iov_len;

  frame[0] = (len >> 16) & 0xFF;
  frame[1] = (len >> 8) & 0xFF;
  frame[2] = len & 0xFF;
  frame[3] = ctx->frametype;
  frame[4] = ctx->flags;
  frame[5] = ((apr_uint32_t)ctx->stream_id >> 24) & 0x7F;
  frame[6] = ((apr_uint32_t)ctx->stream_id >> 16) & 0xFF;
  frame[7] = ((apr_uint32_t)ctx->stream_id >> 8) & 0xFF;
  frame[8] = ctx->stream_id & 0xFF;

  serf_bucket_aggregate_append(ctx->chunk,
              serf_bucket_simple_copy_create((const char *)&frame,
                                             FRAME_PREFIX_SIZE,
                                             ctx->alloc));
  if (vecs_used > 0)
    serf_bucket_aggregate_append_iovec(ctx->chunk, vecs, vecs_used);

  return APR_SUCCESS;
}

static apr_status_t
serf_http2_frame_read(serf_bucket_t *bucket,
                      apr_size_t requested,
                      const char **data,
                      apr_size_t *len)
{
  serf_http2_frame_context_t *ctx = bucket->data;
  apr_status_t status;

  status = http2_prepare_frame(bucket);
  if (status)
    return status;

  status = serf_bucket_read(ctx->chunk, requested, data, len);

  if (APR_STATUS_IS_EOF(status))
    return ctx->stream_status;

  return status;
}

static apr_status_t
serf_http2_frame_read_iovec(serf_bucket_t *bucket,
                            apr_size_t requested,
                            int vecs_size,
                            struct iovec *vecs,
                            int *vecs_used)
{
  serf_http2_frame_context_t *ctx = bucket->data;
  apr_status_t status;

  status = http2_prepare_frame(bucket);
  if (status)
    return status;

  status = serf_bucket_read_iovec(ctx->chunk, requested, vecs_size, vecs,
                                  vecs_used);

  if (APR_STATUS_IS_EOF(status))
    return ctx->stream_status;

  return status;
}

static apr_status_t
serf_http2_frame_peek(serf_bucket_t *bucket,
                      const char **data,
                      apr_size_t *len)
{
  serf_http2_frame_context_t *ctx = bucket->data;
  apr_status_t status;

  status = http2_prepare_frame(bucket);
  if (status)
    return status;

  status = serf_bucket_peek(ctx->chunk, data, len);

  if (APR_STATUS_IS_EOF(status))
    return ctx->stream_status;

  return status;
}

static void
serf_http2_frame_destroy(serf_bucket_t *bucket)
{
  serf_http2_frame_context_t *ctx = bucket->data;

  if (ctx->stream)
    serf_bucket_destroy(ctx->stream);

  serf_bucket_destroy(ctx->chunk);

  serf_default_destroy_and_data(bucket);
}

/* ### need to implement */
#define serf_http2_frame_readline NULL

const serf_bucket_type_t serf_bucket_type__http2_frame = {
  "H2-FRAME",
  serf_http2_frame_read,
  serf_http2_frame_readline,
  serf_http2_frame_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_frame_peek,
  serf_http2_frame_destroy,
  serf_default_read_bucket,
  serf_default_get_remaining,
  serf_default_ignore_config
};

