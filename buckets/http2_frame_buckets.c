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

  serf_bucket_end_of_frame_t end_of_frame;
  void *end_of_frame_baton;

  /* These fields are only set after prefix_remaining is 0 */
  apr_size_t payload_remaining;  /* 0 <= payload_length < 2^24 */
  apr_int32_t stream_id;         /* 0 <= stream_id < 2^31 */
  unsigned char frame_type;
  unsigned char flags;

  unsigned char buffer[FRAME_PREFIX_SIZE];
} http2_unframe_context_t;

serf_bucket_t *
serf__bucket_http2_unframe_create(serf_bucket_t *stream,
                                  apr_size_t max_payload_size,
                                  serf_bucket_alloc_t *allocator)
{
  http2_unframe_context_t *ctx;

  ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
  ctx->stream = stream;
  ctx->max_payload_size = max_payload_size;
  ctx->prefix_remaining = sizeof(ctx->buffer);
  ctx->end_of_frame = NULL;

  return serf_bucket_create(&serf_bucket_type__http2_unframe, allocator, ctx);
}

void
serf__bucket_http2_unframe_set_eof(serf_bucket_t *bucket,
                                   serf_bucket_end_of_frame_t end_of_frame,
                                   void *end_of_frame_baton)
{
  http2_unframe_context_t *ctx = bucket->data;

  ctx->end_of_frame = end_of_frame;
  ctx->end_of_frame_baton = end_of_frame_baton;
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
            {
              if (payload_length == 0x485454 && ctx->frame_type == 0x50
                  && ctx->flags == 0x2F)
                {
                  /* We found "HTTP/" instead of an actual frame. This
                     is clearly above the initial max payload size of 16384,
                     which applies before we negotiate a bigger size.

                     We found a HTTP/1.1 server that didn't understand our
                     HTTP2 prefix "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                   */

                  return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                }

              return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
            }

          status = (ctx->payload_remaining == 0) ? APR_EOF
                                                 : APR_SUCCESS;

          /* If we hava a zero-length frame we have to call the eof callback
             now, as the read operations will just shortcut to APR_EOF */
          if (ctx->payload_remaining == 0 && ctx->end_of_frame)
            {
              apr_status_t cb_status;

              cb_status = (*ctx->end_of_frame)(ctx->end_of_frame_baton,
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
          if (ctx->end_of_frame)
            status = (*ctx->end_of_frame)(ctx->end_of_frame_baton,
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
          if (ctx->end_of_frame)
            status = (*ctx->end_of_frame)(ctx->end_of_frame_baton,
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

const serf_bucket_type_t serf_bucket_type__http2_unframe = {
  "H2-UNFRAME",
  serf_http2_unframe_read,
  serf_default_readline,
  serf_http2_unframe_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_unframe_peek,
  serf_default_destroy_and_data,
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
  char padsize_read;
} http2_unpad_context_t;

serf_bucket_t *
serf__bucket_http2_unpad_create(serf_bucket_t *stream,
                                serf_bucket_alloc_t *allocator)
{
  http2_unpad_context_t *ctx;

  ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
  ctx->stream = stream;
  ctx->padsize_read = FALSE;

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
  else if (ctx->payload_remaining == 0
           && ctx->pad_remaining == 0)
    {
      *vecs_used = 0;
      return APR_EOF;
    }

  if (requested > ctx->payload_remaining)
    requested = ctx->payload_remaining + ctx->pad_remaining;

  status = serf_bucket_read_iovec(ctx->stream, requested,
                                  vecs_size, vecs, vecs_used);
  if (! SERF_BUCKET_READ_ERROR(status))
    {
      int i;
      apr_size_t total = 0;

      for (i = 0; i < *vecs_used; i++)
        total += vecs[i].iov_len;

      if (total < ctx->payload_remaining)
        ctx->payload_remaining -= total;
      else
        {
          apr_size_t padread = (total - ctx->payload_remaining);
          ctx->pad_remaining -= padread;
          ctx->payload_remaining = 0;

          /* Remove padding from returned result? */
          while (padread && *vecs_used)
            {
              struct iovec *cv = &vecs[*vecs_used - 1];

              if (cv->iov_len <= padread)
                {
                  padread -= cv->iov_len;
                  (*vecs_used)--;
                }
              else
                {
                  cv->iov_len -= padread;
                  break;
                }
            }

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

const serf_bucket_type_t serf_bucket_type__http2_unpad = {
  "H2-UNPAD",
  serf_http2_unpad_read,
  serf_default_readline,
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
  apr_size_t bytes_remaining;
  apr_size_t max_payload_size;

  apr_int32_t stream_id;

  unsigned char frametype;
  unsigned char flags;
  char created_frame;

  apr_int32_t *p_stream_id;
  void *stream_id_baton;
  void (*stream_id_alloc)(void *baton, apr_int32_t *stream_id);

  apr_size_t current_window;

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
                                apr_uint32_t max_payload_size,
                                serf_bucket_alloc_t *alloc)
{
  serf_http2_frame_context_t *ctx = serf_bucket_mem_alloc(alloc, sizeof(*ctx));

  ctx->alloc = alloc;
  ctx->stream = stream;
  ctx->chunk = serf_bucket_aggregate_create(alloc);
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
  ctx->created_frame = FALSE;

  return serf_bucket_create(&serf_bucket_type__http2_frame, alloc, ctx);
}

static apr_status_t
http2_prepare_frame(serf_bucket_t *bucket)
{
  serf_http2_frame_context_t *ctx = bucket->data;
  int vecs_used;
  apr_uint64_t payload_remaining;

  if (ctx->created_frame)
    return APR_SUCCESS;

  /* How long will this frame be? */
  if (!ctx->stream)
    payload_remaining = 0;
  else
    payload_remaining = serf_bucket_get_remaining(ctx->stream);

  if (payload_remaining != SERF_LENGTH_UNKNOWN
      && payload_remaining > ctx->max_payload_size)
    {
      return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
    }
  else if (payload_remaining != SERF_LENGTH_UNKNOWN)
    {
      if (ctx->stream)
        serf_bucket_aggregate_append(ctx->chunk, ctx->stream);

      ctx->stream = NULL; /* Now managed by aggregate */
    }
  else
    {
      /* Our payload doesn't know how long it is. Our only option
         now is to create the actual data */
      struct iovec vecs[IOV_MAX];
      apr_status_t status;

      status = serf_bucket_read_iovec(ctx->stream, ctx->max_payload_size,
                                      IOV_MAX, vecs, &vecs_used);

      if (SERF_BUCKET_READ_ERROR(status))
        return status;
      else if (APR_STATUS_IS_EOF(status))
        {
          /* OK, we got everything, let's put the data at the start of the
             aggregate. */
          serf_bucket_aggregate_append_iovec(ctx->chunk, vecs, vecs_used);

          /* Obtain the size now , to avoid problems when the bucket
             doesn't know that it has nothing remaining*/
          payload_remaining = serf_bucket_get_remaining(ctx->chunk);

          /* Just add the stream behind the iovecs. This keeps the chunks
              available exactly until they are no longer necessary */
          serf_bucket_aggregate_append(ctx->chunk, ctx->stream);
          ctx->stream = NULL; /* Managed by aggregate */

          if (payload_remaining == SERF_LENGTH_UNKNOWN)
           {
             /* Should never happen:
                Aggregate with only iovecs should know size */
             return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
           }
        }
      else
        {
          /* Auch... worst case scenario, we have to copy the data. Luckily
             we have an absolute limit after which we may error out */
          apr_size_t total = 0;
          char *data = serf_bucket_mem_alloc(bucket->allocator,
                                             ctx->max_payload_size);

          serf__copy_iovec(data, &total, vecs, vecs_used);

          while (!APR_STATUS_IS_EOF(status)
                 && total < ctx->max_payload_size)
            {
              apr_size_t read;
              status = serf_bucket_read_iovec(ctx->stream,
                                              ctx->max_payload_size - total + 1,
                                              IOV_MAX, vecs, &vecs_used);

              if (SERF_BUCKET_READ_ERROR(status))
                {
                  serf_bucket_mem_free(bucket->allocator, data);
                  return status;
                }

              serf__copy_iovec(data, &read, vecs, vecs_used);
              total += read;

              if (status && !APR_STATUS_IS_EOF(status))
                {
                  /* Checkpoint what we got now...

                     Next time this function is called the buffer is read first and
                     then continued from the original stream */
                  serf_bucket_t *new_stream;
                  new_stream = serf_bucket_aggregate_create(bucket->allocator);

                  serf_bucket_aggregate_append(
                      new_stream,
                      serf_bucket_simple_own_create(data, total, bucket->allocator));

                  serf_bucket_aggregate_append(new_stream, ctx->stream);
                  ctx->stream = new_stream;

                  return status;
                }
            }

          if (total > ctx->max_payload_size)
            {
              /* The chunk is at least 1 byte bigger then allowed */
              serf_bucket_mem_free(bucket->allocator, data);

              return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
            }
          else
            {
              /* Ok, we have what we need in our buffer */
              serf_bucket_aggregate_append(
                    ctx->chunk,
                    serf_bucket_simple_own_create(data, total, bucket->allocator));
              payload_remaining = total;

              /* And we no longer need stream */
              serf_bucket_destroy(ctx->stream);
              ctx->stream = NULL;
            }
        }
    }



  /* Ok, now we can construct the frame */
  ctx->created_frame = TRUE;
  {
    unsigned char frame[FRAME_PREFIX_SIZE];

    /* Allocate the streamid if there isn't one.
       Once the streamid hits the wire it automatically closes all
       unused identifiers < this value.
     */
    if (ctx->stream_id < 0 && ctx->stream_id_alloc)
      {
        ctx->stream_id_alloc(ctx->stream_id_baton, ctx->p_stream_id);
        ctx->stream_id = *ctx->p_stream_id;
      }

    frame[0] = (payload_remaining >> 16) & 0xFF;
    frame[1] = (payload_remaining >> 8) & 0xFF;
    frame[2] = payload_remaining & 0xFF;
    frame[3] = ctx->frametype;
    frame[4] = ctx->flags;
    frame[5] = ((apr_uint32_t)ctx->stream_id >> 24) & 0x7F;
    frame[6] = ((apr_uint32_t)ctx->stream_id >> 16) & 0xFF;
    frame[7] = ((apr_uint32_t)ctx->stream_id >> 8) & 0xFF;
    frame[8] = ctx->stream_id & 0xFF;

    /* Put the frame before the data */
    serf_bucket_aggregate_prepend(ctx->chunk,
              serf_bucket_simple_copy_create((const char *)&frame,
                                             FRAME_PREFIX_SIZE,
                                             ctx->alloc));

    /* And set the amount of data that we verify will be read */
    ctx->bytes_remaining = (apr_size_t)payload_remaining + FRAME_PREFIX_SIZE;
  }
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

  if (!SERF_BUCKET_READ_ERROR(status))
    {
      if (*len > ctx->bytes_remaining)
        {
          /* Frame payload resized after the header was written */
          return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
      ctx->bytes_remaining -= *len;
    }

  if (APR_STATUS_IS_EOF(status))
    {
      if (ctx->bytes_remaining > 0)
        {
          /* Frame payload resized after the header was written */
          return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
    }

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

  if (!SERF_BUCKET_READ_ERROR(status))
    {
      apr_size_t len = 0;
      int i;

      for (i = 0; i < *vecs_used; i++)
        len += vecs[i].iov_len;

      if (len > ctx->bytes_remaining)
        {
          /* Frame resized after the header was written */
          return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
      ctx->bytes_remaining -= len;
    }

  if (APR_STATUS_IS_EOF(status))
    {
      if (ctx->bytes_remaining > 0)
        {
          /* Frame payload resized after the header was written */
          return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
    }

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
    {
      *len = 0;
      return APR_SUCCESS;
    }

  return serf_bucket_peek(ctx->chunk, data, len);
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

const serf_bucket_type_t serf_bucket_type__http2_frame = {
  "H2-FRAME",
  serf_http2_frame_read,
  serf_default_readline,
  serf_http2_frame_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_frame_peek,
  serf_http2_frame_destroy,
  serf_default_read_bucket,
  serf_default_get_remaining,
  serf_default_ignore_config
};

