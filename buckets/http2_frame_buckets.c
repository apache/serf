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

/* https://tools.ietf.org/html/rfc7540#section-4.1 */
#define FRAME_PREFIX_SIZE 9 

typedef struct http2_unframe_context_t
{
  serf_bucket_t *stream;
  apr_size_t max_payload_size;

  apr_size_t prefix_remaining;
  unsigned char prefix_buffer[FRAME_PREFIX_SIZE];

  /* These fields are only set after prefix_remaining is 0 */
  apr_size_t payload_length;  /* 0 <= payload_length < 2^24 */
  apr_int32_t stream_id;      /* 0 <= stream_id < 2^31 */
  unsigned char frame_type;
  unsigned char flags;

  apr_size_t payload_remaining;
} http2_unframe_context_t;

serf_bucket_t *
serf_bucket_http2_unframe_create(serf_bucket_t *stream,
                                 apr_size_t max_payload_size,
                                 serf_bucket_alloc_t *allocator)
{
  http2_unframe_context_t *ctx;

  ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
  ctx->stream = stream;
  ctx->max_payload_size = max_payload_size;
  ctx->prefix_remaining = sizeof(ctx->prefix_buffer);


  return serf_bucket_create(&serf_bucket_type_http2_unframe, allocator, ctx);
}

apr_status_t
serf_http2_unframe_bucket_read_info(serf_bucket_t *bucket,
                                    apr_size_t *payload_length,
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
      if (payload_length)
        *payload_length = ctx->payload_length;
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
      memcpy(ctx->prefix_buffer + FRAME_PREFIX_SIZE - ctx->prefix_remaining,
             data, len);

      ctx->prefix_remaining -= len;

      if (ctx->prefix_remaining == 0)
        {
          ctx->payload_length = (ctx->prefix_buffer[0] << 16)
                                | (ctx->prefix_buffer[1] << 8)
                                | (ctx->prefix_buffer[2]);
          ctx->frame_type = ctx->prefix_buffer[3];
          ctx->flags = ctx->prefix_buffer[4];
          /* Highest bit of stream_id MUST be ignored */
          ctx->stream_id = ((ctx->prefix_buffer[5] & 0x7F) << 24)
                           | (ctx->prefix_buffer[6] << 16)
                           | (ctx->prefix_buffer[7] << 8)
                           | (ctx->prefix_buffer[8]);

          ctx->payload_remaining = ctx->payload_length;

          /* Use recursion to fill output arguments if necessary */
          serf_http2_unframe_bucket_read_info(bucket, payload_length,
                                              stream_id, frame_type, flags);

          /* https://tools.ietf.org/html/rfc7540#section-4.2
            An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame
            exceeds the size defined in SETTINGS_MAX_FRAME_SIZE, exceeds any
            limit defined for the frame type, or is too small to contain
            mandatory frame data.
          */
          if (ctx->max_payload_size < ctx->payload_remaining)
              return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
        }
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

  status = serf_http2_unframe_bucket_read_info(bucket, NULL, NULL,
                                               NULL, NULL);

  if (status)
    return status;

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
        status = APR_EOF;
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

  status = serf_http2_unframe_bucket_read_info(bucket, NULL, NULL,
                                               NULL, NULL);

  if (status)
    return status;

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
        status = APR_EOF;
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

  status = serf_http2_unframe_bucket_read_info(bucket, NULL, NULL,
                                               NULL, NULL);

  if (status)
    return status;

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

  status = serf_http2_unframe_bucket_read_info(bucket, NULL, NULL,
                                               NULL, NULL);

  if (status)
    return SERF_LENGTH_UNKNOWN;

  return ctx->payload_remaining;
}

/* ### need to implement */
#define serf_h2_dechunk_readline NULL

const serf_bucket_type_t serf_bucket_type_http2_unframe = {
  "H2-UNFRAME",
  serf_http2_unframe_read,
  serf_h2_dechunk_readline /* ### TODO */,
  serf_http2_unframe_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_http2_unframe_peek,
  serf_default_destroy_and_data,
  serf_default_read_bucket,
  serf_http2_unframe_get_remaining,
  serf_default_ignore_config
};
