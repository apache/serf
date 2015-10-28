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
#include <apr_poll.h>
#include <apr_version.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"
#include "protocols/http2_buckets.h"
#include "protocols/http2_protocol.h"

static apr_status_t
http2_protocol_read(serf_connection_t *conn);

static apr_status_t
http2_protocol_write(serf_connection_t *conn);

static apr_status_t
http2_protocol_hangup(serf_connection_t *conn);

static void
http2_protocol_teardown(serf_connection_t *conn);

static serf_bucket_t *
serf_bucket_create_numberv(serf_bucket_alloc_t *allocator, const char *format, ...)
{
  va_list argp;
  const char *c;
  char *buffer;
  apr_size_t sz = 0;
  unsigned char *r;

  va_start(argp, format);

  for (c = format; *c; c++)
    {
      switch (*c)
      {
        case '1': /* char */
          sz += 1;
          break;
        case '2': /* apr_int16_t / apr_uint16_t */
          sz += 2;
          break;
        case '3': /* apr_int32_t / apr_uint32_t */
          sz += 3;
          break;
        case '4': /* apr_int32_t / apr_uint32_t */
          sz += 4;
          break;
        case '8': /* apr_int64_t / apr_uint64_t */
          sz += 8;
          break;
        default:
          abort(); /* Invalid format */
      }
    }

  buffer = serf_bucket_mem_alloc(allocator, sz);
  r = (void*)buffer;
  for (c = format; *c; c++)
    {
        apr_uint32_t tmp;
        apr_uint64_t tmp_64;

       switch (*c)
        {
          case '1':
            *r++ = va_arg(argp, char);
            break;
          case '2':
            tmp = va_arg(argp, apr_uint16_t);
            *r++ = (tmp >> 8) & 0xFF;
            *r++ = tmp & 0xFF;
            break;
          case '3':
            tmp = va_arg(argp, apr_uint32_t);
            *r++ = (tmp >> 16) & 0xFF;
            *r++ = (tmp >> 8) & 0xFF;
            *r++ = tmp & 0xFF;
            break;
          case '4':
            tmp = va_arg(argp, apr_uint32_t);
            *r++ = (tmp >> 24) & 0xFF;
            *r++ = (tmp >> 16) & 0xFF;
            *r++ = (tmp >> 8) & 0xFF;
            *r++ = tmp & 0xFF;
            break;
          case '8':
            tmp_64 = va_arg(argp, apr_uint64_t);
            *r++ = (tmp_64 >> 56) & 0xFF;
            *r++ = (tmp_64 >> 48) & 0xFF;
            *r++ = (tmp_64 >> 40) & 0xFF;
            *r++ = (tmp_64 >> 32) & 0xFF;
            *r++ = (tmp_64 >> 24) & 0xFF;
            *r++ = (tmp_64 >> 16) & 0xFF;
            *r++ = (tmp_64 >> 8) & 0xFF;
            *r++ = tmp_64 & 0xFF;
            break;
       }
    }

  va_end(argp);

  return serf_bucket_simple_own_create(buffer, sz, allocator);
}

struct serf_http2_protocol_t
{
  apr_pool_t *pool;
  serf_connection_t *conn;
  serf_bucket_t *ostream;

  serf_hpack_table_t *hpack_tbl;

  apr_uint32_t default_lr_window;
  apr_uint32_t default_rl_window;

  apr_int64_t lr_window; /* local->remote */
  apr_int64_t rl_window; /* remote->local */
  apr_int32_t next_local_streamid;
  apr_int32_t next_remote_streamid;

  serf_http2_stream_t *first;
  serf_http2_stream_t *last;

  char buffer[HTTP2_DEFAULT_MAX_FRAMESIZE];
  apr_size_t buffer_used;
  serf_bucket_t *cur_frame;
  serf_bucket_t *cur_payload;
  int in_payload;

};

static apr_status_t
http2_protocol_cleanup(void *state)
{
  serf_connection_t *conn = state;
  serf_http2_protocol_t *h2 = conn->protocol_baton;
  serf_http2_stream_t *stream, *next;

  /* First clean out all streams */
  for (stream = h2->first; stream; stream = next)
    {
      next = stream->next;
      serf_http2__stream_cleanup(stream);
    }

  h2->first = h2->last = NULL;

  conn->protocol_baton = NULL;
  return APR_SUCCESS;
}

void serf__http2_protocol_init(serf_connection_t *conn)
{
  serf_http2_protocol_t *ctx;
  apr_pool_t *protocol_pool;
  serf_bucket_t *tmp;

  apr_pool_create(&protocol_pool, conn->pool);

  ctx = apr_pcalloc(protocol_pool, sizeof(*ctx));
  ctx->pool = protocol_pool;
  ctx->conn = conn;
  ctx->ostream = conn->ostream_tail;

  /* Defaults until negotiated */
  ctx->default_lr_window = HTTP2_DEFAULT_WINDOW_SIZE;
  ctx->default_rl_window = HTTP2_DEFAULT_WINDOW_SIZE;

  ctx->lr_window = ctx->default_lr_window;
  ctx->rl_window = ctx->default_rl_window;
  ctx->next_local_streamid = 1; /* 2 if we would be the server */
  ctx->next_remote_streamid = 2; /* 1 if we would be the client */

  ctx->first = ctx->last = NULL;

  ctx->hpack_tbl = serf__hpack_table_create(TRUE, 16384, protocol_pool);

  apr_pool_cleanup_register(protocol_pool, conn, http2_protocol_cleanup,
                            apr_pool_cleanup_null);

  conn->perform_read = http2_protocol_read;
  conn->perform_write = http2_protocol_write;
  conn->perform_hangup = http2_protocol_hangup;
  conn->perform_teardown = http2_protocol_teardown;
  conn->protocol_baton = ctx;

  /* Disable HTTP/1.1 guessing that affects writability */
  conn->probable_keepalive_limit = 0;
  conn->max_outstanding_requests = 0;

  /* Send the HTTP/2 Connection Preface */
  tmp = SERF_BUCKET_SIMPLE_STRING("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                                  conn->allocator);
  serf_bucket_aggregate_append(ctx->ostream, tmp);

  /* And now a settings frame and a huge window */
  {
    serf_bucket_t *settings;
    serf_bucket_t *window_size;

    settings = serf_bucket_create_numberv(conn->allocator, "24",
                              (apr_int16_t)HTTP2_SETTING_HEADER_TABLE_SIZE,
                              (apr_int32_t)0);
    tmp = serf__bucket_http2_frame_create(settings, HTTP2_FRAME_TYPE_SETTINGS, 0,
                                          NULL, NULL, NULL, /* Static id: 0*/
                                          HTTP2_DEFAULT_MAX_FRAMESIZE,
                                          NULL, NULL, conn->allocator);

    serf_http2__enqueue_frame(ctx, tmp, FALSE);

    /* Add 2GB - 65535 to the current window.
       (Adding 2GB -1 appears to overflow at at least one server) */
    window_size = serf_bucket_create_numberv(conn->allocator, "4", 0x7FFF0000);
    tmp = serf__bucket_http2_frame_create(window_size,
                                          HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0,
                                          NULL, NULL, NULL,
                                          HTTP2_DEFAULT_MAX_FRAMESIZE,
                                          NULL, NULL, conn->allocator);
    serf_http2__enqueue_frame(ctx, tmp, FALSE);
  }
}

/* Creates a HTTP/2 request from a serf request */
static apr_status_t
setup_for_http2(serf_http2_protocol_t *h2,
                serf_request_t *request)
{
  serf_http2_stream_t *stream;

  stream = serf_http2__stream_create(h2, -1,
                                     h2->default_lr_window,
                                     h2->default_rl_window,
                                     h2->conn->allocator);

  if (h2->first)
    {
      stream->next = h2->first;
      h2->first->prev = stream;
      h2->first = stream;
    }
  else
    h2->last = h2->first = stream;

  return serf_http2__stream_setup_request(stream, h2->hpack_tbl,
                                          request);
}

apr_status_t
serf_http2__enqueue_frame(serf_http2_protocol_t *h2,
                          serf_bucket_t *frame,
                          int pump)
{
  apr_status_t status;

  if (!pump && !h2->conn->dirty_conn)
    {
      const char *data;
      apr_size_t len;

      /* Cheap check to see if we should request a write
         event next time around */
      status = serf_bucket_peek(h2->ostream, &data, &len);

      if (SERF_BUCKET_READ_ERROR(status))
        return status;

      if (len == 0)
        {
          h2->conn->dirty_conn = TRUE;
          h2->conn->ctx->dirty_pollset = TRUE;
        }
    }

  serf_bucket_aggregate_append(h2->ostream, frame);

  if (!pump)
    return APR_SUCCESS;

  /* Flush final output buffer (after ssl, etc.) */
  status = serf__connection_flush(h2->conn, FALSE);
  if (SERF_BUCKET_READ_ERROR(status))
    return status;

  /* Write new data to output buffer if necessary and
     flush again */
  if (!status)
    status = serf__connection_flush(h2->conn, TRUE);

  if (APR_STATUS_IS_EAGAIN(status))
    {
      h2->conn->dirty_conn = TRUE;
      h2->conn->ctx->dirty_pollset = TRUE;
    }
  else if (SERF_BUCKET_READ_ERROR(status))
    return status;

  return APR_SUCCESS;
}


static apr_status_t
http2_read(serf_connection_t *conn)
{
  serf_http2_protocol_t *ctx = conn->protocol_baton;
  apr_status_t status = APR_SUCCESS;

  while (TRUE)
    {
      status = APR_SUCCESS;

      if (ctx->cur_frame)
        {
          const char *data;
          apr_size_t len;

          if (! ctx->in_payload)
            {
              unsigned char flags;
              unsigned char frametype;
              apr_int32_t streamid;
              apr_uint64_t size;

              status = serf__bucket_http2_unframe_read_info(ctx->cur_frame,
                                                            &streamid, &frametype,
                                                            &flags);

              if (status && !APR_STATUS_IS_EOF(status))
                break;

              size = serf_bucket_get_remaining(ctx->cur_frame);

              serf__log(LOGLVL_INFO, SERF_LOGHTTP2, conn->config,
                        "Start 0x%02x http2 frame on stream 0x%x, flags=0x%x, size=0x%x\n",
                        (int)frametype, (int)streamid, (int)flags, (int)size);

              ctx->in_payload = TRUE;

              if (flags & HTTP2_FLAG_PADDED)
                {
                  ctx->cur_payload =
                        serf__bucket_http2_unpad_create(
                              ctx->cur_frame, TRUE,
                              ctx->cur_frame->allocator);
                }
              else
                ctx->cur_payload = ctx->cur_frame;

              if (frametype == HTTP2_FRAME_TYPE_HEADERS)
                {
                  ctx->cur_payload = serf__bucket_hpack_decode_create(
                                            ctx->cur_payload,
                                            NULL, NULL,
                                            16384, ctx->hpack_tbl,
                                            ctx->cur_frame->allocator);
                }
            }

          status = serf_bucket_read(ctx->cur_payload,
                                    sizeof(ctx->buffer) - ctx->buffer_used,
                                    &data, &len);

          if (SERF_BUCKET_READ_ERROR(status))
            break;

          if (len)
            {
              memcpy(&ctx->buffer[ctx->buffer_used], data, len);
              ctx->buffer_used += len;
            }

          if (APR_STATUS_IS_EOF(status))
            {
              apr_int32_t streamid;
              unsigned char frametype;
              unsigned char flags;

              serf__bucket_http2_unframe_read_info(ctx->cur_frame,
                                                   &streamid, &frametype,
                                                   &flags);
              serf__log(LOGLVL_INFO, SERF_LOGHTTP2, conn->config,
                        "Done 0x%02x http2 frame on stream 0x%x, flags=0x%x, size=0x%x\n",
                        (int)frametype, (int)streamid, (int)flags, (int)ctx->buffer_used);

              if (frametype == HTTP2_FRAME_TYPE_DATA
                  || frametype == HTTP2_FRAME_TYPE_HEADERS)
                {
                  /* Ugly hack to dump body. Memory LEAK! */
                  serf__log(LOGLVL_INFO, SERF_LOGHTTP2, conn->config,
                            "%s\n", apr_pstrmemdup(conn->pool, ctx->buffer, ctx->buffer_used));
                }

              if (frametype == HTTP2_FRAME_TYPE_GOAWAY && conn)
                serf__log(LOGLVL_WARNING, SERF_LOGHTTP2, conn->config,
                          "Go away reason %d: %s\n", ctx->buffer[7],
                                                     apr_pstrmemdup(conn->pool,
                                                               &ctx->buffer[8],
                                                               (ctx->buffer_used >= 8)
                                                               ? ctx->buffer_used-8 : 0));

              if (frametype == HTTP2_FRAME_TYPE_RST_STREAM && conn)
                serf__log(LOGLVL_WARNING, SERF_LOGHTTP2, conn->config,
                          "Reset reason %d: %s\n", ctx->buffer[7],
                          apr_pstrmemdup(conn->pool,
                                         &ctx->buffer[8],
                                         (ctx->buffer_used >= 8)
                                         ? ctx->buffer_used - 8 : 0));

              if (frametype == HTTP2_FRAME_TYPE_SETTINGS
                  && !(flags & HTTP2_FLAG_ACK))
                {
                  /* Always ack settings */
                  serf_http2__enqueue_frame(
                    ctx,
                    serf__bucket_http2_frame_create(
                                    NULL,
                                    HTTP2_FRAME_TYPE_SETTINGS,
                                    HTTP2_FLAG_ACK,
                                    NULL, NULL, NULL,
                                    HTTP2_DEFAULT_MAX_FRAMESIZE,
                                    NULL, NULL, conn->allocator),
                    TRUE);
                }
              else if (frametype == HTTP2_FRAME_TYPE_DATA)
                {
                  /* Provide a bit of window space to the server after 
                     receiving data */
                  serf_http2__enqueue_frame(
                    ctx,
                    serf__bucket_http2_frame_create(
                      serf_bucket_create_numberv(conn->allocator, "4", (apr_int32_t)16384),
                              HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0,
                              &streamid, NULL, NULL,
                              HTTP2_DEFAULT_MAX_FRAMESIZE,
                              NULL, NULL, conn->allocator),
                    TRUE);
                }
              else if (frametype == HTTP2_FRAME_TYPE_PING)
                {
                  /* TODO: PONG (=Ping Ack) */
                }

              serf_bucket_destroy(ctx->cur_payload);
              ctx->cur_frame = ctx->cur_payload = NULL;
              ctx->in_payload = FALSE;
              ctx->buffer_used = 0;
            }
          else
            continue;
        }

      if (APR_STATUS_IS_EOF(status))
        {
          const char *data;
          apr_size_t len;
          status = serf_bucket_peek(conn->stream, &data, &len);

          if (SERF_BUCKET_READ_ERROR(status)
              || APR_STATUS_IS_EOF(status))
            {
              /* We have a real EOF*/
              break;
            }
        }

      ctx->cur_frame = ctx->cur_payload =
            serf__bucket_http2_unframe_create(conn->stream, FALSE,
                                              HTTP2_DEFAULT_MAX_FRAMESIZE,
                                              conn->stream->allocator);
    }

  return status;
}

static apr_status_t
http2_protocol_read(serf_connection_t *conn)
{
  apr_status_t status;

  /* If the stop_writing flag was set on the connection, reset it now because
     there is some data to read. */
  if (conn->stop_writing)
    {
      conn->stop_writing = 0;
      conn->dirty_conn = 1;
      conn->ctx->dirty_pollset = 1;
    }

  status = http2_read(conn);

  if (!status)
    return APR_SUCCESS;
  else if (APR_STATUS_IS_EOF(status))
    {
      /* TODO: Teardown connection, reset if necessary, etc. */
      return status;
    }
  else if (APR_STATUS_IS_EAGAIN(status)
           || status == SERF_ERROR_WAIT_CONN)
    {
      /* Update pollset, etc. etc. */
      return APR_SUCCESS;
    }
  else
    return status;
}

static apr_status_t
http2_protocol_write(serf_connection_t *conn)
{
  serf_http2_protocol_t *ctx = conn->protocol_baton;
  serf_request_t *request = conn->unwritten_reqs;
  apr_status_t status;

  if (request)
    {
      /* Yuck.. there must be easier ways to do this, but I don't
          want to change outgoing.c all the time just yet. */
      conn->unwritten_reqs = request->next;
      if (conn->unwritten_reqs_tail == request)
        conn->unwritten_reqs = conn->unwritten_reqs_tail = NULL;

      request->next = NULL;

      if (conn->written_reqs_tail)
        conn->written_reqs_tail->next = request;
      else
        conn->written_reqs = conn->written_reqs_tail = request;

      status = setup_for_http2(ctx, request);
      if (status)
        return status;
    }

  status = serf__connection_flush(conn, TRUE);

  if (APR_STATUS_IS_EAGAIN(status))
    return APR_SUCCESS;
  else if (status)
    return status;

  /* Probably nothing to write. Connection will check new requests */
  conn->dirty_conn = 1;
  conn->ctx->dirty_pollset = 1;

  return APR_SUCCESS;
}

static apr_status_t
http2_protocol_hangup(serf_connection_t *conn)
{
  /* serf_http2_protocol_t *ctx = conn->protocol_baton; */

  return APR_EGENERAL;
}

static void
http2_protocol_teardown(serf_connection_t *conn)
{
  serf_http2_protocol_t *ctx = conn->protocol_baton;

  apr_pool_destroy(ctx->pool);
  conn->protocol_baton = NULL;
}

apr_int32_t
serf_http2__allocate_stream_id(void *baton,
                               apr_int32_t *streamid)
{
  serf_http2_stream_t *stream = baton;

  /* Do we need to assign a new id?

     We do this when converting the frame to on-wire data, to avoid
     creating frames out of order... which would make the other side
     deny our frame.
  */
  if (stream->streamid < 0)
    {
      stream->streamid = stream->h2->next_local_streamid;
      stream->h2->next_local_streamid += 2;

      if (stream->status == H2S_INIT)
        stream->status = H2S_IDLE;
    }

  return stream->streamid;
}

static void
move_to_head(serf_http2_stream_t *stream)
{
  /* Not implemented yet */
}

serf_http2_stream_t *
serf_http2__stream_get(serf_http2_protocol_t *h2,
                       apr_int32_t streamid,
                       int create_for_remote,
                       int move_first)
{
  serf_http2_stream_t *stream;

  if (streamid < 0)
    return NULL;

  for (stream = h2->first; stream; stream->next)
    {
      if (stream->streamid == streamid)
        {
          if (move_first && stream != h2->first)
            move_to_head(stream);

          return stream;
        }
    }

  if (create_for_remote
      && (streamid & 0x01) == (h2->next_remote_streamid & 0x01))
    {
      serf_http2_stream_t *rs;
      stream = serf_http2__stream_create(h2, streamid,
                                         h2->default_lr_window,
                                         h2->default_rl_window,
                                         h2->conn->allocator);

      if (h2->first)
        {
          stream->next = h2->first;
          h2->first->prev = stream;
          h2->first = stream;
        }
      else
        h2->last = h2->first = stream;

      if (streamid < h2->next_remote_streamid)
        stream->status = H2S_CLOSED;
      else
        h2->next_remote_streamid = (streamid + 2);

      for (rs = h2->first; rs; rs = rs->next)
        {
          if (rs->status <= H2S_IDLE
              && rs->streamid < streamid
              && (streamid & 0x01) == (rs->streamid & 0x01))
            {
              /* https://tools.ietf.org/html/rfc7540#section-5.1.1
                 The first use of a new stream identifier implicitly closes
                 all streams in the "idle" state that might have been
                 initiated by that peer with a lower-valued stream identifier.
              */
              rs->status = H2S_CLOSED;
            }
        }

      return stream;
    }
  return NULL;
}
