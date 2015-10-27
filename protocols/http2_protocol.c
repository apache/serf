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


typedef struct serf_http2_stream_t
{
  struct serf_http2_procotol_state_t *ctx;

  /* Linked list of currently existing streams */
  struct serf_http2_stream_t *next;
  struct serf_http2_stream_t *prev;

  serf_request_t *request; /* May be NULL as streams may outlive requests */

  apr_int64_t lr_window; /* local->remote */
  apr_int64_t rl_window; /* remote->local */

  /* -1 until allocated. Odd is client side initiated, even server side */
  apr_int32_t streamid;

  enum
  {
    H2S_IDLE = 0,
    H2S_RESERVED_REMOTE,
    H2S_RESERVED_LOCAL,
    H2S_OPEN,
    H2S_HALFCLOSED_REMOTE,
    H2S_HALFCLOSED_LOCAL,
    H2S_CLOSED
  } status;

  /* TODO: Priority, etc. */
} serf_http2_stream_t;

typedef struct serf_http2_procotol_state_t
{
  apr_pool_t *pool;
  serf_bucket_t *ostream;

  serf_hpack_table_t *hpack_tbl;

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

} serf_http2_procotol_state_t;

static apr_status_t
http2_protocol_cleanup(void *state)
{
  serf_connection_t *conn = state;
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  conn->protocol_baton = NULL;
  return APR_SUCCESS;
}

void serf__http2_protocol_init(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx;
  apr_pool_t *protocol_pool;
  serf_bucket_t *tmp;

  apr_pool_create(&protocol_pool, conn->pool);

  ctx = apr_pcalloc(protocol_pool, sizeof(*ctx));
  ctx->pool = protocol_pool;
  ctx->ostream = conn->ostream_tail;
  ctx->lr_window = HTTP2_DEFAULT_WINDOW_SIZE;
  ctx->rl_window = HTTP2_DEFAULT_WINDOW_SIZE;
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

    serf_bucket_aggregate_append(ctx->ostream, tmp);

    /* Add 2GB - 65535 to the current window.
       (Adding 2GB -1 appears to overflow at at least one server) */
    window_size = serf_bucket_create_numberv(conn->allocator, "4", 0x7FFF0000);
    tmp = serf__bucket_http2_frame_create(window_size,
                                          HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0,
                                          NULL, NULL, NULL,
                                          HTTP2_DEFAULT_MAX_FRAMESIZE,
                                          NULL, NULL, conn->allocator);
    serf_bucket_aggregate_append(ctx->ostream, tmp);
  }
}

/* Creates a HTTP/2 request from a serf request */
static apr_status_t
setup_for_http2(serf_http2_procotol_state_t *ctx,
                serf_request_t *request)
{
  apr_status_t status;
  serf_bucket_t *hpack;
  serf_bucket_t *body;
  static apr_int32_t NEXT_frame = 1;

  apr_int32_t streamid = NEXT_frame;
  NEXT_frame += 2;

  if (!request->req_bkt)
    {
      status = serf__setup_request(request);
      if (status)
        return status;
    }

  serf__bucket_request_read(request->req_bkt, &body, NULL, NULL);
  status = serf__bucket_hpack_create_from_request(&hpack, NULL, request->req_bkt,
                                                  request->conn->host_info.scheme,
                                                  request->allocator);
  if (status)
    return status;

  if (!body)
    {
      /* This destroys the body... Perhaps we should make an extract
         and clear api */
      serf_bucket_destroy(request->req_bkt);
      request->req_bkt = NULL;
    }
  
  hpack = serf__bucket_http2_frame_create(hpack, HTTP2_FRAME_TYPE_HEADERS,
                                          HTTP2_FLAG_END_STREAM
                                          | HTTP2_FLAG_END_HEADERS,
                                          &streamid, NULL, NULL,
                                          HTTP2_DEFAULT_MAX_FRAMESIZE,
                                          NULL, NULL, request->allocator);

  serf_bucket_aggregate_append(ctx->ostream, hpack);

  return APR_SUCCESS;
}

static apr_status_t
http2_read(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx = conn->protocol_baton;
  apr_status_t status = APR_SUCCESS;

  while (TRUE)
    {
      serf_request_t *request = conn->unwritten_reqs;
      status = APR_SUCCESS;

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

      if (ctx->cur_frame)
        {
          const char *data;
          apr_size_t len;

          if (! ctx->in_payload)
            {
              unsigned char flags;
              unsigned char frametype;

              status = serf__bucket_http2_unframe_read_info(ctx->cur_frame,
                                                            NULL, &frametype,
                                                            &flags);

              if (status)
                break;

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
              serf__log(LOGLVL_INFO, LOGCOMP_CONN, __FILE__, conn->config,
                        "Read 0x%02x http2 frame on stream 0x%x, flags=0x%x, size=0x%x\n",
                        (int)frametype, (int)streamid, (int)flags, (int)ctx->buffer_used);

              if (frametype == HTTP2_FRAME_TYPE_DATA
                  || frametype == HTTP2_FRAME_TYPE_HEADERS)
                {
                  /* Ugly hack to dump body. Memory LEAK! */
                  serf__log(LOGLVL_INFO, LOGCOMP_CONN, __FILE__, conn->config,
                            "%s\n", apr_pstrmemdup(conn->pool, ctx->buffer, ctx->buffer_used));
                }

              if (frametype == HTTP2_FRAME_TYPE_GOAWAY && conn)
                serf__log(LOGLVL_WARNING, LOGCOMP_CONN, __FILE__, conn->config,
                          "Go away reason %d: %s\n", ctx->buffer[7],
                                                     apr_pstrmemdup(conn->pool,
                                                               &ctx->buffer[8],
                                                               (ctx->buffer_used >= 8)
                                                               ? ctx->buffer_used-8 : 0));

              if (frametype == HTTP2_FRAME_TYPE_SETTINGS)
                {
                  /* Always ack settings */
                  serf_bucket_aggregate_append(
                    ctx->ostream,
                    serf__bucket_http2_frame_create(
                                    NULL,
                                    HTTP2_FRAME_TYPE_SETTINGS,
                                    HTTP2_FLAG_ACK,
                                    NULL, NULL, NULL,
                                    HTTP2_DEFAULT_MAX_FRAMESIZE,
                                    NULL, NULL, conn->allocator));
                }
              else if (frametype == HTTP2_FRAME_TYPE_DATA)
                {
                  /* Provide a bit of window space to the server after 
                     receiving data */
                  serf_bucket_aggregate_append(
                    ctx->ostream,
                    serf__bucket_http2_frame_create(
                      serf_bucket_create_numberv(conn->allocator, "4", (apr_int32_t)16384),
                              HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0,
                              &streamid, NULL, NULL,
                              HTTP2_DEFAULT_MAX_FRAMESIZE,
                              NULL, NULL, conn->allocator));
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
  serf_http2_procotol_state_t *ctx = conn->protocol_baton;
  apr_status_t status;

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
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  return APR_EGENERAL;
}

static void
http2_protocol_teardown(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx = conn->protocol_baton;

  apr_pool_destroy(ctx->pool);
  conn->protocol_baton = NULL;
}
