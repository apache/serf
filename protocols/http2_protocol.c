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

static apr_status_t
http2_process(serf_http2_protocol_t *h2);

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
      SERF_H2_assert(*c >= '1' && *c <= '4');

      if (*c >= '1' && *c <= '4')
        sz += (*c - '0');
    }

  buffer = serf_bucket_mem_alloc(allocator, sz);
  r = (void*)buffer;
  for (c = format; *c; c++)
    {
      apr_uint32_t tmp;

      switch (*c)
       {
         case '1':
           *r++ = va_arg(argp, int) & 0xFF;
           break;
         case '2':
           tmp = va_arg(argp, int);
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
  serf_bucket_alloc_t *allocator;

  serf_http2_processor_t processor;
  void *processor_baton;
  serf_bucket_t *read_frame;   /* Frame currently being read */
  int in_frame;

  serf_hpack_table_t *hpack_tbl;
  serf_config_t *config;

  /* Local -> Remote. Settings provided by other side */
  apr_uint32_t lr_default_window;
  apr_uint32_t lr_window;
  apr_uint32_t lr_max_framesize;
  apr_uint32_t lr_max_headersize;
  apr_uint32_t lr_max_concurrent;
  apr_uint32_t lr_hpack_table_size;
  apr_int32_t lr_next_streamid;
  char lr_push_enabled;

  /* Remote -> Local. Settings set by us. Acknowledged by other side */
  apr_uint32_t rl_default_window;
  apr_uint32_t rl_window;
  apr_uint32_t rl_max_framesize;
  apr_uint32_t rl_max_headersize;
  apr_uint32_t rl_max_concurrent;
  apr_uint32_t rl_hpack_table_size;
  apr_int32_t rl_next_streamid;
  char rl_push_enabled;

  serf_http2_stream_t *first;
  serf_http2_stream_t *last;

  int setting_acks;
  int enforce_flow_control;

  serf_bucket_t *continuation_bucket;
  apr_int32_t continuation_streamid;
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
  serf_http2_protocol_t *h2;
  apr_pool_t *protocol_pool;
  serf_bucket_t *tmp;
  const int WE_ARE_CLIENT = 1;

  apr_pool_create(&protocol_pool, conn->pool);

  h2 = apr_pcalloc(protocol_pool, sizeof(*h2));
  h2->pool = protocol_pool;
  h2->conn = conn;
  h2->ostream = conn->ostream_tail;
  h2->allocator = conn->allocator;
  h2->config = conn->config;

  /* Defaults until negotiated */
  h2->rl_default_window = HTTP2_DEFAULT_WINDOW_SIZE;
  h2->rl_window = HTTP2_DEFAULT_WINDOW_SIZE;
  h2->rl_next_streamid = WE_ARE_CLIENT ? 2 : 1;
  h2->rl_max_framesize = HTTP2_DEFAULT_MAX_FRAMESIZE;
  h2->rl_max_headersize = APR_UINT32_MAX;
  h2->rl_max_concurrent = HTTP2_DEFAULT_MAX_CONCURRENT;
  h2->rl_hpack_table_size = HTTP2_DEFAULT_HPACK_TABLE_SIZE;
  h2->rl_push_enabled = TRUE;

  h2->lr_default_window = HTTP2_DEFAULT_WINDOW_SIZE;
  h2->lr_window = HTTP2_DEFAULT_WINDOW_SIZE;
  h2->lr_next_streamid = WE_ARE_CLIENT ? 1 : 2;
  h2->lr_max_framesize = HTTP2_DEFAULT_MAX_FRAMESIZE;
  h2->lr_max_headersize = APR_UINT32_MAX;
  h2->lr_max_concurrent = HTTP2_DEFAULT_MAX_CONCURRENT;
  h2->lr_hpack_table_size = HTTP2_DEFAULT_HPACK_TABLE_SIZE;
  h2->lr_push_enabled = TRUE;

  h2->setting_acks = 0;
  h2->enforce_flow_control = TRUE;
  h2->continuation_bucket = NULL;
  h2->continuation_streamid = 0;

  h2->first = h2->last = NULL;

  h2->hpack_tbl = serf__hpack_table_create(TRUE,
                                           HTTP2_DEFAULT_HPACK_TABLE_SIZE,
                                           protocol_pool);

  apr_pool_cleanup_register(protocol_pool, conn, http2_protocol_cleanup,
                            apr_pool_cleanup_null);

  conn->perform_read = http2_protocol_read;
  conn->perform_write = http2_protocol_write;
  conn->perform_hangup = http2_protocol_hangup;
  conn->perform_teardown = http2_protocol_teardown;
  conn->protocol_baton = h2;

  /* Disable HTTP/1.1 guessing that affects writability */
  conn->probable_keepalive_limit = 0;
  conn->max_outstanding_requests = 0;

  /* Send the HTTP/2 Connection Preface */
  tmp = SERF_BUCKET_SIMPLE_STRING("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                                  conn->allocator);
  serf_bucket_aggregate_append(h2->ostream, tmp);

  /* And now a settings frame and a huge window */
  {
    serf_bucket_t *window_size;

    tmp = serf__bucket_http2_frame_create(NULL, HTTP2_FRAME_TYPE_SETTINGS, 0,
                                          NULL, NULL, NULL, /* stream: 0 */
                                          h2->lr_max_framesize,
                                          conn->allocator);

    serf_http2__enqueue_frame(h2, tmp, FALSE);

    /* Add 1GB to the current window. */
    window_size = serf_bucket_create_numberv(conn->allocator, "4", 0x40000000);
    tmp = serf__bucket_http2_frame_create(window_size,
                                          HTTP2_FRAME_TYPE_WINDOW_UPDATE, 0,
                                          NULL, NULL, NULL, /* stream: 0 */
                                          h2->lr_max_framesize,
                                          conn->allocator);
    serf_http2__enqueue_frame(h2, tmp, FALSE);

    h2->rl_window += 0x40000000; /* And update our own administration */
  }
}

/* Creates a HTTP/2 request from a serf request */
static apr_status_t
enqueue_http2_request(serf_http2_protocol_t *h2)
{
  serf_http2_stream_t *stream;

  stream = serf_http2__stream_create(h2, -1,
                                     h2->lr_default_window,
                                     h2->rl_default_window,
                                     h2->allocator);

  if (h2->first)
    {
      stream->next = h2->first;
      h2->first->prev = stream;
      h2->first = stream;
    }
  else
    h2->last = h2->first = stream;

  return serf_http2__stream_setup_next_request(stream, h2->conn,
                                               h2->hpack_tbl);
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
        {
          serf_bucket_destroy(frame);
          return status; 
        }

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

/* Implements serf_bucket_prefix_handler_t.
   Handles PRIORITY frames and the priority prefix of HEADERS frames */
static apr_status_t
http2_handle_priority(void *baton,
                      serf_bucket_t *bucket,
                      const char *data,
                      apr_size_t len)
{
  serf_http2_stream_t *stream = baton;

  if (len != HTTP2_PRIORITY_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  if (stream == NULL)
      return APR_SUCCESS; /* Nothing to record this on */

  /* ### TODO: Store priority information on stream */
  SERF_H2_assert(stream->h2 != NULL);

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles the promise prefix of PUSH_PROMISE frames */
static apr_status_t
http2_handle_promise(void *baton,
                     serf_bucket_t *bucket,
                     const char *data,
                     apr_size_t len)
{
  serf_http2_stream_t *parent_stream = baton;
  serf_http2_protocol_t *h2= parent_stream->h2;
  serf_http2_stream_t *promised_stream;
  apr_int32_t streamid;
  const struct promise_t
  {
    unsigned char s3, s2, s1, s0;
  } *promise;

  if (len != HTTP2_PROMISE_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(h2 != NULL);

  promise = (const void *)data;

  /* Highest bit is reserved */
  streamid = ((promise->s3 & 0x7F) << 24) | (promise->s2 << 16)
             |(promise->s1 << 8) | promise->s0;

  if (streamid == 0
      || (streamid < h2->rl_next_streamid)
      || (streamid & 0x01) != (h2->rl_next_streamid & 0x01))
    {
      /* The promised stream identifier MUST bet a valid choice for the
         next stream sent by the sender */

      /* A receiver MUST treat the receipt of a PUSH_PROMISE that promises an
         illegal stream identifier (Section 5.1.1) as a connection error
         (Section 5.4.1) of type PROTOCOL_ERROR.  Note that an illegal stream
         identifier is an identifier for a stream that is not currently in the
         "idle" state.*/

      return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
    }
  else if (parent_stream->status != H2S_OPEN
           && parent_stream->status != H2S_HALFCLOSED_LOCAL)
    {
      /* PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
         is in either the "open" or "half-closed (remote)" state.  The stream
         identifier of a PUSH_PROMISE frame indicates the stream it is
         associated with.  If the stream identifier field specifies the value
         0x0, a recipient MUST respond with a connection error (Section 5.4.1)
         of type PROTOCOL_ERROR.*/

      return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
    }

  promised_stream = serf_http2__stream_get(h2, streamid, TRUE, FALSE);
  if (!promised_stream || promised_stream->status != H2S_IDLE)
    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;

  promised_stream->status = H2S_RESERVED_REMOTE;

  /* Store data to allow stream to handle the promise */
  parent_stream->new_reserved_stream = promised_stream;

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles the promise prefix of FRAME_RSET frames */
static apr_status_t
http2_handle_frame_reset(void *baton,
                         serf_bucket_t *bucket,
                         const char *data,
                         apr_size_t len)
{
  serf_http2_stream_t *stream = baton;

  if (len != HTTP2_RST_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(stream->h2 != NULL);

  /* ### TODO: Handle error code, etc. */
  stream->status = H2S_CLOSED;

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles WINDOW_UPDATE frames when they apply to a stream */
static apr_status_t
http2_handle_stream_window_update(void *baton,
                                  serf_bucket_t *bucket,
                                  const char *data,
                                  apr_size_t len)
{
  serf_http2_stream_t *stream = baton;
  apr_uint32_t value;
  const struct window_update_t
  {
    unsigned char v3, v2, v1, v0;
  } *window_update;


  if (len != HTTP2_WINDOW_UPDATE_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  window_update = (const void *)data;

  value = (window_update->v3 << 24) | (window_update->v2 << 16)
          | (window_update->v2 << 8) | window_update->v0;

  value &= HTTP2_WINDOW_MAX_ALLOWED; /* The highest bit is reserved */

  if (value == 0)
    {
      /* A receiver MUST treat the receipt of a WINDOW_UPDATE frame with an
        flow - control window increment of 0 as a stream error(Section 5.4.2)
        of type PROTOCOL_ERROR; errors on the connection flow - control window
        MUST be treated as a connection error(Section 5.4.1). */
      return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
    }

  stream->lr_window += value;

  if (stream->lr_window > HTTP2_WINDOW_MAX_ALLOWED)
    {
      /* A sender MUST NOT allow a flow-control window to exceed 2^31-1
         octets.  If a sender receives a WINDOW_UPDATE that causes a flow-
         control window to exceed this maximum, it MUST terminate either the
         stream or the connection, as appropriate.  For streams, the sender
         sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the
         connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR
         is sent.*/
      return SERF_ERROR_HTTP2_FLOW_CONTROL_ERROR;
    }

  serf__log(LOGLVL_INFO, SERF_LOGHTTP2, stream->h2->config,
            "Increasing window on frame %d with 0x%x to 0x%x\n",
            stream->streamid, value, stream->lr_window);

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles WINDOW_UPDATE frames when they apply to the connection */
static apr_status_t
http2_handle_connection_window_update(void *baton,
                                      serf_bucket_t *bucket,
                                      const char *data,
                                      apr_size_t len)
{
  serf_http2_protocol_t *h2 = baton;
  apr_uint32_t value;
  const struct window_update_t
  {
    unsigned char v3, v2, v1, v0;
  } *window_update;

  if (len != HTTP2_WINDOW_UPDATE_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(h2 != NULL);

  window_update = (const void *)data;

  value = (window_update->v3 << 24) | (window_update->v2 << 16)
          | (window_update->v2 << 8) | window_update->v0;

  value &= HTTP2_WINDOW_MAX_ALLOWED; /* The highest bit is reserved */

  if (value == 0)
    {
      /* A receiver MUST treat the receipt of a WINDOW_UPDATE frame with an
        flow - control window increment of 0 as a stream error(Section 5.4.2)
        of type PROTOCOL_ERROR; errors on the connection flow - control window
        MUST be treated as a connection error(Section 5.4.1). */
      return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
    }

  h2->lr_window += value;

  if (h2->lr_window > HTTP2_WINDOW_MAX_ALLOWED)
    {
      /* A sender MUST NOT allow a flow-control window to exceed 2^31-1
         octets.  If a sender receives a WINDOW_UPDATE that causes a flow-
         control window to exceed this maximum, it MUST terminate either the
         stream or the connection, as appropriate.  For streams, the sender
         sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the
         connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR
         is sent.*/
      return SERF_ERROR_HTTP2_FLOW_CONTROL_ERROR;
    }

  serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
            "Increasing window on connection with 0x%x to 0x%x\n",
            value, h2->lr_window);

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles PING frames for pings initiated remotely */
static apr_status_t
http2_handle_ping(void *baton,
                  serf_bucket_t *bucket,
                  const char *data,
                  apr_size_t len)
{
  serf_http2_protocol_t *h2 = baton;
  serf_bucket_t *body;
  apr_status_t status;

  if (len != HTTP2_PING_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(h2 != NULL);

  /* Reply with a PONG (=PING + ACK) with the same data*/

  body = serf_bucket_simple_copy_create(data, len,
                                        h2->allocator);

  status = serf_http2__enqueue_frame(
                  h2,
                  serf__bucket_http2_frame_create(body,
                                                  HTTP2_FRAME_TYPE_PING,
                                                  HTTP2_FLAG_ACK,
                                                  NULL, NULL, NULL,
                                                  h2->lr_max_framesize,
                                                  h2->allocator),
                  TRUE /* pump */);

  if (SERF_BUCKET_READ_ERROR(status))
    return status;

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles PING frames for pings initiated locally */
static apr_status_t
http2_handle_ping_ack(void *baton,
                      serf_bucket_t *bucket,
                      const char *data,
                      apr_size_t len)
{
  serf_http2_protocol_t *h2 = baton;
  if (len != HTTP2_PING_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(h2 != NULL);

  /* Did we send a ping? */

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles SETTINGS frames */
static apr_status_t
http2_handle_settings(void *baton,
                      serf_bucket_t *bucket,
                      const char *data,
                      apr_size_t len)
{
  serf_http2_protocol_t *h2 = baton;
  apr_size_t i;
  const struct setting_t
  {
    unsigned char s1, s0;
    unsigned char v3, v2, v1, v0;
  } *setting;

  if ((len % HTTP2_SETTING_SIZE) != 0)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  /* ### TODO: Handle settings */
  setting = (const void *)data;
  for (i = 0, setting = (const void *)data;
       i < len;
       i += sizeof(*setting), setting++)
    {
      apr_uint16_t id = (setting->s1 << 8) | setting->s0;
      apr_uint32_t value = (setting->v3 << 24) | (setting->v2 << 16)
                           | (setting->v1 << 8) | setting->v0;

      switch (id)
        {
          case HTTP2_SETTING_HEADER_TABLE_SIZE:
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting HPACK Table size to %u\n", value);
            serf__hpack_table_set_max_table_size(h2->hpack_tbl,
                                                 h2->rl_hpack_table_size,
                                                 value);
            break;
          case HTTP2_SETTING_ENABLE_PUSH:
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting Push enabled: %u\n", value);
            h2->lr_push_enabled = (value != 0);
            break;
          case HTTP2_SETTING_MAX_CONCURRENT_STREAMS:
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting Max Concurrent %u\n", value);
            h2->lr_max_concurrent = value;
            break;
          case HTTP2_SETTING_INITIAL_WINDOW_SIZE:
            /* Sanitize? */
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting Initial Window Size %u\n", value);
            h2->lr_default_window = value;
            break;
          case HTTP2_SETTING_MAX_FRAME_SIZE:
            /* Sanitize? */
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting Max framesize %u\n", value);
            h2->lr_max_framesize = value;
            break;
          case HTTP2_SETTING_MAX_HEADER_LIST_SIZE:
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Setting Max header list size %u\n", value);
            h2->lr_max_headersize = value;
            break;
          default:
            /* An endpoint that receives a SETTINGS frame with any unknown
               or unsupported identifier MUST ignore that setting. */
            serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                      "Ignoring unknown setting %d, value %u\n", id, value);
            break;
        }
    }

  /* Always ack settings */
  serf_http2__enqueue_frame(
                    h2,
                    serf__bucket_http2_frame_create(
                                    NULL,
                                    HTTP2_FRAME_TYPE_SETTINGS,
                                    HTTP2_FLAG_ACK,
                                    NULL, NULL, NULL,
                                    h2->lr_max_framesize,
                                    h2->allocator),
                    TRUE);

  return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles GOAWAY frames */
static apr_status_t
http2_handle_goaway(void *baton,
                    serf_bucket_t *bucket,
                    const char *data,
                    apr_size_t len)
{
  serf_http2_protocol_t *h2 = baton;
  apr_int32_t last_streamid;
  apr_uint32_t error_code;
  apr_uint32_t loglevel;
  const struct goaway_t
  {
    unsigned char s3, s2, s1, s0;
    unsigned char e3, e2, e1, e0;
  } *goaway;

  if (len < HTTP2_GOWAWAY_DATA_SIZE)
    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;

  SERF_H2_assert(h2 != NULL);

  goaway = (const void *)data;

  last_streamid = ((goaway->s3 & 0x7F) << 24) | (goaway->s2 << 16)
                  | (goaway->s1 << 8) | goaway->s0;
  error_code = (goaway->e3 << 24) | (goaway->e2 << 16)
               | (goaway->e1 << 8) | goaway->e0;

  switch (error_code + SERF_ERROR_HTTP2_NO_ERROR)
    {
      case SERF_ERROR_HTTP2_PROTOCOL_ERROR:
      case SERF_ERROR_HTTP2_FLOW_CONTROL_ERROR:
      case SERF_ERROR_HTTP2_SETTINGS_TIMEOUT:
      case SERF_ERROR_HTTP2_FRAME_SIZE_ERROR:
      case SERF_ERROR_HTTP2_COMPRESSION_ERROR:
      case SERF_ERROR_HTTP2_INADEQUATE_SECURITY:
        loglevel = LOGLVL_ERROR;
        break;

      case SERF_ERROR_HTTP2_HTTP_1_1_REQUIRED:
      case SERF_ERROR_HTTP2_ENHANCE_YOUR_CALM:
        loglevel = LOGLVL_WARNING;
        break;

      case SERF_ERROR_HTTP2_REFUSED_STREAM:
      case SERF_ERROR_HTTP2_CANCEL:
      case SERF_ERROR_HTTP2_CONNECT_ERROR:
      case SERF_ERROR_HTTP2_STREAM_CLOSED:
        /* These errors should have been sent as a stream
           error. This usually tells us that we have an http/2
           implementation on the other side that doesn't implement
           full stream state handling. (See HTTP/2 RFC)*/
        loglevel = LOGLVL_ERROR;
        break;

      case SERF_ERROR_HTTP2_NO_ERROR:
        loglevel = LOGLVL_INFO;
        break;

      case SERF_ERROR_HTTP2_INTERNAL_ERROR:
      default:
        loglevel = LOGLVL_WARNING;
        break;
    }

  if (len > HTTP2_GOWAWAY_DATA_SIZE)
    {
      char *goaway_text;

      /* The server produced additional information in the error frame
         Usually this is some literal text explaining what went wrong.

         Copy the text to make it 0 terminated and then log it. */

      /* If this value appears truncated, that may be caused by the
         limit set in http2_process */

      goaway_text = serf_bstrmemdup(h2->allocator,
                                    data + HTTP2_GOWAWAY_DATA_SIZE,
                                    len - HTTP2_GOWAWAY_DATA_SIZE);

      serf__log(loglevel, SERF_LOGHTTP2, h2->config,
                "Received GOAWAY, last-stream=0x%x, error=%u: %s\n",
                last_streamid, error_code, goaway_text);

      serf_bucket_mem_free(h2->allocator, goaway_text);
    }
  else
    {
      serf__log(loglevel, SERF_LOGHTTP2, h2->config,
                "Received GOAWAY, last-stream=0x%x, error=%u.\n",
                last_streamid, error_code);
    }

  /* ### TODO: If the error is not critical stop creating new frames
               on this connection, while still going forward with the
               existing frames.

               We may receive a new error later, signalling a more
               important problem */

  return APR_SUCCESS;
}


/* Implements serf_bucket_aggregate_eof_t */
static apr_status_t
http2_handle_continuation(void *baton,
                          serf_bucket_t *aggregate_bucket)
{
  serf_http2_protocol_t *h2 = baton;
  apr_status_t status;
  const char *data;
  apr_size_t len;

  if (h2->continuation_bucket != aggregate_bucket)
    return APR_EOF; /* This is all we have */

  SERF_H2_assert(h2->read_frame == NULL);
  SERF_H2_assert(h2->continuation_bucket == aggregate_bucket);

  status = http2_process(h2);
  if (status)
    return status;

  if (h2->continuation_bucket == aggregate_bucket)
    {
      /* We expect more data in the future. Something
         was done in http2_process() or it didn't
         return APR_SUCCESS */
      return APR_SUCCESS;
    }

  /* As h2->continuation_bucket is no longer attached we don't
     recurse on peeking. Just check if there is more */
  return serf_bucket_peek(aggregate_bucket, &data, &len);
}

/* Implements the serf__bucket_http2_unframe_set_eof callback */
static apr_status_t
http2_end_of_frame(void *baton,
                   serf_bucket_t *frame)
{
  serf_http2_protocol_t *h2 = baton;

  SERF_H2_assert(h2->read_frame == frame);
  h2->read_frame = NULL;
  h2->in_frame = FALSE;
  h2->processor = NULL;
  h2->processor_baton = NULL;

  return APR_SUCCESS;
}

/* Implements serf_http2_processor_t */
static apr_status_t
http2_bucket_processor(void *baton,
                       serf_http2_protocol_t *h2,
                       serf_bucket_t *frame_bucket)
{
  struct iovec vecs[IOV_MAX];
  int vecs_used;
  serf_bucket_t *payload = baton;
  apr_status_t status;

  status = serf_bucket_read_iovec(payload, SERF_READ_ALL_AVAIL, IOV_MAX,
                                  vecs, &vecs_used);

  if (APR_STATUS_IS_EOF(status))
    {
      SERF_H2_assert(!h2->in_frame && !h2->read_frame);
      serf_bucket_destroy(payload);
    }

  return status;
}

/* Processes incoming HTTP2 data */
static apr_status_t
http2_process(serf_http2_protocol_t *h2)
{
  while (TRUE)
    {
      apr_status_t status;
      serf_bucket_t *body;

      if (h2->processor)
        {
          status = h2->processor(h2->processor_baton, h2, h2->read_frame);

          if (SERF_BUCKET_READ_ERROR(status))
            return status;
          else if (APR_STATUS_IS_EOF(status))
            {
              /* ### frame ended */
              SERF_H2_assert(h2->read_frame == NULL);
              h2->processor = NULL;
              h2->processor_baton = NULL;
            }
          else if (h2->in_frame)
            {
              if (status)
                return status;
              else
                continue;
            }
        }
      else
        {
          SERF_H2_assert(!h2->in_frame);
        }

      body = h2->read_frame;

      if (! body)
        {
          SERF_H2_assert(!h2->in_frame);

          body = serf__bucket_http2_unframe_create(
                                             h2->conn->stream,
                                             h2->rl_max_framesize,
                                             h2->allocator);

          serf__bucket_http2_unframe_set_eof(body,
                                             http2_end_of_frame, h2);

          serf_bucket_set_config(body, h2->config);
          h2->read_frame = body;
        }

      if (! h2->in_frame)
        {
          apr_int32_t sid;
          unsigned char frametype;
          unsigned char frameflags;
          apr_size_t remaining;
          serf_http2_processor_t process_handler = NULL;
          void *process_baton = NULL;
          serf_bucket_t *process_bucket = NULL;
          serf_http2_stream_t *stream;
          apr_uint32_t reset_reason;

          status = serf__bucket_http2_unframe_read_info(body, &sid,
                                                        &frametype, &frameflags);

          if (APR_STATUS_IS_EOF(status))
            {
              /* Entire frame is already read (just header) */
              SERF_H2_assert(h2->read_frame == NULL);
              SERF_H2_assert(! h2->in_frame);
            }
          else if (status)
            {
              SERF_H2_assert(h2->read_frame != NULL);
              SERF_H2_assert(! h2->in_frame);
              return status;
            }
          else
            {
              h2->in_frame = TRUE;
              SERF_H2_assert(h2->read_frame != NULL);
            }

          serf__log(LOGLVL_INFO, SERF_LOGHTTP2, h2->config,
                    "Reading 0x%x frame, stream=0x%x, flags=0x%x\n",
                    frametype, sid, frameflags);

          /* If status is EOF then the frame doesn't have/declare a body */
          switch (frametype)
            {
      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_DATA:
              case HTTP2_FRAME_TYPE_HEADERS:
              case HTTP2_FRAME_TYPE_PUSH_PROMISE:
                if (h2->continuation_bucket)
                  {
                    h2->continuation_bucket = NULL;
                    h2->continuation_streamid = 0;
                    return APR_EAGAIN;
                  }

                stream = serf_http2__stream_get(h2, sid, TRUE, TRUE);

                if (sid == 0)
                  {
                    /* DATA, HEADERS and PUSH_PROMISE:

                      These frames MUST be associated with a stream.  If a
                      XXX frame is received whose stream identifier field is 0x0,
                      the recipient MUST respond with a connection error
                      (Section 5.4.1) of type PROTOCOL_ERROR. */
                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }

                reset_reason = 0;

                if (frametype == HTTP2_FRAME_TYPE_DATA)
                  {
                    /* Windowing is applied above padding! */
                    remaining = (apr_size_t)serf_bucket_get_remaining(body);

                    if (h2->rl_window < remaining)
                      {
                        if (h2->enforce_flow_control)
                          reset_reason = SERF_ERROR_HTTP2_FLOW_CONTROL_ERROR;

                        h2->rl_window = 0;
                      }
                    else
                      h2->rl_window -= remaining;

                    if (stream)
                      {
                        if (stream->rl_window < remaining)
                          {
                            if (h2->enforce_flow_control)
                              reset_reason = SERF_ERROR_HTTP2_FLOW_CONTROL_ERROR;

                            stream->rl_window = 0;
                          }
                        else
                          stream->rl_window -= remaining;
                      }
                  }

                /* DATA, HEADERS and PUSH_PROMISE can have padding */
                if (frameflags & HTTP2_FLAG_PADDED)
                  body = serf__bucket_http2_unpad_create(body, h2->allocator);

                /* An HEADERS frame can have an included priority 'frame' */
                if (frametype == HTTP2_FRAME_TYPE_HEADERS
                                        && (frameflags & HTTP2_FLAG_PRIORITY))
                  {
                    body = serf_bucket_prefix_create(body,
                                                     HTTP2_PRIORITY_DATA_SIZE,
                                                     http2_handle_priority,
                                                     stream, h2->allocator);
                  }
                else if (frametype == HTTP2_FRAME_TYPE_PUSH_PROMISE)
                  {
                    body = serf_bucket_prefix_create(body,
                                                     HTTP2_PROMISE_DATA_SIZE,
                                                     http2_handle_promise,
                                                     stream, h2->allocator);
                  }

                if (!stream)
                  {
                    if (!reset_reason)
                      reset_reason = SERF_ERROR_HTTP2_STREAM_CLOSED;
                  }
                else
                  switch (frametype)
                    {
                      case HTTP2_FRAME_TYPE_DATA:
                        if (stream->status != H2S_OPEN
                            && stream->status != H2S_HALFCLOSED_LOCAL)
                          {
                            reset_reason = SERF_ERROR_HTTP2_STREAM_CLOSED;
                          }
                        break;
                      case HTTP2_FRAME_TYPE_HEADERS:
                        if (stream->status != H2S_OPEN
                            && stream->status != H2S_HALFCLOSED_LOCAL
                            && stream->status != H2S_IDLE
                            && stream->status != H2S_RESERVED_REMOTE)
                          {
                            reset_reason = SERF_ERROR_HTTP2_STREAM_CLOSED;
                          }
                        break;
                      case HTTP2_FRAME_TYPE_PUSH_PROMISE:
                        if (stream->status != H2S_OPEN
                            && stream->status != H2S_HALFCLOSED_LOCAL)
                          {
                            reset_reason = SERF_ERROR_HTTP2_STREAM_CLOSED;
                          }
                        break;
                    }

                if (reset_reason)
                  {
                    if (stream)
                      serf_http2__stream_reset(stream, reset_reason, TRUE);
                    else
                      serf_http2__enqueue_stream_reset(h2, sid, reset_reason);
                  }

                if (frametype == HTTP2_FRAME_TYPE_HEADERS
                    || frametype == HTTP2_FRAME_TYPE_PUSH_PROMISE)
                  {
                    if (!(frameflags & HTTP2_FLAG_END_HEADERS))
                      {
                        /* This header frame is *directly* followed by
                           continuation frames... We hide this from the
                           stream code, by providing an aggregate that will
                           read through the body of multiple frames */

                        h2->continuation_bucket = serf_bucket_aggregate_create(
                                                          h2->allocator);
                        h2->continuation_streamid = sid;

                        serf_bucket_aggregate_append(h2->continuation_bucket,
                                                     body);

                        serf_bucket_aggregate_hold_open(
                                      h2->continuation_bucket,
                                      http2_handle_continuation, h2);

                        body = h2->continuation_bucket;
                      }

                    if (stream && !reset_reason)
                      {
                        body = serf_http2__stream_handle_hpack(
                                          stream, body, frametype,
                                          (frameflags & HTTP2_FLAG_END_STREAM),
                                          HTTP2_MAX_HEADER_ENTRYSIZE,
                                          h2->hpack_tbl, h2->config,
                                          h2->allocator);
                      }
                    else
                      {
                        /* Even when we don't want to process the headers we
                            must read them to update the HPACK state */
                        body = serf__bucket_hpack_decode_create(
                                          body, NULL, NULL,
                                          HTTP2_MAX_HEADER_ENTRYSIZE,
                                          h2->hpack_tbl, h2->allocator);
                      }
                  }
                else if (! reset_reason)
                  {
                    /* We have a data bucket */
                    body = serf_http2__stream_handle_data(
                                        stream, body, frametype,
                                        (frameflags & HTTP2_FLAG_END_STREAM),
                                        h2->config, h2->allocator);
                  }

                if (body)
                  process_bucket = body; /* We will take care of discarding */
                else
                  {
                    /* The stream wants to handle the reading itself */
                    process_handler = serf_http2__stream_processor;
                    process_baton = stream;
                  }
                break;

      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_PRIORITY:
                if (sid == 0)
                  {
                    /* The PRIORITY frame always identifies a stream.  If a
                       PRIORITY frame is received with a stream identifier of
                       0x0, the recipient MUST respond with a connection error
                       (Section 5.4.1) of type PROTOCOL_ERROR.*/

                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }
                else if (serf_bucket_get_remaining(body)
                                                  != HTTP2_PRIORITY_DATA_SIZE)
                  {
                    /* A PRIORITY frame with a length other than 5 octets MUST
                       be treated as a stream error (Section 5.4.2) of type
                       FRAME_SIZE_ERROR.*/

                    /* ### But we currently upgrade this to a connection error */
                    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                  }

                stream = serf_http2__stream_get(h2, sid, TRUE, TRUE);

                if (stream)
                  {
                    body = serf_bucket_prefix_create(body,
                                                     HTTP2_PRIORITY_DATA_SIZE,
                                                     http2_handle_priority,
                                                     stream, h2->allocator);
                  }

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;

      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_RST_STREAM:
                if (sid == 0)
                  {
                    /* RST_STREAM frames MUST be associated with a stream.
                       If a RST_STREAM frame is received with a stream
                       identifier of 0x0, the recipient MUST treat this as a
                       connection error (Section 5.4.1) of type PROTOCOL_ERROR.
                     */

                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }
                else if (serf_bucket_get_remaining(body)
                                                  != HTTP2_RST_DATA_SIZE)
                  {
                    /* A RST_STREAM frame with a length other than 4 octets MUST
                       be treated as a connection error (Section 5.4.1) of type
                       FRAME_SIZE_ERROR. */

                    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                  }

                stream = serf_http2__stream_get(h2, sid, TRUE, TRUE);

                if (stream)
                  {
                    body = serf_bucket_prefix_create(body,
                                                     HTTP2_FRAME_TYPE_RST_STREAM,
                                                     http2_handle_frame_reset,
                                                     stream, h2->allocator);
                  }

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;

      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_SETTINGS:
                if (sid != 0)
                  {
                    /* SETTINGS frames always apply to a connection, never a
                       single stream. The stream identifier for a SETTINGS
                       frame MUST be zero (0x0).  If an endpoint receives a
                       SETTINGS frame whose stream identifier field is
                       anything other than 0x0, the endpoint MUST respond
                       with a connection error (Section 5.4.1) of type
                       PROTOCOL_ERROR.
                    */
                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }

                remaining = (apr_size_t)serf_bucket_get_remaining(body);
                if (frameflags & HTTP2_FLAG_ACK)
                  {
                    if (remaining != 0)
                      {
                        /* When this bit is set, the payload of the SETTINGS
                           frame MUST be empty. Receipt of a SETTINGS frame
                           with the ACK flag set and a length field value
                           other than 0 MUST be treated as a connection error
                           (Section 5.4.1) of type FRAME_SIZE_ERROR. */
                        return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                      }
                    h2->setting_acks++;
                  }
                else if ((remaining % HTTP2_SETTING_SIZE) != 0)
                  {
                    /* A SETTINGS frame with a length other than a multiple of
                       6 octets MUST be treated as a connection error (Section
                       5.4.1) of type FRAME_SIZE_ERROR. */
                    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                  }
                else
                  {
                    /* Just read everything... We checked it against our
                       max-framesize */
                    body = serf_bucket_prefix_create(body, remaining,
                                                     http2_handle_settings, h2,
                                                     h2->allocator);
                  }

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;

      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_PING:
                if (sid != 0)
                  {
                    /* PING frames are not associated with any individual
                       stream.  If a PING frame is received with a stream
                       identifier field value other than 0x0, the recipient
                       MUST respond with a connection error (Section 5.4.1)
                       of type PROTOCOL_ERROR.*/
                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }
                else if (serf_bucket_get_remaining(body)
                                                  != HTTP2_PING_DATA_SIZE)
                  {
                    /* Receipt of a PING frame with a length field value other
                       than 8 MUST be treated as a connection error (Section
                       5.4.1) of type FRAME_SIZE_ERROR.. */
                    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                  }

                body = serf_bucket_prefix_create(body, HTTP2_PING_DATA_SIZE,
                                                 (frameflags & HTTP2_FLAG_ACK)
                                                   ? http2_handle_ping
                                                   : http2_handle_ping_ack,
                                                 h2, h2->allocator);

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;
      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_GOAWAY:
                if (sid != 0)
                  {
                    /* The GOAWAY frame applies to the connection, not a
                       specific stream. An endpoint MUST treat a GOAWAY frame
                       with a stream identifier other than 0x0 as a connection
                       error(Section 5.4.1) of type PROTOCOL_ERROR. */
                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }

                /* As the final go-away frame is best effort only we are not
                   checking the bodysize against HTTP2_GOWAWAY_DATA_SIZE here.
                   We'll see what we get in the goaway handler.

                   Go away frames may contain additional opaque debug
                   information at the end, so instead of reading
                   HTTP2_GOWAWAY_DATA_SIZE bytes, we just read the whole frame.
                 */
                remaining = (apr_size_t)serf_bucket_get_remaining(body);

                body = serf_bucket_prefix_create(body,
                                                 MIN(remaining,
                                                     HTTP2_GOWAWAY_DATA_SIZE
                                                                        + 256),
                                                 http2_handle_goaway, h2,
                                                 h2->allocator);

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;
      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
                if (serf_bucket_get_remaining(body)
                                != HTTP2_WINDOW_UPDATE_DATA_SIZE)
                  {
                    /* A WINDOW_UPDATE frame with a length other than 4 octets
                       MUST be treated as a connection error (Section 5.4.1)
                       of type FRAME_SIZE_ERROR. */
                    return SERF_ERROR_HTTP2_FRAME_SIZE_ERROR;
                  }

                if (sid == 0)
                  {
                    body = serf_bucket_prefix_create(
                                  body,
                                  HTTP2_WINDOW_UPDATE_DATA_SIZE,
                                  http2_handle_connection_window_update, h2,
                                  h2->allocator);
                  }
                else
                  {
                    stream = serf_http2__stream_get(h2, sid, TRUE, TRUE);

                    if (stream)
                      body = serf_bucket_prefix_create(
                                  body,
                                  HTTP2_WINDOW_UPDATE_DATA_SIZE,
                                  http2_handle_stream_window_update, stream,
                                  h2->allocator);
                  }

                /* Just reading will do the right thing now */
                process_bucket = body;
                break;

      /* ---------------------------------------------------- */
              case HTTP2_FRAME_TYPE_CONTINUATION:
                if (!h2->continuation_bucket
                    || sid != h2->continuation_streamid)
                  {
                    /* A CONTINUATION frame MUST be preceded by a HEADERS,
                       PUSH_PROMISE or CONTINUATION frame without the
                       END_HEADERS flag set. A recipient that observes
                       violation of this rule MUST respond with a connection
                       error(Section 5.4.1) of type PROTOCOL_ERROR. */
                    h2->continuation_bucket = NULL;
                    h2->continuation_streamid = 0;
                    return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
                  }

                serf_bucket_aggregate_append(h2->continuation_bucket, body);

                if (frameflags & HTTP2_FLAG_END_HEADERS)
                  {
                    h2->continuation_bucket = NULL;
                    h2->continuation_streamid = 0;
                  }

                return APR_SUCCESS;

      /* ---------------------------------------------------- */
              default:
                /* We explicitly ignore all other frames as required,
                   so reading will do the right thing now */
                process_bucket = body;
            } /* switch */

          if (body)
            serf_bucket_set_config(body, h2->config);

          SERF_H2_assert(h2->processor == NULL);

          if (process_handler)
            {
              h2->processor = process_handler;
              h2->processor_baton = process_baton;
            }
          else
            {
              SERF_H2_assert(process_bucket != NULL);
              h2->processor = http2_bucket_processor;
              h2->processor_baton = process_bucket;
            }
        }
    } /* while(TRUE) */
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

  status = http2_process(conn->protocol_baton);

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
  serf_http2_protocol_t *h2 = conn->protocol_baton;
  apr_status_t status;

  if (conn->unwritten_reqs
      && conn->nr_of_written_reqs < h2->lr_max_concurrent)
    {
      status = enqueue_http2_request(h2);
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

void
serf_http2__allocate_stream_id(void *baton,
                               apr_int32_t *streamid)
{
  serf_http2_stream_t *stream = baton;

  SERF_H2_assert(streamid == &stream->streamid);

  /* Do we need to assign a new id?

     We do this when converting the frame to on-wire data, to avoid
     creating frames out of order... which would make the other side
     deny our frame.
  */
  if (stream->streamid < 0)
    {
      stream->streamid = stream->h2->lr_next_streamid;
      stream->h2->lr_next_streamid += 2;

      if (stream->status == H2S_INIT)
        stream->status = H2S_IDLE;
    }
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

  for (stream = h2->first; stream; stream = stream->next)
    {
      if (stream->streamid == streamid)
        {
          if (move_first && stream != h2->first)
            move_to_head(stream);

          return stream;
        }
    }

  if (create_for_remote
      && (streamid & 0x01) == (h2->rl_next_streamid & 0x01))
    {
      stream = serf_http2__stream_create(h2, streamid,
                                         h2->lr_default_window,
                                         h2->rl_default_window,
                                         h2->allocator);

      if (h2->first)
        {
          stream->next = h2->first;
          h2->first->prev = stream;
          h2->first = stream;
        }
      else
        h2->last = h2->first = stream;

      if (streamid < h2->rl_next_streamid)
        {
          /* https://tools.ietf.org/html/rfc7540#section-5.1.1
             The first use of a new stream identifier implicitly closes
             all streams in the "idle" state that might have been
             initiated by that peer with a lower-valued stream identifier.
          */
          stream->status = H2S_CLOSED;
        }
      else
        h2->rl_next_streamid = (streamid + 2);

      return stream;
    }
  return NULL;
}

apr_status_t
serf_http2__enqueue_stream_reset(serf_http2_protocol_t *h2,
                                 apr_int32_t streamid,
                                 apr_status_t reason)
{
  serf_bucket_t *bkt;
  apr_int32_t http_reason;

  if (reason >= SERF_ERROR_HTTP2_NO_ERROR
      && reason <= SERF_ERROR_HTTP2_HTTP_1_1_REQUIRED)
    {
      http_reason = (reason - SERF_ERROR_HTTP2_NO_ERROR);
    }
  else
    http_reason = SERF_ERROR_HTTP2_INTERNAL_ERROR;

  bkt = serf_bucket_create_numberv(h2->allocator, "4", http_reason);

  return serf_http2__enqueue_frame(
            h2,
            serf__bucket_http2_frame_create(bkt,
                                            HTTP2_FRAME_TYPE_RST_STREAM,
                                            0, &streamid, NULL, NULL,
                                            h2->lr_max_framesize,
                                            h2->allocator),
            TRUE);
}
