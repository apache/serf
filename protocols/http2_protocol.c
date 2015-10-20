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
#include "protocols/http2_protocol.h"

static apr_status_t
http2_protocol_read(serf_connection_t *conn);

static apr_status_t
http2_protocol_write(serf_connection_t *conn);

static apr_status_t
http2_protocol_hangup(serf_connection_t *conn);

static void
http2_protocol_teardown(serf_connection_t *conn);

#define HTTP2_DEFAULT_MAX_FRAME_SIZE 16384

#define HTTP2_FLAG_PADDED 0x08

typedef struct serf_http2_procotol_state_t
{
  apr_pool_t *pool;

  char buffer[HTTP2_DEFAULT_MAX_FRAME_SIZE];
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
  serf_bucket_aggregate_append(conn->ostream_tail, tmp);

  /* And now a settings frame */
  {
    serf_bucket_t *no_settings;
    apr_int32_t frame_id = 0;

    no_settings = serf_bucket_simple_create("", 0, NULL, NULL, conn->allocator);
    tmp = serf_bucket_http2_frame_create(no_settings, HTTP2_FRAME_TYPE_SETTINGS, 0,
                                         &frame_id, NULL, NULL, /* Static id: 0*/
                                         16384 /* max_framesize */,
                                         NULL, NULL, conn->allocator);

    serf_bucket_aggregate_append(conn->ostream_tail, tmp);
  }
}

/* Creates a HTTP/2 request from a serf request */
static apr_status_t
setup_for_http2(serf_request_t *request)
{
  apr_status_t status;
  serf_bucket_t *rq;
  serf_bucket_t *hpack;
  serf_bucket_t *body;
  static apr_int32_t NEXT_frame = 1;

  apr_int32_t streamid = NEXT_frame;
  NEXT_frame += 2;

  rq = request->req_bkt;

  status = serf__bucket_hpack_create_from_request(&hpack, NULL,
                                                  rq,
                                                  request->conn->host_info.scheme,
                                                  request->allocator);
  if (status)
    return status;

  hpack = serf_bucket_http2_frame_create(hpack, HTTP2_FRAME_TYPE_HEADERS,
                                         HTTP2_FLAG_END_STREAM
                                         | HTTP2_FLAG_END_HEADERS,
                                         &streamid, NULL, NULL,
                                         HTTP2_DEFAULT_MAX_FRAMESIZE,
                                         NULL, NULL, request->allocator);

  serf_bucket_aggregate_append(request->conn->ostream_tail,
                               hpack);

  return APR_SUCCESS;
}

static apr_status_t
http2_read(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx = conn->protocol_baton;
  apr_status_t status = APR_SUCCESS;


  while (TRUE)
    {
      status = APR_SUCCESS;

      {
        serf_request_t *request = conn->unwritten_reqs;

        if (request)
          {
            apr_status_t status;
            serf_bucket_t *req_bkt;

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

            if (!request->req_bkt
                || !SERF_BUCKET_IS_REQUEST(request->req_bkt))
              {
                status = serf__setup_request(request);
                if (status)
                  return status;
              }

            status = setup_for_http2(request);
            if (status)
              return status;
          }
      }

      if (ctx->cur_frame)
        {
          const char *data;
          apr_size_t len;

          if (! ctx->in_payload)
            {
              unsigned char flags;

              status = serf_bucket_http2_unframe_read_info(ctx->cur_frame,
                                                           NULL, NULL, &flags);

              if (!SERF_BUCKET_READ_ERROR(status))
                {
                  ctx->in_payload = TRUE;

                  if (flags & HTTP2_FLAG_PADDED)
                    {
                      ctx->cur_payload =
                        serf_bucket_http2_unpad_create(
                              ctx->cur_frame, TRUE,
                              ctx->cur_frame->allocator);
                    }
                  else
                    ctx->cur_payload = ctx->cur_frame;
                }

              if (status)
                break;
            }

          status = serf_bucket_read(ctx->cur_frame,
                                    sizeof(ctx->buffer) - ctx->buffer_used,
                                    &data, &len);

          if (!SERF_BUCKET_READ_ERROR(status))
            {
              memcpy(&ctx->buffer[ctx->buffer_used], data, len);
              ctx->buffer_used += len;
            }
          else
            break;

          if (APR_STATUS_IS_EOF(status))
            {
              apr_int32_t streamid;
              unsigned char frametype;
              unsigned char flags;

              serf_bucket_http2_unframe_read_info(ctx->cur_frame,
                                                  &streamid, &frametype,
                                                  &flags);
              serf__log(LOGLVL_INFO, LOGCOMP_CONN, __FILE__, conn->config,
                        "Read 0x%02x http2 frame on stream 0x%x, flags=0x%x\n",
                        (int)frametype, (int)streamid, (int)flags);

              if (frametype == HTTP2_FRAME_TYPE_GOAWAY && conn)
                serf__log(LOGLVL_WARNING, LOGCOMP_CONN, __FILE__, conn->config,
                          "Go away reason %d: %s\n", ctx->buffer[7],
                                                     apr_pstrmemdup(conn->pool,
                                                               &ctx->buffer[8],
                                                               (ctx->buffer_used >= 8)
                                                               ? ctx->buffer_used-8 : 0));

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
            serf_bucket_http2_unframe_create(conn->stream, FALSE,
                                             HTTP2_DEFAULT_MAX_FRAME_SIZE,
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
