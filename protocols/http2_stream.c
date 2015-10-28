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
#include "protocols/http2_protocol.h"

serf_http2_stream_t *
serf_http2__stream_create(serf_http2_protocol_t *h2,
                          apr_int32_t streamid,
                          apr_uint32_t lr_window,
                          apr_uint32_t rl_window,
                          serf_bucket_alloc_t *alloc)
{
  serf_http2_stream_t *stream = serf_bucket_mem_alloc(alloc, sizeof(*stream));

  stream->h2 = h2;
  stream->alloc = alloc;

  stream->next = stream->prev = NULL;
  stream->request = NULL;

  stream->lr_window = lr_window;
  stream->rl_window = rl_window;

  if (streamid >= 0)
    stream->streamid = streamid;
  else
    stream->streamid = -1; /* Undetermined yet */

  stream->status = (streamid >= 0) ? H2S_IDLE : H2S_INIT;

  return stream;
}

void
serf_http2__stream_cleanup(serf_http2_stream_t *stream)
{
  serf_bucket_mem_free(stream->alloc, stream);
}

apr_status_t
serf_http2__stream_setup_request(serf_http2_stream_t *stream,
                                 serf_hpack_table_t *hpack_tbl,
                                 serf_request_t *request)
{
  apr_status_t status;
  serf_bucket_t *hpack;
  serf_bucket_t *body;

  stream->request = request;

  if (!request->req_bkt)
    {
      status = serf__setup_request(request);
      if (status)
        return status;
    }

  serf__bucket_request_read(request->req_bkt, &body, NULL, NULL);
  status = serf__bucket_hpack_create_from_request(&hpack, hpack_tbl,
                                                  request->req_bkt,
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
                                           &stream->streamid,
                                           serf_http2__allocate_stream_id,
                                           stream,
                                           HTTP2_DEFAULT_MAX_FRAMESIZE,
                                           NULL, NULL, request->allocator);

  serf_http2__enqueue_frame(stream->h2, hpack, TRUE);

  stream->status = H2S_OPEN; /* Headers sent */

  return APR_SUCCESS;
}
