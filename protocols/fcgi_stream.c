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
#include <apr_strings.h>
#include <apr_date.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

#include "protocols/fcgi_buckets.h"
#include "protocols/fcgi_protocol.h"

/* Fully opaque variant of serf_fcgi_stream_t */
struct serf_fcgi_stream_data_t
{
    serf_fcgi_stream_t stream_data;

    serf_bucket_t *req_agg;
    bool headers_eof;
    bool stdin_eof;

    serf_request_t *request;
    serf_incoming_request_t *in_request;
};

serf_fcgi_stream_t * serf_fcgi__stream_create(serf_fcgi_protocol_t *fcgi,
                                              apr_uint16_t streamid,
                                              serf_bucket_alloc_t *alloc)
{
    serf_fcgi_stream_t *stream;
    serf_fcgi_stream_data_t *data = serf_bucket_mem_calloc(alloc,
                                                           sizeof(*data));

    stream = &data->stream_data;
    stream->data = data;

    stream->fcgi = fcgi;
    stream->alloc = alloc;
    stream->streamid = streamid;

    stream->next = stream->prev = NULL;

    return stream;
}

void serf_fcgi__stream_destroy(serf_fcgi_stream_t * stream)
{
    if (stream->data->in_request)
        serf__incoming_request_destroy(stream->data->in_request);


    /* Destroy stream and stream->data */
    serf_bucket_mem_free(stream->alloc, stream);
}

/* Aggregate hold open callback for what requests will think is the
   actual body */
static apr_status_t stream_agg_eof(void *baton,
                                   serf_bucket_t *bucket)
{
    serf_fcgi_stream_t *stream = baton;

    if (!stream->data->stdin_eof)
        return APR_EAGAIN;

    return APR_EOF;
}

static apr_status_t close_stream(void *baton,
                                 apr_uint64_t bytes_read)
{
    serf_fcgi_stream_t *stream = baton;

    serf_fcgi__close_stream(stream->fcgi, stream);

    return APR_SUCCESS;
}

static apr_status_t
fcgi_stream_enqueue_response(serf_incoming_request_t *request,
                             void *enqueue_baton,
                             serf_bucket_t *response_bkt)
{
    serf_fcgi_stream_t *stream = enqueue_baton;
    serf_bucket_alloc_t *alloc = response_bkt->allocator;
    serf_linebuf_t *linebuf;
    serf_bucket_t *agg;
    serf_bucket_t *tmp;
    apr_status_t status;

    /* With FCGI we don't send the usual first line of the response.
       We just send a "Status: 200" instead and the actual http
       server will handle the rest */
    agg = serf_bucket_aggregate_create(alloc);

    /* Too big for the stack :( */
    linebuf = serf_bucket_mem_alloc(alloc, sizeof(*linebuf));
    serf_linebuf_init(linebuf);

    do
    {
        status = serf_linebuf_fetch(linebuf, response_bkt, SERF_NEWLINE_ANY);
    } while (status == APR_SUCCESS && linebuf->state != SERF_LINEBUF_READY);

    if (status
        || linebuf->state != SERF_LINEBUF_READY
        || !apr_date_checkmask(linebuf->line, "HTTP/#.# ###*"))
    {
        /* We can't write a response in this state yet :( */
        serf_bucket_mem_free(alloc, linebuf);
        return status;
    }

    tmp = SERF_BUCKET_SIMPLE_STRING("Status: ", alloc);
    serf_bucket_aggregate_append(agg, tmp);

    /* Skip "HTTP/1.1 " but send status and reason */
    tmp = serf_bucket_simple_copy_create(linebuf->line + 9, linebuf->used - 9,
                                         alloc);
    serf_bucket_aggregate_append(agg, tmp);
    serf_bucket_mem_free(alloc, linebuf);

    tmp = SERF_BUCKET_SIMPLE_STRING("\r\n", alloc);
    serf_bucket_aggregate_append(agg, tmp);

    serf_bucket_aggregate_append(agg, response_bkt);

    /* Send response over STDOUT, closing stdout when done */
    status = serf_fcgi__enqueue_frame(
        stream->fcgi,
        serf__bucket_fcgi_frame_create(agg, stream->streamid,
                                       FCGI_FRAMETYPE(FCGI_V1, FCGI_STDOUT),
                                       true, false,
                                       alloc), false);
    if (status)
        return status;

    /* As we don't use STDERR we don't have to close it either */

    /* Send end of request: FCGI_REQUEST_COMPLETE, exit code 0 */
    tmp = SERF_BUCKET_SIMPLE_STRING_LEN("\0\0\0\0\0\0\0\0", 8, alloc);
    tmp = serf__bucket_fcgi_frame_create(tmp, stream->streamid,
                                         FCGI_FRAMETYPE(FCGI_V1, FCGI_END_REQUEST),
                                         false, false,
                                         alloc);

    tmp = serf__bucket_event_create(tmp, stream, NULL, NULL,
                                    close_stream, alloc);

    status = serf_fcgi__enqueue_frame(stream->fcgi, tmp, true);
    return status;
}

static apr_status_t
stream_setup_request(serf_fcgi_stream_t *stream,
                     serf_config_t *config)
{
    serf_bucket_t *agg;
    apr_status_t status;

    agg = serf_bucket_aggregate_create(stream->alloc);
    serf_bucket_aggregate_hold_open(agg, stream_agg_eof, stream);

    serf_bucket_set_config(agg, config);
    stream->data->req_agg = agg;

    if (stream->data->request) {
        serf_request_t *request = stream->data->request;

        if (!request->resp_bkt) {
            apr_pool_t *scratch_pool = request->respool; /* ### Pass scratch pool */

            request->resp_bkt = request->acceptor(request, agg,
                                                  request->acceptor_baton,
                                                  scratch_pool);
        }
    }
    else {
        serf_incoming_request_t *in_request = stream->data->in_request;

        if (!in_request) {
            serf_incoming_request_setup_t req_setup;
            void *req_setup_baton;

            status = serf_fcgi__setup_incoming_request(&in_request, &req_setup,
                                                       &req_setup_baton,
                                                       stream->fcgi);

            if (status)
                return status;

            stream->data->in_request = in_request;

            status = req_setup(&in_request->req_bkt, agg,
                               in_request, req_setup_baton,
                               &in_request->handler,
                               &in_request->handler_baton,
                               &in_request->response_setup,
                               &in_request->response_setup_baton,
                               in_request->pool);

            if (status)
                return status;

            in_request->enqueue_response = fcgi_stream_enqueue_response;
            in_request->enqueue_baton = stream;
        }
    }

    return APR_SUCCESS;
}

serf_bucket_t * serf_fcgi__stream_handle_params(serf_fcgi_stream_t *stream,
                                                serf_bucket_t *body,
                                                serf_config_t *config,
                                                serf_bucket_alloc_t *alloc)
{
    apr_size_t remaining;
    if (!stream->data->req_agg) {
        stream_setup_request(stream, config);
    }

    remaining = (apr_size_t)serf_bucket_get_remaining(body);

    if (remaining) {
        body = serf__bucket_fcgi_params_decode_create(body, body->allocator);
    }
    else {
        stream->data->headers_eof = true;
    }

    /* And add it to our aggregate in both cases */
    serf_bucket_aggregate_append(stream->data->req_agg, body);

    return NULL;
}

serf_bucket_t * serf_fcgi__stream_handle_stdin(serf_fcgi_stream_t *stream,
                                               serf_bucket_t *body,
                                               serf_config_t *config,
                                               serf_bucket_alloc_t *alloc)
{
    apr_size_t remaining;
    SERF_FCGI_assert(stream->data->headers_eof);
    if (!stream->data->req_agg) {
        stream_setup_request(stream, config);
    }

    remaining = (apr_size_t)serf_bucket_get_remaining(body);

    if (!remaining) {
        stream->data->stdin_eof = true;
    }

    /* And add it to our aggregate in both cases */
    serf_bucket_aggregate_append(stream->data->req_agg, body);

    return NULL;
}


apr_status_t serf_fcgi__stream_processor(void *baton,
                                         serf_fcgi_protocol_t *fcgi,
                                         serf_bucket_t *body)
{
    serf_fcgi_stream_t *stream = baton;
    apr_status_t status = APR_SUCCESS;

    SERF_FCGI_assert(stream->data->req_agg != NULL);

    if (stream->data->request) {
        /* ### TODO */
    }
    else if (stream->data->in_request) {
        serf_incoming_request_t *request = stream->data->in_request;

        SERF_FCGI_assert(request->req_bkt != NULL);

        status = request->handler(request, request->req_bkt,
                                  request->handler_baton,
                                  request->pool);

        if (!APR_STATUS_IS_EOF(status)
            && !SERF_BUCKET_READ_ERROR(status))
            return status;

        if (APR_STATUS_IS_EOF(status)) {
            status = serf_incoming_response_create(request);

            if (status)
                return status;
        }

        if (SERF_BUCKET_READ_ERROR(status)) {

            /* SEND ERROR status */

            return status;
        }
    }

    while (!status)
    {
        struct iovec vecs[IOV_MAX];
        int vecs_used;

        /* Drain the bucket as efficiently as possible */
        status = serf_bucket_read_iovec(stream->data->req_agg,
                                        SERF_READ_ALL_AVAIL,
                                        IOV_MAX, vecs, &vecs_used);

        if (vecs_used) {
            /* We have data... What should we do with it? */
            /*int i;

            for (i = 0; i < vecs_used; i++)
                fprintf(stderr, "%.*s", vecs[i].iov_len, vecs[i].iov_base);*/
        }
    }

    if (APR_STATUS_IS_EOF(status))
    {
        /* If there was a request, it is already gone, so we can now safely
        destroy our aggregate which may include everything upto the http2
        frames */
        serf_bucket_destroy(stream->data->req_agg);
        stream->data->req_agg = NULL;
    }

    return status;
}

