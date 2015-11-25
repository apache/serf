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

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

#include "protocols/http2_buckets.h"
#include "protocols/http2_protocol.h"

struct serf_http2_stream_data_t
{
    serf_request_t *request; /* May be NULL as streams may outlive requests */
    serf_incoming_request_t *in_request;
    serf_bucket_t *response_agg;
    serf_hpack_table_t *tbl;
    serf_bucket_t *data_tail;
};

serf_http2_stream_t *
serf_http2__stream_create(serf_http2_protocol_t *h2,
                          apr_int32_t streamid,
                          apr_uint32_t lr_window,
                          apr_uint32_t rl_window,
                          serf_bucket_alloc_t *alloc)
{
    serf_http2_stream_t *stream = serf_bucket_mem_alloc(alloc,
                                                        sizeof(*stream));

    stream->h2 = h2;
    stream->alloc = alloc;

    stream->next = stream->prev = NULL;

    /* Delay creating this? */
    stream->data = serf_bucket_mem_alloc(alloc, sizeof(*stream->data));
    stream->data->request = NULL;
    stream->data->in_request = NULL;
    stream->data->response_agg = NULL;
    stream->data->tbl = NULL;
    stream->data->data_tail = NULL;

    stream->lr_window = lr_window;
    stream->rl_window = rl_window;

    if (streamid >= 0)
        stream->streamid = streamid;
    else
        stream->streamid = -1; /* Undetermined yet */

    stream->status = (streamid >= 0) ? H2S_IDLE : H2S_INIT;
    stream->new_reserved_stream = NULL;

    stream->prev_writable = stream->next_writable = NULL;

    return stream;
}

void
serf_http2__stream_cleanup(serf_http2_stream_t *stream)
{
    if (stream->data) {
        if (stream->data->response_agg)
            serf_bucket_destroy(stream->data->response_agg);

        if (stream->data->data_tail)
            serf_bucket_destroy(stream->data->data_tail);

        serf_bucket_mem_free(stream->alloc, stream->data);
        stream->data = NULL;
    }
    serf_bucket_mem_free(stream->alloc, stream);
}

static apr_status_t stream_send_headers(serf_http2_stream_t *stream,
                                        serf_bucket_t *hpack,
                                        apr_size_t max_payload_size,
                                        bool end_stream,
                                        bool priority)
{
    apr_status_t status;
    bool first_frame = true;

    /* And now schedule the packet for writing. Note that it is required
    by the HTTP/2 spec to send HEADERS and CONTINUATION directly after
    each other, without other frames inbetween. */
    while (hpack != NULL)
    {
        serf_bucket_t *next;
        apr_uint64_t remaining;

        /* hpack buckets implement get_remaining. And if they didn't adding the
        framing around them would apply some reads that fix the buckets.

        So we can ignore the theoretical endless loop here for two different
        reasons
        */
        remaining = serf_bucket_get_remaining(hpack);

        if (remaining > max_payload_size) {
            serf_bucket_split_create(&next, &hpack, hpack,
                                     max_payload_size - (max_payload_size / 4),
                                     max_payload_size);
        }
        else
        {
            next = hpack;
            hpack = NULL;
        }

        next = serf__bucket_http2_frame_create(next,
                                               first_frame
                                               ? HTTP2_FRAME_TYPE_HEADERS
                                               : HTTP2_FRAME_TYPE_CONTINUATION,
                                               (end_stream
                                                ? HTTP2_FLAG_END_STREAM
                                                : 0)
                                               | ((hpack != NULL)
                                                  ? 0
                                                  : HTTP2_FLAG_END_HEADERS)
                                               | (priority
                                                  ? HTTP2_FLAG_PRIORITY
                                                  : 0),
                                               &stream->streamid,
                                               serf_http2__allocate_stream_id,
                                               stream,
                                               max_payload_size,
                                               next->allocator);
        status = serf_http2__enqueue_frame(stream->h2, next, TRUE);

        if (SERF_BUCKET_READ_ERROR(status))
            return status; /* Connection dead */

        first_frame = false; /* Continue with 'continuation' frames */
    }

    return APR_SUCCESS;
}

typedef struct window_allocate_info_t
{
    serf_http2_stream_t *stream;
    serf_bucket_t *bkt;
    apr_size_t allocated;
} window_allocate_info_t;

static apr_status_t data_write_started(void *baton,
                                       apr_uint64_t bytes_read)
{
    window_allocate_info_t *wai = baton;

    bytes_read = serf_bucket_get_remaining(wai->bkt);

    /* Handles unavailable for free */
    if (bytes_read <= wai->allocated) {
        /* Nice, we can return something now */
        apr_size_t to_much = (wai->allocated - (apr_size_t)bytes_read);

        serf_http2__return_window(wai->stream->h2, wai->stream, to_much);

        wai->allocated = 0;
    }
    return APR_SUCCESS;
}

static apr_status_t data_write_done(void *baton,
                                    apr_uint64_t bytes_read)
{
    window_allocate_info_t *wai = baton;

    if (wai->allocated && bytes_read <= wai->allocated) {
        /* Nice, we can return something now */
        apr_size_t to_much = (wai->allocated - (apr_size_t)bytes_read);
        wai->stream->lr_window += to_much;

        serf_http2__return_window(wai->stream->h2, wai->stream, to_much);

        wai->allocated = 0;
    }

    serf_bucket_mem_free(wai->stream->alloc, wai);
    return APR_SUCCESS;
}


static apr_status_t stream_send_data(serf_http2_stream_t *stream,
                                     serf_bucket_t *data)
{
    apr_uint64_t remaining;
    serf_bucket_t *next;
    apr_size_t prefix_len;
    bool end_stream;
    apr_status_t status;

    SERF_H2_assert(stream->status == H2S_OPEN
                   || stream->status == H2S_HALFCLOSED_REMOTE);
    SERF_H2_assert(!stream->data->data_tail || (data ==
                                                stream->data->data_tail));

    /* Sending DATA frames over HTTP/2 is not easy as this usually requires
       handling windowing, priority, etc. This code will improve over time */

    if (!data)
        remaining = 0;
    else
        remaining = serf_bucket_get_remaining(data);

    /* If the stream decided we are already done */
    if (remaining == 0) {
        if (stream->status == H2S_OPEN)
            stream->status = H2S_HALFCLOSED_LOCAL;
        else
            stream->status = H2S_CLOSED;

        serf_bucket_destroy(data);

        next = serf__bucket_http2_frame_create(NULL, HTTP2_FRAME_TYPE_DATA,
                                               HTTP2_FLAG_END_STREAM,
                                               &stream->streamid,
                                               serf_http2__allocate_stream_id,
                                               stream, 0, stream->alloc);
        stream->data->data_tail = NULL;
        return serf_http2__enqueue_frame(stream->h2, next, false);
    }

    prefix_len = serf_http2__alloc_window(stream->h2, stream,
                                          (remaining >= APR_SIZE_MAX)
                                          ? SERF_READ_ALL_AVAIL
                                          : (apr_size_t)remaining);

    if (prefix_len == 0) {
        /* No window left */
        stream->data->data_tail = data;
        return APR_SUCCESS;
    }

    if (prefix_len < remaining) {
        window_allocate_info_t *wai;
        serf_bucket_split_create(&data, &stream->data->data_tail, data,
                                 MIN(prefix_len, 1024), prefix_len);

        wai = serf_bucket_mem_alloc(stream->alloc, sizeof(*wai));
        wai->stream = stream;
        wai->bkt = data;
        wai->allocated = prefix_len;

        data = serf__bucket_event_create(data, wai,
                                         data_write_started,
                                         data_write_done, NULL, stream->alloc);
        end_stream = false;
    }
    else
        end_stream = true;

    next = serf__bucket_http2_frame_create(data, HTTP2_FRAME_TYPE_DATA,
                                           end_stream ? HTTP2_FLAG_END_STREAM
                                                      : 0,
                                           &stream->streamid,
                                           serf_http2__allocate_stream_id,
                                           stream, prefix_len,
                                           data->allocator);

    status = serf_http2__enqueue_frame(stream->h2, next, TRUE);

    if (!end_stream) {
        /* Write more later */
        serf_http2__ensure_writable(stream);
    }

    return status;
}

apr_status_t
serf_http2__stream_write_data(serf_http2_stream_t *stream)
{
    SERF_H2_assert(stream->status == H2S_OPEN
                   || stream->status == H2S_HALFCLOSED_REMOTE);
    SERF_H2_assert(stream->data->data_tail != NULL);

    return stream_send_data(stream, stream->data->data_tail);
}

static apr_status_t destroy_request_bucket(void *baton,
                                           apr_uint64_t bytes_read)
{
    serf_request_t *request = baton;

    serf_bucket_destroy(request->req_bkt);
    request->req_bkt = NULL;
    request->writing = SERF_WRITING_FINISHED;
    return APR_SUCCESS;
}

apr_status_t
serf_http2__stream_setup_next_request(serf_http2_stream_t *stream,
                                      serf_connection_t *conn,
                                      apr_size_t max_payload_size,
                                      serf_hpack_table_t *hpack_tbl)
{
    serf_request_t *request = conn->unwritten_reqs;
    apr_status_t status;
    serf_bucket_t *hpack;
    serf_bucket_t *body;
    bool end_stream;
    bool priority = false;

    SERF_H2_assert(request != NULL);
    if (!request)
        return APR_EGENERAL;

    stream->data->request = request;
    request->protocol_baton = stream;

    if (!request->req_bkt) {
        status = serf__setup_request(request);
        if (status)
            return status;
    }

    conn->unwritten_reqs = request->next;
    if (conn->unwritten_reqs_tail == request)
        conn->unwritten_reqs = conn->unwritten_reqs_tail = NULL;

    request->next = NULL;

    serf__link_requests(&conn->written_reqs, &conn->written_reqs_tail,
                        request);
    conn->nr_of_written_reqs++;
    conn->nr_of_unwritten_reqs--;

    serf__bucket_request_read(request->req_bkt, &body, NULL, NULL);
    status = serf__bucket_hpack_create_from_request(
                            &hpack, hpack_tbl,
                            request->req_bkt,
                            request->conn->host_info.scheme,
                            request->allocator);
    if (status)
        return status;

    if (request->depends_on && request->depends_on->protocol_baton)
    {
        serf_http2_stream_t *ds = request->depends_on->protocol_baton;

        if (ds->streamid >= 0) {
            serf_bucket_t *agg;
            unsigned char priority_data[5];

            agg = serf_bucket_aggregate_create(request->allocator);

            priority_data[0] = (ds->streamid >> 24) & 0x7F;
            /* bit 7 of [0] is the exclusive flag */
            priority_data[1] = (ds->streamid >> 16) & 0xFF;
            priority_data[2] = (ds->streamid >> 8) & 0xFF;
            priority_data[3] = ds->streamid & 0xFF;
            priority_data[4] = request->dep_priority >> 8;

            serf_bucket_aggregate_append(
                agg,
                serf_bucket_simple_copy_create((void *)priority_data,
                                               5, request->allocator));

            serf_bucket_aggregate_append(agg, hpack);
            hpack = agg;

            priority = true;
        }
    }

    if (!body) {
        serf_bucket_destroy(request->req_bkt);
        request->req_bkt = NULL;
        end_stream = true;
    }
    else
        end_stream = false;

    status = stream_send_headers(stream, hpack, max_payload_size,
                                 end_stream, priority);
    if (status)
        return status;

    if (end_stream) {
        stream->status = H2S_HALFCLOSED_LOCAL; /* Headers sent; no body */
        return APR_SUCCESS;
    }

    /* Yuck... we are not allowed to destroy body */
    body = serf_bucket_barrier_create(body, request->allocator);

    /* Setup an event bucket to destroy the actual request bucket when
       the body is done */
    body = serf__bucket_event_create(body, request,
                                     NULL, NULL, destroy_request_bucket,
                                     request->allocator);

    stream->status = H2S_OPEN; /* Headers sent. Body to go */
    request->writing = SERF_WRITING_STARTED;
    return stream_send_data(stream, body);
}

apr_status_t
serf_http2__stream_reset(serf_http2_stream_t *stream,
                         apr_status_t reason,
                         bool local_reset)
{
    stream->status = H2S_CLOSED;

    if (stream->streamid < 0)
        return APR_SUCCESS;

    if (local_reset)
        return serf_http2__enqueue_stream_reset(stream->h2,
                                                stream->streamid,
                                                reason);

    return APR_SUCCESS;
}

void serf_http2__stream_cancel_request(serf_http2_stream_t *stream,
                                               serf_request_t *rq,
                                               apr_status_t reason)
{
    if (stream->streamid < 0)
        return; /* Never hit the wire */
    else if (stream->status == H2S_CLOSED)
        return; /* We are already detached */

    if (reason < SERF_ERROR_HTTP2_NO_ERROR
        || reason > SERF_ERROR_HTTP2_HTTP_1_1_REQUIRED)
    {
        reason = SERF_ERROR_HTTP2_CANCEL;
    }

    /* Let the other party know we don't want anything */
    serf_http2__stream_reset(stream, reason, true);

    if (!stream->data)
        return;

    if (stream->data && stream->data->request)
        stream->data->request = NULL;

    /* Would be nice if we could response_agg, but that is typically
       not safe here, as we might still be reading from it */
}

void serf_http2__stream_prioritize_request(serf_http2_stream_t *stream,
                                           serf_request_t *rq,
                                           bool exclusive)
{
    if (stream->streamid < 0)
        return; /* Never hit the wire */
    else if (stream->status == H2S_CLOSED)
        return; /* We are already detached */

    /* Ignore for now. We start by handling this at setup */
}


static apr_status_t
stream_response_eof(void *baton,
                    serf_bucket_t *aggregate_bucket)
{
    serf_http2_stream_t *stream = baton;

    switch (stream->status)
    {
        case H2S_CLOSED:
        case H2S_HALFCLOSED_REMOTE:
            return APR_EOF;
        default:
            return APR_EAGAIN;
    }
}

static int set_hpack_header(void *baton,
                            const char *key,
                            const char *value)
{
    serf_bucket_t *hpack = baton;

    serf__bucket_hpack_setc(hpack, key, value);
    return 0;
}

static apr_status_t
http2_stream_enqueue_response(serf_incoming_request_t *request,
                              void *enqueue_baton,
                              serf_bucket_t *response_bkt)
{
    serf_http2_stream_t *stream = enqueue_baton;
    serf_bucket_t *hpack;
    serf_bucket_t *headers;
    serf_bucket_t *h1_response;
    serf_status_line sline;
    apr_status_t status;

    /* OK, this could be implemented using knowledge of the buckets, in
       a 100% more efficient, but I don't want to introduce new bucket
       types for this yet. Let's just read everything the http/1 way
       and put it in HTTP/2 appropriate places */
    h1_response = serf_bucket_response_create(response_bkt,
                                              stream->alloc);
    do
    {
        status = serf_bucket_response_status(h1_response, &sline);
    } while (status != APR_SUCCESS);

    if (status != APR_SUCCESS)
        return APR_EGENERAL; /* Can't read statusline. No EAGAIN support before
                                the body (yet) */

    hpack = serf__bucket_hpack_create(stream->data->tbl, stream->alloc);
    serf__bucket_hpack_setc(hpack, ":status",
                            apr_itoa(stream->data->in_request->pool,
                                     sline.code));

    do
    {
        status = serf_bucket_response_wait_for_headers(h1_response);
    } while (status != APR_SUCCESS);

    if (status != APR_SUCCESS)
        return APR_EGENERAL; /* Can't read body. No EAGAIN support before
                                the body (yet) */

    headers = serf_bucket_response_get_headers(h1_response);

    serf_bucket_headers_do(headers, set_hpack_header, hpack);

    status = stream_send_headers(stream, hpack,
                                 serf_http2__max_payload_size(stream->h2),
                                 false /* eos */, false /* priority */);

    if (status)
        return status;

    return stream_send_data(stream, response_bkt);
}

static apr_status_t
stream_setup_response(serf_http2_stream_t *stream,
                      serf_config_t *config)
{
    serf_bucket_t *agg;
    apr_status_t status;

    agg = serf_bucket_aggregate_create(stream->alloc);
    serf_bucket_aggregate_hold_open(agg, stream_response_eof, stream);

    serf_bucket_set_config(agg, config);
    stream->data->response_agg = agg;

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

            status = serf_http2__setup_incoming_request(&in_request, &req_setup,
                                                        &req_setup_baton,
                                                        stream->h2);

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

            stream->status = H2S_OPEN;

            in_request->enqueue_response = http2_stream_enqueue_response;
            in_request->enqueue_baton = stream;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t
stream_promise_done(void *baton,
                    serf_bucket_t *done_agg)
{
    serf_http2_stream_t *parent_stream = baton;
    serf_http2_stream_t *stream = parent_stream->new_reserved_stream;

    SERF_H2_assert(stream != NULL);
    SERF_H2_assert(stream->status == H2S_RESERVED_REMOTE);
    parent_stream->new_reserved_stream = NULL; /* End of PUSH_PROMISE */

    /* Anything else? */


    /* ### Absolute minimal implementation.
           Just sending that we are not interested in the initial SETTINGS
           would be the easier approach. */
    serf_http2__stream_reset(stream, SERF_ERROR_HTTP2_REFUSED_STREAM, TRUE);




    /* Exit condition:
       * Either we should accept the stream and are ready to receive
         HEADERS and DATA on it.
       * Or we aren't and reject the stream
     */
    SERF_H2_assert(stream->status == H2S_CLOSED
                   || stream->data->request != NULL);

    /* We must return a proper error or EOF here! */
    return APR_EOF;
}

serf_bucket_t *
serf_http2__stream_handle_hpack(serf_http2_stream_t *stream,
                                serf_bucket_t *bucket,
                                unsigned char frametype,
                                bool end_stream,
                                apr_size_t max_entry_size,
                                serf_hpack_table_t *hpack_tbl,
                                serf_config_t *config,
                                serf_bucket_alloc_t *allocator)
{
    if (frametype == HTTP2_FRAME_TYPE_HEADERS) {

        if (!stream->data->response_agg)
            stream_setup_response(stream, config);

        stream->data->tbl = hpack_tbl;

        bucket = serf__bucket_hpack_decode_create(bucket, max_entry_size,
                                                  hpack_tbl, allocator);

        serf_bucket_aggregate_append(stream->data->response_agg, bucket);

        if (end_stream) {

            if (stream->status == H2S_HALFCLOSED_LOCAL)
                stream->status = H2S_CLOSED;
            else
                stream->status = H2S_HALFCLOSED_REMOTE;
        }
        return NULL; /* We want to drain the bucket ourselves */
    }
    else
    {
        serf_bucket_t *agg;
        SERF_H2_assert(frametype == HTTP2_FRAME_TYPE_PUSH_PROMISE);

        /* First create the HPACK decoder as requested */

     /* TODO: Store key+value somewhere to allow asking the application
             if it is interested in the promised stream.

             Most likely it is not interested *yet* as the HTTP/2 spec
             recommends pushing promised items *before* the stream that
             references them.

             So we probably want to store the request anyway, to allow
             matching this against a later added outgoing request.
     */
        bucket = serf__bucket_hpack_decode_create(bucket, max_entry_size,
                                                  hpack_tbl, allocator);

        /* And now wrap around it the easiest way to get an EOF callback */
        agg = serf_bucket_aggregate_create(allocator);
        serf_bucket_aggregate_append(agg, bucket);

        serf_bucket_aggregate_hold_open(agg, stream_promise_done, stream);

        /* And return the aggregate, so the bucket will be drained for us */
        return agg;
    }
}

serf_bucket_t *
serf_http2__stream_handle_data(serf_http2_stream_t *stream,
                               serf_bucket_t *bucket,
                               unsigned char frametype,
                               bool end_stream,
                               serf_config_t *config,
                               serf_bucket_alloc_t *allocator)
{
    if (!stream->data->response_agg)
        stream_setup_response(stream, config);

    serf_bucket_aggregate_append(stream->data->response_agg, bucket);

    if (end_stream) {

        if (stream->status == H2S_HALFCLOSED_LOCAL)
            stream->status = H2S_CLOSED;
        else
            stream->status = H2S_HALFCLOSED_REMOTE;
    }

    return NULL;
}

apr_status_t
serf_http2__stream_processor(void *baton,
                             serf_http2_protocol_t *h2,
                             serf_bucket_t *bucket)
{
    serf_http2_stream_t *stream = baton;
    apr_status_t status = APR_SUCCESS;

    SERF_H2_assert(stream->data->response_agg != NULL);

    if (stream->data->request) {
        serf_request_t *request = stream->data->request;

        SERF_H2_assert(request->resp_bkt != NULL);

        /* Response handlers are expected to read until they get some error,
           but at least some implementations assume that just returning
           APR_SUCCESS will have them called again, as that used to work as
           an APR_EAGAIN like system in HTTP/1.

           But we can't just fall back with HTTP/2, as we might still have
           some part of the frame open (good case), or we might have completed
           the frame and are never called again. */
        do {
            status = serf__handle_response(request, request->respool);
        } while (status == APR_SUCCESS);

        if (!APR_STATUS_IS_EOF(status)
            && !SERF_BUCKET_READ_ERROR(status))
            return status;

          /* Ok, the request thinks is done, let's handle the bookkeeping,
             to remove it from the outstanding requests */
        {
            serf_connection_t *conn = serf_request_get_conn(request);
            serf_request_t **rq = &conn->written_reqs;
            serf_request_t *last = NULL;

            while (*rq && (*rq != request)) {
                last = *rq;
                rq = &last->next;
            }

            if (*rq)
            {
                (*rq) = request->next;

                if (conn->written_reqs_tail == request)
                    conn->written_reqs_tail = last;

                conn->nr_of_written_reqs--;
            }

            serf__destroy_request(request);
            stream->data->request = NULL;
        }

        if (SERF_BUCKET_READ_ERROR(status)) {

            if (stream->status != H2S_CLOSED) {
              /* Tell the other side that we are no longer interested
                 to receive more data */
                serf_http2__stream_reset(stream, status, TRUE);
            }

            return status;
        }

        SERF_H2_assert(APR_STATUS_IS_EOF(status));

        /* Even though the request reported that it is done, we might not
           have read all the data that we should (*cough* padding *cough*),
           or perhaps an invalid 'Content-Length' value; maybe both.

           This may even handle not-interested - return EOF cases, but that
           would have broken the pipeline for HTTP/1.1.
           */

        /* ### For now, fall through and eat whatever is left.
               Usually this is 0 bytes */

        status = APR_SUCCESS;
    }
    else if (stream->data->in_request) {
        serf_incoming_request_t *request = stream->data->in_request;

        SERF_H2_assert(request->req_bkt != NULL);

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

            if (stream->status != H2S_CLOSED) {
                /* Tell the other side that we are no longer interested
                to receive more data */
                serf_http2__stream_reset(stream, status, TRUE);
            }

            return status;
        }
    }

    while (!status)
    {
        struct iovec vecs[SERF__STD_IOV_COUNT];
        int vecs_used;

        /* Drain the bucket as efficiently as possible */
        status = serf_bucket_read_iovec(stream->data->response_agg,
                                        SERF_READ_ALL_AVAIL, COUNT_OF(vecs),
                                        vecs, &vecs_used);

        if (vecs_used) {
          /* We have data... What should we do with it? */
        }
    }

    if (APR_STATUS_IS_EOF(status)
        && (stream->status == H2S_CLOSED
            || stream->status == H2S_HALFCLOSED_REMOTE))
    {
      /* If there was a request, it is already gone, so we can now safely
         destroy our aggregate which may include everything upto the http2
         frames */
        serf_bucket_destroy(stream->data->response_agg);
        stream->data->response_agg = NULL;
    }

    return status;
}
