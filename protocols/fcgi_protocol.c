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
#include "protocols/fcgi_buckets.h"
#include "protocols/fcgi_protocol.h"

#define SERF_ERROR_FCGI_RECORD_SIZE_ERROR   SERF_ERROR_HTTP2_FRAME_SIZE_ERROR
#define SERF_ERROR_FCGI_PROTOCOL_ERROR      SERF_ERROR_HTTP2_PROTOCOL_ERROR

struct serf_fcgi_protocol_t
{
    serf_connection_t *conn;
    serf_incoming_t *client;

    serf_io_baton_t *io; /* Low level connection */
    serf_pump_t *pump;

    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;
    serf_config_t *config;

    serf_fcgi_processor_t processor;
    void *processor_baton;

    serf_bucket_t *read_frame;
    bool in_frame;

    serf_fcgi_stream_t *first, *last;

    bool no_keep_conn;

};

static apr_status_t fcgi_cleanup(void *baton)
{
    serf_fcgi_protocol_t *fcgi = baton;

    fcgi = fcgi;

    return APR_SUCCESS;
}

/* Implements serf_bucket_prefix_handler_t.
   Handles PING frames for pings initiated locally */
static apr_status_t fcgi_begin_request(void *baton,
                                       serf_bucket_t *bucket,
                                       const char *data,
                                       apr_size_t len)
{
    serf_fcgi_stream_t *stream = baton;
    const FCGI_BeginRequestBody *brb;

    if (len != sizeof(*brb))
        return SERF_ERROR_FCGI_RECORD_SIZE_ERROR;

    brb = (const void*)data;

    stream->role = (brb->roleB1 << 8) | (brb->roleB0);

    if (!(brb->flags & FCGI_KEEP_CONN))
        stream->fcgi->no_keep_conn = true;


    return APR_SUCCESS;
}


/* Implements the serf_bucket_end_of_frame_t callback */
static apr_status_t
fcgi_end_of_frame(void *baton,
                   serf_bucket_t *frame)
{
    serf_fcgi_protocol_t *fcgi = baton;

    SERF_FCGI_assert(fcgi->read_frame == frame);
    fcgi->read_frame = NULL;
    fcgi->in_frame = FALSE;
    fcgi->processor = NULL;
    fcgi->processor_baton = NULL;

    return APR_SUCCESS;
}

/* Implements serf_fcgi_processor_t */
static apr_status_t
fcgi_bucket_processor(void *baton,
                      serf_fcgi_protocol_t *h2,
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
        SERF_FCGI_assert(!h2->in_frame && !h2->read_frame);
        serf_bucket_destroy(payload);
    }

    return status;
}



static apr_status_t fcgi_process(serf_fcgi_protocol_t *fcgi)
{
    while (true)
    {
        apr_status_t status;
        serf_bucket_t *body;

        if (fcgi->processor)
        {
            status = fcgi->processor(fcgi->processor_baton, fcgi,
                                     fcgi->read_frame);

            if (SERF_BUCKET_READ_ERROR(status))
                return status;
            else if (APR_STATUS_IS_EOF(status))
            {
                /* ### frame ended */
                SERF_FCGI_assert(fcgi->read_frame == NULL);
                fcgi->processor = NULL;
                fcgi->processor_baton = NULL;
            }
            else if (fcgi->in_frame)
            {
                if (status)
                    return status;
                else
                    continue;
            }
        }
        else
        {
            SERF_FCGI_assert(!fcgi->in_frame);
        }

        body = fcgi->read_frame;

        if (!body)
        {
            SERF_FCGI_assert(!fcgi->in_frame);

            body = serf__bucket_fcgi_unframe_create(fcgi->pump->stream,
                                                    fcgi->allocator);

            serf__bucket_fcgi_unframe_set_eof(body,
                                              fcgi_end_of_frame, fcgi);

            serf_bucket_set_config(body, fcgi->config);
            fcgi->read_frame = body;
        }

        if (!fcgi->in_frame)
        {
            apr_uint16_t sid;
            apr_uint16_t frametype;
            apr_size_t remaining;
            serf_fcgi_processor_t process_handler = NULL;
            void *process_baton = NULL;
            serf_bucket_t *process_bucket = NULL;
            serf_fcgi_stream_t *stream;

            status = serf__bucket_fcgi_unframe_read_info(body, &sid,
                                                         &frametype);

            if (APR_STATUS_IS_EOF(status))
            {
                /* Entire frame is already read (just header) */
                SERF_FCGI_assert(fcgi->read_frame == NULL);
                SERF_FCGI_assert(!fcgi->in_frame);
            }
            else if (status)
            {
                SERF_FCGI_assert(fcgi->read_frame != NULL);
                SERF_FCGI_assert(!fcgi->in_frame);
                return (status == SERF_ERROR_EMPTY_READ) ? APR_SUCCESS
                                                         : status;
            }
            else
            {
                fcgi->in_frame = TRUE;
                SERF_FCGI_assert(fcgi->read_frame != NULL);
            }

            serf__log(LOGLVL_INFO, SERF_LOGCOMP_PROTOCOL, __FILE__,
                      fcgi->config,
                      "Reading 0x%x frame, stream=0x%x\n",
                      frametype, sid);

            /* If status is EOF then the frame doesn't have/declare a body */
            switch (frametype)
            {
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_BEGIN_REQUEST):
                    stream = serf_fcgi__stream_get(fcgi, sid, false);

                    if (stream) {
                        /* Stream must be new */
                        return SERF_ERROR_FCGI_PROTOCOL_ERROR;
                    }
                    stream = serf_fcgi__stream_get(fcgi, sid, true);

                    remaining = (apr_size_t)serf_bucket_get_remaining(body);
                    if (remaining != sizeof(FCGI_BeginRequestBody)) {
                        return SERF_ERROR_FCGI_RECORD_SIZE_ERROR;
                    }
                    body = serf_bucket_prefix_create(
                                        body,
                                        sizeof(FCGI_BeginRequestBody),
                                        fcgi_begin_request, stream,
                                        fcgi->allocator);

                    /* Just reading will handle this frame now*/
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_ABORT_REQUEST):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_END_REQUEST):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_PARAMS):
                    stream = serf_fcgi__stream_get(fcgi, sid, false);
                    if (!stream) {
                        return SERF_ERROR_FCGI_PROTOCOL_ERROR;
                    }

                    body = serf_fcgi__stream_handle_params(stream, body,
                                                           fcgi->config,
                                                           fcgi->allocator);

                    if (body) {
                        /* We will take care of discarding */
                        process_bucket = body;
                    }
                    else
                    {
                        /* The stream wants to handle the reading itself */
                        process_handler = serf_fcgi__stream_processor;
                        process_baton = stream;
                    }
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_STDIN):
                    stream = serf_fcgi__stream_get(fcgi, sid, false);
                    if (!stream) {
                        return SERF_ERROR_FCGI_PROTOCOL_ERROR;
                    }

                    body = serf_fcgi__stream_handle_stdin(stream, body,
                                                          fcgi->config,
                                                          fcgi->allocator);

                    if (body) {
                        /* We will take care of discarding */
                        process_bucket = body;
                    }
                    else
                    {
                        /* The stream wants to handle the reading itself */
                        process_handler = serf_fcgi__stream_processor;
                        process_baton = stream;
                    }
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_STDOUT):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_STDERR):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_DATA):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_GET_VALUES):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_GET_VALUES_RESULT):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_UNKNOWN_TYPE):
                    process_bucket = body;
                    break;
                default:
                    process_bucket = body;
            };

            if (body)
                serf_bucket_set_config(body, fcgi->config);

            SERF_FCGI_assert(fcgi->processor == NULL);

            if (process_handler)
            {
                fcgi->processor = process_handler;
                fcgi->processor_baton = process_baton;
            }
            else
            {
                SERF_FCGI_assert(process_bucket != NULL);
                fcgi->processor = fcgi_bucket_processor;
                fcgi->processor_baton = process_bucket;
            }
        }
    } /* while(TRUE) */
}

static apr_status_t fcgi_read(serf_fcgi_protocol_t *fcgi)
{
    apr_status_t status = fcgi_process(fcgi);

    if (!status || SERF_BUCKET_READ_ERROR(status))
        return status;

    return APR_SUCCESS;
}

apr_status_t serf_fcgi__enqueue_frame(serf_fcgi_protocol_t *fcgi,
                                      serf_bucket_t *frame,
                                      bool flush)
{
    return serf_pump__add_output(fcgi->pump, frame, flush);
}

static apr_status_t fcgi_write(serf_fcgi_protocol_t *fcgi)
{
    apr_status_t status;

    if (fcgi->client)
        status = serf__incoming_client_flush(fcgi->client, true);
    else
        status = serf__connection_flush(fcgi->conn, true);

    if (APR_STATUS_IS_EAGAIN(status))
        return APR_SUCCESS;
    else if (status)
        return status;

    /* Probably nothing to write. */
    serf_io__set_pollset_dirty(fcgi->io);

    return APR_SUCCESS;
}

static apr_status_t fcgi_hangup(serf_fcgi_protocol_t *fcgi)
{
    return APR_ENOTIMPL;
}

static void fcgi_teardown(serf_fcgi_protocol_t *fcgi)
{

}

serf_fcgi_stream_t *
serf_fcgi__stream_get(serf_fcgi_protocol_t *fcgi,
                      apr_uint16_t streamid,
                      bool create)
{
    serf_fcgi_stream_t *stream;

    if (streamid == 0)
        return NULL;

    for (stream = fcgi->first; stream; stream = stream->next)
    {
        if (stream->streamid == streamid)
            return stream;
    }

    if (create)
    {
        stream = serf_fcgi__stream_create(fcgi, streamid, fcgi->allocator);

        if (fcgi->first)
        {
            stream->next = fcgi->first;
            fcgi->first->prev = stream;
            fcgi->first = stream;
        }
        else
            fcgi->last = fcgi->first = stream;

        return stream;
    }
    return NULL;
}

void serf_fcgi__close_stream(serf_fcgi_protocol_t *fcgi,
                             serf_fcgi_stream_t *stream)
{
    if (!stream->prev)
        fcgi->first = stream->next;
    else
        stream->prev->next = stream;

    if (stream->next)
        stream->next->prev = stream->prev;
    else
        fcgi->last = stream->prev;

    fcgi->first = fcgi->last = NULL;

    serf_fcgi__stream_destroy(stream);
}

apr_status_t serf_fcgi__setup_incoming_request(
    serf_incoming_request_t **in_request,
    serf_incoming_request_setup_t *req_setup,
    void **req_setup_baton,
    serf_fcgi_protocol_t *fcgi)
{
    if (!fcgi->client)
        return SERF_ERROR_FCGI_PROTOCOL_ERROR;

    *in_request = serf__incoming_request_create(fcgi->client);
    *req_setup = fcgi->client->req_setup;
    *req_setup_baton = fcgi->client->req_setup_baton;

    return APR_SUCCESS;
}


/* --------------- connection support --------------- */
static apr_status_t fcgi_outgoing_read(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_outgoing_write(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_write(fcgi);
}

static apr_status_t fcgi_outgoing_hangup(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_hangup(fcgi);
}

static void fcgi_outgoing_teardown(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    fcgi_teardown(fcgi);
}

void serf__fcgi_protocol_init(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi;
    apr_pool_t *protocol_pool;

    apr_pool_create(&protocol_pool, conn->pool);

    fcgi = apr_pcalloc(protocol_pool, sizeof(*fcgi));
    fcgi->pool = protocol_pool;
    fcgi->conn = conn;
    fcgi->io = &conn->io;
    fcgi->pump = &conn->pump;
    fcgi->allocator = conn->allocator;
    fcgi->config = conn->config;

    apr_pool_cleanup_register(protocol_pool, fcgi, fcgi_cleanup,
                              apr_pool_cleanup_null);

    conn->perform_read = fcgi_outgoing_read;
    conn->perform_write = fcgi_outgoing_write;
    conn->perform_hangup = fcgi_outgoing_hangup;
    conn->perform_teardown = fcgi_outgoing_teardown;
    conn->protocol_baton = fcgi;

    /* Disable HTTP/1.1 guessing that affects writability */
    conn->probable_keepalive_limit = 0;
    conn->max_outstanding_requests = 0;
}

/* --------------- connection support --------------- */
static apr_status_t fcgi_server_read(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_server_write(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_write(fcgi);
}

static apr_status_t fcgi_server_hangup(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_hangup(fcgi);
}

static void fcgi_server_teardown(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    fcgi_teardown(fcgi);
}

void serf__fcgi_protocol_init_server(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi;
    apr_pool_t *protocol_pool;

    apr_pool_create(&protocol_pool, client->pool);

    fcgi = apr_pcalloc(protocol_pool, sizeof(*fcgi));
    fcgi->pool = protocol_pool;
    fcgi->client = client;
    fcgi->io = &client->io;
    fcgi->pump = &client->pump;
    fcgi->allocator = client->allocator;
    fcgi->config = client->config;

    apr_pool_cleanup_register(protocol_pool, fcgi, fcgi_cleanup,
                              apr_pool_cleanup_null);

    client->perform_read = fcgi_server_read;
    client->perform_write = fcgi_server_write;
    client->perform_hangup = fcgi_server_hangup;
    client->perform_teardown = fcgi_server_teardown;
    client->protocol_baton = fcgi;
}

