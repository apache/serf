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

typedef struct serf_fcgi_protocol_t
{
    serf_context_t *ctx;
    serf_connection_t *conn;
    serf_incoming_t *client;

    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;
    bool *dirty_pollset;
    serf_config_t *config;

    apr_int16_t *req_events;

    serf_bucket_t *stream;
    serf_bucket_t *ostream;

    serf_fcgi_processor_t processor;
    void *processor_baton;

    serf_bucket_t *read_frame;
    bool in_frame;

} serf_fcgi_protocol_t;

static apr_status_t fcgi_cleanup(void *baton)
{
    serf_fcgi_protocol_t *fcgi = baton;

    fcgi = fcgi;

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

            body = serf__bucket_fcgi_unframe_create(fcgi->stream,
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
            apr_uint32_t reset_reason;

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
                return status;
            }
            else
            {
                fcgi->in_frame = TRUE;
                SERF_FCGI_assert(fcgi->read_frame != NULL);
            }

            serf__log(LOGLVL_INFO, SERF_LOGFCGI, fcgi->config,
                      "Reading 0x%x frame, stream=0x%x\n",
                      frametype, sid);

            /* If status is EOF then the frame doesn't have/declare a body */
            switch (frametype)
            {
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_BEGIN_REQUEST):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_ABORT_REQUEST):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_END_REQUEST):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_PARAMS):
                    process_bucket = body;
                    break;
                case FCGI_FRAMETYPE(FCGI_V1, FCGI_STDIN):
                    process_bucket = body;
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

static apr_status_t fcgi_write(serf_fcgi_protocol_t *fcgi)
{
    return APR_ENOTIMPL;
}

static apr_status_t fcgi_teardown(serf_fcgi_protocol_t *fcgi)
{
    return APR_ENOTIMPL;
}


/* --------------- connection support --------------- */
static apr_status_t fcgi_outgoing_read(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    if (!fcgi->stream)
        fcgi->stream = conn->stream;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_outgoing_write(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_outgoing_hangup(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_outgoing_teardown(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi = conn->protocol_baton;

    return fcgi_read(fcgi);
}

void serf__fcgi_protocol_init(serf_connection_t *conn)
{
    serf_fcgi_protocol_t *fcgi;
    apr_pool_t *protocol_pool;

    apr_pool_create(&protocol_pool, conn->pool);

    fcgi = apr_pcalloc(protocol_pool, sizeof(*fcgi));
    fcgi->pool = protocol_pool;
    fcgi->conn = conn;
    fcgi->ctx = conn->ctx;
    fcgi->dirty_pollset = &conn->dirty_conn;
    fcgi->req_events = &conn->reqevents;
    fcgi->stream = conn->stream;
    fcgi->ostream = conn->ostream_tail;
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

    if (! fcgi->stream) {
        fcgi->stream = client->stream;
        fcgi->ostream = client->ostream_tail;
    }

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_server_write(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_server_hangup(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_read(fcgi);
}

static apr_status_t fcgi_server_teardown(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi = client->protocol_baton;

    return fcgi_read(fcgi);
}

void serf__fcgi_protocol_init_server(serf_incoming_t *client)
{
    serf_fcgi_protocol_t *fcgi;
    apr_pool_t *protocol_pool;

    apr_pool_create(&protocol_pool, client->pool);

    fcgi = apr_pcalloc(protocol_pool, sizeof(*fcgi));
    fcgi->pool = protocol_pool;
    fcgi->client = client;
    fcgi->ctx = client->ctx;
    fcgi->dirty_pollset = &client->dirty_conn;
    fcgi->req_events = &client->reqevents;
    fcgi->stream = client->stream;
    fcgi->ostream = client->ostream_tail;
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

