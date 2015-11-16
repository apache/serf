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


/* From incoming.c */
typedef struct ic_setup_baton_t
{
    serf_incoming_t *incoming;
    serf_incoming_request_cb_t request;
    serf_context_t *ctx;
    void *request_baton;
} ic_setup_baton_t;

static apr_status_t dummy_setup(apr_socket_t *skt,
                                serf_bucket_t **read_bkt,
                                serf_bucket_t **write_bkt,
                                void *setup_baton,
                                apr_pool_t *pool)
{
    ic_setup_baton_t *isb = setup_baton;

    *read_bkt = serf_bucket_socket_create(skt, isb->incoming->allocator);

    return APR_SUCCESS;
}

static apr_status_t dummy_closed(serf_incoming_t *incoming,
                                 void *closed_baton,
                                 apr_status_t why,
                                 apr_pool_t *pool)
{
    return APR_SUCCESS;
}

static apr_status_t drain_handler(serf_incoming_request_t *req,
                                  serf_bucket_t *request,
                                  void *baton,
                                  apr_pool_t *pool)
{
    apr_status_t status;

    do {
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(request, SERF_READ_ALL_AVAIL, &data, &len);
    } while (status == APR_SUCCESS);

    return status;
}

static apr_status_t response_setup(serf_bucket_t **resp_bkt,
                                   serf_incoming_request_t *req,
                                   void *setup_baton,
                                   serf_bucket_alloc_t *allocator,
                                   apr_pool_t *pool)
{
#define CRLF "\r\n"
    *resp_bkt = SERF_BUCKET_SIMPLE_STRING("HTTP/1.1 200 Discarded" CRLF
                                          "Content-Length: 25" CRLF
                                          "Content-Type: text/plain" CRLF
                                          CRLF
                                          "Successfully Discarded." CRLF,
                                          allocator);
    return APR_SUCCESS;
}

static apr_status_t wrap_request(serf_bucket_t **req_bkt,
                                 serf_bucket_t *stream,
                                 serf_incoming_request_t *req,
                                 void *request_baton,
                                 serf_incoming_request_handler_t *handler,
                                 void **handler_baton,
                                 serf_incoming_response_setup_t *setup,
                                 void **setup_baton,
                                 apr_pool_t *pool)
{
    ic_setup_baton_t *isb = request_baton;
    apr_status_t status;

    status = isb->request(isb->ctx, req, isb->request_baton, pool);

    if (!status) {
        *req_bkt = serf_bucket_incoming_request_create(stream,
                                                       stream->allocator);

        *handler = drain_handler;
        *handler_baton = isb;

        *setup = response_setup;
        *setup_baton = isb;
    }

    return status;
}

apr_status_t serf_incoming_create(
    serf_incoming_t **client,
    serf_context_t *ctx,
    apr_socket_t *insock,
    void *request_baton,
    serf_incoming_request_cb_t request,
    apr_pool_t *pool)
{
    ic_setup_baton_t *isb;
    apr_status_t status;

    isb = apr_pcalloc(pool, sizeof(*isb));

    isb->ctx = ctx;
    isb->request = request;
    isb->request_baton = request_baton;

    status = serf_incoming_create2(client, ctx, insock,
                                   dummy_setup, isb,
                                   dummy_closed, isb,
                                   wrap_request, isb, pool);

    if (!status)
        isb->incoming = *client;

    return status;
}
