/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#include "serf.h"

SERF_DECLARE(serf_request_t *) serf_create_request(apr_pool_t *pool)
{
    serf_request_t *request;

    request = apr_pcalloc(pool, sizeof(serf_request_t));
    request->bucket_allocator = apr_bucket_alloc_create(pool);
    request->entity = apr_brigade_create(pool,
                                         request->bucket_allocator);

    request->request_filters = serf_create_filter_list(pool);
    request->response_filters = serf_create_filter_list(pool);
    request->pool = pool;

    return request;
}

SERF_DECLARE(apr_status_t) serf_write_request(serf_request_t *request,
                                              serf_connection_t *connection)
{
    apr_status_t status;
    serf_request_t **req_ptr;

    if (request->source) {
        status = request->source(request->entity, request, request->pool);
        if (status) {
            return status;
        }
    }

    status = serf_execute_filters(request->request_filters, request->entity,
                                  request->pool);
    if (status) {
        return status;
    }

    status = serf_execute_filters(connection->request_filters,
                                  request->entity, connection->pool);
    if (status) {
        return status;
    }

    req_ptr = apr_array_push(connection->requests);
    *req_ptr = request;

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_read_response(serf_response_t **response,
                                              serf_connection_t *connection,
                                              apr_pool_t *pool)
{
    serf_response_t *new_resp;
    serf_request_t *request, **request_ptr;
    apr_status_t status;

    /* FIXME: Until we have FIFO instead of LIFO, this is busted. */
    request_ptr = apr_array_pop(connection->requests);

    request = *request_ptr;

    new_resp = apr_pcalloc(pool, sizeof(serf_response_t));
    new_resp->bucket_allocator = apr_bucket_alloc_create(pool);
    new_resp->entity = apr_brigade_create(pool, new_resp->bucket_allocator);
    new_resp->request = request;

    status = serf_execute_filters(connection->response_filters,
                                  new_resp->entity, pool);
    if (status) {
        return status;
    }

    status = serf_execute_filters(request->response_filters,
                                  new_resp->entity, pool);
    if (status) {
        return status;
    }

    if (request->handler) {
        status = request->handler(new_resp, pool);
        if (status) {
            return status;
        }
    }
    *response = new_resp;
    return APR_SUCCESS;
}
