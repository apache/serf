/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003 The Apache Software Foundation.  All rights
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

#include <apr_pools.h>

#include "serf.h"


/* ### what the hell? why does the APR interface have a "size" ??
   ### the implication is that, if we bust this limit, we'd need to
   ### stop, rebuild a pollset, and repopulate it. what suckage.  */
#define MAX_CONN 16

struct serf_context_t {
    /* the pool used for self and for other allocations */
    apr_pool_t *pool;

    /* the set of connections to poll */
    apr_pollset_t *pollset;

    /* the list of active connections */
    apr_array_header_t *conns;
};


static apr_status_t serf_connection_process(serf_connection_t *conn,
                                            apr_int16_t events)
{
    return APR_SUCCESS;
}



SERF_DECLARE(serf_context_t *) serf_context_create(apr_pool_t *pool)
{
    serf_context_t *ctx = apr_pcalloc(pool, sizeof(*ctx));

    ctx->pool = pool;

    /* build the pollset with a (default) number of connections */
    (void) apr_pollset_create(&ctx->pollset, MAX_CONN, pool, 0);

    /* default to a single connection since that is the typical case */
    ctx->conns = apr_array_make(pool, 1, sizeof(serf_connection_t *));

    return ctx;
}

SERF_DECLARE(apr_status_t) serf_context_run(serf_context_t *ctx,
                                            apr_short_interval_time_t duration,
                                            apr_pool_t *pool)
{
    apr_status_t status;
    apr_int32_t num;
    const apr_pollfd_t *desc;

    status = apr_pollset_poll(ctx->pollset, duration, &num, &desc);
    if (status) {
        /* ### do we still need to dispatch stuff here?
           ### look at the potential return codes. map to our defined
           ### return values? ...
        */
        return status;
    }

    while (num--) {
        serf_connection_t *conn = desc->client_data;

        status = serf_connection_process(conn, desc++->rtnevents);
        if (status) {
            /* ### what else to do? */
            return status;
        }
    }

    return APR_SUCCESS;
}


static apr_status_t serf_context_add_connection(serf_context_t *ctx,
                                                serf_connection_t *conn)
{
    apr_pollfd_t desc = { 0 };

    desc.desc_type = APR_POLL_SOCKET;
    desc.reqevents = APR_POLLIN | APR_POLLOUT | APR_POLLERR | APR_POLLHUP;
    desc.desc.s = conn->skt;
    desc.client_data = conn;

    return apr_pollset_add(ctx->pollset, &desc);
}

static apr_status_t serf_context_remove_connection(serf_context_t *ctx,
                                                   serf_connection_t *conn)
{
    apr_pollfd_t desc = { 0 };

    desc.desc_type = APR_POLL_SOCKET;
    desc.desc.s = conn->skt;

    return apr_pollset_remove(ctx->pollset, &desc);
}

SERF_DECLARE(serf_connection_t *) serf_connection_create(
    serf_context_t *ctx,
    apr_sockaddr_t *address,
    serf_response_acceptor_t acceptor,
    void *acceptor_baton,
    serf_connection_closed_t closed,
    void *closed_baton,
    apr_pool_t *pool)
{
    serf_connection_t *conn = apr_pcalloc(pool, sizeof(*conn));

    conn->ctx = ctx;
    conn->pool = pool;
    conn->acceptor = acceptor;
    conn->acceptor_baton = acceptor_baton;
    conn->closed = closed;
    conn->closed_baton = closed_baton;

    return conn;
}


SERF_DECLARE(apr_status_t) serf_connection_request_create(
    serf_connection_t *conn,
    serf_bucket_t *request,
    serf_response_handler_t handler,
    void *handler_baton,
    serf_bucket_alloc_t *allocator,
    apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}


SERF_DECLARE(apr_status_t) serf_connection_request_cancel(
    serf_connection_t *conn,
    serf_bucket_t *request)
{
    return APR_ENOTIMPL;
}
