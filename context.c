/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>  /* ### for abort() */

#include <apr_pools.h>
#include <apr_poll.h>

#include "serf.h"


/* ### what the hell? why does the APR interface have a "size" ??
   ### the implication is that, if we bust this limit, we'd need to
   ### stop, rebuild a pollset, and repopulate it. what suckage.  */
#define MAX_CONN 16

/* Holds all the information corresponding to a request/response pair. */
struct serf_request_t {
    serf_connection_t *conn;

    apr_pool_t *respool;
    serf_bucket_alloc_t *allocator;

    /* The bucket corresponding to the request. Will be NULL once the
     * bucket has been emptied (for delivery into the socket).
     */
    serf_bucket_t *req_bkt;

    serf_response_acceptor_t acceptor;
    void *acceptor_baton;

    serf_response_handler_t handler;
    void *handler_baton;

    serf_bucket_t *resp_bkt;

    struct serf_request_t *next;
};

struct serf_context_t {
    /* the pool used for self and for other allocations */
    apr_pool_t *pool;

    /* the set of connections to poll */
    apr_pollset_t *pollset;

    /* the list of active connections */
    apr_array_header_t *conns;
};

struct serf_connection_t {
    serf_context_t *ctx;

    apr_pool_t *pool;
    apr_sockaddr_t *address;

    apr_socket_t *skt;

    /* The list of active requests. */
    serf_request_t *requests;

    const char *unwritten_ptr;
    apr_size_t unwritten_len;

    serf_connection_closed_t closed;
    void *closed_baton;
};


/* Update the pollset for this connection. We tweak the pollset based on
 * whether we want to read and/or write, given conditions within the
 * connection. If the connection is not (yet) in the pollset, then it
 * will be added.
 */
static apr_status_t update_pollset(serf_connection_t *conn)
{
    serf_context_t *ctx = conn->ctx;
    apr_status_t status;
    apr_pollfd_t desc = { 0 };

    /* Remove the socket from the poll set. */
    desc.desc_type = APR_POLL_SOCKET;
    desc.desc.s = conn->skt;
    status = apr_pollset_remove(ctx->pollset, &desc);
    if (status && !APR_STATUS_IS_NOTFOUND(status))
        return status;

    /* Now put it back in with the correct read/write values. */
    desc.reqevents = 0;
    if (conn->requests) {
        /* If there are any outstanding events, then we want to read. */
        /* ### not true. we only want to read IF we have sent some data */
        desc.reqevents |= APR_POLLIN;

        /* If the connection has unwritten data, or there are any requests
         * that still have buckets to write out, then we want to write.
         */
        if (conn->unwritten_len)
            desc.reqevents |= APR_POLLOUT;
        else {
            serf_request_t *request = conn->requests;

            while (request != NULL && request->req_bkt == NULL)
                request = request->next;
            if (request != NULL)
                desc.reqevents |= APR_POLLOUT;
        }
    }

    desc.client_data = conn;

    /* Note: even if we don't want to read/write this socket, we still
     * want to poll it for hangups and errors.
     */
    return apr_pollset_add(ctx->pollset, &desc);
}

#ifdef SERF_DEBUG_BUCKET_USE

/* Make sure all response buckets were drained. */
static void check_buckets_drained(serf_connection_t *conn)
{
    serf_request_t *request = conn->requests;

    for ( ; request ; request = request->next ) {
        if (request->resp_bkt != NULL) {
            /* ### crap. can't do this. this allocator may have un-drained
             * ### REQUEST buckets.
             */
            /* serf_debug__entered_loop(request->resp_bkt->allocator); */
            /* ### for now, pretend we closed the conn (resets the tracking) */
            serf_debug__closed_conn(request->resp_bkt->allocator);
        }
    }
}

#endif

/* Create and connect sockets for any connections which don't have them
 * yet. This is the core of our lazy-connect behavior.
 */
static apr_status_t open_connections(serf_context_t *ctx)
{
    int i;

    for (i = ctx->conns->nelts; i--; ) {
        serf_connection_t *conn = ((serf_connection_t **)ctx->conns->elts)[i];
        apr_status_t status;
        apr_socket_t *skt;

        if (conn->skt != NULL) {
#ifdef SERF_DEBUG_BUCKET_USE
            check_buckets_drained(conn);
#endif
            continue;
        }

        if ((status = apr_socket_create(&skt, APR_INET, SOCK_STREAM,
                                        APR_PROTO_TCP,
                                        conn->pool)) != APR_SUCCESS)
            return status;

        /* Set the socket to be non-blocking */
        if ((status = apr_socket_timeout_set(skt, 0)) != APR_SUCCESS)
            return status;

        /* Disable Nagle's algorithm */
        if ((status = apr_socket_opt_set(skt,
                                         APR_TCP_NODELAY, 0)) != APR_SUCCESS)
            return status;

        /* Configured. Store it into the connection now. */
        conn->skt = skt;

        /* Now that the socket is set up, let's connect it. This should
         * return immediately.
         */
        if ((status = apr_socket_connect(skt,
                                         conn->address)) != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINPROGRESS(status))
                return status;
        }

        /* Add the new socket to the pollset. */
        if ((status = update_pollset(conn)) != APR_SUCCESS)
            return status;
    }

    return APR_SUCCESS;
}

/* write data out to the connection */
static apr_status_t write_to_connection(serf_connection_t *conn)
{
    serf_request_t *request = conn->requests;

    /* Find a request that has data which needs to be delivered. */
    while (request != NULL && request->req_bkt == NULL)
        request = request->next;

    /* assert: request != NULL || conn->unwritten_len */

    /* Keep reading and sending until we run out of stuff to read, or
     * writing would block.
     */
    while (1) {
        int stop_reading = 0;
        apr_status_t status;
        apr_status_t read_status;
        const char *data;
        apr_size_t len;

        /* If we have unwritten data, then write what we can. */
        if ((len = conn->unwritten_len) != 0) {
            status = apr_socket_send(conn->skt, conn->unwritten_ptr, &len);
            conn->unwritten_len -= len;

            /* If the write would have blocked, then we're done. Don't try
             * to write anything else to the socket.
             */
            if (APR_STATUS_IS_EAGAIN(status))
                return APR_SUCCESS;
            if (status)
                return status;
        }
        /* ### can we have a short write, yet no EAGAIN? a short write
           ### would imply unwritten_len > 0 ... */
        /* assert: unwritten_len == 0. */

        /* We may need to move forward to a request which has something
         * to write.
         */
        while (request != NULL && request->req_bkt == NULL)
            request = request->next;

        if (request == NULL) {
            /* No more requests (with data) are registered with the
             * connection. Let's update the pollset so that we don't
             * try to write to this socket again.
             */
            return update_pollset(conn);
        }

        /* ### optimize at some point by using read_for_sendfile */

        read_status = serf_bucket_read(request->req_bkt, SERF_READ_ALL_AVAIL,
                                       &data, &len);
        if (APR_STATUS_IS_EAGAIN(read_status)) {
            /* We read some stuff, but should not try to read again. */
            stop_reading = 1;

            /* ### we should avoid looking for writability for a while so
               ### that (hopefully) something will appear in the bucket so
               ### we can actually write something. otherwise, we could
               ### end up in a CPU spin: socket wants something, but we
               ### don't have anything (and keep returning EAGAIN)
            */
        }
        else if (read_status && !APR_STATUS_IS_EOF(read_status)) {
            /* Something bad happened. Propagate any errors. */
            return read_status;
        }

        /* If we got some data, then deliver it. */
        /* ### what to do if we got no data?? is that a problem? */
        if (len > 0) {
            apr_size_t written = len;

            status = apr_socket_send(conn->skt, data, &written);

            if (written < len) {
                /* We didn't write it all. Save it away for writing later. */
                conn->unwritten_ptr = data + written;
                conn->unwritten_len = len - written;
            }

            /* If we can't write any more, or an error occurred, then
             * we're done here.
             */
            if (APR_STATUS_IS_EAGAIN(status))
                return APR_SUCCESS;
            if (status)
                return status;
        }

        if (APR_STATUS_IS_EOF(read_status)) {
            /* If we hit the end of the request bucket, then clear it out to
             * signify that we're done sending the request. On the next
             * iteration through this loop, we'll see if there are other
             * requests that need to be sent ("pipelining").
             */
            /* ### woah. watch out for the unwritten stuff. gotta restructure
               ### this a bit more to avoid killing a bucket where the
               ### data is hanging out in the unwritten field. */
            serf_bucket_destroy(request->req_bkt);
            request->req_bkt = NULL;
        }

        if (stop_reading) {
            return APR_SUCCESS;
        }
    }
    /* NOTREACHED */
}

/* read data from the connection */
static apr_status_t read_from_connection(serf_connection_t *conn)
{
    apr_status_t status;
    apr_pool_t *tmppool;

    /* Whatever is coming in on the socket corresponds to the first request
     * on our chain.
     */
    serf_request_t *request = conn->requests;

    /* assert: request != NULL */

    if ((status = apr_pool_create(&tmppool, conn->pool)) != APR_SUCCESS)
        goto error;

    /* Invoke response handlers until we have no more work. */
    while (1) {
        apr_pool_clear(tmppool);

        /* If the request doesn't have a response bucket, then call the
         * acceptor to get one created.
         */
        if (request->resp_bkt == NULL) {
            request->resp_bkt = (*request->acceptor)(request, conn->skt,
                                                     request->acceptor_baton,
                                                     tmppool);
            apr_pool_clear(tmppool);
        }

        status = (*request->handler)(request->resp_bkt,
                                     request->handler_baton,
                                     tmppool);
        if (!APR_STATUS_IS_EOF(status)) {
            /* Whether success, or an error, there is no more to do unless
             * this request has been completed.
             */
            goto error;
        }

        /* The request has been fully-delivered, and the response has
         * been fully-read. Remove it from our queue and loop to read
         * another response.
         */
        conn->requests = request->next;

        /* The bucket is no longer needed, nor is the request's pool. */
        serf_bucket_destroy(request->resp_bkt);
        apr_pool_destroy(request->respool);

        request = conn->requests;

        /* If we just ran out of requests, then update the pollset. We
         * don't want to read from this socket any more. We are definitely
         * done with this loop, too.
         */
        if (request == NULL) {
            status = update_pollset(conn);
            goto error;
        }
    }

  error:
    apr_pool_destroy(tmppool);
    return status;
}

/* process all events on the connection */
static apr_status_t process_connection(serf_connection_t *conn,
                                       apr_int16_t events)
{
    apr_status_t status;

    if ((events & APR_POLLOUT) != 0) {
        if ((status = write_to_connection(conn)) != APR_SUCCESS)
            return status;
    }
    if ((events & APR_POLLIN) != 0) {
        if ((status = read_from_connection(conn)) != APR_SUCCESS)
            return status;
    }
    if ((events & APR_POLLHUP) != 0) {
        /* ### needs work */
        abort();
    }
    if ((events & APR_POLLERR) != 0) {
        /* ### needs work */
        puts("Hit APR_POLLERR: what to do?\n");
    }
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

    if ((status = open_connections(ctx)) != APR_SUCCESS)
        return status;

    if ((status = apr_pollset_poll(ctx->pollset, duration, &num,
                                   &desc)) != APR_SUCCESS) {
        /* ### do we still need to dispatch stuff here?
           ### look at the potential return codes. map to our defined
           ### return values? ...
        */
        return status;
    }

    while (num--) {
        serf_connection_t *conn = desc->client_data;

        if ((status = process_connection(conn,
                                         desc++->rtnevents)) != APR_SUCCESS) {
            /* ### what else to do? */
            return status;
        }
    }

    return APR_SUCCESS;
}


static apr_status_t remove_connection(serf_context_t *ctx,
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
    serf_connection_closed_t closed,
    void *closed_baton,
    apr_pool_t *pool)
{
    serf_connection_t *conn = apr_pcalloc(pool, sizeof(*conn));

    conn->ctx = ctx;
    conn->address = address;
    conn->closed = closed;
    conn->closed_baton = closed_baton;
    conn->pool = pool;

    /* ### register a cleanup */

    /* Add the connection to the context. */
    *(serf_connection_t **)apr_array_push(ctx->conns) = conn;

    return conn;
}


SERF_DECLARE(serf_request_t *) serf_connection_request_create(
    serf_connection_t *conn)
{
    apr_pool_t *pool;
    serf_request_t *request;

    /* ### return this status? */
    (void) apr_pool_create(&pool, conn->pool);

    request = apr_pcalloc(pool, sizeof(*request));
    request->conn = conn;
    request->respool = pool;
    request->allocator = serf_bucket_allocator_create(pool, NULL, NULL);

    return request;
}

SERF_DECLARE(void) serf_request_deliver(
    serf_request_t *request,
    serf_bucket_t *req_bkt,
    serf_response_acceptor_t acceptor,
    void *acceptor_baton,
    serf_response_handler_t handler,
    void *handler_baton)
{
    serf_connection_t *conn = request->conn;

    /* Fill in the rest of the values for the request. */
    request->req_bkt = req_bkt;
    request->acceptor = acceptor;
    request->acceptor_baton = acceptor_baton;
    request->handler = handler;
    request->handler_baton = handler_baton;

    /* Link the request to the end of the request chain. */
    if (conn->requests == NULL) {
        conn->requests = request;
    }
    else {
        serf_request_t *scan = conn->requests;

        while (scan->next != NULL)
            scan = scan->next;
        scan->next = request;
    }
}


SERF_DECLARE(apr_status_t) serf_request_cancel(serf_request_t *request)
{
    return APR_ENOTIMPL;
}

SERF_DECLARE(apr_pool_t *) serf_request_get_pool(const serf_request_t *request)
{
    return request->respool;
}

SERF_DECLARE(serf_bucket_alloc_t *) serf_request_get_alloc(
    const serf_request_t *request)
{
    return request->allocator;
}
