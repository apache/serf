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
#include "serf_bucket_util.h"


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

    serf_request_setup_t setup;
    void *setup_baton;

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

    /* one of our connections has a dirty pollset state. */
    int dirty_pollset;

    /* the list of active connections */
    apr_array_header_t *conns;
#define GET_CONN(ctx, i) (((serf_connection_t **)(ctx)->conns->elts)[i])
};

struct serf_connection_t {
    serf_context_t *ctx;

    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    apr_sockaddr_t *address;

    apr_socket_t *skt;
    apr_pool_t *skt_pool;

    /* the last reqevents we gave to pollset_add */
    apr_int16_t reqevents;

    /* the events we've seen for this connection in our returned pollset */
    apr_int16_t seen_in_pollset;

    /* are we a dirty connection that needs its poll status updated? */
    int dirty_conn;

    /* number of completed requests we've sent */
    unsigned int completed_requests;

    /* number of completed responses we've got */
    unsigned int completed_responses;

    /* keepalive */
    unsigned int probable_keepalive_limit;

    /* someone has told us that the connection is closing
     * so, let's start a new socket.
     */
    int closing;

    /* A bucket wrapped around our socket (for reading responses). */
    serf_bucket_t *stream;

    /* The list of active requests. */
    serf_request_t *requests;
    serf_request_t *requests_tail;

    /* The list of requests we're holding on to because we're going to
     * reset the connection soon.
     */
    serf_request_t *hold_requests;
    serf_request_t *hold_requests_tail;

    struct iovec vec[IOV_MAX];
    int vec_len;

    serf_connection_setup_t setup;
    void *setup_baton;
    serf_connection_closed_t closed;
    void *closed_baton;
};

/* cleanup for sockets */
static apr_status_t clean_skt(void *data)
{
    serf_connection_t *conn = data;
    apr_status_t status = APR_SUCCESS;

    if (conn->skt) {
        status = apr_socket_close(conn->skt);
        conn->skt = NULL;
    }

    return status;
}

static apr_status_t clean_resp(void *data)
{
    serf_request_t *req = data;

    /* This pool just got cleared/destroyed. Don't try to destroy the pool
     * (again) when the request is canceled.
     */
    req->respool = NULL;

    return APR_SUCCESS;
}

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
    desc.reqevents = conn->reqevents;

    status = apr_pollset_remove(ctx->pollset, &desc);
    if (status && !APR_STATUS_IS_NOTFOUND(status))
        return status;

    /* Now put it back in with the correct read/write values. */
    desc.reqevents = APR_POLLHUP | APR_POLLERR;
    if (conn->requests) {
        /* If there are any outstanding events, then we want to read. */
        /* ### not true. we only want to read IF we have sent some data */
        desc.reqevents |= APR_POLLIN;

        /* If the connection has unwritten data, or there are any requests
         * that still have buckets to write out, then we want to write.
         */
        if (conn->vec_len)
            desc.reqevents |= APR_POLLOUT;
        else {
            serf_request_t *request = conn->requests;

            if (conn->probable_keepalive_limit &&
                conn->completed_requests > conn->probable_keepalive_limit) {
                /* we wouldn't try to write any way right now. */
            }
            else {
                while (request != NULL && request->req_bkt == NULL &&
                       request->setup == NULL)
                    request = request->next;
                if (request != NULL)
                    desc.reqevents |= APR_POLLOUT;
            }
        }
    }

    desc.client_data = conn;

    /* save our reqevents, so we can pass it in to remove later. */
    conn->reqevents = desc.reqevents;

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
        serf_connection_t *conn = GET_CONN(ctx, i);
        apr_status_t status;
        apr_socket_t *skt;

        conn->seen_in_pollset = 0;

        if (conn->skt != NULL) {
#ifdef SERF_DEBUG_BUCKET_USE
            check_buckets_drained(conn);
#endif
            continue;
        }

        apr_pool_clear(conn->skt_pool);
        apr_pool_cleanup_register(conn->skt_pool, conn, clean_skt, clean_skt);

        if ((status = apr_socket_create(&skt, APR_INET, SOCK_STREAM,
                                        APR_PROTO_TCP,
                                        conn->skt_pool)) != APR_SUCCESS)
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

        /* Flag our pollset as dirty now that we have a new socket. */
        conn->dirty_conn = 1;
        ctx->dirty_pollset = 1;
    }

    return APR_SUCCESS;
}

static apr_status_t no_more_writes(serf_connection_t *conn,
                                   serf_request_t *request)
{
  /* Note that we should hold new requests until we open our new socket. */
  conn->closing = 1;

  /* We can take the *next* request in our list and assume it hasn't
   * been written yet and 'save' it for the new socket.
   */
  conn->hold_requests = request->next;
  conn->hold_requests_tail = conn->requests_tail;
  request->next = NULL;
  conn->requests_tail = request;

  /* Clear our iovec. */
  conn->vec_len = 0;

  /* Update the pollset to know we don't want to write on this socket any
   * more.
   */
  conn->dirty_conn = 1;
  conn->ctx->dirty_pollset = 1;
  return APR_SUCCESS;
}

static apr_status_t socket_writev(serf_connection_t *conn)
{
    apr_size_t written;
    apr_status_t status;

    status = apr_socket_sendv(conn->skt, conn->vec,
                              conn->vec_len, &written);

    /* did we write everything? */
    if (written) {
        apr_size_t len = 0;
        int i;

        for (i = 0; i < conn->vec_len; i++) {
            len += conn->vec[i].iov_len;
            if (written < len) {
                if (i) {
                    memmove(conn->vec, &conn->vec[i],
                            sizeof(struct iovec) * (conn->vec_len - i));
                    conn->vec_len -= i;
                }
                conn->vec[0].iov_base += conn->vec[0].iov_len - (len - written);
                conn->vec[0].iov_len = len - written;
                break;
            }
        }
        if (len == written) {
            conn->vec_len = 0;
        }
    }

    return status;
}

/* write data out to the connection */
static apr_status_t write_to_connection(serf_connection_t *conn)
{
    serf_request_t *request = conn->requests;

    if (conn->probable_keepalive_limit &&
        conn->completed_requests > conn->probable_keepalive_limit) {
        /* backoff for now. */
        return APR_SUCCESS;
    }

    /* Find a request that has data which needs to be delivered. */
    while (request != NULL &&
           request->req_bkt == NULL && request->setup == NULL)
        request = request->next;

    /* assert: request != NULL || conn->vec_len */

    /* Keep reading and sending until we run out of stuff to read, or
     * writing would block.
     */
    while (1) {
        int stop_reading = 0;
        apr_status_t status;
        apr_status_t read_status;
        int i;

        /* If we have unwritten data, then write what we can. */
        while (conn->vec_len) {
            status = socket_writev(conn);

            /* If the write would have blocked, then we're done. Don't try
             * to write anything else to the socket.
             */
            if (APR_STATUS_IS_EAGAIN(status))
                return APR_SUCCESS;
            if (APR_STATUS_IS_EPIPE(status))
                return no_more_writes(conn, request);
            if (status)
                return status;
        }
        /* ### can we have a short write, yet no EAGAIN? a short write
           ### would imply unwritten_len > 0 ... */
        /* assert: unwritten_len == 0. */

        /* We may need to move forward to a request which has something
         * to write.
         */
        while (request != NULL &&
               request->req_bkt == NULL && request->setup == NULL)
            request = request->next;

        if (request == NULL) {
            /* No more requests (with data) are registered with the
             * connection. Let's update the pollset so that we don't
             * try to write to this socket again.
             */
            conn->dirty_conn = 1;
            conn->ctx->dirty_pollset = 1;
            return APR_SUCCESS;
        }

        /* If the connection does not have an associated bucket, then
         * call the setup callback to get one.
         */
        if (conn->stream == NULL) {
            conn->stream = (*conn->setup)(conn->skt,
                                          conn->setup_baton,
                                          conn->pool);
        }

        if (request->req_bkt == NULL) {
            /* Now that we are about to serve the request, allocate a pool. */
            apr_pool_create(&request->respool, conn->pool);
            request->allocator = serf_bucket_allocator_create(request->respool,
                                                              NULL, NULL);
            apr_pool_cleanup_register(request->respool, request,
                                      clean_resp, clean_resp);

            /* Fill in the rest of the values for the request. */
            read_status = request->setup(request, request->setup_baton,
                                         &request->req_bkt,
                                         &request->acceptor,
                                         &request->acceptor_baton,
                                         &request->handler,
                                         &request->handler_baton,
                                         request->respool);
            request->setup = NULL;
        }

        /* ### optimize at some point by using read_for_sendfile */
        read_status = serf_bucket_read_iovec(request->req_bkt,
                                             SERF_READ_ALL_AVAIL,
                                             IOV_MAX,
                                             conn->vec,
                                             &conn->vec_len);

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
        if (conn->vec_len > 0) {
            status = socket_writev(conn);

            /* If we can't write any more, or an error occurred, then
             * we're done here.
             */
            if (APR_STATUS_IS_EAGAIN(status))
                return APR_SUCCESS;
            if (APR_STATUS_IS_EPIPE(status))
                return no_more_writes(conn, request);
            if (APR_STATUS_IS_ECONNRESET(status)) {
                return no_more_writes(conn, request);
            }
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

            conn->completed_requests++;

            if (conn->probable_keepalive_limit &&
                conn->completed_requests > conn->probable_keepalive_limit) {
                /* backoff for now. */
                stop_reading = 1;
            }
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

        /* If the connection does not have an associated bucket, then
         * call the setup callback to get one.
         */
        if (conn->stream == NULL) {
            conn->stream = (*conn->setup)(conn->skt,
                                          conn->setup_baton,
                                          tmppool);
            apr_pool_clear(tmppool);
        }

        /* If the request doesn't have a response bucket, then call the
         * acceptor to get one created.
         */
        if (request->resp_bkt == NULL) {
            request->resp_bkt = (*request->acceptor)(request, conn->stream,
                                                     request->acceptor_baton,
                                                     tmppool);
            apr_pool_clear(tmppool);
        }

        status = (*request->handler)(request,
                                     request->resp_bkt,
                                     request->handler_baton,
                                     tmppool);

        /* Some systems will not generate a HUP poll event so we have to
         * handle the ECONNRESET issue here.
         */
        if (APR_STATUS_IS_ECONNRESET(status)) {
            serf_connection_reset(conn);
            status = APR_SUCCESS;
            goto error;
        }

        /* If our response handler says it can't do anything more, we now
         * treat that as a success.
         */
        if (APR_STATUS_IS_EAGAIN(status)) {
            status = APR_SUCCESS;
            goto error;
        }

        /* If we received APR_SUCCESS, run this loop again. */
        if (!status) {
            continue;
        }

        if (!APR_STATUS_IS_EOF(status) && status != SERF_ERROR_CLOSING) {
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
        if (request->req_bkt) {
            serf_bucket_destroy(request->req_bkt);
        }

        serf_debug__bucket_alloc_check(request->allocator);
        apr_pool_destroy(request->respool);
        serf_bucket_mem_free(conn->allocator, request);

        request = conn->requests;

        /* If we're truly empty, update our tail. */
        if (request == NULL) {
            conn->requests_tail = NULL;
        }

        /* This means that we're being advised that the connection is done. */
        if (status == SERF_ERROR_CLOSING) {
            serf_connection_reset(conn);
            status = APR_SUCCESS;
            goto error;
        }

        conn->completed_responses++;

        /* The server is suddenly deciding to serve more responses than we've
         * seen before.
         *
         * Let our requests go.
         */
        if (conn->probable_keepalive_limit &&
            conn->completed_responses > conn->probable_keepalive_limit) {
            conn->probable_keepalive_limit = 0;
        }

        /* If we just ran out of requests or have unwritten requests, then
         * update the pollset. We don't want to read from this socket any
         * more. We are definitely done with this loop, too.
         */
        if (request == NULL || request->setup) {
            conn->dirty_conn = 1;
            conn->ctx->dirty_pollset = 1;
            status = APR_SUCCESS;
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

    if ((events & APR_POLLHUP) != 0) {
        return APR_ECONNRESET;
    }
    if ((events & APR_POLLERR) != 0) {
        /* We might be talking to a buggy HTTP server that doesn't
         * do lingering-close.  (httpd < 2.1.8 does this.)
         *
         * See:
         *
         * http://issues.apache.org/bugzilla/show_bug.cgi?id=35292
         */
        if (!conn->probable_keepalive_limit) {
            return serf_connection_reset(conn);
        }
        abort();
    }
    if ((events & APR_POLLOUT) != 0) {
        if ((status = write_to_connection(conn)) != APR_SUCCESS)
            return status;
    }
    if ((events & APR_POLLIN) != 0) {
        if ((status = read_from_connection(conn)) != APR_SUCCESS)
            return status;
    }
    return APR_SUCCESS;
}

/* Check for dirty connections and update their pollsets accordingly. */
static apr_status_t check_dirty_pollsets(serf_context_t *ctx)
{
    int i;

    /* if we're not dirty, return now. */
    if (!ctx->dirty_pollset) {
        return APR_SUCCESS;
    }

    for (i = ctx->conns->nelts; i--; ) {
        serf_connection_t *conn = GET_CONN(ctx, i);
        apr_status_t status;

        /* if this connection isn't dirty, skip it. */
        if (!conn->dirty_conn) {
            continue;
        }

        /* reset this connection's flag before we update. */
        conn->dirty_conn = 0;

        if ((status = update_pollset(conn)) != APR_SUCCESS)
            return status;
    }

    /* reset our context flag now */
    ctx->dirty_pollset = 0;

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

    if ((status = check_dirty_pollsets(ctx)) != APR_SUCCESS)
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

        /* apr_pollset_poll() can return a conn multiple times... */
        if ((conn->seen_in_pollset & desc->rtnevents) != 0) {
            continue;
        }
        conn->seen_in_pollset |= desc->rtnevents;

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
    desc.reqevents = conn->reqevents;

    return apr_pollset_remove(ctx->pollset, &desc);
}

static apr_status_t cancel_request(serf_request_t *request,
                                   serf_request_t **list,
                                   int notify_request)
{
    serf_connection_t *conn = request->conn;
    apr_status_t status;

    /* If we haven't run setup, then we won't have a handler to call. */
    if (request->handler && notify_request) {
        /* We actually don't care what the handler returns.
         * We have bigger matters at hand.
         */
        (*request->handler)(request, NULL, request->handler_baton,
                            request->respool);
    }

    if (*list == request) {
        *list = request->next;
    }
    else {
        serf_request_t *scan = *list;

        while (scan->next && scan->next != request)
            scan = scan->next;

        if (scan->next) {
            scan->next = scan->next->next;
        }
    }

    if (request->resp_bkt) {
        serf_debug__closed_conn(request->resp_bkt->allocator);
        serf_bucket_destroy(request->resp_bkt);
    }
    if (request->req_bkt) {
        serf_debug__closed_conn(request->req_bkt->allocator);
        serf_bucket_destroy(request->req_bkt);
    }

    if (request->respool) {
        apr_pool_destroy(request->respool);
    }

    serf_bucket_mem_free(request->conn->allocator, request);

    return APR_SUCCESS;
}

SERF_DECLARE(serf_connection_t *) serf_connection_create(
    serf_context_t *ctx,
    apr_sockaddr_t *address,
    serf_connection_setup_t setup,
    void *setup_baton,
    serf_connection_closed_t closed,
    void *closed_baton,
    apr_pool_t *pool)
{
    serf_connection_t *conn = apr_pcalloc(pool, sizeof(*conn));

    conn->ctx = ctx;
    conn->address = address;
    conn->setup = setup;
    conn->setup_baton = setup_baton;
    conn->closed = closed;
    conn->closed_baton = closed_baton;
    conn->pool = pool;
    conn->allocator = serf_bucket_allocator_create(pool, NULL, NULL);

    /* Create a subpool for our connection. */
    apr_pool_create(&conn->skt_pool, conn->pool);

    /* ### register a cleanup */

    /* Add the connection to the context. */
    *(serf_connection_t **)apr_array_push(ctx->conns) = conn;

    return conn;
}

void link_requests(serf_request_t **list, serf_request_t **tail,
                   serf_request_t *request)
{
    if (*list == NULL) {
        *list = request;
        *tail = request;
    }
    else {
        (*tail)->next = request;
        *tail = request;
    }
}

SERF_DECLARE(apr_status_t) serf_connection_reset(
    serf_connection_t *conn)
{
    int i;
    serf_context_t *ctx = conn->ctx;
    apr_status_t status;
    serf_request_t *old_reqs, *held_reqs, *held_reqs_tail;

    conn->probable_keepalive_limit = conn->completed_responses;
    conn->completed_requests = 0;
    conn->completed_responses = 0;

    old_reqs = conn->requests;
    held_reqs = conn->hold_requests;
    held_reqs_tail = conn->hold_requests_tail;
 
    if (conn->closing) {
        conn->hold_requests = NULL;
        conn->hold_requests_tail = NULL;
        conn->closing = 0;
    }

    conn->requests = NULL;
    conn->requests_tail = NULL;

    while (old_reqs) {
        /* If we haven't started to write the connection, bring it over
         * unchanged to our new socket.  Otherwise, call the cancel function.
         */
        if (old_reqs->setup) {
            serf_request_t *req = old_reqs;
            old_reqs = old_reqs->next;
            req->next = NULL;
            link_requests(&conn->requests, &conn->requests_tail, req);
        }
        else {
            cancel_request(old_reqs, &old_reqs, 1);
        }
    }

    if (conn->requests_tail) {
        conn->requests_tail->next = held_reqs;
    }
    else {
        conn->requests = held_reqs;
    }
    if (held_reqs_tail) {
        conn->requests_tail = held_reqs_tail;
    }

    if (conn->skt != NULL) {
        remove_connection(ctx, conn);
        status = apr_socket_close(conn->skt);
        if (conn->closed != NULL) {
            (*conn->closed)(conn, conn->closed_baton, status,
                            conn->pool);
        }
        conn->skt = NULL;
    }

    if (conn->stream != NULL) {
        serf_bucket_destroy(conn->stream);
        conn->stream = NULL;
    }

    /* Don't try to resume any writes */
    conn->vec_len = 0;

    conn->dirty_conn = 1;
    conn->ctx->dirty_pollset = 1;

    /* Let our context know that we've 'reset' the socket already. */
    conn->seen_in_pollset |= APR_POLLHUP;

    /* Found the connection. Closed it. All done. */
    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_connection_close(
    serf_connection_t *conn)
{
    int i;
    serf_context_t *ctx = conn->ctx;
    apr_status_t status;

    for (i = ctx->conns->nelts; i--; ) {
        serf_connection_t *conn_seq = GET_CONN(ctx, i);

        if (conn_seq == conn) {
            while (conn->requests) {
                serf_request_cancel(conn->requests);
            }
            if (conn->skt != NULL) {
                remove_connection(ctx, conn);
                status = apr_socket_close(conn->skt);
                if (conn->closed != NULL) {
                    (*conn->closed)(conn, conn->closed_baton, status,
                                    conn->pool);
                }
            }

            /* No more need for the wrapper bucket. */
            if (conn->stream != NULL) {
                serf_bucket_destroy(conn->stream);
            }

            /* Remove the connection from the context. We don't want to
             * deal with it any more.
             */
            if (i < ctx->conns->nelts - 1) {
                /* move later connections over this one. */
                memmove(
                    &GET_CONN(ctx, i),
                    &GET_CONN(ctx, i + 1),
                    (ctx->conns->nelts - i - 1) * sizeof(serf_connection_t *));
            }
            --ctx->conns->nelts;

            /* Found the connection. Closed it. All done. */
            return APR_SUCCESS;
        }
    }

    /* We didn't find the specified connection. */
    /* ### doc talks about this w.r.t poll structures. use something else? */
    return APR_NOTFOUND;
}

SERF_DECLARE(serf_request_t *) serf_connection_request_create(
    serf_connection_t *conn,
    serf_request_setup_t setup,
    void *setup_baton)
{
    apr_pool_t *pool;
    serf_request_t *request;

    request = serf_bucket_mem_alloc(conn->allocator, sizeof(*request));
    request->conn = conn;
    request->setup = setup;
    request->setup_baton = setup_baton;
    request->handler = NULL;
    request->req_bkt = NULL;
    request->resp_bkt = NULL;
    request->next = NULL;

    /* Link the request to the end of the request chain. */
    if (conn->closing) {
        link_requests(&conn->hold_requests, &conn->hold_requests_tail, request);
    }
    else {
        link_requests(&conn->requests, &conn->requests_tail, request);

        /* Ensure our pollset becomes writable in context run */
        conn->ctx->dirty_pollset = 1;
        conn->dirty_conn = 1;
    }

    return request;
}


SERF_DECLARE(apr_status_t) serf_request_cancel(serf_request_t *request)
{
    return cancel_request(request, &request->conn->requests, 0);
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

SERF_DECLARE(void) serf_request_set_handler(
    serf_request_t *request,
    const serf_response_handler_t handler,
    const void **handler_baton)
{
    request->handler = handler;
    request->handler_baton = handler_baton;
}
