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

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

static apr_status_t client_connected(serf_incoming_t *client)
{
    /* serf_context_t *ctx = client->ctx; */
    apr_status_t status;
    serf_bucket_t *stream;
    serf_bucket_t *ostream;

    serf_pump__store_ipaddresses_in_config(&client->pump);

    serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, client->config,
              "socket for client 0x%p connected\n", client);

    /* ### Connection does auth setup here */

    serf_pump__prepare_setup(&client->pump);

    ostream = client->pump.ostream_tail;

    status = client->setup(client->skt,
                           &stream,
                           &ostream,
                           client->setup_baton, client->pool);

    if (status) {
        serf_pump__complete_setup(&client->pump, NULL, NULL);
        /* ### Cleanup! (serf__connection_pre_cleanup) */
        return status;
    }

    serf_pump__complete_setup(&client->pump, stream, ostream);

    if (client->framing_type == SERF_CONNECTION_FRAMING_TYPE_NONE) {
        client->proto_peek_bkt = serf_bucket_aggregate_create(
                                        client->allocator);

        serf_bucket_aggregate_append(
            client->proto_peek_bkt,
            serf_bucket_barrier_create(client->pump.stream,
                                       client->allocator));
    }

    return status;
}

/* Destroy an incoming request and its resources */
void serf__incoming_request_destroy(serf_incoming_request_t *request)
{
    serf_incoming_t *incoming = request->incoming;
    apr_pool_destroy(request->pool);

    serf_bucket_mem_free(incoming->allocator, request);
}

/* Called when the response is completely written and the write bucket
   is destroyed. Most likely the request is now 100% done */
static apr_status_t response_finished(void *baton,
                                      apr_uint64_t bytes_written)
{
    serf_incoming_request_t *request = baton;

    request->response_finished = true;

    if (request->request_read && request->response_finished) {
        serf__incoming_request_destroy(request);
    }
    return APR_SUCCESS;
}

static apr_status_t http1_enqueue_reponse(serf_incoming_request_t *request,
                                          void *enqueue_baton,
                                          serf_bucket_t *bucket)
{
    if (SERF_BUCKET_IS_OUTGOING_RESPONSE(bucket))
        serf_bucket_outgoing_response_prepare(bucket, SERF_HTTP_11, TRUE);

    serf_bucket_aggregate_append(request->incoming->pump.ostream_tail,
                                 serf__bucket_event_create(bucket,
                                                           request,
                                                           NULL,
                                                           NULL,
                                                           response_finished,
                                                           bucket->allocator));

    /* Want write event */
    serf_io__set_pollset_dirty(&request->incoming->io);

    return APR_SUCCESS;
}

apr_status_t serf_incoming_response_create(serf_incoming_request_t *request)
{
    apr_status_t status;
    serf_bucket_alloc_t *alloc;
    serf_bucket_t *bucket;

    if (request->response_written)
        return APR_SUCCESS;

    alloc = request->incoming->allocator;

    status = request->response_setup(&bucket, request,
                                     request->response_setup_baton,
                                     alloc, request->pool);

    if (status)
        return status;

    request->response_written = true;

    return request->enqueue_response(request, request->enqueue_baton, bucket);
}

static apr_status_t perform_peek_protocol(serf_incoming_t *client)
{
    const char h2prefix[] = "PRI * HTTP/2.0\r\n\r\n";
    const apr_size_t h2prefixlen = sizeof(h2prefix) - 1;
    const char *data;
    apr_size_t len;

    struct peek_data_t
    {
        char buffer[sizeof(h2prefix)];
        int read;
    } *peek_data = client->protocol_baton;

    apr_status_t status;

    if (!peek_data) {

        status = serf_bucket_peek(client->pump.stream, &data, &len);

        if (len > h2prefixlen)
          len = h2prefixlen;

        if (len && memcmp(data, h2prefix, len) != 0) {
            /* This is not HTTP/2 */
            serf_incoming_set_framing_type(client,
                                           SERF_CONNECTION_FRAMING_TYPE_HTTP1);

            /* Easy out */
            serf_bucket_destroy(client->proto_peek_bkt);
            client->proto_peek_bkt = NULL;

            return APR_SUCCESS;
        }
        else if (len == h2prefixlen) {
            /* We have HTTP/2 */
            serf_incoming_set_framing_type(client,
                                           SERF_CONNECTION_FRAMING_TYPE_HTTP2);

            serf_bucket_destroy(client->proto_peek_bkt);
            client->proto_peek_bkt = NULL;

            return APR_SUCCESS;
        }

        peek_data = serf_bucket_mem_calloc(client->allocator,
                                          sizeof(*peek_data));
        client->protocol_baton = peek_data;
    }

    do {
        status = serf_bucket_read(client->pump.stream,
                                  h2prefixlen - peek_data->read,
                                  &data, &len);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        memcpy(peek_data->buffer + peek_data->read, data, len);
        peek_data->read += len;

        if (len && memcmp(data, h2prefix, len)) {
            /* This is not HTTP/2 */
            serf_incoming_set_framing_type(client,
                                           SERF_CONNECTION_FRAMING_TYPE_HTTP1);

            /* Put data ahead of other data and do the usual thing */
            serf_bucket_aggregate_prepend(client->proto_peek_bkt,
                                          serf_bucket_simple_own_create(
                                                peek_data->buffer,
                                                peek_data->read,
                                                client->allocator));

            return APR_SUCCESS;
        }
        else if (len == h2prefixlen) {
            /* We have HTTP/2 */
            serf_incoming_set_framing_type(client,
                                           SERF_CONNECTION_FRAMING_TYPE_HTTP2);

            /* Put data ahead of other data and do the usual thing */
            serf_bucket_aggregate_prepend(client->proto_peek_bkt,
                                          serf_bucket_simple_own_create(
                                            peek_data->buffer,
                                            peek_data->read,
                                            client->allocator));

            return APR_SUCCESS;
        }
    } while (status == APR_SUCCESS);

    return status;
}

serf_incoming_request_t *serf__incoming_request_create(serf_incoming_t *client)
{
    serf_incoming_request_t *rq;

    rq = serf_bucket_mem_calloc(client->allocator, sizeof(*rq));

    apr_pool_create(&rq->pool, client->pool);
    rq->incoming = client;

    rq->enqueue_response = http1_enqueue_reponse;
    rq->enqueue_baton = rq;

    return rq;
}

static apr_status_t read_from_client(serf_incoming_t *client)
{
    apr_status_t status = APR_SUCCESS;
    serf_incoming_request_t *rq;

    if (client->proto_peek_bkt)
    {
        status = perform_peek_protocol(client);

        /* Did we switch protocol? */
        if (!status
            && client->framing_type != SERF_CONNECTION_FRAMING_TYPE_NONE
            && client->framing_type != SERF_CONNECTION_FRAMING_TYPE_HTTP1)
        {
            return client->perform_read(client);
        }

        /* On error fall through in connection cleanup below while */
    }

    while (status == APR_SUCCESS) {

        rq = client->current_request;
        if (!rq) {
            serf_bucket_t *read_bkt;

            rq = serf__incoming_request_create(client);

            if (client->proto_peek_bkt) {
                read_bkt = client->proto_peek_bkt;
                client->proto_peek_bkt = NULL;
            }
            else
                read_bkt = serf_bucket_barrier_create(client->pump.stream,
                                                      client->allocator);

            status = client->req_setup(&rq->req_bkt, read_bkt, rq,
                                       client->req_setup_baton,
                                       &rq->handler, &rq->handler_baton,
                                       &rq->response_setup,
                                       &rq->response_setup_baton,
                                       rq->pool);

            if (status) {
                apr_pool_destroy(rq->pool);
                serf_bucket_mem_free(client->allocator, rq);
                return status;
            }
        }

        /* Run handler once or multiple times until status? */
        status = rq->handler(rq, rq->req_bkt, rq->handler_baton, rq->pool);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        if (APR_STATUS_IS_EOF(status)) {
            /* Write response if this hasn't been done yet */
            status = serf_incoming_response_create(rq);

            if (SERF_BUCKET_READ_ERROR(status))
                return status;

            rq->request_read = true;
            client->current_request = NULL;

            if (rq->request_read && rq->response_finished) {
                serf__incoming_request_destroy(rq);
            }

            /* Is the connection at eof or just the request? */
            {
                const char *data;
                apr_size_t len;

                status = serf_bucket_peek(client->pump.stream, &data, &len);
            }
        }
    }

    if (!SERF_BUCKET_READ_ERROR(status) && !APR_STATUS_IS_EOF(status))
        return APR_SUCCESS;

    {
        apr_pollfd_t tdesc = { 0 };

        /* Remove us from the pollset */
        tdesc.desc_type = APR_POLL_SOCKET;
        tdesc.desc.s = client->skt;
        tdesc.reqevents = client->io.reqevents;
        client->ctx->pollset_rm(client->ctx->pollset_baton,
                                &tdesc, &client->io);

        client->seen_in_pollset |= APR_POLLHUP; /* No more events */

        /* Note that the client is done. The pool containing skt
           and this listener will now be cleared from the context
           handlers dirty pollset support */
        client->skt = NULL;
        serf_io__set_pollset_dirty(&client->io);
    }

    status = client->closed(client, client->closed_baton, status,
                            client->pool);

    return status;
}

apr_status_t serf__incoming_client_flush(serf_incoming_t *client,
                                         bool pump)
{
    return serf_pump__write(&client->pump, pump);
}

static apr_status_t write_to_client(serf_incoming_t *client)
{
    apr_status_t status;

    status = serf__incoming_client_flush(client, true);

    if (APR_STATUS_IS_EAGAIN(status))
        return APR_SUCCESS;
    else if (status)
        return status;

    /* Probably nothing to write. Connection will check new requests */
    serf_io__set_pollset_dirty(&client->io);

    return APR_SUCCESS;
}

static apr_status_t hangup_client(serf_incoming_t *client)
{
    return APR_ECONNRESET;
}


void serf_incoming_set_framing_type(
    serf_incoming_t *client,
    serf_connection_framing_type_t framing_type)
{
    client->framing_type = framing_type;

    if (client->skt) {
        serf_io__set_pollset_dirty(&client->io);
        client->pump.stop_writing = false;

        /* Close down existing protocol */
        if (client->protocol_baton && client->perform_teardown) {
            if (client->perform_pre_teardown)
                client->perform_pre_teardown(client);
            client->perform_teardown(client);
            client->protocol_baton = NULL;
        }

        /* Reset to default */
        client->perform_read = read_from_client;
        client->perform_write = write_to_client;
        client->perform_hangup = hangup_client;
        client->perform_teardown = NULL;
        client->perform_pre_teardown = NULL;

        switch (framing_type) {
            case SERF_CONNECTION_FRAMING_TYPE_HTTP2:
                serf__http2_protocol_init_server(client);
                break;
            case SERF_CONNECTION_FRAMING_TYPE_FCGI:
                serf__fcgi_protocol_init_server(client);
            default:
                break;
        }
    }
}


apr_status_t serf__process_client(serf_incoming_t *client, apr_int16_t events)
{
    apr_status_t status;

    if (client->wait_for_connect && (events & (APR_POLLIN | APR_POLLOUT))) {
        status = client_connected(client);
        client->wait_for_connect = FALSE;
        if (status) {
            return status;
        }
    }

    if ((events & APR_POLLIN) != 0) {
        /* If the stop_writing flag was set on the connection, reset it
           now because there is some data to read. */
        if (client->pump.stop_writing) {
            client->pump.stop_writing = false;
            serf_io__set_pollset_dirty(&client->io);
        }

        status = client->perform_read(client);
        if (status) {
            return status;
        }

        /* If we decided to close our connection, return now as we don't
         * want to write.
         */
        if ((client->seen_in_pollset & APR_POLLHUP) != 0) {
            return APR_SUCCESS;
        }
    }

    if ((events & APR_POLLHUP) != 0) {
        status = client->perform_hangup(client);
        if (status) {
            return status;
        }
    }

    if ((events & APR_POLLERR) != 0) {
#ifdef SO_ERROR
        /* If possible, get the error from the platform's socket layer and
           convert it to an APR status code. */
        {
            apr_os_sock_t osskt;
            if (!apr_os_sock_get(&osskt, client->skt)) {
                int error;
                apr_socklen_t l = sizeof(error);

                if (!getsockopt(osskt, SOL_SOCKET, SO_ERROR, (char*)&error,
                                &l)) {
                    status = APR_FROM_OS_ERROR(error);


                    if (status)
                        return status;
                }
            }
        }
#endif
        return APR_EGENERAL;
    }

    if ((events & APR_POLLOUT) != 0) {
        status = client->perform_write(client);
        if (status) {
            return status;
        }
    }

    return APR_SUCCESS;
}

apr_status_t serf__process_listener(serf_listener_t *l)
{
    apr_status_t status;
    apr_socket_t *in;
    apr_pool_t *p;
    /* THIS IS NOT OPTIMAL */
    apr_pool_create(&p, l->pool);

    status = apr_socket_accept(&in, l->skt, p);

    if (status != APR_SUCCESS
        && !APR_STATUS_IS_EINPROGRESS(status)) {

        apr_pool_destroy(p);
        return status;
    }

    if ((status = apr_socket_opt_set(l->skt, APR_SO_NONBLOCK, 1)))
        return status;

    /* Set the socket to be non-blocking */
    if ((status = apr_socket_timeout_set(in, 0)) != APR_SUCCESS)
        return status;

    /* Disable Nagle's algorithm */
    if ((status = apr_socket_opt_set(in, APR_TCP_NODELAY, 1)) != APR_SUCCESS)
        return status;

    status = l->accept_func(l->ctx, l, l->accept_baton, in, p);

    if (status) {
        apr_pool_destroy(p);
    }

    return status;
}

static apr_status_t incoming_cleanup(void *baton)
{
    serf_incoming_t *incoming = baton;

    apr_socket_close(incoming->skt);


    return APR_SUCCESS;
}

apr_status_t serf_incoming_create2(
    serf_incoming_t **client,
    serf_context_t *ctx,
    apr_socket_t *insock,
    serf_connection_setup_t setup,
    void *setup_baton,
    serf_incoming_closed_t closed,
    void *closed_baton,
    serf_incoming_request_setup_t req_setup,
    void *req_setup_baton,
    apr_pool_t *client_pool)
{
    apr_status_t status;
    serf_incoming_t *ic;
    serf_config_t *config;

    ic = apr_palloc(client_pool, sizeof(*ic));

    ic->ctx = ctx;
    ic->pool = client_pool;
    ic->allocator = serf_bucket_allocator_create(client_pool, NULL, NULL);
    ic->io.type = SERF_IO_CLIENT;
    ic->io.u.client = ic;
    ic->io.ctx = ctx;
    ic->io.dirty_conn = false;
    ic->io.reqevents = 0;
    ic->req_setup = req_setup;
    ic->req_setup_baton = req_setup_baton;
    ic->skt = insock;

    ic->wait_for_connect = true;
    /* Detect HTTP 1 or 2 via peek operation */
    ic->framing_type = SERF_CONNECTION_FRAMING_TYPE_NONE;

    ic->setup = setup;
    ic->setup_baton = setup_baton;
    ic->closed = closed;
    ic->closed_baton = closed_baton;

    /* Store the connection specific info in the configuration store */
    status = serf__config_store_create_client_config(ic, &config);
    if (status)
        return status;

    ic->config = config;

    /* Prepare wrapping the socket with buckets. */
    serf_pump__init(&ic->pump, &ic->io, ic->skt, config, ic->allocator, ic->pool);

    ic->protocol_baton = NULL;
    ic->perform_read = read_from_client;
    ic->perform_write = write_to_client;
    ic->perform_hangup = hangup_client;
    ic->perform_teardown = NULL;
    ic->perform_pre_teardown = NULL;
    ic->current_request = NULL;

    ic->desc.desc_type = APR_POLL_SOCKET;
    ic->desc.desc.s = ic->skt;
    ic->desc.reqevents = APR_POLLIN | APR_POLLERR | APR_POLLHUP;
    ic->seen_in_pollset = 0;

    status = ctx->pollset_add(ctx->pollset_baton, &ic->desc, &ic->io);

    if (status)
        return status;

    apr_pool_cleanup_register(ic->pool, ic, incoming_cleanup,
                              apr_pool_cleanup_null);

    APR_ARRAY_PUSH(ctx->incomings, serf_incoming_t *) = ic;
    *client = ic;

    return status;
}

apr_status_t serf_listener_create(
    serf_listener_t **listener,
    serf_context_t *ctx,
    const char *host,
    apr_uint16_t port,
    void *accept_baton,
    serf_accept_client_t accept,
    apr_pool_t *pool)
{
    apr_sockaddr_t *sa;
    apr_status_t rv;
    apr_pool_t *listener_pool;
    serf_listener_t *l;
    serf_config_t *config;

    apr_pool_create(&listener_pool, pool);

    l = apr_palloc(pool, sizeof(*l));

    l->pool = listener_pool;

    l->ctx = ctx;
    l->io.type = SERF_IO_LISTENER;
    l->io.u.listener = l;
    l->io.ctx = ctx;
    l->io.dirty_conn = false;
    l->io.reqevents = 0;
    l->accept_func = accept;
    l->accept_baton = accept_baton;

    rv = apr_sockaddr_info_get(&sa, host, APR_UNSPEC, port, 0, l->pool);
    if (rv) {
        apr_pool_destroy(l->pool);
        return rv;
    }

    rv = apr_socket_create(&l->skt, sa->family,
                           SOCK_STREAM,
#if APR_MAJOR_VERSION > 0
                           APR_PROTO_TCP,
#endif
                           l->pool);
    if (rv)
        return rv;

    rv = apr_socket_opt_set(l->skt, APR_SO_NONBLOCK, 1);
    if (rv)
        return rv;

    rv = apr_socket_timeout_set(l->skt, 0);
    if (rv)
        return rv;

    rv = apr_socket_bind(l->skt, sa);
    if (rv) {
      apr_pool_destroy(l->pool);
      return rv;
    }

    rv = apr_socket_listen(l->skt, 5);
    if (rv) {
        apr_pool_destroy(l->pool);
        return rv;
    }

    l->desc.desc_type = APR_POLL_SOCKET;
    l->desc.desc.s = l->skt;
    l->desc.reqevents = APR_POLLIN;

    rv = ctx->pollset_add(ctx->pollset_baton,
                            &l->desc, &l->io);
    if (rv) {
        apr_pool_destroy(l->pool);
        return rv;
    }

    /* Store the connection specific info in the configuration store */
    rv = serf__config_store_create_listener_config(l, &config);
    if (rv)
        return rv;

    l->config = config;

    *listener = l;

    return APR_SUCCESS;
}

apr_status_t serf__incoming_update_pollset(serf_incoming_t *client)
{
    serf_context_t *ctx = client->ctx;
    apr_status_t status;
    apr_pollfd_t desc = { 0 };
    bool data_waiting;

    if (!client->skt) {
        int cid;
        /* We are in the proces of being cleaned up. As we are not
           in the event loop and already notified the close callback
           we can now clear our pool and remove us from the context */

        if (client->config)
            serf__config_store_remove_client(ctx->config_store, client);

        /* And from the incommings list */
        for (cid = 0; cid < ctx->incomings->nelts; cid++) {
            if (GET_INCOMING(ctx, cid) == client) {
                GET_INCOMING(ctx, cid) =
                                GET_INCOMING(ctx,
                                             ctx->incomings->nelts - 1);
                break;
            }
        }
        client->ctx->incomings->nelts--;

        apr_pool_destroy(client->pool);

        if (cid < ctx->incomings->nelts) {
            /* We skipped updating the pollset on this item as we moved it.
               Let's run it now */

            return serf__incoming_update_pollset(GET_INCOMING(ctx, cid));
        }

        return APR_SUCCESS;
    }

    /* Remove the socket from the poll set. */
    desc.desc_type = APR_POLL_SOCKET;
    desc.desc.s = client->skt;
    desc.reqevents = client->io.reqevents;

    status = ctx->pollset_rm(ctx->pollset_baton,
                             &desc, &client->io);
    if (status && !APR_STATUS_IS_NOTFOUND(status))
        return status;

    /* Now put it back in with the correct read/write values. */
    desc.reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;

    /* If we are not connected yet, we just want to know when we are */
    if (client->wait_for_connect) {
        data_waiting = true;
        desc.reqevents |= APR_POLLOUT;
    }
    else {
        /* Directly look at the connection data. While this may look
           more expensive than the cheap checks later this peek is
           just checking a bit of ram.

           But it also has the nice side effect of removing references
           from the aggregate to requests that are done.
         */

        data_waiting = serf_pump__data_pending(&client->pump);

        if (data_waiting) {
            desc.reqevents |= APR_POLLOUT;
        }
    }

    /* save our reqevents, so we can pass it in to remove later. */
    client->io.reqevents = desc.reqevents;

    /* Note: even if we don't want to read/write this socket, we still
     * want to poll it for hangups and errors.
     */
    return ctx->pollset_add(ctx->pollset_baton,
                            &desc, &client->io);
}
