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

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

static apr_status_t client_detect_eof(void *baton,
                                      serf_bucket_t *aggregator)
{
    serf_incoming_t *client = baton;
    client->hit_eof = true;
    return APR_EAGAIN;
}

static apr_status_t client_connected(serf_incoming_t *client)
{
    /* serf_context_t *ctx = client->ctx; */
    apr_status_t status;
    serf_bucket_t *ostream;

    /* ### TODO: Store ip address in config for logging */

    serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, client->config,
              "socket for client 0x%x connected\n", client);

    /* ### Connection does auth setup here */

    if (client->ostream_head == NULL) {
        client->ostream_head = serf_bucket_aggregate_create(client->allocator);
    }

    if (client->ostream_tail == NULL) {
        client->ostream_tail = serf_bucket_aggregate_create(client->allocator);

        serf_bucket_aggregate_hold_open(client->ostream_tail,
                                        client_detect_eof, client);
    }

    ostream = client->ostream_tail;

    status = client->setup(client->skt,
                           &client->stream,
                           &ostream,
                           client->setup_baton, client->pool);

    if (status) {
        /* extra destroy here since it wasn't added to the head bucket yet. */
        serf_bucket_destroy(client->ostream_tail);
        /* ### Cleanup! (serf__connection_pre_cleanup) */
        return status;
    }

    /* Share the configuration with all the buckets in the newly created output
    chain (see PLAIN or ENCRYPTED scenario's), including the request buckets
    created by the application (ostream_tail will handle this for us). */
    serf_bucket_set_config(client->ostream_head, client->config);

    /* Share the configuration with the ssl_decrypt and socket buckets. The
    response buckets wrapping the ssl_decrypt/socket buckets won't get the
    config automatically because they are upstream. */
    serf_bucket_set_config(client->stream, client->config);

    serf_bucket_aggregate_append(client->ostream_head,
                                 ostream);

    return status;
}

static apr_status_t read_from_client(serf_incoming_t *client)
{
    return APR_ENOTIMPL;
}

static apr_status_t write_to_client(serf_incoming_t *client)
{
    return APR_ENOTIMPL;
}

apr_status_t serf__process_client(serf_incoming_t *client, apr_int16_t events)
{
    apr_status_t rv;

    if (client->wait_for_connect && (events & (APR_POLLIN | APR_POLLOUT))) {
        rv = client_connected(client);
        client->wait_for_connect = FALSE;
        if (rv) {
            return rv;
        }
    }

    if ((events & APR_POLLIN) != 0) {
        rv = read_from_client(client);
        if (rv) {
            return rv;
        }
    }

    if ((events & APR_POLLHUP) != 0) {
        return APR_ECONNRESET;
    }

    if ((events & APR_POLLERR) != 0) {
        return APR_EGENERAL;
    }

    if ((events & APR_POLLOUT) != 0) {
        rv = write_to_client(client);
        if (rv) {
            return rv;
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
    serf_incoming_request_cb_t request,
    void *request_baton,
    apr_pool_t *pool)
{
    apr_status_t rv;
    apr_pool_t *ic_pool;

    apr_pool_create(&ic_pool, pool);

    serf_incoming_t *ic = apr_palloc(ic_pool, sizeof(*ic));

    ic->ctx = ctx;
    ic->pool = ic_pool;
    ic->allocator = serf_bucket_allocator_create(ic_pool, NULL, NULL);
    ic->baton.type = SERF_IO_CLIENT;
    ic->baton.u.client = ic;
    ic->request_baton =  request_baton;
    ic->request = request;
    ic->skt = insock;

    ic->dirty_conn = false;
    ic->wait_for_connect = true;

    ic->setup = setup;
    ic->setup_baton = setup_baton;
    ic->closed = closed;
    ic->closed_baton = closed_baton;

    /* A bucket wrapped around our socket (for reading responses). */
    ic->stream = NULL;
    ic->ostream_head = NULL;
    ic->ostream_tail = NULL;
    ic->ssltunnel_ostream = NULL;

    ic->desc.desc_type = APR_POLL_SOCKET;
    ic->desc.desc.s = ic->skt;
    ic->desc.reqevents = APR_POLLIN | APR_POLLERR | APR_POLLHUP;

    /* Store the connection specific info in the configuration store */
    /* ### Doesn't work... Doesn't support listeners yet*/
    /*rv = serf__config_store_get_config(ctx, ic, &config, pool);
    if (rv) {
    apr_pool_destroy(l->pool);
    return rv;
    }
    ic->config = config;*/
    ic->config = NULL; /* FIX!! */

    rv = ctx->pollset_add(ctx->pollset_baton,
                         &ic->desc, &ic->baton);

    if (!rv) {
        apr_pool_cleanup_register(ic->pool, ic, incoming_cleanup,
                                  apr_pool_cleanup_null);
        *client = ic;
    }
    else {
        apr_pool_destroy(ic_pool);
        /* Let caller handle the socket */
    }

    return rv;
}

typedef struct ic_setup_baton_t
{
  serf_incoming_t *incoming;
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

  /* Allocate baton to hand over created listener
     (to get access to its allocator) */
  isb = apr_pcalloc(pool, sizeof(*isb));

  status = serf_incoming_create2(client, ctx, insock,
                                 dummy_setup, isb,
                                 dummy_closed, isb,
                                 request, request_baton, pool);

  if (!status)
    isb->incoming = *client;

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
    serf_listener_t *l = apr_palloc(pool, sizeof(*l));

    l->ctx = ctx;
    l->baton.type = SERF_IO_LISTENER;
    l->baton.u.listener = l;
    l->accept_func = accept;
    l->accept_baton = accept_baton;

    apr_pool_create(&l->pool, pool);

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
                            &l->desc, &l->baton);
    if (rv) {
        apr_pool_destroy(l->pool);
        return rv;
    }

    *listener = l;

    return APR_SUCCESS;
}

apr_status_t serf__incoming_update_pollset(serf_incoming_t *incoming)
{
    serf_context_t *ctx = incoming->ctx;
    apr_status_t status;
    apr_pollfd_t desc = { 0 };
    bool data_waiting;

    if (!incoming->skt) {
        return APR_SUCCESS;
    }

    /* Remove the socket from the poll set. */
    desc.desc_type = APR_POLL_SOCKET;
    desc.desc.s = incoming->skt;
    desc.reqevents = incoming->reqevents;

    status = ctx->pollset_rm(ctx->pollset_baton,
                             &desc, &incoming->baton);
    if (status && !APR_STATUS_IS_NOTFOUND(status))
        return status;

    /* Now put it back in with the correct read/write values. */
    desc.reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;

    /* If we are not connected yet, we just want to know when we are */
    if (incoming->wait_for_connect) {
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
        if (incoming->vec_len) {
            /* We still have vecs in the connection, which lifetime is
               managed by buckets inside conn->ostream_head.

               Don't touch ostream as that might destroy the vecs */

            data_waiting = true;
        }
        else {
            serf_bucket_t *ostream;

            ostream = incoming->ostream_head;

            if (!ostream)
              ostream = incoming->ssltunnel_ostream;

            if (ostream) {
                const char *dummy_data;
                apr_size_t len;

                status = serf_bucket_peek(ostream, &dummy_data, &len);

                if (SERF_BUCKET_READ_ERROR(status) || len > 0) {
                    /* DATA or error waiting */
                    data_waiting = TRUE; /* Error waiting */
                }
                else if (! status || APR_STATUS_IS_EOF(status)) {
                    data_waiting = FALSE;
                }
                else
                    data_waiting = FALSE; /* EAGAIN / EOF / WAIT_CONN */
            }
            else
                data_waiting = FALSE;
        }

        if (data_waiting) {
            desc.reqevents |= APR_POLLOUT;
        }
    }

    /* save our reqevents, so we can pass it in to remove later. */
    incoming->reqevents = desc.reqevents;

    /* Note: even if we don't want to read/write this socket, we still
     * want to poll it for hangups and errors.
     */
    return ctx->pollset_add(ctx->pollset_baton,
                            &desc, &incoming->baton);
}
