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

#include <apr_pools.h>
#include <apr_poll.h>
#include <apr_version.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

/**
 * Callback function (implements serf_progress_t). Takes a number of bytes
 * read @a read and bytes written @a written, adds those to the total for this
 * context and notifies an interested party (if any).
 */
void serf__context_progress_delta(
    void *progress_baton,
    apr_off_t read,
    apr_off_t written)
{
    serf_context_t *ctx = progress_baton;

    ctx->progress_read += read;
    ctx->progress_written += written;

    if (ctx->progress_func)
        ctx->progress_func(ctx->progress_baton,
                           ctx->progress_read,
                           ctx->progress_written);
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

        if ((status = serf__conn_update_pollset(conn)) != APR_SUCCESS)
            return status;
    }

    /* reset our context flag now */
    ctx->dirty_pollset = 0;

    return APR_SUCCESS;
}


static apr_status_t pollset_add(void *user_baton,
                                apr_pollfd_t *pfd,
                                void *serf_baton)
{
    serf_pollset_t *s = (serf_pollset_t*)user_baton;
    pfd->client_data = serf_baton;
    return apr_pollset_add(s->pollset, pfd);
}

static apr_status_t pollset_rm(void *user_baton,
                               apr_pollfd_t *pfd,
                               void *serf_baton)
{
    serf_pollset_t *s = (serf_pollset_t*)user_baton;
    pfd->client_data = serf_baton;
    return apr_pollset_remove(s->pollset, pfd);
}


SERF_DECLARE(void) serf_config_proxy(serf_context_t *ctx,
                                     apr_sockaddr_t *address)
{
    ctx->proxy_address = address;
}

SERF_DECLARE(void) serf_config_credentials_callback(serf_context_t *ctx,
                                                    serf_credentials_callback_t cred_cb)
{
    ctx->cred_cb = cred_cb;
}

SERF_DECLARE(void) serf_config_authn_types(serf_context_t *ctx,
                                           int authn_types)
{
    ctx->authn_types = authn_types;
}

SERF_DECLARE(serf_context_t *) serf_context_create_ex(void *user_baton,
                                                      serf_socket_add_t addf,
                                                      serf_socket_remove_t rmf,
                                                      apr_pool_t *pool)
{
    serf_context_t *ctx = apr_pcalloc(pool, sizeof(*ctx));

    ctx->pool = pool;

    if (user_baton != NULL) {
        ctx->pollset_baton = user_baton;
        ctx->pollset_add = addf;
        ctx->pollset_rm = rmf;
    }
    else {
        /* build the pollset with a (default) number of connections */
        serf_pollset_t *ps = apr_pcalloc(pool, sizeof(*ps));
        (void) apr_pollset_create(&ps->pollset, MAX_CONN, pool, 0);
        ctx->pollset_baton = ps;
        ctx->pollset_add = pollset_add;
        ctx->pollset_rm = pollset_rm;
    }

    /* default to a single connection since that is the typical case */
    ctx->conns = apr_array_make(pool, 1, sizeof(serf_connection_t *));

    /* Initialize progress status */
    ctx->progress_read = 0;
    ctx->progress_written = 0;

    ctx->authn_types = SERF_AUTHN_ALL;

    return ctx;
}

SERF_DECLARE(serf_context_t *) serf_context_create(apr_pool_t *pool)
{
    return serf_context_create_ex(NULL, NULL, NULL, pool);
}

SERF_DECLARE(apr_status_t) serf_context_prerun(serf_context_t *ctx)
{
    apr_status_t status = APR_SUCCESS;
    if ((status = serf__open_connections(ctx)) != APR_SUCCESS)
        return status;

    if ((status = check_dirty_pollsets(ctx)) != APR_SUCCESS)
        return status;
    return status;
}

SERF_DECLARE(apr_status_t) serf_event_trigger(serf_context_t *s,
                                              void *serf_baton,
                                              const apr_pollfd_t *desc)
{
    apr_pollfd_t tdesc = { 0 };
    apr_status_t status = APR_SUCCESS;
    serf_io_baton_t *io = serf_baton;

    if (io->type == SERF_IO_CONN) {
        serf_connection_t *conn = io->u.conn;
        serf_context_t *ctx = conn->ctx;

        /* If this connection has already failed, return the error again, and try
         * to remove it from the pollset again
         */
        if (conn->status) {
            tdesc.desc_type = APR_POLL_SOCKET;
            tdesc.desc.s = conn->skt;
            tdesc.reqevents = conn->reqevents;
            ctx->pollset_rm(ctx->pollset_baton,
                            &tdesc, conn);
            return conn->status;
        }
        /* apr_pollset_poll() can return a conn multiple times... */
        if ((conn->seen_in_pollset & desc->rtnevents) != 0 ||
            (conn->seen_in_pollset & APR_POLLHUP) != 0) {
            return APR_SUCCESS;
        }

        conn->seen_in_pollset |= desc->rtnevents;

        if ((conn->status = serf__process_connection(conn,
                                         desc->rtnevents)) != APR_SUCCESS) {

            /* it's possible that the connection was already reset and thus the
               socket cleaned up. */
            if (conn->skt) {
                tdesc.desc_type = APR_POLL_SOCKET;
                tdesc.desc.s = conn->skt;
                tdesc.reqevents = conn->reqevents;
                ctx->pollset_rm(ctx->pollset_baton,
                                &tdesc, conn);
            }
            return conn->status;
        }
    }
    else if (io->type == SERF_IO_LISTENER) {
        serf_listener_t *l = io->u.listener;

        status = serf__process_listener(l);

        if (status) {
            return status;
        }
    }
    else if (io->type == SERF_IO_CLIENT) {
        serf_incoming_t *c = io->u.client;

        status = serf__process_client(c, desc->rtnevents);

        if (status) {
            return status;
        }
    }
    return status;
}

SERF_DECLARE(apr_status_t) serf_context_run(serf_context_t *ctx,
                                            apr_short_interval_time_t duration,
                                            apr_pool_t *pool)
{
    apr_status_t status;
    apr_int32_t num;
    const apr_pollfd_t *desc;
    serf_pollset_t *ps = (serf_pollset_t*)ctx->pollset_baton;

    if ((status = serf_context_prerun(ctx)) != APR_SUCCESS) {
        return status;
    }

    if ((status = apr_pollset_poll(ps->pollset, duration, &num,
                                   &desc)) != APR_SUCCESS) {
        /* ### do we still need to dispatch stuff here?
           ### look at the potential return codes. map to our defined
           ### return values? ...
        */
        return status;
    }

    while (num--) {
        serf_connection_t *conn = desc->client_data;

        status = serf_event_trigger(ctx, conn, desc);
        if (status) {
            return status;
        }

        desc++;
    }

    return APR_SUCCESS;
}

SERF_DECLARE(void) serf_context_set_progress_cb(
    serf_context_t *ctx,
    const serf_progress_t progress_func,
    void *progress_baton)
{
    ctx->progress_func = progress_func;
    ctx->progress_baton = progress_baton;
}


SERF_DECLARE(serf_bucket_t *) serf_context_bucket_socket_create(
    serf_context_t *ctx,
    apr_socket_t *skt,
    serf_bucket_alloc_t *allocator)
{
    serf_bucket_t *bucket = serf_bucket_socket_create(skt, allocator);

    /* Use serf's default bytes read/written callback */
    serf_bucket_socket_set_read_progress_cb(bucket,
                                            serf__context_progress_delta,
                                            ctx);

    return bucket;
}


/* ### this really ought to go somewhere else, but... meh.  */
SERF_DECLARE(void) serf_lib_version(int *major, int *minor, int *patch)
{
    *major = SERF_MAJOR_VERSION;
    *minor = SERF_MINOR_VERSION;
    *patch = SERF_PATCH_VERSION;
}
