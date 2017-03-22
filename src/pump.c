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

static apr_status_t pump_cleanup(void *baton)
{
    serf_pump_t *pump = baton;

    if (pump->ostream_head != NULL) {
#ifdef SERF_DEBUG_BUCKET_USE
        serf__bucket_drain(pump->ostream_head);
#endif
        serf_bucket_destroy(pump->ostream_head);
        pump->ostream_head = NULL;
        pump->ostream_tail = NULL;
    }

    pump->pool = NULL; /* Don't run again */
    pump->allocator = NULL;
    pump->skt = NULL;
    pump->vec_len = 0;

    return APR_SUCCESS;
}

void serf_pump__init(serf_pump_t *pump,
                     serf_io_baton_t *io,
                     apr_socket_t *skt,
                     serf_config_t *config,
                     serf_bucket_alloc_t *allocator,
                     apr_pool_t *pool)
{
    memset(pump, 0, sizeof(*pump));

    pump->io = io;
    pump->allocator = allocator;
    pump->config = config;
    pump->skt = skt;
    pump->pool = pool;

    apr_pool_cleanup_register(pool, pump, pump_cleanup,
                              apr_pool_cleanup_null);
}

void serf_pump__done(serf_pump_t *pump)
{
    if (pump->pool) {
        apr_pool_cleanup_run(pump->pool, pump, pump_cleanup);
    }

    pump->io = NULL;
    pump->allocator = NULL;
    pump->config = NULL;

    /* pump->stream is managed by the current reader! */

    pump->ostream_head = NULL;
    pump->ostream_tail = NULL;

    pump->done_writing = false;
    pump->stop_writing = false;
    pump->hit_eof = false;

    pump->pool = NULL;
}

/* Safely check if there is still data pending on the connection, carefull
   to not accidentally make it invalid. */
bool serf_pump__data_pending(serf_pump_t *pump)
{
    if (pump->vec_len > 0)
        return TRUE; /* We can't poll right now! */

    if (pump->ostream_head) {
        const char *data;
        apr_size_t len;
        apr_status_t status;

        status = serf_bucket_peek(pump->ostream_head, &data, &len);
        if (!SERF_BUCKET_READ_ERROR(status)) {
            if (len > 0) {
                return true;
            }
        }
        else
            return true; /* Sure, we have data (an error) */
    }

    return false;
}

static apr_status_t detect_eof(void *baton, serf_bucket_t *aggregate_bucket)
{
    serf_pump_t *pump = baton;
    pump->hit_eof = true;

    if (pump->done_writing) {
        pump->ostream_tail = NULL;
        return APR_EOF;
    }
    else
        return APR_EAGAIN;
}

void serf_pump__prepare_setup(serf_pump_t *pump)
{
    if (pump->ostream_head == NULL) {
        pump->ostream_head = serf_bucket_aggregate_create(pump->allocator);
    }

    if (pump->ostream_tail == NULL) {
        pump->ostream_tail = serf_bucket_aggregate_create(pump->allocator);

        serf_bucket_aggregate_hold_open(pump->ostream_tail, detect_eof, pump);
    }
}

void serf_pump__complete_setup(serf_pump_t *pump,
                               serf_bucket_t *stream,
                               serf_bucket_t *ostream)
{
    pump->stream = stream;
    if (ostream)
        serf_bucket_aggregate_append(pump->ostream_head, ostream);
    else
        serf_bucket_aggregate_append(pump->ostream_head, pump->ostream_tail);

    /* Share the configuration with all the buckets in the newly created output
     chain (see PLAIN or ENCRYPTED scenario's), including the request buckets
     created by the application (ostream_tail will handle this for us). */
    serf_bucket_set_config(pump->ostream_head, pump->config);

    /* Share the configuration with the ssl_decrypt and socket buckets. The
     response buckets wrapping the ssl_decrypt/socket buckets won't get the
     config automatically because they are upstream. */
    if (stream != NULL) {
        pump->stream = stream;
        serf_bucket_set_config(pump->stream, pump->config);
    }

    /* We typically have one of two scenarios, based on whether the
       application decided to encrypt this connection:

       PLAIN:

         conn->stream = SOCKET(skt)
         conn->ostream_head = AGGREGATE(ostream_tail)
         conn->ostream_tail = STREAM(<detect_eof>, REQ1, REQ2, ...)

       ENCRYPTED:

         conn->stream = DECRYPT(SOCKET(skt))
         conn->ostream_head = AGGREGATE(ENCRYPT(ostream_tail))
         conn->ostream_tail = STREAM(<detect_eof>, REQ1, REQ2, ...)

       where STREAM is an internal variant of AGGREGATE.
    */
}

void serf_pump__store_ipaddresses_in_config(serf_pump_t *pump)
{
    apr_sockaddr_t *sa;

    if (apr_socket_addr_get(&sa, APR_LOCAL, pump->skt) == APR_SUCCESS) {
        char buf[48];
        if (!apr_sockaddr_ip_getbuf(buf, sizeof(buf), sa))
            serf_config_set_stringf(pump->config, SERF_CONFIG_CONN_LOCALIP,
                                    pump->pool, "%s:%d", buf, (int)sa->port);
    }
    if (apr_socket_addr_get(&sa, APR_REMOTE, pump->skt) == APR_SUCCESS) {
        char buf[48];
        if (!apr_sockaddr_ip_getbuf(buf, sizeof(buf), sa))
            serf_config_set_stringf(pump->config, SERF_CONFIG_CONN_REMOTEIP,
                                    pump->pool, "%s:%d", buf, (int)sa->port);
    }
}

static apr_status_t no_more_writes(serf_pump_t *pump)
{
    /* Note that we should hold new requests until we open our new socket. */
    pump->done_writing = true;
    serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, pump->config,
              "stop writing on 0x%p\n", pump->io->u.v);

    /* Clear our iovec. */
    pump->vec_len = 0;

    /* Update the pollset to know we don't want to write on this socket any
     * more.
     */
    serf_io__set_pollset_dirty(pump->io);
    return APR_SUCCESS;
}

static apr_status_t socket_writev(serf_pump_t *pump)
{
    apr_size_t written;
    apr_status_t status;
    serf_pump_t *conn = pump;

    status = apr_socket_sendv(pump->skt, pump->vec,
                              pump->vec_len, &written);
    if (status && !APR_STATUS_IS_EAGAIN(status))
        serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, pump->config,
                  "socket_sendv error %d on 0x%p\n", status, pump->io->u.v);

    /* did we write everything? */
    if (written) {
        apr_size_t len = 0;
        int i;

        serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, conn->config,
                  "--- socket_sendv: %d bytes on 0x%p. --\n",
                  (int)written, pump->io->u.v);

        for (i = 0; i < conn->vec_len; i++) {
            len += conn->vec[i].iov_len;
            if (written < len) {
                serf__log_nopref(LOGLVL_DEBUG, LOGCOMP_RAWMSG, conn->config,
                                 "%.*s",
                                 (int)(conn->vec[i].iov_len - (len - written)),
                                 (const char *)conn->vec[i].iov_base);
                if (i) {
                    memmove(conn->vec, &conn->vec[i],
                            sizeof(struct iovec) * (conn->vec_len - i));
                    conn->vec_len -= i;
                }
                conn->vec[0].iov_base = (char *)conn->vec[0].iov_base
                                        + conn->vec[0].iov_len
                                        - (len - written);
                conn->vec[0].iov_len = len - written;
                break;
            } else {
                serf__log_nopref(LOGLVL_DEBUG, LOGCOMP_RAWMSG, conn->config,
                                 "%.*s",
                                 (int)conn->vec[i].iov_len,
                                 (const char*)conn->vec[i].iov_base);
            }
        }
        if (len == written) {
            conn->vec_len = 0;
        }
        serf__log_nopref(LOGLVL_DEBUG, LOGCOMP_RAWMSG, conn->config, "\n");

        /* Log progress information */
        serf__context_progress_delta(conn->io->ctx, 0, written);
    }

    return status;
}

apr_status_t serf_pump__write(serf_pump_t *pump,
                              bool fetch_new)
{
    apr_status_t status = APR_SUCCESS;
    apr_status_t read_status = APR_SUCCESS;

    pump->hit_eof = FALSE;

    while (status == APR_SUCCESS) {

        /* First try to write out what is already stored in the
           connection vecs. */
        while (pump->vec_len && !status) {
            status = socket_writev(pump);

            /* If the write would have blocked, then we're done.
             * Don't try to write anything else to the socket.
             */
            if (APR_STATUS_IS_EPIPE(status)
                || APR_STATUS_IS_ECONNRESET(status)
                || APR_STATUS_IS_ECONNABORTED(status))
              return no_more_writes(pump);
        }

        if (status || !fetch_new) {

            /* If we couldn't write everything that we tried,
               make sure that we will receive a write event next time */
            if (APR_STATUS_IS_EAGAIN(status)
                && !pump->io->dirty_conn
                && !(pump->io->reqevents & APR_POLLOUT))
            {
                serf_io__set_pollset_dirty(pump->io);
            }
            return status;
        }
        else if (read_status || pump->vec_len || pump->hit_eof)
            return read_status;

        /* ### optimize at some point by using read_for_sendfile */
        /* TODO: now that read_iovec will effectively try to return as much
           data as available, we probably don't want to read ALL_AVAIL, but
           a lower number, like the size of one or a few TCP packets, the
           available TCP buffer size ... */
        pump->hit_eof = false;
        read_status = serf_bucket_read_iovec(pump->ostream_head,
                                             SERF_READ_ALL_AVAIL,
                                             COUNT_OF(pump->vec),
                                             pump->vec,
                                             &pump->vec_len);

        if (read_status == SERF_ERROR_WAIT_CONN) {
            /* The bucket told us that it can't provide more data until
            more data is read from the socket. This normally happens
            during a SSL handshake.

            We should avoid looking for writability for a while so
            that (hopefully) something will appear in the bucket so
            we can actually write something. otherwise, we could
            end up in a CPU spin: socket wants something, but we
            don't have anything (and keep returning EAGAIN) */

            serf__log(LOGLVL_INFO, LOGCOMP_CONN, __FILE__, pump->config,
                      "Output stream requested temporary write delay "
                      "on 0x%p\n", pump->io->u.v);

            pump->stop_writing = true;
            serf_io__set_pollset_dirty(pump->io);

            read_status = APR_EAGAIN;
        }
        else if (APR_STATUS_IS_EAGAIN(read_status)) {

            /* We read some stuff, but did we read everything ? */
            if (pump->hit_eof)
                read_status = APR_SUCCESS;
        }
        else if (SERF_BUCKET_READ_ERROR(read_status)) {

            /* Something bad happened. Propagate any errors. */
            return read_status;
        }
    }

    return status;
}

apr_status_t serf_pump__add_output(serf_pump_t *pump,
                                   serf_bucket_t *bucket,
                                   bool flush)
{
    apr_status_t status;

    if (!pump->ostream_tail) {
        serf_bucket_destroy(bucket);
        return APR_ENOSOCKET;
    }

    if (!flush
        && !pump->io->dirty_conn
        && !pump->stop_writing
        && !(pump->io->reqevents & APR_POLLOUT)
        && !serf_pump__data_pending(pump))
    {
        /* If not writing now,
           * and not already dirty
           * and nothing pending yet
           Then mark the pollset dirty to trigger a write */

        serf_io__set_pollset_dirty(pump->io);
    }

    serf_bucket_aggregate_append(pump->ostream_tail, bucket);

    if (!flush)
        return APR_SUCCESS;

    /* Flush final output buffer (after ssl, etc.) */
    status = serf_pump__write(pump, TRUE);

    if (SERF_BUCKET_READ_ERROR(status))
        return status;
    else
        return APR_SUCCESS;
}

