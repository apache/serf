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

#ifndef _SERF_PRIVATE_H_
#define _SERF_PRIVATE_H_

/* ### what the hell? why does the APR interface have a "size" ??
   ### the implication is that, if we bust this limit, we'd need to
   ### stop, rebuild a pollset, and repopulate it. what suckage.  */
#define MAX_CONN 16

/* Windows does not define IOV_MAX, so we need to ensure it is defined. */
#ifndef IOV_MAX
#define IOV_MAX 16
#endif

#define SERF_IO_CLIENT (1)
#define SERF_IO_CONN (2)
#define SERF_IO_LISTENER (3)

typedef struct serf_io_baton_t {
    int type;
    union {
        serf_incoming_t *client;
        serf_connection_t *conn;
        serf_listener_t *listener;
    } u;
} serf_io_baton_t;

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

typedef struct serf_pollset_t {
    /* the set of connections to poll */
    apr_pollset_t *pollset;
} serf_pollset_t;

struct serf_context_t {
    /* the pool used for self and for other allocations */
    apr_pool_t *pool;

    void *pollset_baton;
    serf_socket_add_t pollset_add;
    serf_socket_remove_t pollset_rm;

    /* one of our connections has a dirty pollset state. */
    int dirty_pollset;

    /* the list of active connections */
    apr_array_header_t *conns;
#define GET_CONN(ctx, i) (((serf_connection_t **)(ctx)->conns->elts)[i])

    /* Proxy server address */
    apr_sockaddr_t *proxy_address;

    /* Progress callback */
    serf_progress_t progress_func;
    void *progress_baton;
    apr_off_t progress_read;
    apr_off_t progress_written;
};

struct serf_listener_t {
    serf_context_t *ctx;
    serf_io_baton_t baton;
    apr_socket_t *skt;
    apr_pool_t *pool;
    apr_pollfd_t desc;
    void *accept_baton;
    serf_accept_client_t accept;
};

struct serf_incoming_t {
    serf_context_t *ctx;
    serf_io_baton_t baton;
    void *request_baton;
    serf_incoming_request_cb_t request;
    apr_socket_t *skt;
    apr_pollfd_t desc;
};

struct serf_connection_t {
    serf_context_t *ctx;

    serf_io_baton_t baton;

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
    /* A bucket to provide connection level filters for writes. */
    serf_bucket_t *ostream;
    /* A reference to the aggregate bucket that provides the boundary between
     * request level buckets and connection level buckets.
     */
    serf_bucket_t *ostream_tail;

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

    /* Max. number of outstanding requests. */
    unsigned int max_outstanding_requests;

    /* Host info. */
    const char *host_url;
    apr_uri_t host_info;
};


/* fromt context.c */
void serf__context_progress_delta(void *progress_baton, apr_off_t read,
                                  apr_off_t written);

/* from incoming.c */
apr_status_t serf__process_client(serf_incoming_t *l);
apr_status_t serf__process_listener(serf_listener_t *l);

/* from outgoing.c */
apr_status_t serf__open_connections(serf_context_t *ctx);
apr_status_t serf__process_connection(serf_connection_t *conn,
                                       apr_int16_t events);
apr_status_t serf__conn_update_pollset(serf_connection_t *conn);

#endif
