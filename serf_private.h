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

#ifndef _SERF_PRIVATE_H_
#define _SERF_PRIVATE_H_

#if !defined(HAVE_STDBOOL_H) && defined(_MSC_VER) && (_MSC_VER >= 1800)
 /* VS 2015 errors out when redefining bool */
#define HAVE_STDBOOL_H 1
#endif

#if __STDC_VERSION__ >= 199901L || defined(HAVE_STDBOOL_H)
#include <stdbool.h>
#elif defined(__bool_true_false_are_defined) || defined(__cplusplus)
/* Bool defined properly via C99 or C++ */
#elif defined(bool)
/* bool defined some other way (C99 compatible) */
#else
/* Do something C99 like ourself */
typedef int serf__bool_t; /* Not _Bool */
#define __bool_true_false_are_defined 1
#define bool serf__bool_t
#ifndef true
#define false 0
#define true 1
#endif
#endif

#include <apr.h> /* For __attribute__ */

 /* Define a MAX macro if we don't already have one */
#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

 /* Define a MIN macro if we don't already have one */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Define a COUNT_OF macro if we don't already have one */
#ifndef COUNT_OF
#define COUNT_OF(x) (sizeof(x) / sizeof(x[0]))
#endif

/* ### what the hell? why does the APR interface have a "size" ??
   ### the implication is that, if we bust this limit, we'd need to
   ### stop, rebuild a pollset, and repopulate it. what suckage.  */
#define MAX_CONN 16

/* But we use our own limit in most cases. Typically 50 on Windows
   (see IOV_MAX definition above) and typically 64 on posix */
#define SERF__STD_IOV_COUNT MIN(APR_MAX_IOVEC_SIZE, 64)


/* Older versions of APR do not have this macro.  */
#ifdef APR_SIZE_MAX
#define REQUESTED_MAX APR_SIZE_MAX
#else
#define REQUESTED_MAX (~((apr_size_t)0))
#endif

#ifndef APR_VERSION_AT_LEAST /* Introduced in APR 1.3.0 */
#define APR_VERSION_AT_LEAST(major,minor,patch)                           \
    (((major) < APR_MAJOR_VERSION)                                        \
      || ((major) == APR_MAJOR_VERSION && (minor) < APR_MINOR_VERSION)    \
      || ((major) == APR_MAJOR_VERSION && (minor) == APR_MINOR_VERSION && \
               (patch) <= APR_PATCH_VERSION))
#endif /* APR_VERSION_AT_LEAST */

#define SERF_IO_CLIENT (1)
#define SERF_IO_CONN (2)
#define SERF_IO_LISTENER (3)

/*** Logging facilities ***/

/* Check for the SERF_DISABLE_LOGGING define, as set by scons. */
#ifndef SERF_DISABLE_LOGGING
  #define SERF_LOGGING_ENABLED
#endif

/* Slightly shorter names for internal use. */
#define LOGLVL_ERROR   SERF_LOG_ERROR
#define LOGLVL_WARNING SERF_LOG_WARNING
#define LOGLVL_INFO    SERF_LOG_INFO
#define LOGLVL_DEBUG   SERF_LOG_DEBUG
#define LOGLVL_NONE    SERF_LOG_NONE

/* List of components, used as a mask. */
#define LOGCOMP_ALL_MSG SERF_LOGCOMP_ALL_MSG
#define LOGCOMP_ALL     SERF_LOGCOMP_ALL
#define LOGCOMP_SSL     SERF_LOGCOMP_SSL
#define LOGCOMP_AUTHN   SERF_LOGCOMP_AUTHN
#define LOGCOMP_CONN    SERF_LOGCOMP_CONN
#define LOGCOMP_COMPR   SERF_LOGCOMP_COMPR

#define LOGCOMP_RAWMSG  SERF_LOGCOMP_RAWMSG
#define LOGCOMP_SSLMSG  SERF_LOGCOMP_SSLMSG
#define LOGCOMP_NONE    SERF_LOGCOMP_NONE

/* TODO: remove before next serf release, FOR TESTING ONLY */
#define ACTIVE_LOGLEVEL SERF_LOG_NONE
#define ACTIVE_LOGCOMPS SERF_LOGCOMP_NONE

/* Older versions of APR do not have the APR_VERSION_AT_LEAST macro. Those
   implementations are safe.

   If the macro *is* defined, and we're on WIN32, and APR is version 1.4.0+,
   then we have a broken WSAPoll() implementation.

   See serf_context_create_ex() below.  */
#if defined(APR_VERSION_AT_LEAST) && defined(WIN32)
#if APR_VERSION_AT_LEAST(1,4,0)
#define BROKEN_WSAPOLL
#endif
#endif

typedef struct serf__authn_scheme_t serf__authn_scheme_t;

typedef struct serf_io_baton_t {
    int type;
    union {
        serf_incoming_t *client;
        serf_connection_t *conn;
        serf_listener_t *listener;
        const void *const v;
    } u;

    /* are we a dirty connection that needs its poll status updated? */
    serf_context_t *ctx;
    bool dirty_conn;

    /* the last reqevents we gave to pollset_add */
    apr_int16_t reqevents;

} serf_io_baton_t;

typedef struct serf_pump_t
{
    serf_io_baton_t *io;

    serf_bucket_alloc_t *allocator;
    serf_config_t *config;

    /* The incoming stream. Stored here for easy access by users,
       but not managed as part of the pump */
    serf_bucket_t *stream;

    /* The outgoing stream */
    serf_bucket_t *ostream_head;
    serf_bucket_t *ostream_tail;

    apr_socket_t *skt;

    /* Outgoing vecs, waiting to be written.
       Read from ostream_head as outgoing data buffer */
    struct iovec vec[SERF__STD_IOV_COUNT];
    int vec_len;

    /* True when connection failed while writing */
    bool done_writing;
    bool stop_writing; /* Wait for read (E.g. SSL) */

    /* Set to true when ostream_tail was read to EOF */
    bool hit_eof;

    apr_pool_t *pool;
} serf_pump_t;


/* Should we use static APR_INLINE instead? */
#define serf_io__set_pollset_dirty(io_baton)                    \
    do                                                          \
    {   serf_io_baton_t *serf__tmp_io_baton = io_baton;         \
        serf__tmp_io_baton->dirty_conn = true;                  \
        serf__tmp_io_baton->ctx->dirty_pollset = true;          \
    } while (0)

typedef enum serf_request_writing_t {
    SERF_WRITING_NONE,          /* Nothing written */
    SERF_WRITING_STARTED,       /* Data in write bucket(s) */
    SERF_WRITING_DONE,          /* Everything written */
    SERF_WRITING_FINISHED,      /* Safe to destroy */
} serf_request_writing_t;

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

    serf_request_writing_t writing;
    bool priority;
    /* 1 if this is a request to setup a SSL tunnel, 0 for normal requests. */
    bool ssltunnel;
    bool auth_done; /* auth and connection level handling done */

    serf_request_t *depends_on;      /* On what request do we depend */
    serf_request_t *depends_next;    /* Next dependency on parent*/
    serf_request_t *depends_first;   /* First dependency on us */
    apr_uint16_t dep_priority;

    /* This baton is currently only used for digest authentication, which
       needs access to the uri of the request in the response handler.
       If serf_request_t is replaced by a serf_http_request_t in the future,
       which knows about uri and method and such, this baton won't be needed
       anymore. */
    void *auth_baton;

    /* This baton is free to set by protocol handlers. They typically use it
       for identifying or storing related information */
    void *protocol_baton;

    struct serf_request_t *next;
};

struct serf_incoming_request_t
{
    serf_incoming_t *incoming;
    apr_pool_t *pool;

    serf_bucket_t *req_bkt;

    serf_incoming_request_handler_t handler;
    void *handler_baton;

    serf_incoming_response_setup_t response_setup;
    void *response_setup_baton;

    apr_status_t (*enqueue_response)(serf_incoming_request_t *request,
                                     void *enqueue_baton,
                                     serf_bucket_t *response);
    void *enqueue_baton;

    bool request_read;
    bool response_written;
    bool response_finished;
    serf_bucket_t *response_bkt;
};

typedef struct serf_pollset_t {
    /* the set of connections to poll */
    apr_pollset_t *pollset;
} serf_pollset_t;

typedef struct serf__authn_info_t {
    const serf__authn_scheme_t *scheme;

    void *baton;

    int failed_authn_types;
} serf__authn_info_t;

/*** Configuration store declarations ***/

typedef struct serf__config_hdr_t serf__config_hdr_t;

struct serf_config_t {
    apr_pool_t *ctx_pool;
    serf_bucket_alloc_t *allocator;

    /* Configuration key/value pairs per context */
    serf__config_hdr_t *per_context;
    /* Configuration key/value pairs per host */
    serf__config_hdr_t *per_host;
    /* Configuration key/value pairs per connection */
    serf__config_hdr_t *per_conn;
};

typedef struct serf__config_store_t {
    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    /* Configuration key/value pairs per context */
    serf__config_hdr_t *global_per_context;

    /* Configuration per host:
     Key: hostname:port
     Value: serf__config_hdr_t *
     */
    apr_hash_t *global_per_host;

    /* Configuration per connection:
     Key: string(connection ptr as string)
     Value: serf__config_hdr_t *
     */
    apr_hash_t *global_per_conn;

} serf__config_store_t;

/* Initializes the data structures used by the configuration store */
apr_status_t serf__config_store_init(serf_context_t *ctx);

/* Create a config object, which is a read/write view on the configuration
   store. This view is limited to:
   - all per context configuration
   - per host configuration (host as defined in CONN)
   - per connection configuration

   The host and connection entries will be created in the configuration store
   when not existing already.

   The config object will be allocated in OUT_POOL. The config object's
   lifecycle cannot extend beyond that of the serf context!
 */
apr_status_t serf__config_store_create_conn_config(serf_connection_t *conn,
                                                   serf_config_t **config);

/* Same thing, but for incoming connections */
apr_status_t serf__config_store_create_client_config(serf_incoming_t *client,
                                                     serf_config_t **config);

/* Same thing, but for listeners */
apr_status_t serf__config_store_create_listener_config(serf_listener_t *listener,
                                                       serf_config_t **config);

/* Same thing, but for the context itself */
apr_status_t serf__config_store_create_ctx_config(serf_context_t *ctx,
                                                  serf_config_t **config);


/* Cleans up all connection specific configuration values */
apr_status_t
serf__config_store_remove_connection(serf__config_store_t config_store,
                                     serf_connection_t *conn);

apr_status_t
serf__config_store_remove_client(serf__config_store_t config_store,
                                 serf_incoming_t *client);

/* Cleans up all host specific configuration values */
apr_status_t
serf__config_store_remove_host(serf__config_store_t config_store,
                               const char *hostname_port);

struct serf_context_t {
    /* the pool used for self and for other allocations */
    apr_pool_t *pool;

    serf__config_store_t config_store;

    void *pollset_baton;
    serf_socket_add_t pollset_add;
    serf_socket_remove_t pollset_rm;

    /* one of our connections has a dirty pollset state. */
    bool dirty_pollset;

    /* the list of active connections */
    apr_array_header_t *conns;
#define GET_CONN(ctx, i) (((serf_connection_t **)(ctx)->conns->elts)[i])

    apr_array_header_t *incomings;
#define GET_INCOMING(ctx, i) (((serf_incoming_t **)(ctx)->incomings->elts)[i])

    /* Proxy server address */
    apr_sockaddr_t *proxy_address;

    /* Progress callback */
    serf_progress_t progress_func;
    void *progress_baton;
    apr_off_t progress_read;
    apr_off_t progress_written;

    /* authentication info for the servers used in this context. Shared by all
       connections to the same server.
       Structure of the hashtable:  key: host url, e.g. https://localhost:80
                                  value: serf__authn_info_t *
     */
    apr_hash_t *server_authn_info;

    /* authentication info for the proxy configured in this context, shared by
       all connections. */
    serf__authn_info_t proxy_authn_info;

    /* List of authn types supported by the client.*/
    int authn_types;
    /* Callback function used to get credentials for a realm. */
    serf_credentials_callback_t cred_cb;

    serf_config_t *config;
};

struct serf_listener_t {
    serf_context_t *ctx;
    serf_io_baton_t io;
    apr_socket_t *skt;
    apr_pool_t *pool;
    apr_pollfd_t desc;
    void *accept_baton;
    serf_accept_client_t accept_func;
    serf_config_t *config;
};

struct serf_incoming_t {
    serf_context_t *ctx;

    serf_io_baton_t io;
    serf_pump_t pump;
    serf_incoming_request_setup_t req_setup;
    void *req_setup_baton;

    apr_socket_t *skt; /* Lives in parent of POOL */
    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    apr_pollfd_t desc;

    apr_int16_t seen_in_pollset;

    serf_connection_setup_t setup;
    void *setup_baton;
    serf_incoming_closed_t closed;
    void *closed_baton;

    serf_connection_framing_type_t framing_type;

    bool wait_for_connect;

    /* Event callbacks, called from serf__process_client() to do the actual
    processing. */
    apr_status_t(*perform_read)(serf_incoming_t *client);
    apr_status_t(*perform_write)(serf_incoming_t *client);
    apr_status_t(*perform_hangup)(serf_incoming_t *client);

    /* Cleanup of protocol handling */
    void(*perform_pre_teardown)(serf_incoming_t *conn);
    void(*perform_teardown)(serf_incoming_t *conn);
    void *protocol_baton;

    serf_config_t *config;

    serf_bucket_t *proto_peek_bkt;

    serf_incoming_request_t *current_request; /* For HTTP/1 */
};

/* States for the different stages in the lifecyle of a connection. */
typedef enum {
    SERF_CONN_INIT,             /* no socket created yet */
    SERF_CONN_SETUP_SSLTUNNEL,  /* ssl tunnel being setup, no requests sent */
    SERF_CONN_CONNECTED,        /* conn is ready to send requests */
} serf__connection_state_t;

struct serf_connection_t {
    serf_context_t *ctx;

    apr_status_t status;
    serf_io_baton_t io;
    serf_pump_t pump;

    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    apr_sockaddr_t *address;

    apr_socket_t *skt;
    apr_pool_t *skt_pool;

    /* the events we've seen for this connection in our returned pollset */
    apr_int16_t seen_in_pollset;

    /* number of completed requests we've sent */
    unsigned int completed_requests;

    /* number of completed responses we've got */
    unsigned int completed_responses;

    /* keepalive */
    unsigned int probable_keepalive_limit;

    /* Current state of the connection (whether or not it is connected). */
    serf__connection_state_t state;

    /* This connection may have responses without a request! */
    int async_responses;
    serf_bucket_t *current_async_response;
    serf_response_acceptor_t async_acceptor;
    void *async_acceptor_baton;
    serf_response_handler_t async_handler;
    void *async_handler_baton;

    /* The list of requests that are written but no response has been received
       yet. */
    serf_request_t *written_reqs;
    serf_request_t *written_reqs_tail;
    unsigned int nr_of_written_reqs;

    /* The list of requests that hasn't been written */
    serf_request_t *unwritten_reqs;
    serf_request_t *unwritten_reqs_tail;
    unsigned int nr_of_unwritten_reqs;

    /* Requests that are done, but not destroyed yet because they may still
       have data pending in their pools. Will be destroyed at several
       safe points. */
    serf_request_t *done_reqs;
    serf_request_t *done_reqs_tail;

    serf_connection_setup_t setup;
    void *setup_baton;
    serf_connection_closed_t closed;
    void *closed_baton;

    /* Max. number of outstanding requests. */
    unsigned int max_outstanding_requests;

    /* Framing type to use on the connection */
    serf_connection_framing_type_t framing_type;

    /* Flag to enable or disable HTTP pipelining. This flag is used internally
       only. */
    int pipelining;

    /* Host url, path ommitted, syntax: https://svn.apache.org . */
    const char *host_url;

    /* Exploded host url, path ommitted. Only scheme, hostinfo, hostname &
       port values are filled in. */
    apr_uri_t host_info;

    /* authentication info for this connection. */
    serf__authn_info_t authn_info;

    /* Time marker when connection begins. */
    apr_time_t connect_time;

    /* Calculated connection latency. Negative value if latency is unknown. */
    apr_interval_time_t latency;

    /* Write out information now */
    bool write_now;

    /* Wait for connect: connect() returned APR_EINPROGRESS.
       Socket not usable yet */
    bool wait_for_connect;

    /* Event callbacks, called from serf__process_connection() to do the actual
       processing. */
    apr_status_t (*perform_read)(serf_connection_t *conn);
    apr_status_t (*perform_write)(serf_connection_t *conn);
    apr_status_t (*perform_hangup)(serf_connection_t *conn);

    /* Cleanup of protocol handling */
    void(*perform_pre_teardown)(serf_connection_t *conn);
    void (*perform_teardown)(serf_connection_t *conn);
    void *protocol_baton;

    /* Request callbacks. NULL unless handled by the protocol implementation */
    void (*perform_cancel_request)(serf_request_t *request,
                                   apr_status_t reason);
    void (*perform_prioritize_request)(serf_request_t *request,
                                       bool exclusive);

    /* Configuration shared with buckets and authn plugins */
    serf_config_t *config;
};

/* Called by requests that still have outstanding requests to allow cleaning
   up buckets that may still reference buckets of this request */
void serf__connection_pre_cleanup(serf_connection_t *);

/*** Internal bucket functions ***/

/* Copies all data contained in vecs to *data, optionally telling how much was
   copied */
void serf__copy_iovec(char *data,
                      apr_size_t *copied,
                      struct iovec *vecs,
                      int vecs_used);

/* Drains the bucket as far as possible without waiting for more data */
void serf__bucket_drain(serf_bucket_t *bucket);

/** Transform a response_bucket in-place into an aggregate bucket. Restore the
    status line and all headers, not just the body.

    This can only be used when we haven't started reading the body of the
    response yet.

    Keep internal for now, probably only useful within serf.
 */
apr_status_t serf_response_full_become_aggregate(serf_bucket_t *bucket);

/**
 * Replace the response body's EOF status with an error status. This can be used
 * to signal an error to the application (see handle_response in outgoing.c).
 */
void serf__bucket_response_set_error_on_eof(serf_bucket_t *bucket,
                                            apr_status_t error);

/**
 * Remove the header from the list, do nothing if the header wasn't added.
 */
void serf__bucket_headers_remove(serf_bucket_t *headers_bucket,
                                 const char *header);

/**
 * Read raw information stored in request REQUEST_BUCKET. All output values
 * are directly copied from the internal state.
 *
 * Output values can be passed as NULL when not interested.
 */
void serf__bucket_request_read(serf_bucket_t *request_bucket,
                               serf_bucket_t **body_bkt,
                               const char **uri,
                               const char **method);

serf_bucket_t *serf_bucket_request_get_body(
  serf_bucket_t *bucket);


/*** Authentication handler declarations ***/

typedef enum { PROXY, HOST } peer_t;

/* Perform authentication related initialization of connection CONN. */
apr_status_t serf__auth_setup_connection(peer_t peer,
                                         serf_connection_t *conn);

/* Perform authentication related initialization of request REQUEST. */
apr_status_t serf__auth_setup_request(peer_t peer,
                                      serf_request_t *request,
                                      const char *method,
                                      const char *uri,
                                      serf_bucket_t *hdrs_bkt);

/**
 * Handles a 401 or 407 response, tries the different available authentication
 * handlers.
 */
apr_status_t serf__handle_auth_response(bool *consumed_response,
                                        serf_request_t *request,
                                        serf_bucket_t *response,
                                        apr_pool_t *pool);

/* Get the cached serf__authn_info_t object for the target server, or create one
   when this is the first connection to the server.
   TODO: The serf__authn_info_t objects are allocated in the context pool, so
   a context that's used to connect to many different servers using Basic or
   Digest authencation will hold on to many objects indefinitely. We should be
   able to cleanup stale objects from time to time. */
serf__authn_info_t *serf__get_authn_info_for_server(serf_connection_t *conn);

/* fromt context.c */
void serf__context_progress_delta(void *progress_baton, apr_off_t read,
                                  apr_off_t written);

/* from incoming.c */
apr_status_t serf__process_client(serf_incoming_t *l, apr_int16_t events);
apr_status_t serf__process_listener(serf_listener_t *l);
apr_status_t serf__incoming_update_pollset(serf_incoming_t *incoming);
apr_status_t serf__incoming_client_flush(serf_incoming_t *client, bool pump);
serf_incoming_request_t *serf__incoming_request_create(serf_incoming_t *client);
void serf__incoming_request_destroy(serf_incoming_request_t *request);

/* from outgoing.c */
apr_status_t serf__open_connections(serf_context_t *ctx);
apr_status_t serf__process_connection(serf_connection_t *conn,
                                       apr_int16_t events);
apr_status_t serf__conn_update_pollset(serf_connection_t *conn);
serf_request_t *serf__ssltunnel_request_create(serf_connection_t *conn,
                                               serf_request_setup_t setup,
                                               void *setup_baton);
void serf__connection_set_pipelining(serf_connection_t *conn, int enabled);
apr_status_t serf__connection_flush(serf_connection_t *conn,
                                    bool fetch_new);

apr_status_t serf__provide_credentials(serf_context_t *ctx,
                                       char **username,
                                       char **password,
                                       serf_request_t *request,
                                       int code, const char *authn_type,
                                       const char *realm,
                                       apr_pool_t *pool);

/* Requeue a request (at the front).  */
apr_status_t serf_connection__request_requeue(serf_request_t *request);

apr_status_t serf_connection__perform_setup(serf_connection_t *conn);

/* from ssltunnel.c */
apr_status_t serf__ssltunnel_connect(serf_connection_t *conn);



/* Creates a bucket that logs all data returned by one of the read functions
   of the wrapped bucket. The new bucket will replace the wrapped bucket, so
   the wrapped ptr will be invalid when this function returns. */
serf_bucket_t *serf__bucket_log_wrapper_create(serf_bucket_t *wrapped,
                                               const char *prefix,
                                               serf_bucket_alloc_t *allocator);

/* From http2_protocol.c: Initializes http2 state on connection */
void serf__http2_protocol_init(serf_connection_t *conn);
void serf__http2_protocol_init_server(serf_incoming_t *client);

/* From fcgi_protocol.c: Initializes http2 state on connection */
void serf__fcgi_protocol_init(serf_connection_t *conn);
void serf__fcgi_protocol_init_server(serf_incoming_t *client);

typedef struct serf_hpack_table_t serf_hpack_table_t;

/* From http2_hpack_buckets.c */
apr_status_t serf__hpack_huffman_decode(const unsigned char *encoded,
                                        apr_size_t encoded_len,
                                        apr_size_t text_avail,
                                        char *text,
                                        apr_size_t *text_len);

apr_status_t serf__hpack_huffman_encode(const char *text,
                                        apr_size_t text_len,
                                        apr_size_t encoded_avail,
                                        unsigned char *encoded,
                                        apr_size_t *encoded_len);

apr_status_t serf__bucket_hpack_create_from_request(
                                        serf_bucket_t **new_hpack_bucket,
                                        serf_hpack_table_t *hpack_table,
                                        serf_bucket_t *request,
                                        const char *scheme,
                                        serf_bucket_alloc_t *allocator);

/* From connection_request.c */
void serf__link_requests(serf_request_t **list, serf_request_t **tail,
                         serf_request_t *request);
apr_status_t serf__destroy_request(serf_request_t *request);
apr_status_t serf__cancel_request(serf_request_t *request,
                                  serf_request_t **list,
                                  int notify_request);
unsigned int serf__req_list_length(serf_request_t *req);
apr_status_t serf__setup_request(serf_request_t *request);
void serf__link_requests(serf_request_t **list, serf_request_t **tail,
                         serf_request_t *request);

apr_status_t serf__handle_response(serf_request_t *request,
                                   apr_pool_t *pool);

/* From pump.c */
void serf_pump__init(serf_pump_t *pump,
                     serf_io_baton_t *io,
                     apr_socket_t *skt,
                     serf_config_t *config,
                     serf_bucket_alloc_t *allocator,
                     apr_pool_t *pool);

void serf_pump__done(serf_pump_t *pump);

bool serf_pump__data_pending(serf_pump_t *pump);
void serf_pump__store_ipaddresses_in_config(serf_pump_t *pump);

apr_status_t serf_pump__write(serf_pump_t *pump,
                              bool fetch_new);

apr_status_t serf_pump__add_output(serf_pump_t *pump,
                                   serf_bucket_t *bucket,
                                   bool flush);

/* These must always be called as a pair to avoid a memory leak */
void serf_pump__prepare_setup(serf_pump_t *pump);
void serf_pump__complete_setup(serf_pump_t *pump,
                               serf_bucket_t *stream,
                               serf_bucket_t *ostream);


/** Logging functions. **/

/* Initialize the logging subsystem. This will store a log baton in the
   context's configuration store. */
apr_status_t serf__log_init(serf_context_t *ctx);

/* Logs a standard event, but without prefix. This is useful to build up
   log lines in parts. */
void serf__log_nopref(apr_uint32_t level, apr_uint32_t comp,
                      serf_config_t *config, const char *fmt, ...)
                      __attribute__((format(printf, 4, 5)));

/* Logs an event, uses CONFIG to find out socket related info. */
void serf__log(apr_uint32_t level, apr_uint32_t comp, const char *filename,
               serf_config_t *config, const char *fmt, ...)
               __attribute__((format(printf, 5, 6)));

/* Returns non-zero if logging is enabled for provided LEVEL/COMP.
 * This function can be useful in cases if logging information if somewhat
 * expensive to obtain. */
int serf__log_enabled(apr_uint32_t level, apr_uint32_t comp,
                      serf_config_t *config);


/* Event bucket */

extern const serf_bucket_type_t serf_bucket_type__event;
#define SERF__BUCKET_IS_EVENT(b) SERF_BUCKET_CHECK((b), _event)

typedef apr_status_t(*serf_bucket_event_callback_t)(void *baton,
                                                    apr_uint64_t bytes_read);

serf_bucket_t *serf__bucket_event_create(
                        serf_bucket_t *stream,
                        void *baton,
                        serf_bucket_event_callback_t start_cb,
                        serf_bucket_event_callback_t eof_cb,
                        serf_bucket_event_callback_t destroy_cb,
                        serf_bucket_alloc_t *allocator);


#endif
