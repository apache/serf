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

#ifndef SERF_H
#define SERF_H

/**
 * @file serf.h
 * @brief Main serf header file
 */

#include <apr_pools.h>
#include <apr_buckets.h>
#include <apr_network_io.h>
#include <apr_tables.h>
#include <apr_uri.h>

#include "serf_config.h"
#include "serf_declare.h"
#include "serf_buckets.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare some structures */
typedef struct serf_filter_type_t serf_filter_type_t;
typedef struct serf_filter_t serf_filter_t;
typedef struct serf_connection_t serf_connection_t;
typedef struct serf_request_t serf_request_t;
typedef struct serf_response_t serf_response_t;


/* A callback function for processing a response. When operating in
 * asynchronous mode, the processing loop will invoke this function when
 * a response arrives.
 *
 * The client can reach its context via response->request->ctx.
 *
 * All temporary allocations should occur in POOL.
 */
typedef apr_status_t (*serf_response_handler_t) (
    serf_response_t *response,
    apr_pool_t *pool
    );

/* This callback is used to fetch data for delivery to the remote server.
 *
 * A brigade should be provided. All data for delivery will be appended
 * to this brigade.
 *
 * All temporary allocations should occur in POOL.
 */
typedef apr_status_t (*serf_source_t) (
    apr_bucket_brigade *brigade,
    apr_pool_t *pool
    );

/* This function is used to defined a filter function. It accepts data
 * within the brigade, transforms it, and passes it to the next filter.
 *
 * All temporary allocations should occur in POOL.
 */
typedef apr_status_t (*serf_filter_func_t) (
    apr_bucket_brigade *brigade,
    serf_filter_t *filter,
    apr_pool_t *pool
    );

/*
 * Filtering primitives.
 *
 * All filters are designed as "push" filters. The caller "pushes"
 * data into the filter, it will process the data, then pass the
 * resulting data to the "next" filter.
 *
 * In certain types of applications and callin environments, a "pull"
 * filter is desired. To turn the push filters into "pull" filters, it
 * is assumed that some kind of pull-based data source is available in
 * the environment. In a pull model, the result data would be mapped
 * as:
 *
 *   DATA = F1( F2( F3( SOURCE )))
 *
 * However, the filter chain is organized as:
 *
 *   F3.write(SOURCE) -> F2 -> F1 -> DATA
 *
 * The mapping is performed by inserting a "gathering filter":
 *
 *   ORIG_DATA = get(SOURCE)
 *   F3.write(ORIG_DATA) -> F2 -> F1 -> GATHER
 *   DATA = GATHER.fetch()
 *
 * We have chosen the "push" model as the basis of the filter design,
 * as it can easily be reversed, and the construction of a filter is
 * much more straightforward.
 */
struct serf_filter_type_t {
    /* The filter's name (for reference and for debugging). */
    const char *name;

    /* The function that processes the data for this filter. */
    serf_filter_func_t func;
};

struct serf_filter_t {
    /* The type of this filter. */
    const serf_filter_type_t *type;

    /* Filter-specific context. */
    void *ctx;

    /* The next filter in this chain. */
    serf_filter_t *next;
};


/*
 * Connection primitive.
 */
struct serf_connection_t {
    /* The address that we will connect to. */
    apr_sockaddr_t *address;

    /* The socket that we are connected to the server with. This value may
       be NULL if we have not (yet) connected (e.g. lazy connect). */
    apr_socket_t *socket;

    /* Should we reconnect automatically on an EPIPE? */
    /* ### gjs: what about retry limits? timeouts? etc. */
    int auto_reconnect;

    /* All of the requests which are (currently) associated with this
       connection. */
    apr_array_header_t *requests;

    /* Filters that are applied to all buckets before they are delivered
       to the remote server. */
    serf_filter_t *request_filters;

    /* Filters that are applied to all buckets as they arrive from the
       remote server. */
    serf_filter_t *response_filters;
};

/*
 * Request primitive.
 */
struct serf_request_t {
    /* Method to retrieve this request by */
    const char *method;

    /* The path component for this request. 
     * This includes the query args and fragment.
     */
    const char *uri_path;

    /* Indicate whether keepalive of connection is desired. */
    /* ### gjs: axe this. we should always operate as an HTTP/1.1 client
       ### with keepalive enabled
       ### jre: flood needs control over this behavior.  */
    int keepalive;

    /* Client-managed context associated with this request. */
    void *ctx;

    /* Represents any entity and header information to include with the
     * request.
     *
     * Will be processed by filters before being sent.
     */
    apr_bucket_brigade *entity;

    /* When operating in asynchronous (callback) mode, use this function
     * as the callback for processing the response associated with this
     * request. 
     *
     * If this is NULL, we are assumed to be running in synchronous mode
     * and we will wait for serf_read_response() to be called.
     */
    serf_response_handler_t *handler;

    /* When operating in asynchronous (callback) mode, use this function
     * to provide source data for the request.
     *
     * This is the SOURCE, in reference to the filtering discussion above.
     *
     * If this is NULL, we are assumed to be running in synchronous mode
     * and we will only use the buckets in the entity brigade available
     * at the beginning of writing the request.
     */
    serf_source_t *source;

    /* Filters that are applied to the request buckets as they are sent
     * to the remote server.
     * These filters execute BEFORE the connection filters.
     */
    serf_filter_t *request_filters;

    /* Filters that are applied to the response buckets as they are
     * received from the remote server.
     * These filters execute AFTER the connection filters.
     */
    serf_filter_t *response_filters;
};

/*
 * Response primitive.
 */
struct serf_response_t {
    /* Represents any entity and/or header fields included with the response.
     * Will be processed by filters before being received.
     */
    apr_bucket_brigade *entity;

    /* Pointer to the associated request object. */
    serf_request_t *request;
};

/*
 * Create a connection structure.
 */
SERF_DECLARE(serf_connection_t *) serf_create_connection(apr_pool_t *pool);

/*
 * Opens the specified connection.
 *
 * ### gjs: IMO, we should lazy-connect. toss this.
 * ### jre: flood needs to control when the connection is opened.
 */
SERF_DECLARE(apr_status_t) serf_open_connection(serf_connection_t *conn);

/*
 * Closes the specified connection and any requests that may be underneath it.
 */
SERF_DECLARE(apr_status_t) serf_close_connection(serf_connection_t *conn);

/*
 * Create a request object.
 *
 * The request is not tied to a connection until serf_write_request is called.
 */
SERF_DECLARE(serf_request_t *) serf_create_request(apr_pool_t *pool);

/*
 * Writes the specifed request to a connection.
 *
 * This is a blocking operation. The connection will be opened to the
 * server, if it has not been connected yet.
 */
SERF_DECLARE(apr_status_t) serf_write_request(serf_request_t *request,
                                              serf_connection_t *conn);

/*
 * Read a response from the specified connection.
 *
 * This function blocks until enough of a response can be constructed
 * and returned. The application can use (?? other APIs) to continue
 * reading the rest of the response.
 *
 * The response is allocated in the specified pool.
 */
SERF_DECLARE(apr_status_t) serf_read_response(serf_response_t **response,
                                              serf_connection_t *conn,
                                              apr_pool_t *pool);

/*
 * Helper function that will create a connection and a request based on the
 * provided URI. 
 *
 * The connection and the request are allocated in the specified pool.
 */
SERF_DECLARE(apr_status_t) serf_open_uri(apr_uri_t *url,
                                         serf_connection_t **conn, 
                                         serf_request_t **request,
                                         apr_pool_t *pool);

/*
 * Process all of the requests that have been associated with the
 * specified connections. This function will return when the last
 * response has been delivered.
 *
 * If requests are added to the connection while in the callbacks,
 * then they will be processed, too, before this function returns.
 *
 * As each response arrives, the response handler from the response's
 * corresponding request structure will be invoked with the response
 * object.
 *
 * The application should ensure that a bottom-most filter is installed
 * in the request chain to provide data, and a bottom-most filter in
 * the response chain to deal with the response data.
 */
SERF_DECLARE(apr_status_t) serf_process_connection(serf_connection_t *conn);


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_H */
