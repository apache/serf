/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#ifdef __cplusplus
extern "C" {
#endif

#include "serf_methods.h"
#include "serf_buckets.h"

/*
 * Connection primative.
 */
struct serf_connection_t {
    const char *host;
    const char *port;
    
    serf_socket_t *socket;
};
typedef struct serf_connection_t serf_connection_t;

/*
 * Request primative.
 */
struct serf_request_t {
    /* Method to retrieve this request by */
    serf_method_t method;

    /* The path component for this request. */
    char *path;
    /* Any potential query arguments. */
    char *query_args;

    /* Indicate whether keepalive of connection is desired. */
    int keepalive;

    /* Represents any entity and header information to include with the
     * request.
     *
     * Will be processed by filters before being sent.
     */
    apr_bucket_brigade_t *entity;

    /* Pointer to the connection being used. */
    serf_connection_t *conn;
};
typedef struct serf_request_t serf_request_t;

/*
 * Response primative.
 */
struct serf_response_t {
    /* Represents any entity and/or header fields included with the response.
     * Will be processed by filters before being received.
     */
    apr_bucket_brigade_t *entity;

    /* Pointer to the associated request object. */
    serf_request_t *request;
};
typedef struct serf_response_t serf_response_t;

/*
 * Create a connection structure.
 */
serf_connection_t* serf_create_connection();

/*
 * Opens the specified connection.
 */
serf_status_t serf_open_connection(serf_connection_t *conn);

/*
 * Closes the specified connection and any requests that may be underneath it.
 */
serf_status_t serf_close_connection(serf_connection_t *conn);

/*
 * Create a request object for a specific connection.
 */
serf_request_t* serf_create_request(serf_connection_t *conn);

/*
 * Writes the specifed request to its associated connection.
 */
serf_status_t serf_write_request(serf_request_t *request);

/*
 * Creates a response object tied in with a request object.
 */
serf_response_t* serf_create_response(serf_response_t *response);

/*
 * Indicates that the application is ready to read the response.
 */
serf_status_t serf_read_response(serf_response_t *response);

/*
 * Helper function that will open a connection and a request based on the
 * provided URI. 
 */
serf_status_t serf_open_uri(apr_uri_t *url,
                            serf_connection_t **conn, 
                            serf_request_t **request);


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_H */
