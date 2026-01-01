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

#include "serf.h"
#include "serf_private.h"

/* Global error processing. */

static apr_status_t
default_global_error_callback(void *baton,
                              unsigned source,
                              apr_status_t status,
                              const char *message)
{
    return APR_SUCCESS;
}

static void *global_error_callback_baton = NULL;
static serf_error_cb_t global_error_callback = default_global_error_callback;

void serf_global_error_callback_set(serf_error_cb_t callback, void *baton)
{
    global_error_callback_baton = baton;
    global_error_callback = callback;
}

/* The various process_*_error functions set the error source, then either
   call the appropriate error callback or, if that's not defined, send the
   message up the hierarchy until it's either handled by a registered
   callback or thrown away by default_global_error_callback().

   This way, the callers of serf__*_error() don't have to bother with
   the error source or check if their callbacks have been defined. */

static apr_status_t process_global_error(unsigned source,
                                         apr_status_t status,
                                         const char *message)
{
    if (0 == (source & SERF_ERROR_CB_MASK)) {
        source |= SERF_ERROR_CB_GLOBAL;
    }
    return global_error_callback(global_error_callback_baton,
                                 source, status, message);
}

/* Context error processing. */

static apr_status_t process_context_error(unsigned source,
                                          const serf_context_t* ctx,
                                          apr_status_t status,
                                          const char *message)
{
    if (0 == (source & SERF_ERROR_CB_MASK)) {
        source |= SERF_ERROR_CB_CONTEXT;
    }
    if (ctx->error_callback) {
        return ctx->error_callback(ctx->error_callback_baton,
                                   source, status, message);
    }
    return process_global_error(source, status, message);
}

apr_status_t serf__context_error(const serf_context_t* ctx,
                                 apr_status_t status,
                                 const char *message)
{
    return process_context_error(SERF_ERROR_CB_CONTEXT,
                                 ctx, status, message);
}

/* Connection error processing. */

static apr_status_t process_connection_error(unsigned source,
                                             const serf_connection_t *conn,
                                             apr_status_t status,
                                             const char *message)
{
    if (0 == (source & SERF_ERROR_CB_MASK)) {
        source |= SERF_ERROR_CB_OUTGOING;
    }
    if (conn->error_callback) {
        return conn->error_callback(conn->error_callback_baton,
                                    source, status, message);
    }
    return process_context_error(source, conn->ctx, status, message);
}

apr_status_t serf__connection_error(const serf_connection_t *conn,
                                    apr_status_t status,
                                    const char *message)
{
    return process_connection_error(SERF_ERROR_CB_OUTGOING,
                                    conn, status, message);
}

apr_status_t serf__request_error(const serf_request_t *req,
                                 apr_status_t status,
                                 const char *message)
{
    return process_connection_error(SERF_ERROR_CB_OUTGOING
                                    | SERF_ERROR_CB_REQUEST,
                                    req->conn, status, message);
}

apr_status_t serf__response_error(const serf_request_t *req,
                                  apr_status_t status,
                                  const char *message)
{
    return process_connection_error(SERF_ERROR_CB_OUTGOING
                                    | SERF_ERROR_CB_RESPONSE,
                                    req->conn, status, message);
}

/* Incoming error processing. */

static apr_status_t process_incoming_error(unsigned source,
                                           const serf_incoming_t *client,
                                           apr_status_t status,
                                           const char *message)
{
    if (0 == (source & SERF_ERROR_CB_MASK)) {
        source |= SERF_ERROR_CB_INCOMING;
    }
    if (client->error_callback) {
        return client->error_callback(client->error_callback_baton,
                                      source, status, message);
    }
    return process_context_error(source, client->ctx, status, message);
}

apr_status_t serf__incoming_error(const serf_incoming_t *client,
                                  apr_status_t status,
                                  const char *message)
{
    return process_incoming_error(SERF_ERROR_CB_INCOMING,
                                  client, status, message);
}

apr_status_t serf__incoming_request_error(const serf_incoming_request_t *req,
                                          apr_status_t status,
                                          const char *message)
{
    return process_incoming_error(SERF_ERROR_CB_INCOMING
                                  | SERF_ERROR_CB_REQUEST,
                                  req->incoming, status, message);
}

apr_status_t serf__incoming_response_error(const serf_incoming_request_t *req,
                                           apr_status_t status,
                                           const char *message)
{
    return process_incoming_error(SERF_ERROR_CB_INCOMING
                                  | SERF_ERROR_CB_RESPONSE,
                                  req->incoming, status, message);
}

/* Errors from the SSL context.

   Callers of the SSL functions can create an serf__ssl_error_ctx_t
   on the stack and pass it to the called function, which can then
   dispatch any errors it generates to the appropriate callback. */

apr_status_t serf__global_ssl_error(const void *baton,
                                    apr_status_t status,
                                    const char *message)
{
    /* Ignores the baton, since there's only one global error callback. */
    return process_global_error(SERF_ERROR_CB_SSL_CONTEXT
                                | SERF_ERROR_CB_GLOBAL,
                                status, message);
}

apr_status_t serf__context_ssl_error(const void *baton,
                                     apr_status_t status,
                                     const char *message)
{
    const serf_context_t *const ctx = baton;
    return process_context_error(SERF_ERROR_CB_SSL_CONTEXT
                                 | SERF_ERROR_CB_CONTEXT,
                                 ctx, status, message);
}


apr_status_t serf__connection_ssl_error(const void *baton,
                                        apr_status_t status,
                                        const char *message)
{
    const serf_connection_t *const conn = baton;
    return process_connection_error(SERF_ERROR_CB_SSL_CONTEXT
                                    | SERF_ERROR_CB_OUTGOING,
                                    conn, status, message);
}

apr_status_t serf__request_ssl_error(const void *baton,
                                     apr_status_t status,
                                     const char *message)
{
    const serf_request_t *const req = baton;
    return process_connection_error(SERF_ERROR_CB_SSL_CONTEXT
                                    | SERF_ERROR_CB_OUTGOING
                                    | SERF_ERROR_CB_REQUEST,
                                    req->conn, status, message);
}

apr_status_t serf__response_ssl_error(const void *baton,
                                      apr_status_t status,
                                      const char *message)
{
    const serf_request_t *const req = baton;
    return process_connection_error(SERF_ERROR_CB_SSL_CONTEXT
                                    | SERF_ERROR_CB_OUTGOING
                                    | SERF_ERROR_CB_RESPONSE,
                                    req->conn, status, message);
}

apr_status_t serf__incoming_ssl_error(const void *baton,
                                      apr_status_t status,
                                      const char *message)
{
    const serf_incoming_t *const client = baton;
    return process_incoming_error(SERF_ERROR_CB_SSL_CONTEXT
                                  | SERF_ERROR_CB_INCOMING,
                                  client, status, message);
}

apr_status_t serf__incoming_request_ssl_error(const void *baton,
                                              apr_status_t status,
                                              const char *message)
{
    const serf_incoming_request_t *const req = baton;
    return process_incoming_error(SERF_ERROR_CB_SSL_CONTEXT
                                  | SERF_ERROR_CB_INCOMING
                                  | SERF_ERROR_CB_REQUEST,
                                  req->incoming, status, message);
}

apr_status_t serf__incoming_response_ssl_error(const void *baton,
                                               apr_status_t status,
                                               const char *message)
{
    const serf_incoming_request_t *const req = baton;
    return process_incoming_error(SERF_ERROR_CB_SSL_CONTEXT
                                  | SERF_ERROR_CB_INCOMING
                                  | SERF_ERROR_CB_RESPONSE,
                                  req->incoming, status, message);
}
