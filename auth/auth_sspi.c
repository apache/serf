/* Copyright 2009 Justin Erenkrantz and Greg Stein
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

#ifdef SERF_HAVE_SSPI

/*
 * NTLM/Negotitate authentication for HTTP
 *
 * 1. C  --> S:    GET
 *
 *    C <--  S:    401 Authentication Required
 *                 WWW-Authenticate: NTLM
 *
 * -> Initialize the NTLM authentication handler.
 *
 * 2. C  --> S:    GET
 *                 Authorization: NTLM <Base64 encoded Type 1 message>
 *                 sspi_ctx->state = sspi_auth_in_progress;
 *
 *    C <--  S:    401 Authentication Required
 *                 WWW-Authenticate: NTLM <Base64 encoded Type 2 message>
 *
 * 3. C  --> S:    GET
 *                 Authorization: NTLM <Base64 encoded Type 3 message>
 *                 sspi_ctx->state = sspi_auth_completed;
 *
 *    C <--  S:    200 Ok
 *
 * This handshake is required for every new connection. If the handshake is
 * completed successfully, all other requested on the same connection will
 * be authenticated without needing to pass the WWW-Authenticate header.
 *
 */

/*** Includes ***/
#include <serf.h>
#include <serf_private.h>
#include <auth/auth.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_strings.h>

#define SECURITY_WIN32
#include <sspi.h>

apr_status_t
serf__init_sspi(int code,
                serf_context_t *ctx,
                apr_pool_t *pool)
{
    return APR_SUCCESS;
}

/* A new connection is created to a server that's known to use
   NTLM or Negotiate. */
apr_status_t
serf__init_sspi_connection(int code,
                           serf_connection_t *conn,
                           apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

/* A 401/407 response was received, handle the authentication. */
apr_status_t
serf__handle_sspi_auth(int code,
                       serf_request_t *request,
                       serf_bucket_t *response,
                       const char *auth_hdr,
                       const char *auth_attr,
                       void *baton,
                       apr_pool_t *pool)
{
    serf_connection_t *conn = request->conn;
    serf_context_t *ctx = conn->ctx;

    return APR_ENOTIMPL;
}

/* Setup the authn headers on this request message. */
apr_status_t
serf__setup_request_sspi_auth(int code,
                              serf_connection_t *conn,
                              const char *method,
                              const char *uri,
                              serf_bucket_t *hdrs_bkt)
{
    return APR_ENOTIMPL;
}

/* Function is called when 2xx responses are received. Normally we don't
 * have to do anything, except for the first response after the
 * authentication handshake. This specific response includes authentication
 * data which should be validated by the client (mutual authentication).
 */
apr_status_t
serf__validate_response_sspi_auth(int code,
                                  serf_connection_t *conn,
                                  serf_request_t *request,
                                  serf_bucket_t *response,
                                  apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

#endif  /* SERF_HAVE_SSPI */
