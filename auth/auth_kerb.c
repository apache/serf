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

#include "auth_kerb.h"

#ifdef SERF_HAVE_KERB

/*** Kerberos authentication ***/

#include <serf.h>
#include <serf_private.h>
#include <auth/auth.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_strings.h>

/** These functions implements Kerberos authentication, using GSS-API
 *  (RFC 2743). The message-exchange is documented in RFC 4559.
 *
 * Note: this implementation uses gssapi and only works on *nix.
 **/

/** TODO:
 ** - send session key directly on new connections where we already know
 **   the server requires Kerberos authn.
 ** - fix authn status, as the COMPLETE/CONTINUE status values
 **   are never used.
 ** - Add a way for serf to give detailed error information back to the
 **   application.
 ** - proxy support
 **/

/* Authentication over HTTP using Kerberos
 *
 * Kerberos involves three servers:
 * - Authentication Server (AS): verifies users during login
 * - Ticket-Granting Server (TGS): issues proof of identity tickets
 * - HTTP server (S)
 *
 * Steps:
 * 0. User logs in to the AS and receives a TGS ticket. On workstations
 * where the login program doesn't support Kerberos, the user can use
 * 'kinit'.
 *
 * 1. C  --> S:    GET
 *
 *    C <--  S:    401 Authentication Required
 *                 WWW-Authenticate: Negotiate
 *
 * -> app contacts the TGS to request a session key for the HTTP service
 *    @ target host. The returned session key is encrypted with the HTTP
 *    service's secret key, so we can safely send it to the server.
 *
 * 2. C  --> S:    GET
 *                 Authorization: Negotiate <Base64 encoded session key>
 *                 gss_api_ctx->state = gss_api_auth_in_progress;
 *
 *    C <--  S:    200 OK
 *                 WWW-Authenticate: Negotiate <Base64 encoded server
 *                                              authentication data>
 *
 * -> The server returned a key to proof itself to us. We check this key
 *    with the TGS again.
 *
 * Note: It's possible that the server returns 401 again in step 3, if the
 *       Kerberos context isn't complete yet. Some (simple) tests with
 *       mod_auth_kerb and MIT Kerberos 5 show this never happens.
 *
 * This handshake is required for every new connection. If the handshake is
 * completed successfully, all other requests on the same connection will
 * be authenticated without needing to pass the WWW-Authenticate header.
 *
 * Note: Step 1 of the handshake will only happen on the first connection, once
 * we know the server requires Kerberos authentication, the initial requests
 * on the other connections will include a session key, so we start  at
 * step 2 in the handshake.
 * ### TODO: Not implemented yet!
 */

typedef enum {
    gss_api_auth_not_started,
    gss_api_auth_in_progress,
    gss_api_auth_completed,
} gss_api_auth_state;

/* HTTP Service name, used to get the session key.  */
#define KRB_HTTP_SERVICE "HTTP"

/* Stores the context information related to Kerberos authentication. */
typedef struct
{
    apr_pool_t *pool;

    /* GSSAPI context */
    serf__kerb_context_t *gss_ctx;

    /* Current state of the authentication cycle. */
    gss_api_auth_state state;

    const char *header;
    const char *value;
} gss_authn_info_t;

/* On the initial 401 response of the server, request a session key from
   the Kerberos KDC to pass to the server, proving that we are who we
   claim to be. The session key can only be used with the HTTP service
   on the target host. */
static apr_status_t
gss_api_get_credentials(char *token, apr_size_t token_len,
                        const char *hostname,
                        const char **buf, apr_size_t *buf_len,
                        gss_authn_info_t *gss_info)
{
    serf__kerb_buffer_t input_buf;
    serf__kerb_buffer_t output_buf;
    apr_status_t status = APR_SUCCESS;

    /* If the server sent us a token, pass it to gss_init_sec_token for
       validation. */
    if (token) {
        input_buf.value = token;
        input_buf.length = token_len;
    } else {
        input_buf.value = 0;
        input_buf.length = 0;
    }

    /* Establish a security context to the server. */
    status = serf__kerb_init_sec_context
        (gss_info->gss_ctx,
         KRB_HTTP_SERVICE, hostname,
         &input_buf,
         &output_buf,
         gss_info->pool,
         gss_info->pool
        );

    switch(status) {
    case APR_SUCCESS:
        gss_info->state = gss_api_auth_completed;
        break;
    case APR_EAGAIN:
        gss_info->state = gss_api_auth_in_progress;
        status = APR_SUCCESS;
        break;
    default:
        status = SERF_ERROR_AUTHN_FAILED;
        break;
    }

    /* Return the session key to our caller. */
    *buf = output_buf.value;
    *buf_len = output_buf.length;

    return status;
}

/* Read the header sent by the server (if any), invoke the gssapi authn
   code and use the resulting Server Ticket  on the next request to the
   server. */
static apr_status_t
do_auth(peer_t peer,
        gss_authn_info_t *gss_info,
        serf_connection_t *conn,
        const char *auth_hdr,
        apr_pool_t *pool)
{
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info = (peer == HOST) ? &ctx->authn_info :
        &ctx->proxy_authn_info;
    const char *tmp = NULL;
    char *token = NULL;
    apr_size_t tmp_len = 0, token_len = 0;
    const char *space = NULL;
    apr_status_t status;

    /* The server will return a token as attribute to the Negotiate key.
       Negotiate YGwGCSqGSIb3EgECAgIAb10wW6ADAgEFoQMCAQ+iTzBNoAMCARCiRgREa6mouM
       BAMFqKVdTGtfpZNXKzyw4Yo1paphJdIA3VOgncaoIlXxZLnkHiIHS2v65pVvrp
       bRIyjF8xve9HxpnNIucCY9c=

       Read this base64 value, decode it and validate it so we're sure the server
       is who we expect it to be. */
    if (auth_hdr)
        space = strchr(auth_hdr, ' ');

    if (space) {
        token = apr_palloc(pool, apr_base64_decode_len(space + 1));
        token_len = apr_base64_decode(token, space + 1);
    }

    /* We can get a whole batch of 401 responses from the server, but we should
       only start the authentication phase once, so if we started authentication
       already ignore all responses with initial Negotiate authentication header.

       Note: as we set the max. transfer rate to one message at a time until the
       authentication cycle is finished, this check shouldn't be needed. */
    if (!token && gss_info->state != gss_api_auth_not_started) {
        serf__log_skt(AUTH_VERBOSE, __FILE__, conn->skt,
                      "We already started the Kerberos handshake, ignoring "\
                      "response with initial authz header.\n");
        return APR_SUCCESS;
    }

    if (peer == HOST) {
        status = gss_api_get_credentials(token, token_len,
                                         conn->host_info.hostname,
                                         &tmp, &tmp_len,
                                         gss_info);
    } else {
        char *proxy_host;
        apr_getnameinfo(&proxy_host, conn->ctx->proxy_address, 0);
        status = gss_api_get_credentials(token, token_len, proxy_host,
                                         &tmp, &tmp_len,
                                         gss_info);
    }
    if (status)
        return status;

    /* On the next request, add an Authorization header. */
    if (tmp_len) {
        serf__encode_auth_header(&gss_info->value, authn_info->scheme->name,
                                 tmp,
                                 tmp_len,
                                 pool);
        gss_info->header = (peer == HOST) ?
            "Authorization" : "Proxy-Authorization";
    }

    /* If the handshake is finished tell serf it can send as much requests as it
       likes. */
    if (gss_info->state == gss_api_auth_completed) {
        serf__log_skt(AUTH_VERBOSE, __FILE__, conn->skt,
                      "Kerberos authz completed.\n");
        serf_connection_set_max_outstanding_requests(conn, 0);
    }

    return APR_SUCCESS;
}

apr_status_t
serf__init_kerb(int code,
                serf_context_t *ctx,
                apr_pool_t *pool)
{
    return APR_SUCCESS;
}

/* A new connection is created to a server that's known to use
   Kerberos. */
apr_status_t
serf__init_kerb_connection(int code,
                           serf_connection_t *conn,
                           apr_pool_t *pool)
{
    gss_authn_info_t *gss_info;
    apr_status_t status;

    gss_info = apr_pcalloc(pool, sizeof(*gss_info));
    gss_info->pool = conn->pool;
    gss_info->state = gss_api_auth_not_started;
    status = serf__kerb_create_sec_context(&gss_info->gss_ctx, pool,
                                           gss_info->pool);

    if (status) {
        return status;
    }

    if (code == 401) {
        conn->authn_baton = gss_info;
    } else {
        conn->proxy_authn_baton = gss_info;
    }

    /* Make serf send the initial requests one by one */
    serf_connection_set_max_outstanding_requests(conn, 1);

    serf__log_skt(AUTH_VERBOSE, __FILE__, conn->skt,
                  "Initialized Kerberos context for this connection.\n");

    return APR_SUCCESS;
}

/* A 401 response was received, handle the authentication. */
apr_status_t
serf__handle_kerb_auth(int code,
                       serf_request_t *request,
                       serf_bucket_t *response,
                       const char *auth_hdr,
                       const char *auth_attr,
                       void *baton,
                       apr_pool_t *pool)
{
    serf_connection_t *conn = request->conn;
    gss_authn_info_t *gss_info = (code == 401) ? conn->authn_baton :
        conn->proxy_authn_baton;

    return do_auth(code == 401 ? HOST : PROXY,
                   gss_info,
                   request->conn,
                   auth_hdr,
                   pool);
}

/* Setup the authn headers on this request message. */
apr_status_t
serf__setup_request_kerb_auth(int code,
                              serf_connection_t *conn,
                              const char *method,
                              const char *uri,
                              serf_bucket_t *hdrs_bkt)
{
    gss_authn_info_t *gss_info = (code == 401) ? conn->authn_baton :
        conn->proxy_authn_baton;

    if (gss_info && gss_info->header && gss_info->value) {
        serf_bucket_headers_setn(hdrs_bkt, gss_info->header,
                                 gss_info->value);

        /* We should send each token only once. */
        gss_info->header = NULL;
        gss_info->value = NULL;
        return APR_SUCCESS;
    }

    return SERF_ERROR_AUTHN_FAILED;
}

/* Function is called when 2xx responses are received. Normally we don't
 * have to do anything, except for the first response after the
 * authentication handshake. This specific response includes authentication
 * data which should be validated by the client (mutual authentication).
 */
apr_status_t
serf__validate_response_kerb_auth(peer_t peer,
                                  int code,
                                  serf_connection_t *conn,
                                  serf_request_t *request,
                                  serf_bucket_t *response,
                                  apr_pool_t *pool)
{
    gss_authn_info_t *gss_info;
    serf_bucket_t *hdrs;
    const char *auth_hdr;

    hdrs = serf_bucket_response_get_headers(response);
    if (peer == HOST) {
        gss_info = conn->authn_baton;
        auth_hdr = serf_bucket_headers_get(hdrs, "WWW-Authenticate");
    } else {
        gss_info = conn->proxy_authn_baton;
        auth_hdr = serf_bucket_headers_get(hdrs, "Proxy-Authenticate");
    }
    if (gss_info->state != gss_api_auth_completed) {
        return do_auth(peer,
                       gss_info,
                       conn,
                       auth_hdr,
                       pool);
    }

    return APR_SUCCESS;
}

#endif /* SERF_HAVE_GSSAPI */
