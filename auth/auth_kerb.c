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

/*** Kerberos authentication ***/

#include <serf.h>
#include <serf_private.h>
#include <auth/auth.h>

#include <apr.h>
#include <apr_base64.h>
#include <apr_strings.h>
#include <gssapi/gssapi.h>

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
    gss_ctx_id_t gss_ctx;

    /* Current state of the authentication cycle. */
    gss_api_auth_state state;

    /* Mechanism used to authenticate, should be Kerberos. */
    gss_OID mech;

    const char *header;
    const char *value;
} gss_authn_info_t;

static apr_status_t
create_gss_api_error(OM_uint32 maj_err, OM_uint32 min_err, apr_pool_t *pool)
{
    OM_uint32 message_ctx = 0;
    OM_uint32 min_stat;
    char *maj_err_str = NULL, *min_err_str = NULL;

    maj_err_str = apr_psprintf(pool, "major status: %8.8x", maj_err);
    do {
        gss_buffer_desc err_str;
        if (GSS_ERROR(gss_display_status(&min_stat, maj_err, GSS_C_GSS_CODE,
                                         GSS_C_NO_OID, &message_ctx, &err_str)))
            break;
        maj_err_str = apr_pstrcat(pool, maj_err_str, ": ",
                                  (char *)err_str.value, NULL);
        gss_release_buffer(&min_stat, &err_str);
    } while (message_ctx);

    message_ctx = 0;
    min_err_str = apr_psprintf(pool, "minor status: %8.8x", min_err);
    do {
        gss_buffer_desc err_str;
        if (GSS_ERROR(gss_display_status(&min_stat, min_err, GSS_C_MECH_CODE,
                                         GSS_C_NO_OID, &message_ctx, &err_str)))
            break;
        min_err_str = apr_pstrcat(pool, min_err_str, ": ",
                                  (char *)err_str.value, NULL);
        gss_release_buffer(&min_stat, &err_str);
    } while (message_ctx);

    /* Initialization of the GSSAPI context failed.
       See min_err_str and maj_err_str for more information. */
    return SERF_ERROR_AUTHN_INITALIZATION_FAILED;
}

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
    gss_buffer_desc input_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_buf;
    OM_uint32 min_stat, maj_stat;
    gss_name_t host_gss_name;
    gss_buffer_desc bufdesc;
    apr_status_t status = APR_SUCCESS;

    /* Get the name for the HTTP service at the target host. */
    bufdesc.value = apr_psprintf(gss_info->pool, KRB_HTTP_SERVICE "@%s",
                                 hostname);
    bufdesc.length = strlen(bufdesc.value);
    maj_stat = gss_import_name (&min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
                                &host_gss_name);
    if(GSS_ERROR(maj_stat)) {
        return create_gss_api_error(maj_stat, min_stat, gss_info->pool);
    }

    /* If the server sent us a token, pass it to gss_init_sec_token for
       validation. */
    if (token) {
        input_buf.value = token;
        input_buf.length = token_len;
    }

    /* Establish a security context to the server. */
    maj_stat = gss_init_sec_context
        (&min_stat,                 /* minor_status */
         GSS_C_NO_CREDENTIAL,       /* XXXXX claimant_cred_handle */
         &gss_info->gss_ctx,        /* gssapi context handle */
         host_gss_name,             /* HTTP@server name */
         gss_info->mech,            /* mech_type (0 ininitially */
         GSS_C_MUTUAL_FLAG,         /* ensure the peer authenticates itself */
         0,                         /* default validity period */
         GSS_C_NO_CHANNEL_BINDINGS, /* do not use channel bindings */
         &input_buf,                /* server token, initially empty */
         &gss_info->mech,           /* actual mech type */
         &output_buf,               /* output_token */
         NULL,                      /* ret_flags */
         NULL                       /* not interested in remaining validity */
         );

    if(GSS_ERROR(maj_stat)) {
        switch(maj_stat) {
        case GSS_S_COMPLETE:
            gss_info->state = gss_api_auth_completed;
            break;
        case GSS_S_CONTINUE_NEEDED:
            gss_info->state = gss_api_auth_in_progress;
            break;
        default:
            status = create_gss_api_error(maj_stat, min_stat, gss_info->pool);
            goto cleanup;
        }
    }

    /* Return the session key to our caller. */
    *buf = apr_pmemdup(gss_info->pool, output_buf.value, output_buf.length);
    *buf_len = output_buf.length;

    gss_release_buffer(&min_stat, &output_buf);

 cleanup:
    gss_release_name(&min_stat, &host_gss_name);

    return status;
}

/* Read the header sent by the server (if any), invoke the gssapi authn
   code and use the resulting Server Ticket  on the next request to the
   server. */
static apr_status_t
do_auth(int code,
        gss_authn_info_t *gss_info,
        serf_connection_t *conn,
        const char *auth_attr,
        apr_pool_t *pool)
{
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info = (code == 401) ? &ctx->authn_info :
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
    if (auth_attr)
        space = strchr(auth_attr, ' ');

    if (space) {
        token = apr_palloc(pool, apr_base64_decode_len(space + 1));
        token_len = apr_base64_decode(token, space + 1);
    }

    /* We can get a whole batch of 401 responses from the server, but we should
       only start the authentication phase once, so if we started authentication
       already ignore all responses with initial Negotiate authentication header.

       Note: as we set the max. transfer rate to one message at a time until the
       authentication cycle is finished, this check shouldn't be needed. */
    if (!token && gss_info->state != gss_api_auth_not_started)
        return APR_SUCCESS;

    status = gss_api_get_credentials(token, token_len, conn->host_info.hostname,
                                     &tmp, &tmp_len,
                                     gss_info);
    if (status)
        return status;

    serf__encode_auth_header(&gss_info->value, authn_info->scheme->name,
                             tmp,
                             tmp_len,
                             pool);
    gss_info->header = (code == 401) ? "Authorization" : "Proxy-Authorization";

    /* If the handshake is finished tell serf it can send as much requests as it
       likes. */
    if (gss_info->state == gss_api_auth_completed)
        serf_connection_set_max_outstanding_requests(conn, 0);

    return APR_SUCCESS;
}

apr_status_t
serf__init_kerb(int code,
                serf_context_t *ctx,
                apr_pool_t *pool)
{
    return APR_SUCCESS;
}

/* Cleans the gssapi context object, when the pool used to create it gets
   cleared or destroyed. */
static apr_status_t
cleanup_gss_ctx(void *data)
{
    gss_ctx_id_t gss_ctx = data;
    OM_uint32 min_stat;

    if (gss_ctx != GSS_C_NO_CONTEXT) {
        if (gss_delete_sec_context(&min_stat, &gss_ctx,
                                   GSS_C_NO_BUFFER) == GSS_S_FAILURE)
            return APR_EGENERAL;
    }

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

    gss_info = apr_pcalloc(pool, sizeof(*gss_info));
    gss_info->pool = conn->pool;
    gss_info->state = gss_api_auth_not_started;
    gss_info->gss_ctx = GSS_C_NO_CONTEXT;
    if (code == 401) {
        conn->authn_baton = gss_info;
    } else {
        conn->proxy_authn_baton = gss_info;
    }

    apr_pool_cleanup_register(gss_info->pool, gss_info->gss_ctx,
                              cleanup_gss_ctx,
                              apr_pool_cleanup_null);

    /* Make serf send the initial requests one by one */
    serf_connection_set_max_outstanding_requests(conn, 1);

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

    return do_auth(code,
                   gss_info,
                   request->conn,
                   auth_attr,
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
serf__validate_response_kerb_auth(int code,
                                    serf_connection_t *conn,
                                    serf_request_t *request,
                                    serf_bucket_t *response,
                                    apr_pool_t *pool)
{
    gss_authn_info_t *gss_info = (code == 401) ? conn->authn_baton :
        conn->proxy_authn_baton;
    serf_bucket_t *hdrs;
    const char *auth_attr;

    hdrs = serf_bucket_response_get_headers(response);
    auth_attr = serf_bucket_headers_get(hdrs, "WWW-Authenticate");

    if (gss_info->state != gss_api_auth_completed) {
        return do_auth(code,
                       gss_info,
                       conn,
                       auth_attr,
                       pool);
    }

    return APR_SUCCESS;
}
