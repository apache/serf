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

#include <serf.h>
#include <serf_private.h>

#include "apr_errno.h"
#include "auth.h"


static bool validate_user_authn(const serf__authn_scheme_t *scheme)
{
    return (scheme->type & *serf__authn_user__type_mask
            && scheme->user_magic == serf__authn_user__magic);
}


static serf__authn_info_t *get_authn_info(int code, serf_connection_t *conn)
{
    switch (code)
    {
    case SERF_AUTHN_CODE_HOST:
        return serf__get_authn_info_for_server(conn);
    case SERF_AUTHN_CODE_PROXY:
        return &conn->ctx->proxy_authn_info;
    }

    /* FIXME: ??? Shouldn't be possible. */
    return NULL;
}


/* Used for serf__authn_info_t::baton  */
struct authn_baton_wrapper {
    /* The connection's pipelining state before we changed it. */
    int pipelining;

    /* Was pipelining reset to its previous value?. */
    bool pipelining_reset;

    /* The user-defined scheme's per-connection baton. */
    void *user_authn_baton;
};


typedef apr_status_t (*callback_fn_t)();
static apr_status_t validate_handler(serf_config_t *config,
                                     const serf__authn_scheme_t *scheme,
                                     int peer_id,
                                     const char *callback_name,
                                     callback_fn_t callback_func,
                                     serf__authn_info_t *authn_info)
{
    if (!validate_user_authn(scheme)) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, config,
                  "Not a user-defined scheme: %s\n", scheme->name);
        return APR_EINVAL;
    }
    if (!scheme->user_init_conn_func) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, config,
                  "User-defined scheme %s: missing callback: %s\n",
                  scheme->name, callback_name);
        return APR_ENOTIMPL;
    }
    if (!authn_info) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, config,
                  "User-defined scheme %s %s: invalid peer: %d\n",
                  scheme->name, callback_name, peer_id);
        return APR_ERANGE;
    }
    return APR_SUCCESS;
}


apr_status_t
serf__authn_user__init_conn(const serf__authn_scheme_t *scheme,
                            int code,
                            serf_connection_t *conn,
                            apr_pool_t *pool)
{
    serf__authn_info_t *const authn_info = get_authn_info(code, conn);
    struct authn_baton_wrapper *authn_baton;
    apr_status_t status;

    status = validate_handler(conn->config, scheme, code, "init-conn",
                              scheme->user_init_conn_func,
                              authn_info);
    if (status)
        return status;

    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: init-conn\n",
              scheme->name);

    authn_baton = authn_info->baton;
    if (authn_baton == NULL) {
        apr_pool_t *scratch_pool;

        serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: create authn baton\n",
                  scheme->name);

        apr_pool_create(&scratch_pool, pool);
        authn_baton = apr_pcalloc(pool, sizeof(*authn_baton));
        status = scheme->user_init_conn_func(&authn_baton->user_authn_baton,
                                             scheme->user_baton, code,
                                             pool, scratch_pool);
        apr_pool_destroy(scratch_pool);

        if (status == APR_SUCCESS)
            authn_info->baton = authn_baton;
    }

    /* Turn off pipelining if the scheme requires it. */
    if (status == APR_SUCCESS
        && !(scheme->user_flags & SERF_AUTHN_FLAG_PIPE)) {
        serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: pipelining off for %s\n",
                  scheme->name, conn->host_url);
        authn_baton->pipelining = serf__connection_set_pipelining(conn, 0);
        authn_baton->pipelining_reset = false;
    } else {
        authn_baton->pipelining_reset = true;
    }
    return status;
}


apr_status_t
serf__authn_user__handle(const serf__authn_scheme_t *scheme,
                         int code,
                         serf_request_t *request,
                         serf_bucket_t *response,
                         const char *auth_hdr,
                         const char *auth_attr,
                         apr_pool_t *pool)
{
    serf_connection_t *const conn = request->conn;
    serf__authn_info_t *const authn_info = get_authn_info(code, conn);
    serf_context_t *const ctx = conn->ctx;
    struct authn_baton_wrapper *authn_baton;
    char *username, *password;
    apr_pool_t *scratch_pool;
    apr_status_t status;

    status = validate_handler(conn->config, scheme, code, "handle-auth",
                              scheme->user_handle_func,
                              authn_info);
    if (status)
        return status;

    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, ctx->config,
              "User-defined scheme %s: callback: handle-auth\n",
              scheme->name);

    /* The credentials callback must be set if the scheme requires it. */
    if (scheme->user_flags & SERF_AUTHN_FLAG_CREDS) {
        bool failed = false;

        if (!ctx->cred_cb) {
            serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                      "User-defined scheme %s handle-auth:"
                      " missing credentials callback\n",
                      scheme->name);
            failed = true;
        }

        if (!scheme->user_get_realm_func) {
            serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, ctx->config,
                      "User-defined scheme %s handle-auth:"
                      " missing callback: get-realm\n",
                      scheme->name);
            failed = true;
        }

        if (failed)
            return SERF_ERROR_AUTHN_FAILED;
    }

    authn_baton = authn_info->baton;
    apr_pool_create(&scratch_pool, pool);

    status = APR_SUCCESS;
    if (scheme->user_flags & SERF_AUTHN_FLAG_CREDS) {
        const char *realm_name;
        status = scheme->user_get_realm_func(&realm_name,
                                             scheme->user_baton,
                                             authn_baton->user_authn_baton,
                                             auth_hdr, auth_attr,
                                             scratch_pool, scratch_pool);
        if (!status) {
            const char *const realm = serf__construct_realm(
                SERF__PEER_FROM_CODE(code), conn, realm_name, scratch_pool);
            status = serf__provide_credentials(ctx,
                                               &username, &password,
                                               request,
                                               code, scheme->name,
                                               realm, scratch_pool);
        }
        if (status)
            goto cleanup;
    } else {
        username = password = NULL;
    }

    status = scheme->user_handle_func(scheme->user_baton,
                                      authn_baton->user_authn_baton, code,
                                      auth_hdr, auth_attr,
                                      SERF__HEADER_FROM_CODE(code),
                                      username, password,
                                      request, response,
                                      pool, scratch_pool);

  cleanup:
    apr_pool_destroy(scratch_pool);
    return status;
}


apr_status_t
serf__authn_user__setup_request(const serf__authn_scheme_t *scheme,
                                peer_t peer,
                                int code, /* Ignored, always 0. */
                                serf_connection_t *conn,
                                serf_request_t *request,
                                const char *method,
                                const char *uri,
                                serf_bucket_t *hdrs_bkt)
{
    const int peer_id = SERF__CODE_FROM_PEER(peer);
    serf__authn_info_t *const authn_info = get_authn_info(peer_id, conn);
    struct authn_baton_wrapper *authn_baton;
    apr_pool_t *scratch_pool;
    apr_status_t status;

    status = validate_handler(conn->config, scheme, peer_id, "setup-request",
                              scheme->user_setup_request_func,
                              authn_info);
    if (status)
        return status;

    if (!authn_info->baton) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s setup-request: no authn data\n",
                  scheme->name);
        return APR_ERANGE;
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: setup-request\n",
              scheme->name);

    authn_baton = authn_info->baton;
    apr_pool_create(&scratch_pool, conn->pool);
    status = scheme->user_setup_request_func(scheme->user_baton,
                                             authn_baton->user_authn_baton,
                                             conn, request,
                                             method, uri, hdrs_bkt,
                                             scratch_pool);
    apr_pool_destroy(scratch_pool);
    return status;
}


apr_status_t
serf__authn_user__validate_response(const serf__authn_scheme_t *scheme,
                                    peer_t peer,
                                    int code,
                                    serf_connection_t *conn,
                                    serf_request_t *request,
                                    serf_bucket_t *response,
                                    apr_pool_t *pool)
{
    const int peer_id = SERF__CODE_FROM_PEER(peer);
    serf__authn_info_t *const authn_info = get_authn_info(peer_id, conn);
    int reset_pipelining = 0;
    struct authn_baton_wrapper *authn_baton;
    apr_pool_t *scratch_pool;
    apr_status_t status;

    status = validate_handler(conn->config, scheme, peer_id,
                              "validate-response",
                              scheme->user_validate_response_func,
                              authn_info);
    if (status)
        return status;

    if (!authn_info->baton) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s validate-response: no authn data\n",
                  scheme->name);
        return APR_ERANGE;
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: validate-response\n",
              scheme->name);

    authn_baton = authn_info->baton;
    apr_pool_create(&scratch_pool, conn->pool);
    status = scheme->user_validate_response_func(&reset_pipelining,
                                                 scheme->user_baton,
                                                 authn_baton->user_authn_baton,
                                                 code, conn, request, response,
                                                 scratch_pool);

    /* Reset pipelining if the scheme requires it. */
    if (status == APR_SUCCESS && reset_pipelining
        && !authn_baton->pipelining_reset
        && !(scheme->user_flags & SERF_AUTHN_FLAG_PIPE)) {
        serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: pipelining reset to %s for %s\n",
                  scheme->name,
                  authn_baton->pipelining ? "on" : "off",
                  conn->host_url);
        serf__connection_set_pipelining(conn, authn_baton->pipelining);
        authn_baton->pipelining_reset = true;
    }

    apr_pool_destroy(scratch_pool);
    return status;
}
