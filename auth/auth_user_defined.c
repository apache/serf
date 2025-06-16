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
struct callback_authn_baton {
    /* The connection's pipelining state before we changed it. */
    int pipelining;

    /* The user-defined scheme's per-connection baton. */
    void *user_authn_baton;
};


apr_status_t
serf__authn_user__init_conn(const serf__authn_scheme_t *scheme,
                            int code,
                            serf_connection_t *conn,
                            apr_pool_t *pool)
{
    serf__authn_info_t *const authn_info = get_authn_info(code, conn);
    struct callback_authn_baton *authn_baton;
    apr_status_t status = APR_SUCCESS;

    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: init-conn\n",
              scheme->name);

    if (!validate_user_authn(scheme)) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "Not a user-defined scheme: %s\n", scheme->name);
        return APR_EINVAL;
    }
    if (!scheme->user_init_conn_func) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: missing callback: init-conn\n",
                  scheme->name);
        return APR_ENOTIMPL;
    }
    if (!authn_info) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s init-conn: invalid code: %d\n",
                  scheme->name, code);
        return APR_ERANGE;
    }

    authn_baton = authn_info->baton;
    if (authn_baton == NULL) {
        apr_pool_t *scratch_pool;

        serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: create authn baton\n",
                  scheme->name);

        apr_pool_create(&scratch_pool, pool);
        authn_baton = apr_pcalloc(pool, sizeof(*authn_baton));
        status = scheme->user_init_conn_func(scheme->user_baton, code,
                                             pool, scratch_pool,
                                             &authn_baton->user_authn_baton);
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
    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, request->conn->config,
              "User-defined scheme %s: callback: handle-auth\n",
              scheme->name);

    if (!validate_user_authn(scheme)) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, request->conn->config,
                  "Not a user-defined scheme: %s\n", scheme->name);
        return APR_EINVAL;
    }
    if (!scheme->user_handle_func) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, request->conn->config,
                  "User-defined scheme %s: missing callback: handle-auth\n",
                  scheme->name);
        return APR_ENOTIMPL;
    }

    return APR_ENOTIMPL;
}


apr_status_t
serf__authn_user__setup_request(const serf__authn_scheme_t *scheme,
                                peer_t peer,
                                int code,
                                serf_connection_t *conn,
                                serf_request_t *request,
                                const char *method,
                                const char *uri,
                                serf_bucket_t *hdrs_bkt)
{
    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: setup-request\n",
              scheme->name);

    if (!validate_user_authn(scheme)) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "Not a user-defined scheme: %s\n", scheme->name);
        return APR_EINVAL;
    }
    if (!scheme->user_setup_request_func) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s: missing callback: setup-request\n",
                  scheme->name);
        return APR_ENOTIMPL;
    }

    return APR_ENOTIMPL;
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
    serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__, conn->config,
              "User-defined scheme %s: callback: validate-response\n",
              scheme->name);

    if (!validate_user_authn(scheme)) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "Not a user-defined scheme: %s\n", scheme->name);
        return APR_EINVAL;
    }
    if (!scheme->user_validate_response_func) {
        serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "User-defined scheme %s:"
                  " missing callback: validate-response\n",
                  scheme->name);
        return APR_ENOTIMPL;
    }

    return APR_ENOTIMPL;
}
