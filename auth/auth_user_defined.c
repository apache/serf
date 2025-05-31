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


static const serf__user_authn_scheme_t *
safe_cast_scheme(const serf__authn_scheme_t *scheme)
{
    const serf__user_authn_scheme_t *const user_scheme = (const void *)scheme;
    if (scheme->type >= SERF__AUTHN_USER_FIRST
        && user_scheme->magic == serf__authn_user__magic)
        return user_scheme;
    return NULL;
}

apr_status_t
serf__authn_user__init_conn(const serf__authn_scheme_t *scheme,
                            int code,
                            serf_connection_t *conn,
                            apr_pool_t *pool)
{
    if (!safe_cast_scheme(scheme))
        return APR_EINVAL;

    return APR_ENOTIMPL;
}

apr_status_t
serf__authn_user__handler(const serf__authn_scheme_t *scheme,
                          int code,
                          serf_request_t *request,
                          serf_bucket_t *response,
                          const char *auth_hdr,
                          const char *auth_attr,
                          apr_pool_t *pool)
{
    if (!safe_cast_scheme(scheme))
        return APR_EINVAL;

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
    if (!safe_cast_scheme(scheme))
        return APR_EINVAL;

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
    if (!safe_cast_scheme(scheme))
        return APR_EINVAL;

    return APR_ENOTIMPL;
}
