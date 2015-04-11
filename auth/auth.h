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

#ifndef AUTH_H
#define AUTH_H

#include "auth_spnego.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * For each authentication scheme we need a handler function of type
 * serf__auth_handler_func_t. This function will be called when an
 * authentication challenge is received in a session.
 */
typedef apr_status_t
(*serf__auth_handler_func_t)(const serf__authn_scheme_t *scheme,
                             int code,
                             serf_request_t *request,
                             serf_bucket_t *response,
                             const char *auth_hdr,
                             const char *auth_attr,
                             apr_pool_t *pool);

/**
 * For each authentication scheme we need an initialization function of type
 * serf__init_conn_func_t. This function will be called when a new
 * connection is opened.
 */
typedef apr_status_t
(*serf__init_conn_func_t)(const serf__authn_scheme_t *scheme,
                          int code,
                          serf_connection_t *conn,
                          apr_pool_t *pool);

/**
 * For each authentication scheme we need a setup_request function of type
 * serf__setup_request_func_t. This function will be called when a
 * new serf_request_t object is created and should fill in the correct
 * authentication headers (if needed).
 */
typedef apr_status_t
(*serf__setup_request_func_t)(const serf__authn_scheme_t *scheme,
                              peer_t peer,
                              int code,
                              serf_connection_t *conn,
                              serf_request_t *request,
                              const char *method,
                              const char *uri,
                              serf_bucket_t *hdrs_bkt);

/**
 * This function will be called when a response is received, so that the 
 * scheme handler can validate the Authentication related response headers
 * (if needed).
 */
typedef apr_status_t
(*serf__validate_response_func_t)(const serf__authn_scheme_t *scheme,
                                  peer_t peer,
                                  int code,
                                  serf_connection_t *conn,
                                  serf_request_t *request,
                                  serf_bucket_t *response,
                                  apr_pool_t *pool);

/**
 * serf__authn_scheme_t: vtable for an authn scheme provider.
 */
struct serf__authn_scheme_t {
    /* The name of this authentication scheme. Used in headers of requests and
       for logging. */
    const char *name;

    /* Key is the name of the authentication scheme in lower case, to
       facilitate case insensitive matching of the response headers. */
    const char *key;

    /* Internal code used for this authn type. */
    int type;

    /* The connection initialization function if any; otherwise, NULL */
    serf__init_conn_func_t init_conn_func;

    /* The authentication handler function */
    serf__auth_handler_func_t handle_func;

    /* Function to set up the authentication header of a request */
    serf__setup_request_func_t setup_request_func;

    /* Function to validate the authentication header of a response */
    serf__validate_response_func_t validate_response_func;
};


void serf__encode_auth_header(const char **header, const char *protocol,
                              const char *data, apr_size_t data_len,
                              apr_pool_t *pool);

/* Prefixes the realm_name with a string containing scheme, hostname and port
   of the connection, for providing it to the application. */
const char *serf__construct_realm(peer_t peer,
                                  serf_connection_t *conn,
                                  const char *realm_name,
                                  apr_pool_t *pool);

/** Basic authentication **/
extern const serf__authn_scheme_t serf__basic_authn_scheme;
;
/** Digest authentication **/
extern const serf__authn_scheme_t serf__digest_authn_scheme;

#ifdef SERF_HAVE_SPNEGO
/** Kerberos authentication **/

extern const serf__authn_scheme_t serf__spnego_authn_scheme;

#ifdef WIN32
extern const serf__authn_scheme_t serf__ntlm_authn_scheme;
#endif /* #ifdef WIN32 */

#endif /* SERF_HAVE_SPNEGO */

#ifdef __cplusplus
}
#endif

#endif    /* !AUTH_H */
