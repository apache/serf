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
#include "auth.h"

#include <apr.h>
#include <apr_base64.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_lib.h>
#if APR_HAS_THREADS
#  include <stdlib.h>
#  include <apr_atomic.h>
#  include <apr_time.h>
#  include <apr_thread_mutex.h>
#endif

#include <limits.h>

/* These authentication schemes are in order of decreasing security, the topmost
   scheme will be used first when the server supports it.

   Each set of handlers should support both server (401) and proxy (407)
   authentication.

   Use lower case for the scheme names to enable case insensitive matching.

   The size of the array is the number of bits in serf__authn_scheme_t::type,
   plus one slot for the NULL sentinel.
 */
#define AUTHN_SCHEMES_SIZE (sizeof(unsigned int) * CHAR_BIT + 1)
static const serf__authn_scheme_t *serf_authn_schemes[AUTHN_SCHEMES_SIZE] = {
#ifdef SERF_HAVE_SPNEGO
    &serf__spnego_authn_scheme,
#ifdef WIN32
    &serf__ntlm_authn_scheme,
#endif /* #ifdef WIN32 */
#endif /* SERF_HAVE_SPNEGO */
    &serf__digest_authn_scheme,
    &serf__basic_authn_scheme,
    /* ADD NEW AUTHENTICATION IMPLEMENTATIONS HERE (as they're written) */

    /* sentinel */
    NULL

    /* The rest of the array will be automagically zero-initialized. */
};

#if APR_HAS_THREADS
/* Guard access to serf_authn_schemes and related global data. */
static apr_thread_mutex_t *authn_schemes_guard;
static apr_pool_t *authn_schemes_guard_pool;
static apr_status_t init_authn_schemes_guard();
#endif

static apr_status_t lock_autn_schemes(serf_config_t *config)
{
#if APR_HAS_THREADS
    apr_status_t status = init_authn_schemes_guard();
    if (status == APR_SUCCESS) {
        status = apr_thread_mutex_lock(authn_schemes_guard);
        if (status) {
            char buffer[256];
            serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, config,
                      "Lock authn schemes: %s\n",
                      apr_strerror(status, buffer, sizeof(buffer)));
        }
    }
    return status;
#else
    return APR_SUCCESS;
#endif
}

static apr_status_t unlock_autn_schemes(serf_config_t *config)
{
#if APR_HAS_THREADS
    apr_status_t status = init_authn_schemes_guard();
    if (status == APR_SUCCESS) {
        status = apr_thread_mutex_unlock(authn_schemes_guard);
        if (status) {
            char buffer[256];
            serf__log(LOGLVL_ERROR, LOGCOMP_AUTHN, __FILE__, config,
                      "Unlock authn schemes: %s\n",
                      apr_strerror(status, buffer, sizeof(buffer)));
        }
    }
    return status;
#else
    return APR_SUCCESS;
#endif
}


/* Reads and discards all bytes in the response body. */
static apr_status_t discard_body(serf_bucket_t *response)
{
    apr_status_t status;
    const char *data;
    apr_size_t len;

    while (1) {
        status = serf_bucket_read(response, SERF_READ_ALL_AVAIL, &data, &len);

        if (status) {
            return status;
        }

        /* feed me */
    }
}

/**
 * handle_auth_header is called for each header in the response. It filters
 * out the Authenticate headers (WWW or Proxy depending on what's needed) and
 * tries to find a matching scheme handler.
 *
 * Returns a non-0 value of a matching handler was found.
 */
static int handle_auth_headers(int code,
                               apr_hash_t *hdrs,
                               serf_request_t *request,
                               serf_bucket_t *response,
                               apr_pool_t *pool)
{
    int scheme_idx;
    serf_connection_t *conn = request->conn;
    serf_context_t *ctx = conn->ctx;
    apr_status_t status, lock_status;

    lock_status = lock_autn_schemes(conn->config);
    if (lock_status)
        return lock_status;

    status = SERF_ERROR_AUTHN_NOT_SUPPORTED;

    /* Find the matching authentication handler.
       Note that we don't reuse the auth scheme stored in the context,
       as that may have changed. (ex. fallback from ntlm to basic.) */
    for (scheme_idx = 0; serf_authn_schemes[scheme_idx]; ++scheme_idx) {
        const char *auth_hdr;
        serf__auth_handler_func_t handler;
        serf__authn_info_t *authn_info;
        const serf__authn_scheme_t *scheme = serf_authn_schemes[scheme_idx];

        if (! (ctx->authn_types & scheme->type))
            continue;

        serf__log(LOGLVL_INFO, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "Client supports: %s\n", scheme->name);

        auth_hdr = apr_hash_get(hdrs, scheme->key, APR_HASH_KEY_STRING);

        if (!auth_hdr)
            continue;

        if (code == 401) {
            authn_info = serf__get_authn_info_for_server(conn);
        } else {
            authn_info = &ctx->proxy_authn_info;
        }

        if (authn_info->failed_authn_types & scheme->type) {
            /* Skip this authn type since we already tried it before. */
            continue;
        }

        /* Found a matching scheme */
        status = APR_SUCCESS;

        handler = scheme->handle_func;

        serf__log(LOGLVL_INFO, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "... matched: %s\n", scheme->name);

        /* If this is the first time we use this scheme on this connection,
           make sure to initialize the authentication handler first. */
        if (authn_info->scheme != scheme) {
            status = scheme->init_conn_func(scheme, code, conn,
                                            conn->pool);
            if (!status)
                authn_info->scheme = scheme;
            else
                authn_info->scheme = NULL;
        }

        if (!status) {
            const char *auth_attr = strchr(auth_hdr, ' ');
            if (auth_attr) {
                auth_attr++;
            }

            status = handler(scheme, code, request, response,
                             auth_hdr, auth_attr, ctx->pool);
        }

        if (status == APR_SUCCESS)
            break;

        /* No success authenticating with this scheme, try the next.
           If no more authn schemes are found the status of this scheme will be
           returned.
        */
        serf__log(LOGLVL_INFO, LOGCOMP_AUTHN, __FILE__, conn->config,
                  "%s authentication failed.\n", scheme->name);

        /* Clear per-request auth_baton when switching to next auth scheme. */
        request->auth_baton = NULL;

        /* Remember failed auth types to skip it in future. */
        authn_info->failed_authn_types |= scheme->type;
    }

    lock_status = unlock_autn_schemes(conn->config);
    if (lock_status)
        return lock_status;

    return status;
}

/**
 * Baton passed to the store_header_in_dict callback function
 */
typedef struct auth_baton_t {
    const char *header;
    apr_pool_t *pool;
    apr_hash_t *hdrs;
} auth_baton_t;

static int store_header_in_dict(void *baton,
                                const char *key,
                                const char *header)
{
    auth_baton_t *ab = baton;
    const char *auth_attr;
    char *auth_name, *c;

    /* We're only interested in xxxx-Authenticate headers. */
    if (strcasecmp(key, ab->header) != 0)
        return 0;

    /* Extract the authentication scheme name.  */
    auth_attr = strchr(header, ' ');
    if (auth_attr) {
        auth_name = apr_pstrmemdup(ab->pool, header, auth_attr - header);
    }
    else
        auth_name = apr_pstrmemdup(ab->pool, header, strlen(header));

    /* Convert scheme name to lower case to enable case insensitive matching. */
    for (c = auth_name; *c != '\0'; c++)
        *c = (char)apr_tolower(*c);

    apr_hash_set(ab->hdrs, auth_name, APR_HASH_KEY_STRING,
                 apr_pstrdup(ab->pool, header));

    return 0;
}

/* Dispatch authentication handling. This function matches the possible
   authentication mechanisms with those available. Server and proxy
   authentication are evaluated separately. */
static apr_status_t dispatch_auth(int code,
                                  serf_request_t *request,
                                  serf_bucket_t *response,
                                  apr_pool_t *pool)
{
    if (code == 401 || code == 407) {
        serf_bucket_t *hdrs;
        auth_baton_t ab = { 0 };

        ab.hdrs = apr_hash_make(pool);
        ab.pool = pool;

        if (code == 401)
            ab.header = "WWW-Authenticate";
        else
            ab.header = "Proxy-Authenticate";

        hdrs = serf_bucket_response_get_headers(response);

#ifdef SERF_LOGGING_ENABLED
        if (serf__log_enabled(LOGLVL_WARNING, LOGCOMP_AUTHN,
                              request->conn->config)) {
            const char *auth_hdr;

            /* ### headers_get() doesn't tell us whether to free this result
               ### or not. but... meh. debug mode.  */
            auth_hdr = serf_bucket_headers_get(hdrs, ab.header);
            if (auth_hdr == NULL) {
                serf__log(LOGLVL_WARNING, LOGCOMP_AUTHN, __FILE__,
                          request->conn->config,
                          "%s header missing in response!\n", ab.header);
            } else {
                serf__log(LOGLVL_DEBUG, LOGCOMP_AUTHN, __FILE__,
                          request->conn->config,
                          "%s authz required. Response header(s): %s\n",
                          code == 401 ? "Server" : "Proxy", auth_hdr);
            }
        }
#endif /* SERF_LOGGING_ENABLED */

        /* Store all WWW- or Proxy-Authenticate headers in a dictionary.

           Note: it is possible to have multiple Authentication: headers. We do
           not want to combine them (per normal header combination rules) as that
           would make it hard to parse. Instead, we want to individually parse
           and handle each header in the response, looking for one that we can
           work with.
        */
        serf_bucket_headers_do(hdrs,
                               store_header_in_dict,
                               &ab);
        if (apr_hash_count(ab.hdrs) == 0)
            return SERF_ERROR_AUTHN_FAILED;

        /* Iterate over all authentication schemes, in order of decreasing
           security. Try to find a authentication schema the server support. */
        return handle_auth_headers(code, ab.hdrs,
                                   request, response, pool);
    }

    return APR_SUCCESS;
}

/* Read the headers of the response and try the available handlers if
   authentication or validation is needed.
   *CONSUMED_RESPONSE will be 1 if authentication is involved (either a 401/407
   response or a response with an authn header), 0 otherwise. */
apr_status_t serf__handle_auth_response(bool *consumed_response,
                                        serf_request_t *request,
                                        serf_bucket_t *response,
                                        apr_pool_t *pool)
{
    apr_status_t status;
    serf_status_line sl;

    *consumed_response = false;

    /* TODO: the response bucket was created by the application, not at all
       guaranteed that this is of type response_bucket!! */
    status = serf_bucket_response_status(response, &sl);
    if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }
    if (!sl.version && (APR_STATUS_IS_EOF(status) ||
                        APR_STATUS_IS_EAGAIN(status))) {
        return status;
    }

    status = serf_bucket_response_wait_for_headers(response);
    if (status) {
        if (!APR_STATUS_IS_EOF(status)) {
            return status;
        }

        /* If status is APR_EOF, there were no headers to read.
           This can be ok in some situations, and it definitely
           means there's no authentication requested now. */
        return APR_SUCCESS;
    }

    if (sl.code == 401 || sl.code == 407) {
        /* Authentication requested. */

        /* Don't bother handling the authentication request if the response
           wasn't received completely yet. Serf will call serf__handle_auth_response
           again when more data is received. */

        status = dispatch_auth(sl.code, request, response, pool);
        if (status != APR_SUCCESS) {
            return status;
        }

        request->auth_done = true;

        /* Requeue the request with the necessary auth headers.*/
        status = serf_connection__request_requeue(request);

        if (status)
            return status;

        *consumed_response = true;

        return APR_SUCCESS;
    } else {
        serf__validate_response_func_t validate_resp;
        serf_connection_t *conn = request->conn;
        serf_context_t *ctx = conn->ctx;
        serf__authn_info_t *authn_info;
        apr_status_t resp_status = APR_SUCCESS;


        /* Validate the response server authn headers. */
        authn_info = serf__get_authn_info_for_server(conn);
        if (authn_info->scheme) {
            validate_resp = authn_info->scheme->validate_response_func;
            resp_status = validate_resp(authn_info->scheme, HOST, sl.code,
                                        conn, request, response, pool);
        }

        /* Validate the response proxy authn headers. */
        authn_info = &ctx->proxy_authn_info;
        if (!resp_status && authn_info->scheme) {
            validate_resp = authn_info->scheme->validate_response_func;
            resp_status = validate_resp(authn_info->scheme, PROXY, sl.code,
                                        conn, request, response, pool);
        }

        if (resp_status) {
            /* If there was an error in the final step of the authentication,
               consider the response body as invalid and discard it. */
            status = discard_body(response);
            *consumed_response = true;

            if (!APR_STATUS_IS_EOF(status)) {
                return status;
            }
            /* The whole body was discarded, now return our error. */
            return resp_status;
        }
    }

    request->auth_done = true;

    return APR_SUCCESS;
}

/**
 * base64 encode the authentication data and build an authentication
 * header in this format:
 * [SCHEME] [BASE64 of auth DATA]
 */
void serf__encode_auth_header(const char **header,
                              const char *scheme,
                              const char *data,
                              apr_size_t data_len,
                              apr_pool_t *pool)
{
    apr_size_t encoded_len, scheme_len;
    int int_data_len;
    char *ptr;


    SERF__POSITIVE_TO_INT(int_data_len, apr_size_t, data_len);

    encoded_len = apr_base64_encode_len(int_data_len);
    scheme_len = strlen(scheme);

    ptr = apr_palloc(pool, encoded_len + scheme_len + 1);
    *header = ptr;

    apr_cpystrn(ptr, scheme, scheme_len + 1);
    ptr += scheme_len;
    *ptr++ = ' ';

    apr_base64_encode(ptr, data, int_data_len);
}

const char *serf__construct_realm(peer_t peer,
                                  serf_connection_t *conn,
                                  const char *realm_name,
                                  apr_pool_t *pool)
{
    if (peer == HOST) {
        return apr_psprintf(pool, "<%s://%s:%d> %s",
                            conn->host_info.scheme,
                            conn->host_info.hostname,
                            conn->host_info.port,
                            realm_name);
    } else {
        serf_context_t *ctx = conn->ctx;

        return apr_psprintf(pool, "<http://%s:%d> %s",
                            ctx->proxy_address->hostname,
                            ctx->proxy_address->port,
                            realm_name);
    }
}

serf__authn_info_t *serf__get_authn_info_for_server(serf_connection_t *conn)
{
    serf_context_t *ctx = conn->ctx;
    serf__authn_info_t *authn_info;

    authn_info = apr_hash_get(ctx->server_authn_info, conn->host_url,
                              APR_HASH_KEY_STRING);

    if (!authn_info) {
        authn_info = apr_pcalloc(ctx->pool, sizeof(serf__authn_info_t));
        apr_hash_set(ctx->server_authn_info,
                     apr_pstrdup(ctx->pool, conn->host_url),
                     APR_HASH_KEY_STRING, authn_info);
    }

    return authn_info;
}

apr_status_t serf__auth_setup_connection(peer_t peer,
                                         serf_connection_t *conn)
{
    serf__authn_info_t *authn_info;
    serf_context_t *ctx = conn->ctx;
    apr_status_t status = APR_SUCCESS;

    if (peer == PROXY) {
        authn_info = &ctx->proxy_authn_info;
        if (authn_info->scheme) {
            status = authn_info->scheme->init_conn_func(authn_info->scheme,
                                                        407, conn,
                                                        conn->pool);
        }
    }
    else {
        authn_info = serf__get_authn_info_for_server(conn);
        if (authn_info->scheme) {
            status = authn_info->scheme->init_conn_func(authn_info->scheme,
                                                        401, conn,
                                                        conn->pool);
        }
    }

    return status;
}

apr_status_t serf__auth_setup_request(peer_t peer,
                                      serf_request_t *request,
                                      const char *method,
                                      const char *uri,
                                      serf_bucket_t *hdrs_bkt)
{

    if (peer == PROXY && request->conn->ctx->proxy_authn_info.scheme) {
        serf__authn_info_t *authn_info = &request->conn->ctx->proxy_authn_info;
        authn_info->scheme->setup_request_func(authn_info->scheme,
                                               peer, 0,
                                               request->conn, request,
                                               method, uri,
                                               hdrs_bkt);
    }
    else if (peer == HOST)
    {
        serf__authn_info_t *authn_info;

        authn_info = serf__get_authn_info_for_server(request->conn);
        if (authn_info->scheme) {
            authn_info->scheme->setup_request_func(authn_info->scheme,
                                                   HOST, 0, request->conn,
                                                   request, method, uri,
                                                   hdrs_bkt);
        }
    }

    return APR_SUCCESS;
}

/* User-defined authentication providers. */

/* The type range for user-defined schemes: */
#if UINT_MAX >= 0xFFFFFFFFFFFFFFFF /* Integers are at least 64 bits wide. */
#define SERF__AUTHN_USER_FIRST 0x80000000000u  /* 43 built-in + 21 user. */
#elif UINT_MAX >= 0xFFFFFFFF       /* Integers are at least 32 bits wide. */
#define SERF__AUTHN_USER_FIRST 0x200000u       /* 21 built-in + 11 user. */
#else                              /* Integers are at least 16 bits wide. */
#define SERF__AUTHN_USER_FIRST 0x800u          /* 11 built-in + 5 user. */
#endif

/* The magic number in the scheme struct.      serfauthnschemes */
const apr_uint64_t serf__authn_user__magic = 0x5e6fa02895c8e3e5;

/* The available user-defined scheme types. This is a bit mask based on the
   first scheme, later modified to account for any overlfow from the built-in
   schemes list (not likely, but safey). Should be const, but it's modified
   during one-time initialization.

   Access is controlled by authn_schemes_guard. */
static unsigned int user_authn_type_mask = ~(SERF__AUTHN_USER_FIRST - 1u);

/* Access to the above from other modules, made const. */
const unsigned int *const serf__authn_user__type_mask = &user_authn_type_mask;

/* The currently registered user-defined scheme types.

   Access is controlled by authn_schemes_guard. */
static unsigned int user_authn_registered = 0;

/* Find the next available bit for a user-defined authentication
   scheme. Computes an available bit, using user_authn_type_mask
   and user_authn_registered. Returns 0 if there's no more room for
   user-defined schemes.

   The authn_schemes_guard mutex must be locked. */
static unsigned int find_next_user_scheme_type(void)
{
    const unsigned int avail = user_authn_type_mask & ~user_authn_registered;

    /* For the source of this horrible hack, see:
       https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan

      return avail & ~(avail & (avail - 1));

      Along comes clang and optimizes the above to just two instructions... */
    return avail & -avail;
}

apr_status_t serf_authn_register_scheme(const char *name,
                                        void *baton,
                                        apr_pool_t *result_pool,
                                        int *type)
{
    serf__user_authn_scheme_t *user_scheme;
    apr_status_t lock_status;
    apr_status_t status;
    unsigned int scheme_type;
    const char *key;
    char *cp;
    int index;

    *type = SERF_AUTHN_NONE;
    user_scheme = apr_palloc(result_pool, sizeof(*user_scheme));
    user_scheme->magic = serf__authn_user__magic;
    user_scheme->baton = baton;

    /* Generate a lower-case key for the scheme. */
    key = cp = apr_pstrdup(result_pool, name);
    while (*cp) {
        *cp = apr_tolower(*cp);
        ++cp;
    }
    user_scheme->authn_scheme.name = apr_pstrdup(result_pool, name);
    user_scheme->authn_scheme.key = key;
    /* user_scheme->authn_scheme.type = ?; Will be updated later, under lock. */
    user_scheme->authn_scheme.init_conn_func = serf__authn_user__init_conn;
    user_scheme->authn_scheme.handle_func = serf__authn_user__handler;
    user_scheme->authn_scheme.setup_request_func = serf__authn_user__setup_request;
    user_scheme->authn_scheme.validate_response_func = serf__authn_user__validate_response;

    lock_status = lock_autn_schemes(NULL /* TODO: whence cometh config? */);
    if (lock_status)
        return lock_status;

    scheme_type = find_next_user_scheme_type();
    if (!scheme_type) {
        status = APR_ENOSPC;
        goto cleanup;
    }

    status = APR_SUCCESS;

    /* Scan the array for a free slot and also check that this
       scheme type hasn't been used yet. */
    for (index = 0; index < AUTHN_SCHEMES_SIZE - 1; ++index)
    {
        const serf__authn_scheme_t *const slot = serf_authn_schemes[index];
        if (slot == NULL)
            break;

        if (slot->type & scheme_type || 0 == strcmp(slot->key, key)) {
            /* We somehow managed to register the same thing twice. */
            status = APR_EEXIST;
            goto cleanup;
        }
    }
    if (index >= AUTHN_SCHEMES_SIZE - 1) {
        /* No more space in the table. Not very likely. */
        status = APR_ENOSPC;
        goto cleanup;
    }

    /* Insert into the slot, and add the sentinel. */
    user_scheme->authn_scheme.type = scheme_type;
    serf_authn_schemes[index] = &user_scheme->authn_scheme;
    serf_authn_schemes[index + 1] = NULL;
    *type = scheme_type;

    /* Add the scheme type to the registered mask. */
    user_authn_registered |= scheme_type;

  cleanup:
    lock_status = unlock_autn_schemes(NULL /* TODO: whence cometh config? */);
    if (lock_status)
        return lock_status;
    return status;
}

#ifdef SERF__AUTHN__HAVE_UNREGISTER
apr_status_t serf_authn_unregister_scheme(int type,
                                          const char *name,
                                          apr_pool_t *scratch_pool)
#else
apr_status_t serf__authn__unregister_scheme(int type,
                                            const char *name,
                                            apr_pool_t *scratch_pool)
{
    const unsigned int scheme_type = type;
    apr_status_t lock_status;
    apr_status_t status;
    const char *key;
    char *cp;
    int index;

    /* Generate a lower-case key for the scheme. */
    key = cp = apr_pstrdup(scratch_pool, name);
    while (*cp) {
        *cp = apr_tolower(*cp);
        ++cp;
    }

    lock_status = lock_autn_schemes(NULL /* TODO: whence cometh config? */);
    if (lock_status)
        return lock_status;

    status = APR_SUCCESS;

    /* Look for the scheme in the table. */
    for (index = 0; index < AUTHN_SCHEMES_SIZE - 1; ++index)
    {
        const serf__authn_scheme_t *const slot = serf_authn_schemes[index];
        if (slot == NULL) {
            status = APR_ENOENT;
            goto cleanup;
        }

        if (slot->type == scheme_type && 0 == strcmp(slot->key, key))
            break;
    }
    if (index >= AUTHN_SCHEMES_SIZE - 1) {
        /* The scheme wasn't registered */
        status = APR_ENOENT;
        goto cleanup;
    }

    /* Move all the following schemes back. This is a memmove, but
       it doesn't make much sense to use that since we don't knkow
       how many schemes are left after this one. */
    for (; index < AUTHN_SCHEMES_SIZE - 1; ++index)
    {
        serf_authn_schemes[index] = serf_authn_schemes[index + 1];
        if (serf_authn_schemes[index] == NULL)
            break;
    }

    /* Remove the scheme type from the registered mask. */
    user_authn_registered &= ~scheme_type;

  cleanup:
    lock_status = unlock_autn_schemes(NULL /* TODO: whence cometh config? */);
    if (lock_status)
        return lock_status;
    return status;
}
#endif  /* SERF__AUTHN__HAVE_UNREGISTER */


#if APR_HAS_THREADS
/* Unfortunately APR does not provide a statically-initialized mutex type, so we
   use a simple spinlock to make sure that authn_schemes_guard is initialized
   exaclty once. This includes creating a detached global pool where the mutex
   will be allocated ...

   ... yuck. */
static apr_status_t init_authn_schemes_guard()
{
    static volatile apr_uint32_t global_state = 0; /* uninitialized */
    static const apr_uint32_t uninitialized = 0;
    static const apr_uint32_t init_starting = 1;
    static const apr_uint32_t init_failed   = 2;
    static const apr_uint32_t initialized   = 3;

    static apr_status_t init_failed_status = APR_EGENERAL;

    int scheme_idx;
    unsigned int builtin_types;
    apr_allocator_t *allocator;
    apr_status_t status;
    apr_uint32_t current_state = apr_atomic_cas32(&global_state,
                                                  init_starting,
                                                  uninitialized);
    for (;;)
    {
        if (current_state == initialized)
            return APR_SUCCESS;

        if (current_state == uninitialized)
            /* We're the single initializer, run the init code. */
            break;

        if (current_state == init_starting)
        {
            /* Spin while the initializer is working. */
            apr_sleep(APR_USEC_PER_SEC / 100);
            current_state = apr_atomic_cas32(&global_state,
                                             uninitialized,
                                             uninitialized);
            continue;
        }

        if (current_state == init_failed)
            return init_failed_status;

        /* Not reached, can't happen. */
        return APR_EGENERAL;    /* FIXME: Just abort()? */
    }

    /* Create a self-contained root pool for the mutex. */
    status = apr_allocator_create(&allocator);
    if (status || !allocator)
        goto error_return;

    status = apr_pool_create_ex(&authn_schemes_guard_pool,
                                NULL, NULL, allocator);
    if (status || !authn_schemes_guard_pool)
        goto error_return;
#if APR_POOL_DEBUG
    apr_pool_tag(authn_schemes_guard_pool, "serf-authn-guard");
#endif

    status = apr_thread_mutex_create(&authn_schemes_guard,
                                     APR_THREAD_MUTEX_DEFAULT,
                                     authn_schemes_guard_pool);
    if (status || !authn_schemes_guard)
        goto error_return;

    /* Adjust the mask of available user-defined schemes. */
    builtin_types = 0;
    for (scheme_idx = 0; serf_authn_schemes[scheme_idx]; ++scheme_idx)
        builtin_types |= serf_authn_schemes[scheme_idx]->type;
    user_authn_type_mask &= ~builtin_types;

    /* Release the spinlock. */
    apr_atomic_cas32(&global_state, initialized, init_starting);
    return APR_SUCCESS;

  error_return:
    /* We only reach here if something went wrong during initialization. */
    if (status == APR_SUCCESS)  /* Not likely, but don't return "OK". */
        status = APR_ENOMEM;    /* Probable failures are allocations. */
    init_failed_status = status;
    apr_atomic_cas32(&global_state, init_failed, init_starting);
    return status;
}
#endif  /* APR_HAS_THREADS */
