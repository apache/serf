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
 *
 * ----
 *
 * Originally developed by Aaron Bannert and Justin Erenkrantz, eBuilt.
 */

#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_portable.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_version.h>
#include <apr_atomic.h>

#include "serf.h"
#include "serf_private.h"
#include "serf_bucket_util.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_OCSP /* requires openssl 0.9.7 or later */
#include <openssl/ocsp.h>
#endif

#ifndef APR_ARRAY_PUSH
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
#define USE_LEGACY_OPENSSL
#define X509_STORE_get0_param(store) store->param
#endif


/*
 * Here's an overview of the SSL bucket's relationship to OpenSSL and serf.
 *
 * HTTP request:  SSLENCRYPT(REQUEST)
 *   [context.c reads from SSLENCRYPT and writes out to the socket]
 * HTTP response: RESPONSE(SSLDECRYPT(SOCKET))
 *   [handler function reads from RESPONSE which in turn reads from SSLDECRYPT]
 *
 * HTTP request read call path:
 *
 * write_to_connection
 *  |- serf_bucket_read on SSLENCRYPT
 *    |- serf_ssl_read
 *      |- serf_databuf_read
 *        |- common_databuf_prep
 *          |- ssl_encrypt
 *            |- 1. Try to read pending encrypted data; If available, return.
 *            |- 2. Try to read from ctx->stream [REQUEST bucket]
 *            |- 3. Call SSL_write with read data
 *              |- ...
 *                |- bio_bucket_read can be called
 *                  |- read data from ctx->decrypt.stream
 *                |- bio_bucket_write with encrypted data
 *                  |- store in sink
 *            |- 4. If successful, read pending encrypted data and return.
 *            |- 5. If fails, place read data back in ctx->stream
 *
 * HTTP response read call path:
 *
 * read_from_connection
 *  |- acceptor
 *  |- handler
 *    |- ...
 *      |- serf_bucket_read(SSLDECRYPT)
 *        |- serf_ssl_read
 *          |- serf_databuf_read
 *            |- ssl_decrypt
 *              |- Call SSL_read()
 *                |- ...
 *                  |- bio_bucket_read
 *                    |- read data from ctx->decrypt.stream
 *                  |- bio_bucket_write can be called
 *                    |- store in sink
 *              |- If data read, return it.
 *              |- If an error, set the STATUS value and return.
 *
 */

typedef struct bucket_list {
    serf_bucket_t *bucket;
    struct bucket_list *next;
} bucket_list_t;

typedef struct serf_ssl_stream_t {
    /* Helper to read data. Wraps stream. */
    serf_databuf_t databuf;

    /* Our source for more data. */
    serf_bucket_t *stream;

    /* The next set of buckets */
    bucket_list_t *stream_next;
} serf_ssl_stream_t;

struct serf_ssl_context_t {
    /* How many open buckets refer to this context. */
    int refcount;

    /* The pool that this context uses. */
    apr_pool_t *pool;

    /* The allocator associated with the above pool. */
    serf_bucket_alloc_t *allocator;

    /* Internal OpenSSL parameters */
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    BIO_METHOD *biom;

    serf_ssl_stream_t encrypt;
    serf_ssl_stream_t decrypt;

    /* The status of the last thing we read or wrote. */
    apr_status_t crypt_status;

    /* Encrypted data waiting to be written. */
    serf_bucket_t *encrypt_pending;

    /* Should we read before we can write again? */
    int want_read;
    int handshake_done;

    /* Client cert callbacks */
    serf_ssl_need_client_cert_t cert_callback;
    void *cert_userdata;
    apr_pool_t *cert_cache_pool;
    const char *cert_file_success;

    /* Client cert PW callbacks */
    serf_ssl_need_cert_password_t cert_pw_callback;
    void *cert_pw_userdata;
    apr_pool_t *cert_pw_cache_pool;
    const char *cert_pw_success;

    /* Server cert callbacks */
    serf_ssl_need_server_cert_t server_cert_callback;
    serf_ssl_server_cert_chain_cb_t server_cert_chain_callback;
    void *server_cert_userdata;

    const char *cert_path;

    X509 *cached_cert;
    EVP_PKEY *cached_cert_pw;

    apr_status_t pending_err;

    /* Status of a fatal error, returned on subsequent encrypt or decrypt
       requests. */
    apr_status_t fatal_err;

    /* Flag is set to 1 when a renegotiation is in progress. */
    int renegotiation;
    int handshake_finished; /* True after SSL internal connection is through
                               the handshake */

    const char *selected_protocol; /* Cached protocol value once available */
    /* Protocol callback */
    serf_ssl_protocol_result_cb_t protocol_callback;
    void *protocol_userdata;

    serf_config_t *config;
};

typedef struct ssl_context_t {
    /* The bucket-independent ssl context that this bucket is associated with */
    serf_ssl_context_t *ssl_ctx;

    /* Pointer to the 'right' databuf. */
    serf_databuf_t *databuf;

    /* Pointer to our stream, so we can find it later. */
    serf_bucket_t **our_stream;
} ssl_context_t;

struct serf_ssl_certificate_t {
    X509 *ssl_cert;
    int depth;
};

static void disable_compression(serf_ssl_context_t *ssl_ctx);
static char *
    pstrdup_escape_nul_bytes(const char *buf, int len, apr_pool_t *pool);

static const char *ssl_get_selected_protocol(serf_ssl_context_t *context);

#ifdef SERF_LOGGING_ENABLED
/* Log all ssl alerts that we receive from the server. */
static void
apps_ssl_info_callback(const SSL *s, int where, int ret)
{
    const char *str;
    serf_ssl_context_t *ctx;
    int w;
    int in_write = (where & SSL_CB_WRITE);
    const char *read_write_str = (in_write ? "write" : "read");
    int ssl_error = SSL_get_error(s, ret);

    ctx = SSL_get_app_data(s);

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
        serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                  "%s:%s\n", str, SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT) {
        serf__log(LOGLVL_WARNING, LOGCOMP_SSL, __FILE__, ctx->config,
                  "SSL %s alert: %s: %s\n",
                  read_write_str,
                  SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
        int level;
        const char *how = (ret == 0) ? "failed" : "error";

        if (ret < 0 && ssl_error != SSL_ERROR_WANT_READ)
            level = LOGLVL_ERROR;
        else if (ret == 0)
            level = LOGLVL_WARNING;
        else if (ssl_error != SSL_ERROR_WANT_READ)
            level = LOGLVL_INFO;
        else
            level = LOGLVL_DEBUG;

        if (ret > 0) {
            /* ret > 0: Just a state change; not an error */
            serf__log(level, LOGCOMP_SSL, __FILE__, ctx->config,
                      "%s: %s (%d)\n",
                      str, SSL_state_string_long(s),
                      ctx->crypt_status);
        }
        else if (ssl_error == 0) {
            serf__log(level, LOGCOMP_SSL, __FILE__, ctx->config,
                      "%s:%s %s in %s, status=%d\n",
                      str, read_write_str, how, SSL_state_string_long(s),
                      ctx->crypt_status);
        }
        else if (ssl_error != SSL_ERROR_SYSCALL) {
            serf__log(level, LOGCOMP_SSL, __FILE__, ctx->config,
                      "%s:%s %s in %s: ssl_error=%d, status=%d\n",
                      str, read_write_str, how, SSL_state_string_long(s),
                      ssl_error, ctx->crypt_status);
        }
        else {
            serf__log(level, LOGCOMP_SSL, __FILE__, ctx->config,
                      "%s:%s %s in %s: status=%d\n",
                      str, read_write_str, how, SSL_state_string_long(s),
                      ctx->crypt_status);
        }
    }
}
#endif


/* Listens for the SSL renegotiate ciphers alert and report it back to the
   serf context. */
static void
detect_renegotiate(const SSL *s, int where, int ret)
{
    /* This callback overrides the SSL state logging callback, so call it here
       (if logging is compiled in). */
#ifdef SERF_LOGGING_ENABLED
    apps_ssl_info_callback(s, where, ret);
#endif

    /* The server asked to renegotiate the SSL session. */
#ifndef USE_LEGACY_OPENSSL
    if (SSL_get_state(s) == TLS_ST_SW_HELLO_REQ) {
#else
    if (SSL_state(s) == SSL_ST_RENEGOTIATE) {
#endif
        serf_ssl_context_t *ssl_ctx = SSL_get_app_data(s);

        ssl_ctx->renegotiation = 1;
        ssl_ctx->fatal_err = SERF_ERROR_SSL_NEGOTIATE_IN_PROGRESS;
    }
}

static void log_ssl_error(serf_ssl_context_t *ctx)
{
    unsigned long e = ERR_get_error();
    serf__log(LOGLVL_ERROR, LOGCOMP_SSL, __FILE__, ctx->config,
              "SSL Error: %s\n", ERR_error_string(e, NULL));

}

static void bio_set_data(BIO *bio, void *data)
{
#ifndef USE_LEGACY_OPENSSL
    BIO_set_data(bio, data);
#else
    bio->ptr = data;
#endif
}

static void *bio_get_data(BIO *bio)
{
#ifndef USE_LEGACY_OPENSSL
    return BIO_get_data(bio);
#else
    return bio->ptr;
#endif
}

/* Returns the amount read. */
static int bio_bucket_read(BIO *bio, char *in, int inlen)
{
    serf_ssl_context_t *ctx = bio_get_data(bio);
    const char *data;
    apr_status_t status;
    apr_size_t len;

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "bio_bucket_read called for %d bytes\n", inlen);

    BIO_clear_retry_flags(bio); /* Clear retry hints */

    /* The server initiated a renegotiation and we were instructed to report
       that as an error asap. */
    if (ctx->renegotiation) {
      ctx->crypt_status = SERF_ERROR_SSL_NEGOTIATE_IN_PROGRESS;
      return -1;
    }

    status = serf_bucket_read(ctx->decrypt.stream, inlen, &data, &len);
    ctx->crypt_status = status;
    ctx->want_read = FALSE;

    if (SERF_BUCKET_READ_ERROR(status)) {
        return -1; /* Raises: SSL_ERROR_SYSCALL; caller reads crypt_status */
    }

    if (status && !APR_STATUS_IS_EOF(status)) {
        BIO_set_retry_read(bio); /* Signal SSL: Retry later */
    }

    if (! len) {
        return -1; /* Raises: SSL_ERROR_SYSCALL; caller reads crypt_status */
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "bio_bucket_read received %"APR_SIZE_T_FMT" bytes (%d)\n", len, status);

    memcpy(in, data, len);
    return len;
}

/* Returns the amount written. */
static int bio_bucket_write(BIO *bio, const char *in, int inl)
{
    serf_ssl_context_t *ctx = bio_get_data(bio);
    serf_bucket_t *tmp;

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "bio_bucket_write called for %d bytes\n", inl);

    BIO_clear_retry_flags(bio); /* Clear retry hints */

    /* The server initiated a renegotiation and we were instructed to report
       that as an error asap. */
    if (ctx->renegotiation) {
      ctx->crypt_status = SERF_ERROR_SSL_NEGOTIATE_IN_PROGRESS;
      return -1;
    }

    ctx->crypt_status = APR_SUCCESS;

    tmp = serf_bucket_simple_copy_create(in, inl,
                                         ctx->encrypt_pending->allocator);

    serf_bucket_aggregate_append(ctx->encrypt_pending, tmp);

    return inl;
}

/* Returns the amount read. */
static int bio_file_read(BIO *bio, char *in, int inlen)
{
    apr_file_t *file = bio_get_data(bio);
    apr_status_t status;
    apr_size_t len;

    len = inlen;
    status = apr_file_read(file, in, &len);

    if (!SERF_BUCKET_READ_ERROR(status)) {
        /* Oh suck. */
        if (APR_STATUS_IS_EOF(status)) {
            return -1;
        } else {
            return len;
        }
    }

    return -1;
}

/* Returns the amount written. */
static int bio_file_write(BIO *bio, const char *in, int inl)
{
    apr_file_t *file = bio_get_data(bio);
    apr_size_t nbytes;

    BIO_clear_retry_flags(bio);

    nbytes = inl;
    apr_file_write(file, in, &nbytes);

    return nbytes;
}

static int bio_file_gets(BIO *bio, char *in, int inlen)
{
    apr_file_t *file = bio_get_data(bio);
    apr_status_t status;

    status = apr_file_gets(in, inlen, file);

    if (! status) {
        return (int)strlen(in);
    } else if (APR_STATUS_IS_EOF(status)) {
        return 0;
    } else {
        return -1; /* Signal generic error */
    }
}

static int bio_bucket_create(BIO *bio)
{
#ifndef USE_LEGACY_OPENSSL
    BIO_set_shutdown(bio, 1);
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
#else
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;
#endif

    return 1;
}

static int bio_bucket_destroy(BIO *bio)
{
    /* Did we already free this? */
    if (bio == NULL) {
        return 0;
    }

    return 1;
}

static long bio_bucket_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
    default:
        /* abort(); */
        break;
    case BIO_CTRL_FLUSH:
        /* At this point we can't force a flush. */
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
        ret = 0;
        break;
    }
    return ret;
}

#ifdef USE_LEGACY_OPENSSL
static BIO_METHOD bio_bucket_method = {
    BIO_TYPE_MEM,
    "Serf SSL encryption and decryption buckets",
    bio_bucket_write,
    bio_bucket_read,
    NULL,                        /* Is this called? */
    NULL,                        /* Is this called? */
    bio_bucket_ctrl,
    bio_bucket_create,
    bio_bucket_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

static BIO_METHOD bio_file_method = {
    BIO_TYPE_FILE,
    "Wrapper around APR file structures",
    bio_file_write,
    bio_file_read,
    NULL,                        /* Is this called? */
    bio_file_gets,               /* Is this called? */
    bio_bucket_ctrl,
    bio_bucket_create,
    bio_bucket_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};
#endif

static BIO_METHOD *bio_meth_bucket_new(void)
{
    BIO_METHOD *biom = NULL;

#ifndef USE_LEGACY_OPENSSL
    biom = BIO_meth_new(BIO_TYPE_MEM,
                        "Serf SSL encryption and decryption buckets");
    if (biom) {
        BIO_meth_set_write(biom, bio_bucket_write);
        BIO_meth_set_read(biom, bio_bucket_read);
        BIO_meth_set_ctrl(biom, bio_bucket_ctrl);
        BIO_meth_set_create(biom, bio_bucket_create);
        BIO_meth_set_destroy(biom, bio_bucket_destroy);
    }
#else
    biom = &bio_bucket_method;
#endif

    return biom;
}

static BIO_METHOD *bio_meth_file_new(void)
{
    BIO_METHOD *biom = NULL;

#ifndef USE_LEGACY_OPENSSL
    biom = BIO_meth_new(BIO_TYPE_FILE, "Wrapper around APR file structures");
    if (biom) {
        BIO_meth_set_write(biom, bio_file_write);
        BIO_meth_set_read(biom, bio_file_read);
        BIO_meth_set_gets(biom, bio_file_gets);
        BIO_meth_set_ctrl(biom, bio_bucket_ctrl);
        BIO_meth_set_create(biom, bio_bucket_create);
        BIO_meth_set_destroy(biom, bio_bucket_destroy);
    }
#else
    biom = &bio_file_method;
#endif

    return biom;
}

static void bio_meth_free(BIO_METHOD *biom)
{
#ifndef USE_LEGACY_OPENSSL
    BIO_meth_free(biom);
#endif
}

#ifndef OPENSSL_NO_TLSEXT
/* Callback called when the server response has some OCSP info.
   Returns 1 if the application accepts the OCSP response as successful,
           0 in case of error.
 */
static int ocsp_callback(SSL *ssl, void *baton)
{
    serf_ssl_context_t *ctx = (serf_ssl_context_t*)baton;
    OCSP_RESPONSE *response;
    const unsigned char *resp_der;
    int len;
    long resp_status;
    int failures = 0;
    int cert_valid = 0;

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "OCSP callback called.\n");
    len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp_der);

    if (!resp_der) {
        /* TODO: hard fail vs soft fail */
        /* No response sent */
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    response = d2i_OCSP_RESPONSE(NULL, &resp_der, len);
    if (!response) {
        /* Error parsing OCSP response - tell the app? */
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* Did the server get a valid response from the OCSP responder */
    resp_status = OCSP_response_status(response);
    switch (resp_status) {
        case OCSP_RESPONSE_STATUS_SUCCESSFUL:
            break;
        case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
        case OCSP_RESPONSE_STATUS_INTERNALERROR:
        case OCSP_RESPONSE_STATUS_SIGREQUIRED:
        case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
            failures |= SERF_SSL_OCSP_RESPONDER_ERROR;
            break;
        case OCSP_RESPONSE_STATUS_TRYLATER:
            failures |= SERF_SSL_OCSP_RESPONDER_TRYLATER;
            break;
        default:
            failures |= SERF_SSL_OCSP_RESPONDER_UNKNOWN_FAILURE;
            break;
    }

    /* TODO: check certificate status */

    OCSP_RESPONSE_free(response);

    if (ctx->server_cert_callback && failures) {
        apr_status_t status;

        /* TODO: try to find which certificate this is about. */

        /* Callback for further verification. */
        status = ctx->server_cert_callback(ctx->server_cert_userdata,
                                           failures, NULL);
        if (status == APR_SUCCESS)
            cert_valid = 1;
        else {
            /* The application is not happy with the OCSP response status. */
            cert_valid = 0;

            /* Pass the error back to the caller through the context-run. */
            ctx->pending_err = status;
        }
    }

    /* If OCSP stapling was enabled, an error was reported but no callback set,
       fail with an error. */
    if (!cert_valid &&
        !ctx->server_cert_chain_callback &&
        !ctx->server_cert_callback)
    {
        ctx->pending_err = SERF_ERROR_SSL_CERT_FAILED;
    }

    return cert_valid;
}
#endif

typedef enum san_copy_t {
    EscapeNulAndCopy = 0,
    ErrorOnNul = 1,
} san_copy_t;


/* get_subject_alt_names can run in two modes:
   COPY_ACTION = ErrorOnNul: return an error status if the san's (if any) contain
       \0 chars. In this mode, SAN_ARR and POOL aren't used and can be NULL.
   COPY_ACTION = EscapeNulAndCopy: copy the san's to the SAN_ARR array. Any \0
       chars are escaped as '\00', the memory is allocated in pool POOL.
 */
static apr_status_t
get_subject_alt_names(apr_array_header_t **san_arr, X509 *ssl_cert,
                      san_copy_t copy_action, apr_pool_t *pool)
{
    STACK_OF(GENERAL_NAME) *names;

    /* assert: copy_action == ErrorOnNul || (san_arr && pool) */

    if (san_arr) {
        *san_arr = NULL;
    }

    /* Get subjectAltNames */
    names = X509_get_ext_d2i(ssl_cert, NID_subject_alt_name, NULL, NULL);
    if (names) {
        int names_count = sk_GENERAL_NAME_num(names);
        int name_idx;

        if (san_arr)
            *san_arr = apr_array_make(pool, names_count, sizeof(char*));
        for (name_idx = 0; name_idx < names_count; name_idx++) {
            char *p = NULL;
            GENERAL_NAME *nm = sk_GENERAL_NAME_value(names, name_idx);

            switch (nm->type) {
                case GEN_DNS:
                    if (copy_action == ErrorOnNul &&
                        strlen((const char *)nm->d.ia5->data) != nm->d.ia5->length)
                        return SERF_ERROR_SSL_CERT_FAILED;
                    if (san_arr && *san_arr)
                        p = pstrdup_escape_nul_bytes((const char *)nm->d.ia5->data,
                                                     nm->d.ia5->length,
                                                     pool);
                    break;
                default:
                    /* Don't know what to do - skip. */
                    break;
            }

            if (p) {
                APR_ARRAY_PUSH(*san_arr, char*) = p;
            }
        }
        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }

    return APR_SUCCESS;
}


static apr_status_t
get_ocsp_responders(apr_array_header_t **ocsp_arr, X509 *ssl_cert,
                    apr_pool_t *pool)
{
    /* assert: (ocsp_arr && pool) */

    if (ocsp_arr) {
        STACK_OF(OPENSSL_STRING) *uris;

        *ocsp_arr = NULL;
        uris = X509_get1_ocsp(ssl_cert);
        if (uris) {
            int uris_count = sk_OPENSSL_STRING_num(uris);
            int uri_idx;

            *ocsp_arr = apr_array_make(pool, uris_count, sizeof(char*));

            for (uri_idx = 0; uri_idx < uris_count; ++uri_idx) {
                OPENSSL_STRING uri = sk_OPENSSL_STRING_value(uris, uri_idx);
                if (uri) {
                    char *p = apr_pstrdup(pool, uri);

                    if (p) {
                        APR_ARRAY_PUSH(*ocsp_arr, char*) = p;
                    }
                }
            }
        }
        X509_email_free(uris);
    }

    return APR_SUCCESS;
}


static apr_status_t validate_cert_hostname(X509 *server_cert, apr_pool_t *pool)
{
    char buf[1024];
    int length;
    apr_status_t ret;

    ret = get_subject_alt_names(NULL, server_cert, ErrorOnNul, NULL);
    if (ret) {
      return ret;
    } else {
        /* Fail if the subject's CN field contains \0 characters. */
        X509_NAME *subject = X509_get_subject_name(server_cert);
        if (!subject)
            return SERF_ERROR_SSL_CERT_FAILED;

        length = X509_NAME_get_text_by_NID(subject, NID_commonName, buf, 1024);
        if (length != -1)
            if (strlen(buf) != length)
                return SERF_ERROR_SSL_CERT_FAILED;
    }

    return APR_SUCCESS;
}

static int
validate_server_certificate(int cert_valid, X509_STORE_CTX *store_ctx)
{
    SSL *ssl;
    serf_ssl_context_t *ctx;
    X509 *server_cert;
    int depth;
    int failures = 0;
    apr_status_t status;

    ssl = X509_STORE_CTX_get_ex_data(store_ctx,
                                     SSL_get_ex_data_X509_STORE_CTX_idx());
    ctx = SSL_get_app_data(ssl);

    server_cert = X509_STORE_CTX_get_current_cert(store_ctx);
    depth = X509_STORE_CTX_get_error_depth(store_ctx);

    /* If the certification was found invalid, get the error and convert it to
       something our caller will understand. */
    if (! cert_valid) {
        int err = X509_STORE_CTX_get_error(store_ctx);

        switch(err) {
            case X509_V_ERR_CERT_NOT_YET_VALID:
                    failures |= SERF_SSL_CERT_NOTYETVALID;
                    break;
            case X509_V_ERR_CERT_HAS_EXPIRED:
                    failures |= SERF_SSL_CERT_EXPIRED;
                    break;
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                    failures |= SERF_SSL_CERT_SELF_SIGNED;
                    break;
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            case X509_V_ERR_CERT_UNTRUSTED:
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                    failures |= SERF_SSL_CERT_UNKNOWNCA;
                    break;
            case X509_V_ERR_CERT_REVOKED:
                    failures |= SERF_SSL_CERT_REVOKED;
                    break;
            case X509_V_ERR_UNABLE_TO_GET_CRL:
                    failures |= SERF_SSL_CERT_UNABLE_TO_GET_CRL;
                    break;
            default:
                    serf__log(LOGLVL_WARNING, LOGCOMP_SSL, __FILE__,
                              ctx->config,
                              "validate_server_certificate, unknown cert "
                              "failure %d at depth %d.\n", err, depth);
                    failures |= SERF_SSL_CERT_UNKNOWN_FAILURE;
                    break;
        }
    }

    /* Validate hostname */
    status = validate_cert_hostname(server_cert, ctx->pool);
    if (status)
        failures |= SERF_SSL_CERT_INVALID_HOST;

    /* Check certificate expiry dates. */
    if (X509_cmp_current_time(X509_get_notBefore(server_cert)) >= 0) {
        failures |= SERF_SSL_CERT_NOTYETVALID;
    }
    else if (X509_cmp_current_time(X509_get_notAfter(server_cert)) <= 0) {
        failures |= SERF_SSL_CERT_EXPIRED;
    }

    if (ctx->server_cert_callback &&
        (depth == 0 || failures)) {
        serf_ssl_certificate_t *cert;
        apr_pool_t *subpool;

        apr_pool_create(&subpool, ctx->pool);

        cert = apr_palloc(subpool, sizeof(serf_ssl_certificate_t));
        cert->ssl_cert = server_cert;
        cert->depth = depth;

        /* Callback for further verification. */
        status = ctx->server_cert_callback(ctx->server_cert_userdata,
                                           failures, cert);
        if (status == APR_SUCCESS)
            cert_valid = 1;
        else {
            /* Even if openssl found the certificate valid, the application
               told us to reject it. */
            cert_valid = 0;
            /* Pass the error back to the caller through the context-run. */
            ctx->pending_err = status;
        }
        apr_pool_destroy(subpool);
    }

    if (ctx->server_cert_chain_callback
        && (depth == 0 || failures)) {
        STACK_OF(X509) *chain;
        const serf_ssl_certificate_t **certs;
        int certs_len;
        apr_pool_t *subpool;

        apr_pool_create(&subpool, ctx->pool);

        /* Borrow the chain to pass to the callback. */
        chain = X509_STORE_CTX_get_chain(store_ctx);

        /* If the chain can't be retrieved, just pass the current
           certificate. */
        /* ### can this actually happen with _get_chain() ?  */
        if (!chain) {
            serf_ssl_certificate_t *cert = apr_palloc(subpool, sizeof(*cert));

            cert->ssl_cert = server_cert;
            cert->depth = depth;

            /* Room for the server_cert and a trailing NULL.  */
            certs = apr_palloc(subpool, sizeof(*certs) * 2);
            certs[0] = cert;

            certs_len = 1;
        } else {
            int i;

            certs_len = sk_X509_num(chain);

            /* Room for all the certs and a trailing NULL.  */
            certs = apr_palloc(subpool, sizeof(*certs) * (certs_len + 1));
            for (i = 0; i < certs_len; ++i) {
                serf_ssl_certificate_t *cert;

                cert = apr_palloc(subpool, sizeof(*cert));
                cert->ssl_cert = sk_X509_value(chain, i);
                cert->depth = i;

                certs[i] = cert;
            }
        }
        certs[certs_len] = NULL;

        /* Callback for further verification. */
        status = ctx->server_cert_chain_callback(ctx->server_cert_userdata,
                                                 failures, depth,
                                                 certs, certs_len);
        if (status == APR_SUCCESS) {
            cert_valid = 1;
        } else {
            /* Even if openssl found the certificate valid, the application
               told us to reject it. */
            cert_valid = 0;
            /* Pass the error back to the caller through the context-run. */
            ctx->pending_err = status;
        }

        apr_pool_destroy(subpool);
    }

    /* Return a specific error if the server certificate is not accepted by
       OpenSSL and the application has not set callbacks to override this. */
    if (!cert_valid &&
        !ctx->server_cert_chain_callback &&
        !ctx->server_cert_callback)
    {
        ctx->pending_err = SERF_ERROR_SSL_CERT_FAILED;
    }

    return cert_valid;
}

/* Helper function to convert the ssl error code contained in ret_code + the
   ssl context to a proper serf status code.

   If DO_WANT_READ is true, handle the SSL_ERROR_WANT_* as SERF_ERROR_WAIT_CONN
   and set ctx->want_read.
 */
static apr_status_t status_from_ssl_error(serf_ssl_context_t *ctx,
                                          int ret_code,
                                          int do_want_read)
{
    int ssl_err = SSL_get_error(ctx->ssl, ret_code);
    apr_status_t status;

    switch (ssl_err) {
        case SSL_ERROR_SYSCALL:
            /* One of the bio functions returned a failure by returning -1.
               Return the underlying status that caused OpenSSL to fail.

               There is no ssl status to log here, as the only reason
               the call failed is that our data delivery function didn't
               deliver data. And even that is already logged by the info
               callback if you turn up the logging level high enough. */
            status = ctx->crypt_status;
            break;

        case SSL_ERROR_WANT_READ:
            if (do_want_read)
                ctx->want_read = TRUE;
            /* Fall through */

        case SSL_ERROR_WANT_WRITE:
            status = do_want_read ? SERF_ERROR_WAIT_CONN : APR_EAGAIN;
            break;

        case SSL_ERROR_SSL:
            if (ctx->pending_err) {
                status = ctx->pending_err;
                ctx->pending_err = APR_SUCCESS;
            } else {
                /*unsigned long l = ERR_peek_error();
                int lib = ERR_GET_LIB(l);
                int func = ERR_GET_FUNC(l);
                int reason = ERR_GET_REASON(l);*/

                /* ### Detect more specific errors?
                  When lib is ERR_LIB_SSL, then reason is one of the
                  many SSL_R_XXXX reasons in ssl.h
                */

                if (SSL_in_init(ctx->ssl))
                    ctx->fatal_err = SERF_ERROR_SSL_SETUP_FAILED;
                else
                    ctx->fatal_err = SERF_ERROR_SSL_COMM_FAILED;

                status = ctx->fatal_err;
                log_ssl_error(ctx);
            }
            break;
        default:
            status = ctx->fatal_err = SERF_ERROR_SSL_COMM_FAILED;
            log_ssl_error(ctx);
            break;
    }

    return status;
}

/* Explicitly perform the SSL handshake without waiting for the first
   write */
static apr_status_t ssl_handshake(serf_ssl_context_t *ctx,
                                  int do_want_read)
{
    int ssl_result;
    const unsigned char *data;
    apr_size_t len;

    /* If we have a cached session, use it to allow speeding up the handshake */
    if (ctx->config
        && !serf__config_store_get_ssl_session(ctx->config, &data, &len)) {

        SSL_SESSION *sess;

        sess = d2i_SSL_SESSION(NULL, &data, (long)len);

        SSL_set_session(ctx->ssl, sess);
    }

    ctx->crypt_status = APR_SUCCESS; /* Clear before calling SSL */
    ssl_result = SSL_do_handshake(ctx->ssl);
    if (ssl_result <= 0) {
        apr_status_t status = status_from_ssl_error(ctx, ssl_result,
                                                    do_want_read);

        if (SERF_BUCKET_READ_ERROR(status)) {
            return status;
        }
    }

    return APR_SUCCESS;
}

/* This function reads an encrypted stream and returns the decrypted stream.
   Implements serf_databuf_reader_t */
static apr_status_t ssl_decrypt(void *baton, apr_size_t bufsize,
                                char *buf, apr_size_t *len)
{
    serf_ssl_context_t *ctx = baton;
    apr_status_t status;
    int ssl_len;

    if (ctx->fatal_err)
        return ctx->fatal_err;

    if (!ctx->handshake_done) {

        ctx->handshake_done = TRUE;

        status = ssl_handshake(ctx, FALSE);

        if (SERF_BUCKET_READ_ERROR(status)) {
            *len = 0;
            return status;
        }
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "ssl_decrypt: begin %" APR_SIZE_T_FMT "\n", bufsize);

    ctx->want_read = FALSE; /* Reading now */
    ctx->crypt_status = APR_SUCCESS; /* Clear before calling SSL */

    /* When an SSL_read() operation has to be repeated because of
       SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be repeated
       with the same arguments.

       Luckily we can assume that we are called from the databuffer
       implementation */
    /* Is there some data waiting to be read? */
    ssl_len = SSL_read(ctx->ssl, buf, bufsize);
    if (ssl_len < 0) {

        *len = 0;
        status = status_from_ssl_error(ctx, ssl_len, FALSE);
    } else if (ssl_len == 0) {
        /* The server shut down the connection. */
        int ssl_err, shutdown;
        *len = 0;

        /* Check for SSL_RECEIVED_SHUTDOWN */
        shutdown = SSL_get_shutdown(ctx->ssl);
        /* Check for SSL_ERROR_ZERO_RETURN */
        ssl_err = SSL_get_error(ctx->ssl, ssl_len);

        if (shutdown == SSL_RECEIVED_SHUTDOWN &&
            ssl_err == SSL_ERROR_ZERO_RETURN) {
            /* The server closed the SSL session. While this doesn't
            necessary mean the connection is closed, let's close
            it here anyway.
            We can optimize this later. */
            serf__log(LOGLVL_ERROR, LOGCOMP_SSL, __FILE__, ctx->config,
                        "ssl_decrypt: SSL read error: server"
                        " shut down connection!\n");
            status = APR_EOF;
        } else {
            /* A fatal error occurred. */
            ctx->fatal_err = status = SERF_ERROR_SSL_COMM_FAILED;
            log_ssl_error(ctx);
        }
    } else {
        *len = ssl_len;
        status = ctx->crypt_status;
        serf__log(LOGLVL_DEBUG, LOGCOMP_SSLMSG, __FILE__, ctx->config,
                  "---\n%.*s\n-(%"APR_SIZE_T_FMT")-\n", (int)*len, buf, *len);
    }


    if (!ctx->handshake_finished
        && !SERF_BUCKET_READ_ERROR(status)) {

        apr_status_t s = APR_SUCCESS;

        /* Once we got through the initial handshake, we should have received
           the ALPN information if there is such information. */
        ctx->handshake_finished = SSL_is_init_finished(ctx->ssl)
#ifndef USE_LEGACY_OPENSSL
                                  || (SSL_get_state(ctx->ssl) == TLS_ST_OK);
#else
                                  || (SSL_state(ctx->ssl)
                                      & SSL_CB_HANDSHAKE_DONE);
#endif

        /* Call the protocol callback as soon as possible as this triggers
           pipelining data for the selected protocol. */
        if (ctx->protocol_callback) {
            const char *protocol = ssl_get_selected_protocol(ctx);

            /* When ctx->init_finished is TRUE protocol will never be NULL,
               reporting the final result if not already handled */
            if (protocol) {
                s = ctx->protocol_callback(ctx->protocol_userdata, protocol);
                ctx->protocol_callback = NULL;
            }
        }

        if (SERF_BUCKET_READ_ERROR(s)) {
            serf__log(LOGLVL_ERROR, LOGCOMP_SSL, __FILE__, ctx->config,
                      "ssl_decrypt: negotiation reported: %d\n", status);
            status = s;
        }
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "ssl_decrypt: %d %"APR_SIZE_T_FMT"\n", status, *len);

    return status;
}

/* This function reads a decrypted stream and returns an encrypted stream.
   Implements serf_databuf_reader_t */
static apr_status_t ssl_encrypt(void *baton, apr_size_t bufsize,
                                char *buf, apr_size_t *len)
{
    const char *data;
    apr_size_t interim_bufsize;
    serf_ssl_context_t *ctx = baton;
    apr_status_t status;

    if (ctx->fatal_err)
        return ctx->fatal_err;

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "ssl_encrypt: begin %"APR_SIZE_T_FMT"\n", bufsize);

    if (!ctx->handshake_done) {

        ctx->handshake_done = TRUE;

        status = ssl_handshake(ctx, TRUE);

        if (SERF_BUCKET_READ_ERROR(status)) {
            return status;
        }
    }

    /* Try to read already encrypted but unread data first. */
    status = serf_bucket_read(ctx->encrypt_pending, bufsize, &data, len);
    if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }

    /* Aha, we read something.  Return that now. */
    if (*len) {
        memcpy(buf, data, *len);
        if (APR_STATUS_IS_EOF(status)) {
            status = APR_SUCCESS;
        }

        serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                  "ssl_encrypt: %d %"APR_SIZE_T_FMT" (quick read)\n",
                  status, *len);

        return status;
    }

    /* Oh well, read from our stream now. */
    interim_bufsize = bufsize;
    do {
        apr_size_t interim_len;

        if (!ctx->want_read) {
            struct iovec vecs[SERF__STD_IOV_COUNT];
            int vecs_read;

            status = serf_bucket_read_iovec(ctx->encrypt.stream,
                                            interim_bufsize,
                                            COUNT_OF(vecs), vecs,
                                            &vecs_read);

            if (!SERF_BUCKET_READ_ERROR(status) && vecs_read) {
                char *vecs_data;
                int i, cur, vecs_data_len;
                int ssl_len;

                /* Combine the buffers of the iovec into one buffer, as
                   that is with SSL_write requires. */
                vecs_data_len = 0;
                for (i = 0; i < vecs_read; i++) {
                    vecs_data_len += vecs[i].iov_len;
                }

                vecs_data = serf_bucket_mem_alloc(ctx->allocator,
                                                  vecs_data_len);

                cur = 0;
                for (i = 0; i < vecs_read; i++) {
                    memcpy(vecs_data + cur, vecs[i].iov_base, vecs[i].iov_len);
                    cur += vecs[i].iov_len;
                }

                interim_bufsize -= vecs_data_len;
                interim_len = vecs_data_len;

                serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                          "ssl_encrypt: bucket read %"APR_SIZE_T_FMT" bytes; "\
                          "status %d\n", interim_len, status);

                /* When an SSL_write() operation has to be repeated because of
                   SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it MUST be
                   repeated with the same arguments.

                   Unless SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is set...
                   ... which we now do.
                */
                ctx->crypt_status = APR_SUCCESS; /* Clear before calling SSL */
                ssl_len = SSL_write(ctx->ssl, vecs_data, interim_len);

                serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                          "ssl_encrypt: SSL write: %d\n", ssl_len);

                /* If we failed to write... */
                if (ssl_len <= 0) {

                    /* Ah, bugger. We need to put that data back.
                       Note: use the copy here, we do not own the original iovec
                       data buffer so it will be freed on next read. */
                    serf_bucket_t *vecs_copy =
                        serf_bucket_simple_own_create(vecs_data,
                                                      vecs_data_len,
                                                      ctx->allocator);
                    serf_bucket_aggregate_prepend(ctx->encrypt.stream,
                                                  vecs_copy);

                    status = status_from_ssl_error(ctx, ssl_len, TRUE);
                } else {
                    /* We're done with this data. */
                    serf_bucket_mem_free(ctx->allocator, vecs_data);

                    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                              "---\n%.*s\n-(%"APR_SIZE_T_FMT")-\n",
                              (int)interim_len, vecs_data, interim_len);

                }
            }
        }
        else {
            interim_len = 0;
            *len = 0;
            status = ctx->crypt_status;

            if (!status) {
                status = APR_EAGAIN; /* Exit loop */
            }
        }

    } while (!status && interim_bufsize);

    /* Okay, we exhausted our underlying stream. */
    if (!SERF_BUCKET_READ_ERROR(status)) {
        apr_status_t agg_status;
        struct iovec vecs[SERF__STD_IOV_COUNT];
        int vecs_read, i;

        /* We read something! */
        agg_status = serf_bucket_read_iovec(ctx->encrypt_pending, bufsize,
                                            COUNT_OF(vecs), vecs, &vecs_read);
        *len = 0;
        for (i = 0; i < vecs_read; i++) {
            memcpy(buf + *len, vecs[i].iov_base, vecs[i].iov_len);
            *len += vecs[i].iov_len;
        }

        serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
                  "ssl_encrypt read agg: %d %d %d %"APR_SIZE_T_FMT"\n", status, agg_status,
                  ctx->crypt_status, *len);

        if (!agg_status) {
            status = APR_SUCCESS;
        }
    }

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "ssl_encrypt finished: %d %"APR_SIZE_T_FMT"\n", status, *len);

    return status;
}

#if APR_HAS_THREADS && defined(USE_LEGACY_OPENSSL)
static apr_pool_t *ssl_pool;
static apr_thread_mutex_t **ssl_locks;

typedef struct CRYPTO_dynlock_value {
    apr_thread_mutex_t *lock;
} CRYPTO_dynlock_value;

static CRYPTO_dynlock_value *ssl_dyn_create(const char* file, int line)
{
    CRYPTO_dynlock_value *l;
    apr_status_t rv;

    l = apr_palloc(ssl_pool, sizeof(CRYPTO_dynlock_value));
    rv = apr_thread_mutex_create(&l->lock, APR_THREAD_MUTEX_DEFAULT, ssl_pool);
    if (rv != APR_SUCCESS) {
        /* FIXME: return error here */
    }
    return l;
}

static void ssl_dyn_lock(int mode, CRYPTO_dynlock_value *l, const char *file,
                         int line)
{
    if (mode & CRYPTO_LOCK) {
        apr_thread_mutex_lock(l->lock);
    }
    else if (mode & CRYPTO_UNLOCK) {
        apr_thread_mutex_unlock(l->lock);
    }
}

static void ssl_dyn_destroy(CRYPTO_dynlock_value *l, const char *file,
                            int line)
{
    apr_thread_mutex_destroy(l->lock);
}

static void ssl_lock(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        apr_thread_mutex_lock(ssl_locks[n]);
    }
    else if (mode & CRYPTO_UNLOCK) {
        apr_thread_mutex_unlock(ssl_locks[n]);
    }
}

static unsigned long ssl_id(void)
{
    /* FIXME: This is lame and not portable. -aaron */
    return (unsigned long) apr_os_thread_current();
}

static apr_status_t cleanup_ssl(void *data)
{
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    return APR_SUCCESS;
}

#endif

#if !APR_VERSION_AT_LEAST(1,0,0)
#define apr_atomic_cas32(mem, with, cmp) apr_atomic_cas(mem, with, cmp)
#endif

enum ssl_init_e
{
   INIT_UNINITIALIZED = 0,
   INIT_BUSY = 1,
   INIT_DONE = 2
};

static volatile apr_uint32_t have_init_ssl = INIT_UNINITIALIZED;

static void init_ssl_libraries(void)
{
    apr_uint32_t val;

    val = apr_atomic_cas32(&have_init_ssl, INIT_BUSY, INIT_UNINITIALIZED);

    if (!val) {
#if APR_HAS_THREADS && defined(USE_LEGACY_OPENSSL)
        int i, numlocks;
#endif

#ifdef SERF_LOGGING_ENABLED
        /* Warn when compile-time and run-time version of OpenSSL differ in
           major/minor version number. */
        long libver = SSLeay();

        if ((libver ^ OPENSSL_VERSION_NUMBER) & 0xFFF00000) {
            serf__log(LOGLVL_WARNING, LOGCOMP_SSL, __FILE__, NULL,
                      "Warning: OpenSSL library version mismatch, compile-"
                      "time was %lx, runtime is %lx.\n",
                      OPENSSL_VERSION_NUMBER, libver);
        }
#endif

#ifndef USE_LEGACY_OPENSSL
        OPENSSL_malloc_init();
#else
        CRYPTO_malloc_init();
#endif
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();

#if APR_HAS_THREADS && defined(USE_LEGACY_OPENSSL)
        numlocks = CRYPTO_num_locks();
        apr_pool_create(&ssl_pool, NULL);
        ssl_locks = apr_palloc(ssl_pool, sizeof(apr_thread_mutex_t*)*numlocks);
        for (i = 0; i < numlocks; i++) {
            apr_status_t rv;

            /* Intraprocess locks don't /need/ a filename... */
            rv = apr_thread_mutex_create(&ssl_locks[i],
                                         APR_THREAD_MUTEX_DEFAULT, ssl_pool);
            if (rv != APR_SUCCESS) {
                /* FIXME: error out here */
            }
        }
        CRYPTO_set_locking_callback(ssl_lock);
        CRYPTO_set_id_callback(ssl_id);
        CRYPTO_set_dynlock_create_callback(ssl_dyn_create);
        CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock);
        CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy);

        apr_pool_cleanup_register(ssl_pool, NULL, cleanup_ssl, cleanup_ssl);
#endif
        apr_atomic_cas32(&have_init_ssl, INIT_DONE, INIT_BUSY);
    }
  else
    {
        /* Make sure we don't continue before the initialization in another
           thread has completed */
        while (val != INIT_DONE) {
            apr_sleep(APR_USEC_PER_SEC / 1000);

            val = apr_atomic_cas32(&have_init_ssl,
                                   INIT_UNINITIALIZED,
                                   INIT_UNINITIALIZED);
        }
    }
}

static int ssl_need_client_cert(SSL *ssl, X509 **cert, EVP_PKEY **pkey)
{
    serf_ssl_context_t *ctx = SSL_get_app_data(ssl);
    apr_status_t status;

    serf__log(LOGLVL_DEBUG, LOGCOMP_SSL, __FILE__, ctx->config,
              "Server requests a client certificate.\n");

    if (ctx->cached_cert) {
        *cert = ctx->cached_cert;
        *pkey = ctx->cached_cert_pw;
        return 1;
    }

    while (ctx->cert_callback) {
        const char *cert_path;
        apr_file_t *cert_file;
        BIO *bio;
        BIO_METHOD *biom;
        PKCS12 *p12;
        int i;
        int retrying_success = 0;

        if (ctx->cert_file_success) {
            status = APR_SUCCESS;
            cert_path = ctx->cert_file_success;
            ctx->cert_file_success = NULL;
            retrying_success = 1;
        } else {
            status = ctx->cert_callback(ctx->cert_userdata, &cert_path);
        }

        if (status || !cert_path) {
            break;
        }

        /* Load the x.509 cert file stored in PKCS12 */
        status = apr_file_open(&cert_file, cert_path, APR_READ, APR_OS_DEFAULT,
                               ctx->pool);

        /* TODO: this will hang indefintely when the file can't be found. */
        if (status) {
            continue;
        }

        biom = bio_meth_file_new();
        bio = BIO_new(biom);
        bio_set_data(bio, cert_file);

        ctx->cert_path = cert_path;
        p12 = d2i_PKCS12_bio(bio, NULL);
        BIO_free(bio);
        apr_file_close(cert_file);

        i = PKCS12_parse(p12, NULL, pkey, cert, NULL);

        if (i == 1) {
            PKCS12_free(p12);
            bio_meth_free(biom);
            ctx->cached_cert = *cert;
            ctx->cached_cert_pw = *pkey;
            if (!retrying_success && ctx->cert_cache_pool) {
                const char *c;

                c = apr_pstrdup(ctx->cert_cache_pool, ctx->cert_path);

                apr_pool_userdata_setn(c, "serf:ssl:cert",
                                       apr_pool_cleanup_null,
                                       ctx->cert_cache_pool);
            }
            return 1;
        }
        else {
            int err = ERR_get_error();
            ERR_clear_error();
            if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
                ERR_GET_REASON(err) == PKCS12_R_MAC_VERIFY_FAILURE) {
                if (ctx->cert_pw_callback) {
                    const char *password;

                    if (ctx->cert_pw_success) {
                        status = APR_SUCCESS;
                        password = ctx->cert_pw_success;
                        ctx->cert_pw_success = NULL;
                    } else {
                        status = ctx->cert_pw_callback(ctx->cert_pw_userdata,
                                                       ctx->cert_path,
                                                       &password);
                    }

                    if (!status && password) {
                        i = PKCS12_parse(p12, password, pkey, cert, NULL);
                        if (i == 1) {
                            PKCS12_free(p12);
                            bio_meth_free(biom);
                            ctx->cached_cert = *cert;
                            ctx->cached_cert_pw = *pkey;
                            if (!retrying_success && ctx->cert_cache_pool) {
                                const char *c;

                                c = apr_pstrdup(ctx->cert_cache_pool,
                                                ctx->cert_path);

                                apr_pool_userdata_setn(c, "serf:ssl:cert",
                                                       apr_pool_cleanup_null,
                                                       ctx->cert_cache_pool);
                            }
                            if (!retrying_success && ctx->cert_pw_cache_pool) {
                                const char *c;

                                c = apr_pstrdup(ctx->cert_pw_cache_pool,
                                                password);

                                apr_pool_userdata_setn(c, "serf:ssl:certpw",
                                                       apr_pool_cleanup_null,
                                                       ctx->cert_pw_cache_pool);
                            }
                            return 1;
                        }
                    }
                }
                PKCS12_free(p12);
                bio_meth_free(biom);
                return 0;
            }
            else {
                serf__log(LOGLVL_ERROR, LOGCOMP_SSL, __FILE__, ctx->config,
                          "OpenSSL cert error: %d %d %d\n", ERR_GET_LIB(err),
                          ERR_GET_FUNC(err),
                          ERR_GET_REASON(err));
                PKCS12_free(p12);
                bio_meth_free(biom);
            }
        }
    }

    return 0;
}


void serf_ssl_client_cert_provider_set(
    serf_ssl_context_t *context,
    serf_ssl_need_client_cert_t callback,
    void *data,
    void *cache_pool)
{
    context->cert_callback = callback;
    context->cert_userdata = data;
    context->cert_cache_pool = cache_pool;
    if (context->cert_cache_pool) {
        apr_pool_userdata_get((void**)&context->cert_file_success,
                              "serf:ssl:cert", cache_pool);
    }
}


void serf_ssl_client_cert_password_set(
    serf_ssl_context_t *context,
    serf_ssl_need_cert_password_t callback,
    void *data,
    void *cache_pool)
{
    context->cert_pw_callback = callback;
    context->cert_pw_userdata = data;
    context->cert_pw_cache_pool = cache_pool;
    if (context->cert_pw_cache_pool) {
        apr_pool_userdata_get((void**)&context->cert_pw_success,
                              "serf:ssl:certpw", cache_pool);
    }
}


void serf_ssl_server_cert_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t callback,
    void *data)
{
    context->server_cert_callback = callback;
    context->server_cert_userdata = data;
}

void serf_ssl_server_cert_chain_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t cert_callback,
    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
    void *data)
{
    context->server_cert_callback = cert_callback;
    context->server_cert_chain_callback = cert_chain_callback;
    context->server_cert_userdata = data;
}

static int ssl_new_session(SSL *ssl, SSL_SESSION *session)
{
    serf_ssl_context_t *ctx = SSL_get_app_data(ssl);
    void *mem;
    unsigned char *der_data;
    apr_size_t der_len;

    if (!ctx->config)
        return 0;

    der_len = i2d_SSL_SESSION(session, NULL);

    mem = serf_bucket_mem_alloc(ctx->allocator, der_len);
    der_data = mem;
    if (der_len == i2d_SSL_SESSION(session, &der_data)) {
        /* der_data was modified by i2d_SSL_SESSION(), so
           we store the original pointer */
        (void)serf__config_store_set_ssl_session(ctx->config,
                                                 mem, der_len);
    }

    serf_bucket_mem_free(ctx->allocator, mem);

    return 0;
}

static serf_ssl_context_t *ssl_init_context(serf_bucket_alloc_t *allocator)
{
    serf_ssl_context_t *ssl_ctx;

    init_ssl_libraries();

    ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));

    ssl_ctx->refcount = 0;
    ssl_ctx->pool = serf_bucket_allocator_get_pool(allocator);
    ssl_ctx->allocator = allocator;

    /* Use the best possible protocol version, but disable the broken SSLv2/3 */
    ssl_ctx->ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    /* Allow calling SSL_write() with different buffer pointers */
    SSL_CTX_set_mode(ssl_ctx->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_CTX_set_client_cert_cb(ssl_ctx->ctx, ssl_need_client_cert);
    ssl_ctx->cached_cert = 0;
    ssl_ctx->cached_cert_pw = 0;
    ssl_ctx->pending_err = APR_SUCCESS;
    ssl_ctx->fatal_err = APR_SUCCESS;
    ssl_ctx->renegotiation = 0;
    ssl_ctx->config = NULL;

    ssl_ctx->cert_callback = NULL;
    ssl_ctx->cert_pw_callback = NULL;
    ssl_ctx->server_cert_callback = NULL;
    ssl_ctx->server_cert_chain_callback = NULL;

    ssl_ctx->selected_protocol = "";
    ssl_ctx->handshake_finished = FALSE;
    ssl_ctx->protocol_callback = NULL;
    ssl_ctx->protocol_userdata = NULL;

    SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER,
                       validate_server_certificate);
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_ALL);
    /* Disable SSL compression by default. */
    disable_compression(ssl_ctx);

    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    ssl_ctx->biom = bio_meth_bucket_new();
    ssl_ctx->bio = BIO_new(ssl_ctx->biom);
    bio_set_data(ssl_ctx->bio, ssl_ctx);

    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);

    /* Enable SSL callback to store the SSL session state to allow
       optimized resumption later. */
    SSL_CTX_sess_set_new_cb(ssl_ctx->ctx, ssl_new_session);

    SSL_set_connect_state(ssl_ctx->ssl);

    SSL_set_app_data(ssl_ctx->ssl, ssl_ctx);

#ifdef SERF_LOGGING_ENABLED
    SSL_CTX_set_info_callback(ssl_ctx->ctx, apps_ssl_info_callback);
#endif

    ssl_ctx->encrypt.stream = NULL;
    ssl_ctx->encrypt.stream_next = NULL;
    ssl_ctx->encrypt_pending = serf_bucket_aggregate_create(allocator);
    serf_databuf_init(&ssl_ctx->encrypt.databuf);
    ssl_ctx->encrypt.databuf.read = ssl_encrypt;
    ssl_ctx->encrypt.databuf.read_baton = ssl_ctx;

    ssl_ctx->decrypt.stream = NULL;
    serf_databuf_init(&ssl_ctx->decrypt.databuf);
    ssl_ctx->decrypt.databuf.read = ssl_decrypt;
    ssl_ctx->decrypt.databuf.read_baton = ssl_ctx;

    ssl_ctx->crypt_status = APR_SUCCESS;
    ssl_ctx->want_read = FALSE;
    ssl_ctx->handshake_done = FALSE;

    return ssl_ctx;
}

static apr_status_t ssl_free_context(
    serf_ssl_context_t *ssl_ctx)
{
    /* If never had the pending buckets, don't try to free them. */
    if (ssl_ctx->encrypt_pending != NULL) {
        serf_bucket_destroy(ssl_ctx->encrypt_pending);
    }

    /* SSL_free implicitly frees the underlying BIO. */
    SSL_free(ssl_ctx->ssl);
    SSL_CTX_free(ssl_ctx->ctx);
    bio_meth_free(ssl_ctx->biom);

    serf_bucket_mem_free(ssl_ctx->allocator, ssl_ctx);

    return APR_SUCCESS;
}

static serf_bucket_t * serf_bucket_ssl_create(
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator,
    const serf_bucket_type_t *type)
{
    ssl_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    if (!ssl_ctx) {
        ctx->ssl_ctx = ssl_init_context(allocator);
    }
    else {
        ctx->ssl_ctx = ssl_ctx;
    }
    ctx->ssl_ctx->refcount++;

    return serf_bucket_create(type, allocator, ctx);
}

apr_status_t serf_ssl_set_hostname(serf_ssl_context_t *context,
                                   const char * hostname)
{
#ifdef SSL_set_tlsext_host_name
    if (SSL_set_tlsext_host_name(context->ssl, hostname) != 1) {
        ERR_clear_error();
    }
    return APR_SUCCESS;
#endif
    return APR_ENOTIMPL;
}

apr_status_t serf_ssl_negotiate_protocol(serf_ssl_context_t *context,
                                         const char *protocols,
                                         serf_ssl_protocol_result_cb_t callback,
                                         void *callback_data)
{
    apr_pool_t *subpool;
    unsigned char *raw_header;
    unsigned char *at;
    const char *next;
    apr_size_t raw_len = strlen(protocols)+1;
    apr_size_t len;

    if (raw_len >= 65536)
        return APR_EINVAL;

    /* The OpenSSL api wants the value in network format.
       A length byte followed by the value for all items. */

    apr_pool_create(&subpool, context->pool);

    at = raw_header = apr_palloc(subpool, raw_len);

    while ((next = strchr(protocols, ','))) {
        len = (next - protocols);

        if (len > 255) {
            apr_pool_destroy(subpool);
            return APR_EINVAL;
        }

        *at = (unsigned char)len;
        at++;
        memcpy(at, protocols, len);
        at += len;

        protocols = next + 1;
    }

    len = strlen(protocols);
    if (len > 255) {
      apr_pool_destroy(subpool);
      return APR_EINVAL;
    }

    *at = (unsigned char)len;
    at++;
    memcpy(at, protocols, len);
    at += len;

#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* >= 1.0.2 */
    if (SSL_set_alpn_protos(context->ssl, raw_header, raw_len)) {
        ERR_clear_error();
    }
    apr_pool_destroy(subpool);

    context->protocol_callback = callback;
    context->protocol_userdata = callback_data;
    context->selected_protocol = NULL;
    return APR_SUCCESS;
#else
    apr_pool_destroy(subpool);
    return APR_ENOTIMPL;
#endif
}

/* Gets the protocol selected by the server via ALPN. Returns NULL if
 * ALPN and "" if no selection is made.
 *
 * ### Should we make this public as serf_ssl_get_selected_protocol(),
 *     or is the callback the only relevant scenario?
 */
static const char *ssl_get_selected_protocol(serf_ssl_context_t *context)
{
    if (! context->selected_protocol) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* >= 1.0.2 */
        const unsigned char *data = NULL;
        unsigned len = 0;

        SSL_get0_alpn_selected(context->ssl, &data, &len);

        if (data && len)
            context->selected_protocol = apr_pstrmemdup(context->pool,
                                                        (void*)data, len);
        else if (context->handshake_finished)
            context->selected_protocol = "";
#endif
    }
    return context->selected_protocol;
}

/* Pool cleanup function for certificates */
static apr_status_t free_ssl_cert(void *data)
{
    X509_free(data);
    return APR_SUCCESS;
}

apr_status_t serf_ssl_use_default_certificates(serf_ssl_context_t *ssl_ctx)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx->ctx);

    int result = X509_STORE_set_default_paths(store);

    return result ? APR_SUCCESS : SERF_ERROR_SSL_CERT_FAILED;
}

apr_status_t serf_ssl_load_cert_file(
    serf_ssl_certificate_t **cert,
    const char *file_path,
    apr_pool_t *pool)
{
    apr_file_t *cert_file;
    apr_status_t status;
    BIO *bio;
    BIO_METHOD *biom;
    X509 *ssl_cert;

    /* We use an apr file instead of an stdio.h file to avoid usage problems
       on Windows. See http://www.openssl.org/support/faq.html#prog2 */
    status = apr_file_open(&cert_file, file_path, APR_READ, APR_OS_DEFAULT,
                           pool);

    if (status) {
        return status;
    }

    init_ssl_libraries();

    biom = bio_meth_file_new();
    bio = BIO_new(biom);
    bio_set_data(bio, cert_file);

    ssl_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    apr_file_close(cert_file);
    BIO_free(bio);
    bio_meth_free(biom);

    if (ssl_cert) {
        *cert = apr_palloc(pool, sizeof(serf_ssl_certificate_t));
        (*cert)->ssl_cert = ssl_cert;

        apr_pool_cleanup_register(pool, ssl_cert, free_ssl_cert,
                                  apr_pool_cleanup_null);

        return APR_SUCCESS;
    }
#if 0
    else {
        /* If we'd have had a serf context *, we could have used serf logging */
        ERR_print_errors_fp(stderr);
    }
#endif

    return SERF_ERROR_SSL_CERT_FAILED;
}


apr_status_t serf_ssl_trust_cert(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_certificate_t *cert)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx->ctx);

    int result = X509_STORE_add_cert(store, cert->ssl_cert);

    return result ? APR_SUCCESS : SERF_ERROR_SSL_CERT_FAILED;
}

apr_status_t serf_ssl_check_crl(serf_ssl_context_t *ssl_ctx, int enabled)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx->ctx);

    if (enabled) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK|
                             X509_V_FLAG_CRL_CHECK_ALL);
    } else {
        X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(store), X509_V_FLAG_CRL_CHECK|
                                      X509_V_FLAG_CRL_CHECK_ALL);
    }
    return APR_SUCCESS;
}

apr_status_t serf_ssl_add_crl_from_file(serf_ssl_context_t *ssl_ctx,
                                        const char *file_path,
                                        apr_pool_t *pool)
{
    apr_file_t *crl_file;
    X509_CRL *crl = NULL;
    X509_STORE *store;
    BIO *bio;
    BIO_METHOD *biom;
    int result;
    apr_status_t status;

    status = apr_file_open(&crl_file, file_path, APR_READ, APR_OS_DEFAULT,
                           pool);
    if (status) {
        return status;
    }

    biom = bio_meth_file_new();
    bio = BIO_new(biom);
    bio_set_data(bio, crl_file);

    crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);

    apr_file_close(crl_file);
    BIO_free(bio);
    bio_meth_free(biom);

    store = SSL_CTX_get_cert_store(ssl_ctx->ctx);

    result = X509_STORE_add_crl(store, crl);
    if (!result) {
        log_ssl_error(ssl_ctx);
        return SERF_ERROR_SSL_CERT_FAILED;
    }

    /* TODO: free crl when closing ssl session */
    return serf_ssl_check_crl(ssl_ctx, 1);
}

apr_status_t
serf_ssl_check_cert_status_request(serf_ssl_context_t *ssl_ctx, int enabled)
{

#ifndef OPENSSL_NO_TLSEXT
    SSL_CTX_set_tlsext_status_cb(ssl_ctx->ctx, ocsp_callback);
    SSL_CTX_set_tlsext_status_arg(ssl_ctx->ctx, ssl_ctx);
    SSL_set_tlsext_status_type(ssl_ctx->ssl, TLSEXT_STATUSTYPE_ocsp);
    return APR_SUCCESS;
#endif
    return APR_ENOTIMPL;
}

serf_bucket_t *serf_bucket_ssl_decrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    serf_bucket_t *bkt;
    ssl_context_t *ctx;

    bkt = serf_bucket_ssl_create(ssl_ctx, allocator,
                                 &serf_bucket_type_ssl_decrypt);

    ctx = bkt->data;

    ctx->databuf = &ctx->ssl_ctx->decrypt.databuf;
    if (ctx->ssl_ctx->decrypt.stream != NULL) {
        return NULL;
    }
    ctx->ssl_ctx->decrypt.stream = stream;
    ctx->our_stream = &ctx->ssl_ctx->decrypt.stream;

    return bkt;
}


serf_ssl_context_t *serf_bucket_ssl_decrypt_context_get(
     serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;
    return ctx->ssl_ctx;
}


serf_bucket_t *serf_bucket_ssl_encrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    serf_bucket_t *bkt;
    ssl_context_t *ctx;

    bkt = serf_bucket_ssl_create(ssl_ctx, allocator,
                                 &serf_bucket_type_ssl_encrypt);

    ctx = bkt->data;

    ctx->databuf = &ctx->ssl_ctx->encrypt.databuf;
    ctx->our_stream = &ctx->ssl_ctx->encrypt.stream;
    if (ctx->ssl_ctx->encrypt.stream == NULL) {
        serf_bucket_t *tmp = serf_bucket_aggregate_create(stream->allocator);
        serf_bucket_aggregate_append(tmp, stream);
        ctx->ssl_ctx->encrypt.stream = tmp;
        if (ctx->ssl_ctx->config) {
            serf_bucket_set_config(ssl_ctx->encrypt.stream,
                                   ctx->ssl_ctx->config);
        }
    }
    else {
        bucket_list_t *new_list;

        new_list = serf_bucket_mem_alloc(ctx->ssl_ctx->allocator,
                                         sizeof(*new_list));
        new_list->bucket = stream;
        new_list->next = NULL;
        if (ctx->ssl_ctx->encrypt.stream_next == NULL) {
            ctx->ssl_ctx->encrypt.stream_next = new_list;
        }
        else {
            bucket_list_t *scan = ctx->ssl_ctx->encrypt.stream_next;

            while (scan->next != NULL)
                scan = scan->next;
            scan->next = new_list;
        }
    }

    return bkt;
}


serf_ssl_context_t *serf_bucket_ssl_encrypt_context_get(
     serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;
    return ctx->ssl_ctx;
}

/* Functions to read a serf_ssl_certificate structure. */

/* Takes a counted length string and escapes any NUL bytes so that
 * it can be used as a C string.  NUL bytes are escaped as 3 characters
 * "\00" (that's a literal backslash).
 * The returned string is allocated in POOL.
 */
static char *
pstrdup_escape_nul_bytes(const char *buf, int len, apr_pool_t *pool)
{
    int i, nul_count = 0;
    char *ret;

    /* First determine if there are any nul bytes in the string. */
    for (i = 0; i < len; i++) {
        if (buf[i] == '\0')
            nul_count++;
    }

    if (nul_count == 0) {
        /* There aren't so easy case to just copy the string */
        ret = apr_pstrdup(pool, buf);
    } else {
        /* There are so we have to replace nul bytes with escape codes
         * Proper length is the length of the original string, plus
         * 2 times the number of nulls (for two digit hex code for
         * the value) + the trailing null. */
        char *pos;
        ret = pos = apr_palloc(pool, len + 2 * nul_count + 1);
        for (i = 0; i < len; i++) {
            if (buf[i] != '\0') {
                *(pos++) = buf[i];
            } else {
                *(pos++) = '\\';
                *(pos++) = '0';
                *(pos++) = '0';
            }
        }
        *pos = '\0';
    }

    return ret;
}

/* Creates a hash_table with keys (E, CN, OU, O, L, ST and C). Any NUL bytes in
   these fields in the certificate will be escaped as \00. */
static apr_hash_t *
convert_X509_NAME_to_table(X509_NAME *org, apr_pool_t *pool)
{
    char buf[1024];
    int ret;

    apr_hash_t *tgt = apr_hash_make(pool);

    ret = X509_NAME_get_text_by_NID(org,
                                    NID_commonName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "CN", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_pkcs9_emailAddress,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "E", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_organizationalUnitName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "OU", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_organizationName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "O", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_localityName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "L", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_stateOrProvinceName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "ST", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));
    ret = X509_NAME_get_text_by_NID(org,
                                    NID_countryName,
                                    buf, 1024);
    if (ret != -1)
        apr_hash_set(tgt, "C", APR_HASH_KEY_STRING,
                     pstrdup_escape_nul_bytes(buf, ret, pool));

    return tgt;
}


int serf_ssl_cert_depth(const serf_ssl_certificate_t *cert)
{
    return cert->depth;
}


apr_hash_t *serf_ssl_cert_issuer(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    X509_NAME *issuer = X509_get_issuer_name(cert->ssl_cert);

    if (!issuer)
        return NULL;

    return convert_X509_NAME_to_table(issuer, pool);
}


apr_hash_t *serf_ssl_cert_subject(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    X509_NAME *subject = X509_get_subject_name(cert->ssl_cert);

    if (!subject)
        return NULL;

    return convert_X509_NAME_to_table(subject, pool);
}


apr_hash_t *serf_ssl_cert_certificate(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    apr_hash_t *tgt = apr_hash_make(pool);
    unsigned int md_size;
    unsigned char md[EVP_MAX_MD_SIZE];
    BIO *bio;
    apr_array_header_t *san_arr;
    apr_array_header_t *ocsp_arr;

    /* sha1 fingerprint */
    if (X509_digest(cert->ssl_cert, EVP_sha1(), md, &md_size)) {
        unsigned int i;
        const char hex[] = "0123456789ABCDEF";
        char fingerprint[EVP_MAX_MD_SIZE * 3];

        for (i=0; i<md_size; i++) {
            fingerprint[3*i] = hex[(md[i] & 0xf0) >> 4];
            fingerprint[(3*i)+1] = hex[(md[i] & 0x0f)];
            fingerprint[(3*i)+2] = ':';
        }
        if (md_size > 0)
            fingerprint[(3*(md_size-1))+2] = '\0';
        else
            fingerprint[0] = '\0';

        apr_hash_set(tgt, "sha1", APR_HASH_KEY_STRING,
                     apr_pstrdup(pool, fingerprint));
    }

    /* set expiry dates */
    bio = BIO_new(BIO_s_mem());
    if (bio) {
        ASN1_TIME *notBefore, *notAfter;
        char buf[256];

        memset (buf, 0, sizeof (buf));
        notBefore = X509_get_notBefore(cert->ssl_cert);
        if (ASN1_TIME_print(bio, notBefore)) {
            BIO_read(bio, buf, 255);
            apr_hash_set(tgt, "notBefore", APR_HASH_KEY_STRING,
                         apr_pstrdup(pool, buf));
        }
        memset (buf, 0, sizeof (buf));
        notAfter = X509_get_notAfter(cert->ssl_cert);
        if (ASN1_TIME_print(bio, notAfter)) {
            BIO_read(bio, buf, 255);
            apr_hash_set(tgt, "notAfter", APR_HASH_KEY_STRING,
                         apr_pstrdup(pool, buf));
        }
    }
    BIO_free(bio);

    /* Get subjectAltNames */
    if (!get_subject_alt_names(&san_arr, cert->ssl_cert, EscapeNulAndCopy, pool))
      apr_hash_set(tgt, "subjectAltName", APR_HASH_KEY_STRING, san_arr);

    /* Get authorityAccessInfo.OCSP */
    if (!get_ocsp_responders(&ocsp_arr, cert->ssl_cert, pool))
      apr_hash_set(tgt, "OCSP", APR_HASH_KEY_STRING, ocsp_arr);

    return tgt;
}


const char *serf_ssl_cert_export(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return serf_ssl_cert_export2(cert, pool, pool);
}

const char *serf_ssl_cert_export2(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
    char *binary_cert;
    char *encoded_cert;
    int len;
    unsigned char *unused;

    /* find the length of the DER encoding. */
    len = i2d_X509(cert->ssl_cert, NULL);
    if (len < 0) {
        return NULL;
    }

    binary_cert = apr_palloc(scratch_pool, len);
    unused = (unsigned char *)binary_cert;
    len = i2d_X509(cert->ssl_cert, &unused);  /* unused is incremented  */
    if (len < 0) {
        return NULL;
    }

    encoded_cert = apr_palloc(result_pool, apr_base64_encode_len(len));
    apr_base64_encode(encoded_cert, binary_cert, len);

    return encoded_cert;
}


serf_ssl_certificate_t *serf_ssl_cert_import(
    const char *encoded_cert,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
    char *binary_cert;
    int binary_len;
    const unsigned char *unused;
    X509* ssl_cert;
    serf_ssl_certificate_t *cert;

    binary_cert = apr_palloc(scratch_pool, apr_base64_decode_len(encoded_cert));
    binary_len = apr_base64_decode(binary_cert, encoded_cert);

    unused = (unsigned char*) binary_cert; /* unused is incremented  */
    ssl_cert = d2i_X509(NULL, &unused, binary_len);
    if (!ssl_cert) {
        return NULL;
    }

    cert = apr_palloc(result_pool, sizeof(serf_ssl_certificate_t));
    cert->ssl_cert = ssl_cert;

    apr_pool_cleanup_register(result_pool, ssl_cert, free_ssl_cert,
                              apr_pool_cleanup_null);

    return cert;
}


/* Disables compression for all SSL sessions. */
static void disable_compression(serf_ssl_context_t *ssl_ctx)
{
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_COMPRESSION);
#endif
}

apr_status_t serf_ssl_use_compression(serf_ssl_context_t *ssl_ctx, int enabled)
{
    if (enabled) {
#ifdef SSL_OP_NO_COMPRESSION
        SSL_clear_options(ssl_ctx->ssl, SSL_OP_NO_COMPRESSION);
        return APR_SUCCESS;
#endif
    } else {
#ifdef SSL_OP_NO_COMPRESSION
        SSL_set_options(ssl_ctx->ssl, SSL_OP_NO_COMPRESSION);
        return APR_SUCCESS;
#endif
    }

    return APR_EGENERAL;
}

static void serf_ssl_destroy_and_data(serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;

    if (!--ctx->ssl_ctx->refcount) {
        ssl_free_context(ctx->ssl_ctx);
    }

    serf_default_destroy_and_data(bucket);
}

static void serf_ssl_decrypt_destroy_and_data(serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;

    serf_bucket_destroy(*ctx->our_stream);

    serf_ssl_destroy_and_data(bucket);
}

static void serf_ssl_encrypt_destroy_and_data(serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;
    serf_ssl_context_t *ssl_ctx = ctx->ssl_ctx;

    if (ssl_ctx->encrypt.stream == *ctx->our_stream) {
        serf_bucket_destroy(*ctx->our_stream);
        serf_bucket_destroy(ssl_ctx->encrypt_pending);

        /* Reset our status and databuf. */
        ssl_ctx->crypt_status = APR_SUCCESS;
        ssl_ctx->encrypt.databuf.status = APR_SUCCESS;

        /* Advance to the next stream - if we have one. */
        if (ssl_ctx->encrypt.stream_next == NULL) {
            ssl_ctx->encrypt.stream = NULL;
            ssl_ctx->encrypt_pending = NULL;
        }
        else {
            bucket_list_t *cur;

            cur = ssl_ctx->encrypt.stream_next;
            ssl_ctx->encrypt.stream = cur->bucket;
            ssl_ctx->encrypt_pending =
                serf_bucket_aggregate_create(cur->bucket->allocator);
            ssl_ctx->encrypt.stream_next = cur->next;
            serf_bucket_mem_free(ssl_ctx->allocator, cur);
        }
    }
    else {
        /* Ah, darn.  We haven't sent this one along yet. */
        return;
    }
    serf_ssl_destroy_and_data(bucket);
}

static apr_status_t serf_ssl_read(serf_bucket_t *bucket,
                                  apr_size_t requested,
                                  const char **data, apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_read(ctx->databuf, requested, data, len);
}

static apr_status_t serf_ssl_readline(serf_bucket_t *bucket,
                                      int acceptable, int *found,
                                      const char **data,
                                      apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_readline(ctx->databuf, acceptable, found, data, len);
}

static apr_status_t serf_ssl_peek(serf_bucket_t *bucket,
                                  const char **data,
                                  apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_peek(ctx->databuf, data, len);
}

static apr_status_t serf_ssl_set_config(serf_bucket_t *bucket,
                                        serf_config_t *config)
{
    ssl_context_t *ctx = bucket->data;
    serf_ssl_context_t *ssl_ctx = ctx->ssl_ctx;
    apr_status_t err_status = APR_SUCCESS;
    const char *pipelining;
    apr_status_t status;

    if (ssl_ctx->config == config)
        return APR_SUCCESS; /* Don't loop */

    ssl_ctx->config = config;

    /* Distribute the shared config as much as possible. */
    if (ssl_ctx) {
        if (ssl_ctx->encrypt.stream) {
            status = serf_bucket_set_config(ssl_ctx->encrypt.stream, config);
            if (status)
                err_status = status;
        }
        if (ssl_ctx->decrypt.stream) {
            status = serf_bucket_set_config(ssl_ctx->decrypt.stream, config);
            if (status)
                err_status = status;
        }
    }

    if (config) {
        status = serf_config_get_string(config, SERF_CONFIG_CONN_PIPELINING,
                                        &pipelining);
        if (status)
            return status;

        if (strcmp(pipelining, "Y") == 0) {
            SSL_CTX_set_info_callback(ssl_ctx->ctx, detect_renegotiate);
        }
    }

    return err_status;
}

const serf_bucket_type_t serf_bucket_type_ssl_encrypt = {
    "SSLENCRYPT",
    serf_ssl_read,
    serf_ssl_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_ssl_peek,
    serf_ssl_encrypt_destroy_and_data,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_ssl_set_config,
};

const serf_bucket_type_t serf_bucket_type_ssl_decrypt = {
    "SSLDECRYPT",
    serf_ssl_read,
    serf_ssl_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_ssl_peek,
    serf_ssl_decrypt_destroy_and_data,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_ssl_set_config,
};


/*
 * OCSP bits are here because they depend on OpenSSL and private types
 * defined in this file.
 */

#ifndef OPENSSL_NO_OCSP
struct serf_ssl_ocsp_request_t {
    /* OpenSSL's internal representation of the OCSP request. */
    OCSP_REQUEST *request;

    /* DER-encoded request and size. */
    const void *der_request;
    apr_size_t der_request_size;

    /* Exported server and issuer certificates. */
    const char *encoded_server_cert;
    const char *encoded_issuer_cert;
};

static apr_status_t free_ocsp_request(void *data)
{
    OCSP_REQUEST_free(data);
    return APR_SUCCESS;
}
#endif  /* OPENSSL_NO_OCSP */


serf_ssl_ocsp_request_t *serf_ssl_ocsp_request_create(
    const serf_ssl_certificate_t *server_cert,
    const serf_ssl_certificate_t *issuer_cert,
    int generate_nonce,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
#ifndef OPENSSL_NO_OCSP
    X509 *const cert = server_cert->ssl_cert;
    X509 *const issuer = issuer_cert->ssl_cert;

    serf_ssl_ocsp_request_t *req = NULL;
    OCSP_REQUEST *ocsp_req = NULL;
    OCSP_CERTID *cert_id = NULL;
    unsigned char *unused;
    void *der;
    int len;

    if (X509_V_OK != X509_check_issued(issuer, cert))
        goto cleanup;

    /* TODO: Support other hash algorithms besides the default SHA1. */
    cert_id = OCSP_cert_to_id(NULL, cert, issuer);
    if (!cert_id)
        goto cleanup;

    ocsp_req = OCSP_REQUEST_new();
    if (!ocsp_req)
        goto cleanup;

    if (!OCSP_request_add0_id(ocsp_req, cert_id))
        goto cleanup;
    cert_id = NULL;

    if (generate_nonce) {
        /* Generates a random nonce, using the internal random generator. */
        if (!OCSP_request_add1_nonce(ocsp_req, NULL, -1))
            goto cleanup;
    }

    /* Generate the DER form of the request. */
    len = i2d_OCSP_REQUEST(ocsp_req, NULL);
    if (len < 0)
        goto cleanup;

    unused = der = apr_palloc(result_pool, len);
    len = i2d_OCSP_REQUEST(ocsp_req, &unused); /* unused is incremented */
    if (len < 0)
        goto cleanup;

    req = apr_palloc(result_pool, sizeof(*req));
    req->der_request = der;
    req->der_request_size = len;
    req->encoded_server_cert =
        serf_ssl_cert_export2(server_cert, result_pool, scratch_pool);
    req->encoded_issuer_cert =
        serf_ssl_cert_export2(issuer_cert, result_pool, scratch_pool);

    /* Now move the unencoded request to the result. */
    req->request = ocsp_req;
    apr_pool_cleanup_register(result_pool, ocsp_req,
                              free_ocsp_request,
                              apr_pool_cleanup_null);
    ocsp_req = NULL;

  cleanup:
    if (ocsp_req)
        OCSP_REQUEST_free(ocsp_req);
    if (cert_id)
        OCSP_CERTID_free(cert_id);
    return req;
#else
    return NULL;
#endif  /* OPENSSL_NO_OCSP */
}

const void *serf_ssl_ocsp_request_body(
    const serf_ssl_ocsp_request_t *ocsp_request)
{
#ifndef OPENSSL_NO_OCSP
    return ocsp_request->der_request;
#else
    return NULL;
#endif  /* OPENSSL_NO_OCSP */
}

apr_size_t serf_ssl_ocsp_request_body_size(
    const serf_ssl_ocsp_request_t *ocsp_request)
{
#ifndef OPENSSL_NO_OCSP
    return ocsp_request->der_request_size;
#else
    return 0;
#endif  /* OPENSSL_NO_OCSP */
}

const char *serf_ssl_ocsp_request_export(
    const serf_ssl_ocsp_request_t *ocsp_request,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
#ifndef OPENSSL_NO_OCSP

    /*
      The structure of the exported request is:

        "Base64-server-cert" "\x1"
        "Base64-issuer-cert" "\x1"
        "Base64-DER-formatted-request" "\0"
    */

    const apr_size_t s_size = strlen(ocsp_request->encoded_server_cert);
    const apr_size_t i_size = strlen(ocsp_request->encoded_issuer_cert);
    const apr_size_t all_size = (
        apr_base64_encode_len(ocsp_request->der_request_size)
        + s_size + i_size + 3); /* Three terminator bytes */

    char *const buffer = apr_palloc(result_pool, all_size);
    char *p = buffer;

    memcpy(p, ocsp_request->encoded_server_cert, s_size);
    p += s_size;
    *p++ = '\x1';

    memcpy(p, ocsp_request->encoded_issuer_cert, i_size);
    p += i_size;
    *p++ = '\x1';

    apr_base64_encode(p, ocsp_request->der_request,
                      ocsp_request->der_request_size);

    return buffer;
#else
    return NULL;
#endif  /* OPENSSL_NO_OCSP */
}

serf_ssl_ocsp_request_t *serf_ssl_ocsp_request_import(
    const char *encoded_ocsp_request,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
#ifndef OPENSSL_NO_OCSP
    serf_ssl_ocsp_request_t *req = NULL;
    const char *encoded_server_cert = encoded_ocsp_request;
    const char *encoded_issuer_cert;
    const char *end_server_cert;
    const char *end_issuer_cert;

    end_server_cert = strchr(encoded_server_cert, '\x1');
    if (!end_server_cert)
        return NULL;

    encoded_issuer_cert = end_server_cert + 1;
    end_issuer_cert = strchr(encoded_issuer_cert, '\x1');

    if (end_issuer_cert) {
        OCSP_REQUEST *ocsp_req;
        const char *base64_request = end_issuer_cert + 1;
        long der_request_size = apr_base64_decode_len(base64_request);
        /* FIXME: Use scratch pool instead and pmemdup later? */
        void *der_request = apr_palloc(result_pool, der_request_size);
        const unsigned char *unused = der_request;

        der_request_size = apr_base64_decode(der_request, base64_request);
        ocsp_req = d2i_OCSP_REQUEST(NULL, &unused, der_request_size);
        if (!ocsp_req)
            return NULL;

        req = apr_palloc(result_pool, sizeof(*req));
        req->der_request = der_request;
        req->der_request_size = der_request_size;
        req->encoded_server_cert =
            apr_pstrmemdup(result_pool, encoded_server_cert,
                           end_server_cert - encoded_server_cert);
        req->encoded_issuer_cert =
            apr_pstrmemdup(result_pool, encoded_issuer_cert,
                           end_issuer_cert - encoded_issuer_cert);

        req->request = ocsp_req;
        apr_pool_cleanup_register(result_pool, ocsp_req,
                                  free_ocsp_request,
                                  apr_pool_cleanup_null);
    }

    return req;
#else
    return NULL;
#endif  /* OPENSSL_NO_OCSP */
}

#ifndef OPENSSL_NO_OCSP
struct serf_ssl_ocsp_response_t {
    /* OpenSSL's internal representation of the OCSP response. */
    OCSP_BASICRESP *response;
};
#endif  /* OPENSSL_NO_OCSP */

serf_ssl_ocsp_response_t *serf_ssl_ocsp_response_parse(
    const void *ocsp_response_body,
    apr_size_t ocsp_response_size,
    apr_pool_t *result_pool,
    apr_pool_t *scratch_pool)
{
#ifndef OPENSSL_NO_OCSP
    return NULL;
#else
    return NULL;
#endif  /* OPENSSL_NO_OCSP */
}

apr_status_t serf_ssl_ocsp_response_verify(
    const serf_ssl_ocsp_response_t *ocsp_response,
    const serf_ssl_ocsp_request_t *ocsp_request,
    apr_time_t *this_update,
    apr_time_t *next_update,
    apr_time_t *produced_at,
    apr_pool_t *scratch_pool)
{
#ifndef OPENSSL_NO_OCSP
    return SERF_ERROR_SSL_OCSP_RESPONSE_INVALID;
#else
    return SERF_ERROR_SSL_OCSP_RESPONSE_INVALID;
#endif  /* OPENSSL_NO_OCSP */
}
