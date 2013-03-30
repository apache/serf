/* Copyright 2013 Justin Erenkrantz and Greg Stein
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

#ifdef SERF_HAVE_SECURETRANSPORT

#include "serf.h"
#include "serf_private.h"
#include "serf_bucket_util.h"
#include "bucket_private.h"

#include <Security/SecureTransport.h>

static OSStatus
sectrans_read_cb(SSLConnectionRef connection, void *data, size_t *dataLength);
static OSStatus
sectrans_write_cb(SSLConnectionRef connection, const void *data, size_t *dataLength);

typedef struct sectrans_ssl_stream_t {
    /* For an encrypt stream: data encrypted & not yet written to the network.
       For a decrypt stream: data decrypted & not yet read by the application.*/
    serf_bucket_t *pending;

    /* For an encrypt stream: the outgoing data provided by the application.
       For a decrypt stream: encrypted data read from the network. */
    serf_bucket_t *stream;
} sectrans_ssl_stream_t;


/* States for the different stages in the lifecyle of an SSL session. */
typedef enum {
    SERF_SECTRANS_INIT,       /* no SSL handshake yet */
    SERF_SECTRANS_HANDSHAKE,  /* SSL handshake in progress */
    SERF_SECTRANS_CONNECTED,  /* SSL handshake successfully finished */
    SERF_SECTRANS_CLOSING,    /* SSL session closing */
} sectrans_session_state_t;

typedef struct sectrans_context_t {
    /* How many open buckets refer to this context. */
    int refcount;

    SSLContextRef st_ctxr;

    /* stream of (to be) encrypted data, outgoing to the network. */
    sectrans_ssl_stream_t encrypt;

    /* stream of (to be) decrypted data, read from the network. */
    sectrans_ssl_stream_t decrypt;

    sectrans_session_state_t state;
} sectrans_context_t;

static apr_status_t
translate_sectrans_status(OSStatus status)
{
    switch (status)
    {
        case noErr:
            return APR_SUCCESS;
        case errSSLWouldBlock:
            return APR_EAGAIN;
        default:
            serf__log(SSL_VERBOSE, __FILE__,
                      "Unknown Secure Transport error %d\n", status);
            return APR_EGENERAL;
    }
}

apr_status_t pending_stream_eof(void *baton,
                                serf_bucket_t *pending)
{
    /* TODO: peek stream bucket for status */
    return APR_EAGAIN;
}

static sectrans_context_t *
sectrans_init_context(serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->refcount = 0;

    /* Set up the stream objects. */
    ctx->encrypt.pending = serf__bucket_stream_create(allocator,
                                                      pending_stream_eof,
                                                      ctx->encrypt.stream);
    ctx->decrypt.pending = serf__bucket_stream_create(allocator,
                                                      pending_stream_eof,
                                                      ctx->decrypt.stream);

    /* Set up a Secure Transport session. */
    ctx->state = SERF_SECTRANS_INIT;

    if (SSLNewContext(FALSE, &ctx->st_ctxr))
        return NULL;

    if (SSLSetIOFuncs(ctx->st_ctxr, sectrans_read_cb, sectrans_write_cb))
        return 0;

    /* Ensure the sectrans_context will be passed to the read and write callback
       functions. */
    if (SSLSetConnection(ctx->st_ctxr, ctx))
        return 0;

    return ctx;
}

static apr_status_t
sectrans_free_context(sectrans_context_t * ctx, serf_bucket_alloc_t *allocator)
{
    OSStatus status = SSLDisposeContext (ctx->st_ctxr);

    serf_bucket_mem_free(allocator, ctx);

    if (status)
        return APR_EGENERAL;

    return APR_SUCCESS;
}

/**
 * Note for both read and write callback functions, from SecureTransport.h:
 * "Data's memory is allocated by caller; on entry to these two functions
 *  the *length argument indicates both the size of the available data and the
 *  requested byte count. Number of bytes actually transferred is returned in
 *  *length."
 **/

/** Secure Transport callback function.
    Reads encrypted data from the network. **/
static OSStatus
sectrans_read_cb(SSLConnectionRef connection,
                 void *data,
                 size_t *dataLength)
{
    const sectrans_context_t *ctx = connection;
    apr_status_t status = 0;
    const char *buf, *outbuf = data;
    size_t requested = *dataLength;

    serf__log(SSL_VERBOSE, __FILE__, "sectrans_read_cb called for "
              "%d bytes\n", requested);

    while (!status && requested) {
        status = serf_bucket_read(ctx->decrypt.stream, requested,
                                  &buf, dataLength);

        if (SERF_BUCKET_READ_ERROR(status))
            return -1;

        if (*dataLength)
        {
            serf__log(SSL_VERBOSE, __FILE__, "sectrans_read_cb read %d bytes with "
                      "status %d\n", *dataLength, status);

            /* Copy the data in the buffer provided by the caller. */
            memcpy(outbuf, buf, *dataLength);
            outbuf += *dataLength;
            requested -= *dataLength;
        }
    }

    if (APR_STATUS_IS_EAGAIN(status))
        return errSSLWouldBlock;

    if (!status)
        return noErr;

    /* TODO: map apr status to Mac OS X error codes(??) */
    return -1;
}

/** Secure Transport callback function.
    Writes encrypted data to the network. **/
static OSStatus
sectrans_write_cb(SSLConnectionRef connection,
                  const void *data,
                  size_t *dataLength)
{
    serf_bucket_t *tmp;
    const sectrans_context_t *ctx = connection;

    serf__log(SSL_VERBOSE, __FILE__, "sectrans_write_cb called for "
              "%d bytes.\n", *dataLength);

    tmp = serf_bucket_simple_copy_create(data, *dataLength,
                                         ctx->encrypt.pending->allocator);

    serf_bucket_aggregate_append(ctx->encrypt.pending, tmp);

    return noErr;
}

static apr_status_t do_handshake(sectrans_context_t *ssl_ctx)
{
    serf__log(SSL_VERBOSE, __FILE__, "do_handshake called.\n");

    OSStatus status = SSLHandshake(ssl_ctx->st_ctxr);

    return translate_sectrans_status(status);
}

/**** SSL_BUCKET API ****/
/************************/
static void *
decrypt_create(serf_bucket_t *bucket,
               serf_bucket_t *stream,
               void *impl_ctx,
               serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ctx;
    bucket->type = &serf_bucket_type_sectrans_decrypt;
    bucket->allocator = allocator;

    if (impl_ctx)
        bucket->data = impl_ctx;
    else
        bucket->data = sectrans_init_context(allocator);

    ctx = bucket->data;
    ctx->refcount++;
    ctx->decrypt.stream = stream;

    return bucket->data;
}

static void *
encrypt_create(serf_bucket_t *bucket,
               serf_bucket_t *stream,
               void *impl_ctx,
               serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ctx;
    bucket->type = &serf_bucket_type_sectrans_encrypt;
    bucket->allocator = allocator;

    if (impl_ctx)
        bucket->data = impl_ctx;
    else
        bucket->data = sectrans_init_context(allocator);

    ctx = bucket->data;
    ctx->refcount++;
    ctx->encrypt.stream = stream;

    return bucket->data;
}

static void *
decrypt_context_get(serf_bucket_t *bucket)
{
    return NULL;
}

static void *
encrypt_context_get(serf_bucket_t *bucket)
{
    return NULL;
}


static void
client_cert_provider_set(void *impl_ctx,
                         serf_ssl_need_client_cert_t callback,
                         void *data,
                         void *cache_pool)
{
    return;
}


static void
client_cert_password_set(void *impl_ctx,
                         serf_ssl_need_cert_password_t callback,
                         void *data,
                         void *cache_pool)
{
    return;
}


static void
server_cert_callback_set(void *impl_ctx,
                         serf_ssl_need_server_cert_t callback,
                         void *data)
{
    return;
}

static void
server_cert_chain_callback_set(
    void *impl_ctx,
    serf_ssl_need_server_cert_t cert_callback,
    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
    void *data)
{
    return;
}

static apr_status_t
set_hostname(void *impl_ctx, const char * hostname)
{
    sectrans_context_t *ctx = impl_ctx;

    OSStatus status = SSLSetPeerDomainName(ctx->st_ctxr,
                                           hostname,
                                           strlen(hostname));
    return status;
}

static apr_status_t
use_default_certificates(void *impl_ctx)
{
    /* Secure transport uses default certificates automatically.
       TODO: verify if this true. */
    return APR_SUCCESS;
}

static apr_status_t
load_cert_file(serf_ssl_certificate_t **cert,
               const char *file_path,
               apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function load_cert_file not implemented.\n");

    return APR_ENOTIMPL;
}


static apr_status_t trust_cert(void *impl_ctx,
                               serf_ssl_certificate_t *cert)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function trust_cert not implemented.\n");

    return APR_ENOTIMPL;
}

static apr_status_t use_compression(void *impl_ctx, int enabled)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function use_compression not implemented.\n");

    return APR_ENOTIMPL;
}

/**** ENCRYPTION BUCKET API *****/
/********************************/
static apr_status_t
serf_sectrans_encrypt_read(serf_bucket_t *bucket,
                           apr_size_t requested,
                           const char **data, apr_size_t *len)
{
    sectrans_context_t *ctx = bucket->data;

    serf__log(SSL_VERBOSE, __FILE__, "serf_sectrans_encrypt_read called for "
              "%d bytes.\n", requested);

    if (ctx->state == SERF_SECTRANS_INIT ||
        ctx->state == SERF_SECTRANS_HANDSHAKE)
    {
        apr_status_t status;

        ctx->state = SERF_SECTRANS_HANDSHAKE;
        status = do_handshake(ctx);

        if (!status)
        {
            serf__log(SSL_VERBOSE, __FILE__, "ssl/tls handshake successful.\n");
            ctx->state = SERF_SECTRANS_CONNECTED;
            return APR_SUCCESS;
        }
        if (SERF_BUCKET_READ_ERROR(status))
            return status;
    }

    /* Maybe the handshake algorithm put some data in the pending outgoing
       bucket */
    return serf_bucket_read(ctx->encrypt.pending, requested, data, len);
}

static apr_status_t
serf_sectrans_encrypt_peek(serf_bucket_t *bucket,
                           const char **data,
                           apr_size_t *len)
{
    sectrans_context_t *ctx = bucket->data;

    return serf_bucket_peek(ctx->decrypt.pending, data, len);
}

static void
serf_sectrans_encrypt_destroy_and_data(serf_bucket_t *bucket)
{
    sectrans_context_t *ctx = bucket->data;

    if (!--ctx->refcount) {
        sectrans_free_context(ctx, bucket->allocator);
    }

    serf_bucket_ssl_destroy_and_data(bucket);
}

/**** DECRYPTION BUCKET API *****/
/********************************/
static apr_status_t
serf_sectrans_decrypt_peek(serf_bucket_t *bucket,
                           const char **data,
                           apr_size_t *len)
{
    sectrans_context_t *ctx = bucket->data;
    
    return serf_bucket_peek(ctx->encrypt.pending, data, len);
}

static apr_status_t
serf_sectrans_decrypt_read(serf_bucket_t *bucket,
                           apr_size_t requested,
                           const char **data, apr_size_t *len)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function serf_sectrans_decrypt_read not implemented.\n");
    return APR_ENOTIMPL;
}

static apr_status_t
serf_sectrans_readline(serf_bucket_t *bucket,
                       int acceptable, int *found,
                       const char **data,
                       apr_size_t *len)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function serf_sectrans_readline not implemented.\n");
    return APR_ENOTIMPL;
}

static void
serf_sectrans_decrypt_destroy_and_data(serf_bucket_t *bucket)
{
    sectrans_context_t *ctx = bucket->data;

    if (!--ctx->refcount) {
        sectrans_free_context(ctx, bucket->allocator);
    }

    serf_bucket_ssl_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_sectrans_encrypt = {
    "SECURETRANSPORTENCRYPT",
    serf_sectrans_encrypt_read,
    serf_sectrans_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_sectrans_encrypt_peek,
    serf_sectrans_encrypt_destroy_and_data,
};

const serf_bucket_type_t serf_bucket_type_sectrans_decrypt = {
    "SECURETRANSPORTDECRYPT",
    serf_sectrans_decrypt_read,
    serf_sectrans_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_sectrans_decrypt_peek,
    serf_sectrans_decrypt_destroy_and_data,
};

const serf_ssl_bucket_type_t serf_ssl_bucket_type_securetransport = {
    decrypt_create,
    decrypt_context_get,
    encrypt_create,
    encrypt_context_get,
    set_hostname,
    client_cert_provider_set,
    client_cert_password_set,
    server_cert_callback_set,
    server_cert_chain_callback_set,
    use_default_certificates,
    load_cert_file,
    trust_cert,
    use_compression,
};

#endif /* SERF_HAVE_SECURETRANSPORT */
