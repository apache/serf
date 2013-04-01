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
#include <Security/SecPolicy.h>

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

    serf_bucket_alloc_t *allocator;

    SSLContextRef st_ctxr;

    /* stream of (to be) encrypted data, outgoing to the network. */
    sectrans_ssl_stream_t encrypt;

    /* stream of (to be) decrypted data, read from the network. */
    sectrans_ssl_stream_t decrypt;

    sectrans_session_state_t state;

    /* Server cert callbacks */
    serf_ssl_need_server_cert_t server_cert_callback;
    serf_ssl_server_cert_chain_cb_t server_cert_chain_callback;
    void *server_cert_userdata;
    
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
    sectrans_context_t *ssl_ctx;

    ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));
    ssl_ctx->refcount = 0;

    /* Set up the stream objects. */
    ssl_ctx->encrypt.pending = serf__bucket_stream_create(allocator,
                                                          pending_stream_eof,
                                                          ssl_ctx->encrypt.stream);
    ssl_ctx->decrypt.pending = serf__bucket_stream_create(allocator,
                                                          pending_stream_eof,
                                                          ssl_ctx->decrypt.stream);

    /* Set up a Secure Transport session. */
    ssl_ctx->state = SERF_SECTRANS_INIT;

    if (SSLNewContext(FALSE, &ssl_ctx->st_ctxr))
        return NULL;

    if (SSLSetIOFuncs(ssl_ctx->st_ctxr, sectrans_read_cb, sectrans_write_cb))
        return NULL;

    /* Ensure the sectrans_context will be passed to the read and write callback
       functions. */
    if (SSLSetConnection(ssl_ctx->st_ctxr, ssl_ctx))
        return NULL;

    /* We do our own validation of server certificates.
       Note that Secure Transport will not do any validation with this option
       enabled, it's all or nothing. */
    if (SSLSetSessionOption(ssl_ctx->st_ctxr,
                            kSSLSessionOptionBreakOnServerAuth,
                            true))
        return NULL;
    if (SSLSetEnableCertVerify(ssl_ctx->st_ctxr, false))
        return NULL;

    return ssl_ctx;
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
    const sectrans_context_t *ssl_ctx = connection;
    apr_status_t status = 0;
    const char *buf;
    char *outbuf = data;
    size_t requested = *dataLength, buflen = 0;

    serf__log(SSL_VERBOSE, __FILE__, "sectrans_read_cb called for "
              "%d bytes\n", requested);

    *dataLength = 0;
    while (!status && requested) {
        status = serf_bucket_read(ssl_ctx->decrypt.stream, requested,
                                  &buf, &buflen);

        if (SERF_BUCKET_READ_ERROR(status))
            return -1;

        if (buflen)
        {
            serf__log(SSL_VERBOSE, __FILE__, "sectrans_read_cb read %d bytes "
                      "with status %d\n", buflen, status);

            /* Copy the data in the buffer provided by the caller. */
            memcpy(outbuf, buf, buflen);
            outbuf += buflen;
            requested -= buflen;
            (*dataLength) += buflen;
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

/* Get the hostname back from the Secure Transport layer.
   Uses ssl_ctx->allocator to allocate a sufficiently large buffer, caller is
   responsible to free the buffer. */
static char*
get_hostname(sectrans_context_t *ssl_ctx)
{
    size_t strlen;
    char *str;

    (void)SSLGetPeerDomainNameLength(ssl_ctx->st_ctxr, &strlen);
    str = serf_bucket_mem_alloc(ssl_ctx->allocator, strlen);

    (void)SSLGetPeerDomainName(ssl_ctx->st_ctxr, str, &strlen);

    return str;
}

static int
validate_server_certificate(sectrans_context_t *ssl_ctx)
{
    OSStatus sectrans_status;
    CFArrayRef certs;
    SecTrustRef trust;
    SecTrustResultType result;
    SecPolicyRef policy;
    CFStringRef hostname;
    char *str;
    int failures = 0;
    size_t depth;

    serf__log(SSL_VERBOSE, __FILE__, "validate_server_certificate called.\n");
    /* Get the server certificate chain. */
    sectrans_status = SSLCopyPeerCertificates(ssl_ctx->st_ctxr, &certs);
    if (sectrans_status != noErr)
        return translate_sectrans_status(sectrans_status);
    depth = (size_t)CFArrayGetCount(certs);
    
    /* Use Certificate, Key and Trust services to validate the server
       certificate chain. */

    /* Get a policy for evaluation of SSL certificate chains.
       Note: requires Mac OS X v10.6 or later */
    str = get_hostname(ssl_ctx);
    hostname = CFStringCreateWithCStringNoCopy(NULL, str,
                                               kCFStringEncodingMacRoman,
                                               kCFAllocatorNull);
    policy = SecPolicyCreateSSL (false, hostname);

    /* Evaluate the certificate chain against the SSL policy */
    sectrans_status = SecTrustCreateWithCertificates(certs, policy, &trust);
    if (sectrans_status != noErr)
        return translate_sectrans_status(sectrans_status);

    /* TODO: SecTrustEvaluateAsync */
    sectrans_status = SecTrustEvaluate(trust, &result);
    if (sectrans_status != noErr)
        return translate_sectrans_status(sectrans_status);

    /* TODO: Decide per case how to handle. */
    switch (result)
    {
        case kSecTrustResultInvalid:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultInvalid.\n");
            break;
        case kSecTrustResultProceed:
            failures = 0;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultProceed.\n");
            break;
        case kSecTrustResultConfirm:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultConfirm.\n");
            break;
        case kSecTrustResultDeny:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultDeny.\n");
            break;
        case kSecTrustResultUnspecified:
            failures = 0;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultUnspecified.\n");
            break;
        case kSecTrustResultRecoverableTrustFailure:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultRecoverableTrustFailure.\n");
            break;
        case kSecTrustResultFatalTrustFailure:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultFatalTrustFailure.\n");
            break;
        case kSecTrustResultOtherError:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultOtherError.\n");
            break;
        default:
            failures = 1;
            serf__log(SSL_VERBOSE, __FILE__, "unknown.\n");
            break;

    }

    if (ssl_ctx->server_cert_callback &&
        (depth == 0 || failures)) {
        apr_status_t status;
        serf_ssl_certificate_t *cert;

        cert = serf__create_certificate(ssl_ctx->allocator,
                                        &serf_ssl_bucket_type_securetransport,
                                        (void *)CFArrayGetValueAtIndex(certs, 0),
                                        depth);

        /* Callback for further verification. */
        status = ssl_ctx->server_cert_callback(ssl_ctx->server_cert_userdata,
                                               failures, cert);
        if (status == APR_SUCCESS)
        {
            serf__log(SSL_VERBOSE, __FILE__, "don't know how to handle this yet.\n");
            abort();
        }
        else
            return status;

        serf_bucket_mem_free(ssl_ctx->allocator, cert);
    }

    CFRelease(hostname);
    serf_bucket_mem_free(ssl_ctx->allocator, str);
    CFRelease(policy);
    CFRelease(certs);
    CFRelease(trust);

    return APR_EAGAIN;
}

static apr_status_t do_handshake(sectrans_context_t *ssl_ctx)
{
    OSStatus sectrans_status;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__, "do_handshake called.\n");

    sectrans_status = SSLHandshake(ssl_ctx->st_ctxr);

    switch(sectrans_status) {
        case errSSLServerAuthCompleted:
            return validate_server_certificate(ssl_ctx);
        case errSSLClientCertRequested:
            
        default:
            status = translate_sectrans_status(sectrans_status);
            break;
    }

    return status;
}


/**** SSL_BUCKET API ****/
/************************/
static void *
decrypt_create(serf_bucket_t *bucket,
               serf_bucket_t *stream,
               void *impl_ctx,
               serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ssl_ctx;
    bucket->type = &serf_bucket_type_sectrans_decrypt;
    bucket->allocator = allocator;

    if (impl_ctx)
        bucket->data = impl_ctx;
    else
        bucket->data = sectrans_init_context(allocator);

    ssl_ctx = bucket->data;
    ssl_ctx->refcount++;
    ssl_ctx->decrypt.stream = stream;
    ssl_ctx->allocator = allocator;

    return bucket->data;
}

static void *
encrypt_create(serf_bucket_t *bucket,
               serf_bucket_t *stream,
               void *impl_ctx,
               serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ssl_ctx;
    bucket->type = &serf_bucket_type_sectrans_encrypt;
    bucket->allocator = allocator;

    if (impl_ctx)
        bucket->data = impl_ctx;
    else
        bucket->data = sectrans_init_context(allocator);

    ssl_ctx = bucket->data;
    ssl_ctx->refcount++;
    ssl_ctx->encrypt.stream = stream;
    ssl_ctx->allocator = allocator;

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


void server_cert_callback_set(void *impl_ctx,
                              serf_ssl_need_server_cert_t callback,
                              void *data)
{
    sectrans_context_t *ssl_ctx = impl_ctx;

    ssl_ctx->server_cert_callback = callback;
    ssl_ctx->server_cert_userdata = data;
}

void server_cert_chain_callback_set(void *impl_ctx,
                                    serf_ssl_need_server_cert_t cert_callback,
                                    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
                                    void *data)
{
    sectrans_context_t *ssl_ctx = impl_ctx;
    
    ssl_ctx->server_cert_callback = cert_callback;
    ssl_ctx->server_cert_chain_callback = cert_chain_callback;
    ssl_ctx->server_cert_userdata = data;
}

static apr_status_t
set_hostname(void *impl_ctx, const char * hostname)
{
    sectrans_context_t *ssl_ctx = impl_ctx;

    OSStatus status = SSLSetPeerDomainName(ssl_ctx->st_ctxr,
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

/* Functions to read a serf_ssl_certificate structure. */
int cert_depth(const serf_ssl_certificate_t *cert)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_depth not implemented.\n");

    return 0;
}

apr_hash_t *cert_issuer(const serf_ssl_certificate_t *cert,
                        apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_issuer not implemented.\n");

    return NULL;
}

apr_hash_t *cert_subject(const serf_ssl_certificate_t *cert,
                         apr_pool_t *pool)
{
#if 0
    SecCertificateRef cr = cert->impl_cert;
    CFStringRef commonName;
    
    SecCertificateCopyCommonName(cr, &commonName);


    CFRelease(commonName);
#endif
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_subject not implemented.\n");

    return NULL;
}

apr_hash_t *cert_certificate(const serf_ssl_certificate_t *cert,
                             apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_certificate not implemented.\n");
    
    return NULL;
}

apr_hash_t *cert_export(const serf_ssl_certificate_t *cert,
                        apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_export not implemented.\n");

    return NULL;
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
    sectrans_context_t *ssl_ctx = bucket->data;
    apr_status_t status;
    const char *unenc_data;
    size_t unenc_len;
    
    serf__log(SSL_VERBOSE, __FILE__, "serf_sectrans_encrypt_read called for "
              "%d bytes.\n", requested);

    /* Pending handshake? */
    if (ssl_ctx->state == SERF_SECTRANS_INIT ||
        ssl_ctx->state == SERF_SECTRANS_HANDSHAKE)
    {
        ssl_ctx->state = SERF_SECTRANS_HANDSHAKE;
        status = do_handshake(ssl_ctx);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        if (!status)
        {
            serf__log(SSL_VERBOSE, __FILE__, "ssl/tls handshake successful.\n");
            ssl_ctx->state = SERF_SECTRANS_CONNECTED;
        } else {
            /* Maybe the handshake algorithm put some data in the pending
               outgoing bucket? */
            return serf_bucket_read(ssl_ctx->encrypt.pending, requested, data, len);
        }
    }

    /* Handshake successful. */

    /* First use any pending encrypted data. */
    status = serf_bucket_read(ssl_ctx->encrypt.pending, requested, data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    if (*len)
        return status;

    /* Encrypt more data. */
    status = serf_bucket_read(ssl_ctx->encrypt.stream, requested, &unenc_data,
                              &unenc_len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    if (unenc_len)
    {
        OSStatus sectrans_status;
        size_t written;

        sectrans_status = SSLWrite(ssl_ctx->st_ctxr, unenc_data, unenc_len,
                                   &written);
        /* TODO: check status */

        status = serf_bucket_read(ssl_ctx->encrypt.pending, requested, data, len);
    }

    return status;
    /* TODO: write data */
}

static apr_status_t
serf_sectrans_encrypt_readline(serf_bucket_t *bucket,
                               int acceptable, int *found,
                               const char **data,
                               apr_size_t *len)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function serf_sectrans_encrypt_readline not implemented.\n");
    return APR_ENOTIMPL;
}


static apr_status_t
serf_sectrans_encrypt_peek(serf_bucket_t *bucket,
                           const char **data,
                           apr_size_t *len)
{
    sectrans_context_t *ssl_ctx = bucket->data;

    return serf_bucket_peek(ssl_ctx->encrypt.pending, data, len);
}

static void
serf_sectrans_encrypt_destroy_and_data(serf_bucket_t *bucket)
{
    sectrans_context_t *ssl_ctx = bucket->data;

    if (!--ssl_ctx->refcount) {
        sectrans_free_context(ssl_ctx, bucket->allocator);
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
    sectrans_context_t *ssl_ctx = bucket->data;
    
    return serf_bucket_peek(ssl_ctx->decrypt.pending, data, len);
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
serf_sectrans_decrypt_readline(serf_bucket_t *bucket,
                               int acceptable, int *found,
                               const char **data,
                               apr_size_t *len)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "function serf_sectrans_decrypt_readline not implemented.\n");
    return APR_ENOTIMPL;
}

static void
serf_sectrans_decrypt_destroy_and_data(serf_bucket_t *bucket)
{
    sectrans_context_t *ssl_ctx = bucket->data;

    if (!--ssl_ctx->refcount) {
        sectrans_free_context(ssl_ctx, bucket->allocator);
    }

    serf_bucket_ssl_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_sectrans_encrypt = {
    "SECURETRANSPORTENCRYPT",
    serf_sectrans_encrypt_read,
    serf_sectrans_encrypt_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_sectrans_encrypt_peek,
    serf_sectrans_encrypt_destroy_and_data,
};

const serf_bucket_type_t    serf_bucket_type_sectrans_decrypt = {
    "SECURETRANSPORTDECRYPT",
    serf_sectrans_decrypt_read,
    serf_sectrans_decrypt_readline,
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
    cert_issuer,
    cert_subject,
    cert_certificate,
    cert_export,
    use_compression,
};

#endif /* SERF_HAVE_SECURETRANSPORT */
