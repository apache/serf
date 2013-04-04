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
#include <Security/SecCertificate.h>
#include <objc/runtime.h>
#include <objc/message.h>

#define SECURE_TRANSPORT_READ_BUFSIZE 8000

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

    /* name of the peer, used with TLS's Server Name Indication extension. */
    char *hostname;

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

/* Callback function for the encrypt.pending and decrypt.pending stream-type
   aggregate buckets.
 */
apr_status_t pending_stream_eof(void *baton,
                                serf_bucket_t *pending)
{
    /* Both pending streams have to stay open so that the Secure Transport
       library can keep appending data buckets. */
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
                                                          NULL);
    ssl_ctx->decrypt.pending = serf__bucket_stream_create(allocator,
                                                          pending_stream_eof,
                                                          NULL);

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
              "%d bytes.\n", requested);

    *dataLength = 0;
    while (!status && requested) {
        status = serf_bucket_read(ssl_ctx->decrypt.stream, requested,
                                  &buf, &buflen);

        if (SERF_BUCKET_READ_ERROR(status)) {
            serf__log(SSL_VERBOSE, __FILE__, "Returned status %d.\n", status);
            return -1;
        }

        if (buflen) {
            serf__log(SSL_VERBOSE, __FILE__, "Read %d bytes with status %d.\n",
                      buflen, status);

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

/* Show a SFCertificateTrustPanel. This is the Mac OS X default dialog to
   ask the user to confirm or deny the use of the certificate. This panel
   also gives the option to store the user's decision for this certificate
   permantly in the Keychain (requires password).
 */

/* TODO: serf or application? If serf, let appl. customize labels. If 
   application, how to get SecTrustRef object back to app? */
static apr_status_t
ask_approval_gui(sectrans_context_t *ssl_ctx, SecTrustRef trust)
{
    const CFStringRef OkButtonLbl = CFSTR("Accept");
    const CFStringRef CancelButtonLbl = CFSTR("Cancel");
    const CFStringRef Message = CFSTR("The server certificate requires validation.");

    /* Creates an NSApplication object (enables GUI for cocoa apps) if one
       doesn't exist already. */
    void *nsapp_cls = objc_getClass("NSApplication");
    (void) objc_msgSend(nsapp_cls,sel_registerName("sharedApplication"));

    void *stp_cls = objc_getClass("SFCertificateTrustPanel");
    void *stp = objc_msgSend(stp_cls, sel_registerName("alloc"));
    stp = objc_msgSend(stp, sel_registerName("init"));

    /* TODO: find a way to get the panel in front of all other windows. */

    /* Don't use these methods as is, they create a small application window
       and have no effect on the z-order of the modal dialog. */
//    objc_msgSend(obj, sel_getUid("orderFrontRegardless"));
//    objc_msgSend (obj, sel_getUid ("makeKeyAndOrderFront:"), app);

    /* Setting name of the cancel button also makes it visible on the panel. */
    objc_msgSend(stp, sel_getUid("setDefaultButtonTitle:"), OkButtonLbl);
    objc_msgSend(stp, sel_getUid("setAlternateButtonTitle:"), CancelButtonLbl);
    
    long result = (long)objc_msgSend(stp,
                                     sel_getUid("runModalForTrust:message:"),
                                     trust, Message);
    serf__log(SSL_VERBOSE, __FILE__, "User clicked %s button.\n",
              result ? "Accept" : "Cancel");

    if (result) /* NSOKButton = 1 */
        return APR_SUCCESS;
    else        /* NSCancelButton = 0 */
        return APR_EGENERAL;
}

/* Validate a server certificate. Call back to the application if needed.
   Returns APR_SUCCESS if the server certificate is accepted.
   Otherwise returns an error.
 */
static int
validate_server_certificate(sectrans_context_t *ssl_ctx)
{
    OSStatus sectrans_status;
    CFArrayRef certs;
    SecTrustRef trust;
    SecTrustResultType result;
    int failures = 0;
    size_t depth_of_error;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__, "validate_server_certificate called.\n");

    /* Get the server certificate chain. */
    sectrans_status = SSLCopyPeerCertificates(ssl_ctx->st_ctxr, &certs);
    if (sectrans_status != noErr)
        return translate_sectrans_status(sectrans_status);
    /* TODO: 0, oh really? How can we know where the error occurred? */
    depth_of_error = 0;

    sectrans_status = SSLCopyPeerTrust(ssl_ctx->st_ctxr, &trust);
    if (sectrans_status != noErr) {
        status = translate_sectrans_status(sectrans_status);
        goto cleanup;
    }

    /* TODO: SecTrustEvaluateAsync */
    sectrans_status = SecTrustEvaluate(trust, &result);
    if (sectrans_status != noErr) {
        status = translate_sectrans_status(sectrans_status);
        goto cleanup;
    }

    /* Based on the contents of the user's Keychain, Secure Transport will make
       a first validation of this certificate chain. */
    switch (result)
    {
        case kSecTrustResultUnspecified:
        case kSecTrustResultProceed:
            failures = SERF_SSL_CERT_ALL_OK;
            serf__log(SSL_VERBOSE, __FILE__,
                      "kSecTrustResultProceed/Unspecified.\n");
            status = APR_EAGAIN;
            break;
        case kSecTrustResultConfirm:
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultConfirm.\n");
            failures = SERF_SSL_CERT_CONFIRM_NEEDED &
                       SERF_SSL_CERT_RECOVERABLE;
            status = ask_approval_gui(ssl_ctx, trust);
            break;
        case kSecTrustResultRecoverableTrustFailure:
        {
            serf__log(SSL_VERBOSE, __FILE__,
                      "kSecTrustResultRecoverableTrustFailure.\n");
            failures = SERF_SSL_CERT_RECOVERABLE &
                       SERF_SSL_CERT_UNKNOWN_FAILURE;
            status = ask_approval_gui(ssl_ctx, trust);
            break;
        }
        /* Fatal errors */
        case kSecTrustResultInvalid:
            failures = SERF_SSL_CERT_FATAL;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultInvalid.\n");
            break;
        case kSecTrustResultDeny:
            failures = SERF_SSL_CERT_FATAL;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultDeny.\n");
            break;
        case kSecTrustResultFatalTrustFailure:
            failures = SERF_SSL_CERT_FATAL;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultFatalTrustFailure.\n");
            break;
        case kSecTrustResultOtherError:
            failures = SERF_SSL_CERT_FATAL;
            serf__log(SSL_VERBOSE, __FILE__, "kSecTrustResultOtherError.\n");
            break;
        default:
            failures = SERF_SSL_CERT_FATAL;
            serf__log(SSL_VERBOSE, __FILE__, "unknown.\n");
            break;
    }

#if 0
    /* First implement certificate accessor methods, otherwise this will only
       result in crashes. */
    if (ssl_ctx->server_cert_callback &&
        (depth_of_error == 0 || failures)) {
        apr_status_t status;
        serf_ssl_certificate_t *cert;

        cert = serf__create_certificate(ssl_ctx->allocator,
                                        &serf_ssl_bucket_type_securetransport,
                                        (void *)CFArrayGetValueAtIndex(certs, 0),
                                        depth_of_error);

        /* Callback for further verification. */
        status = ssl_ctx->server_cert_callback(ssl_ctx->server_cert_userdata,
                                               failures, cert);
        if (status == APR_SUCCESS)
        {
            if (!(failures & SERF_SSL_CERT_RECOVERABLE)) {
                serf__log(SSL_VERBOSE, __FILE__,
                          "don't know how to handle this yet.\n");
                status = APR_ENOTIMPL;
            }
        }
        serf_bucket_mem_free(ssl_ctx->allocator, cert);
        goto cleanup;
    }
#endif

cleanup:
    CFRelease(certs);
    CFRelease(trust);

    return status;
}

/* Run the SSL handshake. */
static apr_status_t do_handshake(sectrans_context_t *ssl_ctx)
{
    OSStatus sectrans_status;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__, "do_handshake called.\n");

    sectrans_status = SSLHandshake(ssl_ctx->st_ctxr);
    if (sectrans_status)
        serf__log(SSL_VERBOSE, __FILE__, "do_handshake returned err %d.\n",
                  sectrans_status);

    switch(sectrans_status) {
        case noErr:
            status = APR_SUCCESS;
            break;
        case errSSLServerAuthCompleted:
            /* Server's cert chain is valid, or was ignored if cert verification
               was disabled via SSLSetEnableCertVerify.
             */
            status = validate_server_certificate(ssl_ctx);
            if (!status)
                return APR_EAGAIN;
            break;
        case errSSLClientCertRequested:
            return APR_ENOTIMPL;
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

    ssl_ctx->hostname = serf_bstrdup(ssl_ctx->allocator, hostname);
    OSStatus status = SSLSetPeerDomainName(ssl_ctx->st_ctxr,
                                           ssl_ctx->hostname,
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

const char *cert_export(const serf_ssl_certificate_t *cert,
                        apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function cert_export not implemented.\n");

    return NULL;
}

static apr_status_t
use_compression(void *impl_ctx, int enabled)
{
    if (enabled) {
        serf__log(SSL_VERBOSE, __FILE__,
                  "Secure Transport does not support any type of "
                  "SSL compression.\n");
        return APR_ENOTIMPL;
    } else {
        return APR_SUCCESS;
    }
}

/**** ENCRYPTION BUCKET API *****/
/********************************/
static apr_status_t
serf_sectrans_encrypt_read(serf_bucket_t *bucket,
                           apr_size_t requested,
                           const char **data, apr_size_t *len)
{
    sectrans_context_t *ssl_ctx = bucket->data;
    apr_status_t status, status_unenc_stream;
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

    if (*len) {
        /* status can be either APR_EAGAIN or APR_SUCCESS. In both cases,
           we want the caller to try again as there's probably more data
           to be encrypted. */
        return APR_SUCCESS;
    }

    /* Encrypt more data. */
    status_unenc_stream = serf_bucket_read(ssl_ctx->encrypt.stream, requested,
                                           &unenc_data, &unenc_len);
    if (SERF_BUCKET_READ_ERROR(status_unenc_stream))
        return status_unenc_stream;

    if (unenc_len)
    {
        OSStatus sectrans_status;
        size_t written;

        /* TODO: we now feed each individual chunk of data one by one to 
           SSLWrite. This seems to add a record header etc. per call, 
           so 2 bytes of data in results in 37 bytes of data out.
           Need to add a real buffer and feed this function chunks of
           e.g. 8KB. */
        sectrans_status = SSLWrite(ssl_ctx->st_ctxr, unenc_data, unenc_len,
                                   &written);
        status = translate_sectrans_status(sectrans_status);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        serf__log(SSL_MSG_VERBOSE, __FILE__, "%dB ready with status %d, %d encrypted and written:\n"
                  "---%.*s-(%d)-\n", unenc_len, status_unenc_stream, written, written, unenc_data, written);

        status = serf_bucket_read(ssl_ctx->encrypt.pending, requested,
                                  data, len);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* Tell the caller there's more data readily available. */
        if (status == APR_SUCCESS)
            return status;
    }

    /* All encrypted data was returned, if there's more available depends
       on what's pending on the to-be-encrypted stream. */
    return status_unenc_stream;
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

/* Ask Secure Transport to decrypt some more data. If anything was received,
   add it to the to decrypt.pending buffer.
 */
static apr_status_t
decrypt_more_data(sectrans_context_t *ssl_ctx)
{
    /* Decrypt more data. */
    serf_bucket_t *tmp;
    char *dec_data;
    size_t dec_len;
    OSStatus sectrans_status;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__,
              "decrypt_more_data called.\n");

    /* We have to provide ST with the buffer for the decrypted data. */
    dec_data = serf_bucket_mem_alloc(ssl_ctx->decrypt.pending->allocator,
                                     SECURE_TRANSPORT_READ_BUFSIZE);

    sectrans_status = SSLRead(ssl_ctx->st_ctxr, dec_data,
                              SECURE_TRANSPORT_READ_BUFSIZE,
                              &dec_len);
    status = translate_sectrans_status(sectrans_status);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    /* Successfully received and decrypted some data, add to pending. */
    serf__log(SSL_MSG_VERBOSE, __FILE__, " received and decrypted data:"
              "---\n%.*s\n-(%d)-\n", dec_len, dec_data, dec_len);

    tmp = SERF_BUCKET_SIMPLE_STRING_LEN(dec_data, dec_len,
                                        ssl_ctx->decrypt.pending->allocator);
    serf_bucket_aggregate_append(ssl_ctx->decrypt.pending, tmp);

    return status;
}

static apr_status_t
serf_sectrans_decrypt_read(serf_bucket_t *bucket,
                           apr_size_t requested,
                           const char **data, apr_size_t *len)
{
    sectrans_context_t *ssl_ctx = bucket->data;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__,
              "serf_sectrans_decrypt_read called for %d bytes.\n", requested);

    /* First use any pending encrypted data. */
    status = serf_bucket_read(ssl_ctx->decrypt.pending,
                              requested, data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    if (*len)
        return status;

    /* TODO: integrate this loop in decrypt_more_data so we can be more 
       efficient with memory. */
    do {
        /* Pending buffer empty, decrypt more. */
        status = decrypt_more_data(ssl_ctx);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;
    } while (status == APR_SUCCESS);

    /* We should now have more decrypted data in the pending buffer. */
    return serf_bucket_read(ssl_ctx->decrypt.pending, requested, data,
                            len);
}

/* TODO: remove some logging to make the function easier to read. */
static apr_status_t
serf_sectrans_decrypt_readline(serf_bucket_t *bucket,
                               int acceptable, int *found,
                               const char **data,
                               apr_size_t *len)
{
    sectrans_context_t *ssl_ctx = bucket->data;
    apr_status_t status;

    serf__log(SSL_VERBOSE, __FILE__,
              "serf_sectrans_decrypt_readline called.\n");

    /* First use any pending encrypted data. */
    status = serf_bucket_readline(ssl_ctx->decrypt.pending, acceptable, found,
                                  data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        goto error;

    if (*len) {
        serf__log(SSL_VERBOSE, __FILE__, "  read one %s line.\n",
                  *found ? "complete" : "partial");
        return status;
    }

    do {
        /* Pending buffer empty, decrypt more. */
        status = decrypt_more_data(ssl_ctx);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;
    } while (status == APR_SUCCESS);

    /* We have more decrypted data in the pending buffer. */
    status = serf_bucket_readline(ssl_ctx->decrypt.pending, acceptable, found,
                                  data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        goto error;

    serf__log(SSL_VERBOSE, __FILE__, "  read one %s line.\n",
              *found ? "complete" : "partial");
    return status;

error:
    serf__log(SSL_VERBOSE, __FILE__, "  return with status %d.\n", status);
    return status;
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
