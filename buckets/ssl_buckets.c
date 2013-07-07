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

#include "serf.h"
#include "serf_private.h"
#include "serf_bucket_util.h"
#include "bucket_private.h"

typedef struct serf_ssl_bucket_t {
    serf_bucket_t bucket;
    
    /* context (including the type of this bucket) shared between encrypt and
       decrypt ssl_bucket */
    serf_ssl_context_t *ssl_ctx;

    /** the allocator used for this context (needed at destroy time) */
    serf_bucket_alloc_t *allocator;
} serf_ssl_bucket_t;

struct serf_ssl_context_t
{
    /* How many open buckets refer to this context. */
    int refcount;

    /* Which SSL implementation is used for this context. */
    const serf_ssl_bucket_type_t *type;

    /** implementation specific context */
    void *impl_ctx;
};

void *serf__ssl_get_impl_context(serf_ssl_context_t *ssl_ctx)
{
    return ssl_ctx->impl_ctx;
}

static const serf_ssl_bucket_type_t *decide_ssl_bucket_type(void)
{
    apr_uint32_t bucket_impls = serf_config_get_bucket_impls();

    /* Prefer SSL implementation integrated in host platform, depending
       on what's builtin and what the application allows. */
#ifdef SERF_HAVE_MACOSXSSL
    if (bucket_impls & SERF_IMPL_SSL_MACOSXSSL)
        return &serf_ssl_bucket_type_macosxssl;
#endif
#ifdef SERF_HAVE_OPENSSL
    if (bucket_impls & SERF_IMPL_SSL_OPENSSL)
        return &serf_ssl_bucket_type_openssl;
#endif

    return NULL;
}

void serf_ssl_client_cert_provider_set(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_need_client_cert_t callback,
    void *data,
    void *cache_pool)
{
    return ssl_ctx->type->client_cert_provider_set(ssl_ctx->impl_ctx, callback,
                                                   data, cache_pool);
}

void serf_ssl_client_cert_password_set(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_need_cert_password_t callback,
    void *data,
    void *cache_pool)
{
    return ssl_ctx->type->client_cert_password_set(ssl_ctx->impl_ctx, callback,
                                                   data, cache_pool);
}

void serf_ssl_identity_provider_set(serf_ssl_context_t *ssl_ctx,
                                    serf_ssl_need_identity_t callback,
                                    void *data,
                                    void *cache_pool)
{
    return ssl_ctx->type->identity_provider_set(ssl_ctx->impl_ctx, callback,
                                                data, cache_pool);
}

void serf_ssl_identity_password_callback_set(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_need_cert_password_t callback,
    void *data,
    void *cache_pool)
{
    return ssl_ctx->type->client_cert_password_set(ssl_ctx->impl_ctx, callback,
                                                   data, cache_pool);
}

void serf_ssl_server_cert_callback_set(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_need_server_cert_t callback,
    void *data)
{
    return ssl_ctx->type->server_cert_callback_set(ssl_ctx->impl_ctx,
                                                   callback, data);
}

void serf_ssl_server_cert_chain_callback_set(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_need_server_cert_t cert_callback,
    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
    void *data)
{
    return ssl_ctx->type->server_cert_chain_callback_set(ssl_ctx->impl_ctx,
                                                         cert_callback,
                                                         cert_chain_callback,
                                                         data);
}

apr_status_t serf_ssl_set_hostname(serf_ssl_context_t *ssl_ctx,
                                   const char * hostname)
{
    return ssl_ctx->type->set_hostname(ssl_ctx->impl_ctx, hostname);
}

apr_status_t
serf_ssl_use_compression(serf_ssl_context_t *ssl_ctx, int enabled)
{
    return ssl_ctx->type->use_compression(ssl_ctx->impl_ctx, enabled);
}


serf_bucket_t *serf_bucket_ssl_decrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    const serf_ssl_bucket_type_t *type = decide_ssl_bucket_type();
    serf_ssl_bucket_t *ssl_bkt;

    /* If no SSL implementation is available or allowed, we can't create
       a bucket. */
    if (!type)
        return NULL;

    ssl_bkt = serf_bucket_mem_alloc(allocator, sizeof(*ssl_bkt));
    ssl_bkt->allocator = allocator;

    if (!ssl_ctx) {
        ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));
        ssl_ctx->type = type;
        ssl_ctx->refcount = 0;
        ssl_ctx->impl_ctx = NULL;
    }

    ssl_ctx->impl_ctx = type->decrypt_create(&ssl_bkt->bucket,
                                             stream,
                                             ssl_ctx->impl_ctx,
                                             allocator);
    ssl_ctx->refcount++;
    ssl_bkt->ssl_ctx = ssl_ctx;

    return (serf_bucket_t*)ssl_bkt;
}


serf_ssl_context_t *serf_bucket_ssl_decrypt_context_get(
     serf_bucket_t *bucket)
{
    serf_ssl_bucket_t *ssl_bucket = (serf_ssl_bucket_t *)bucket;

    return ssl_bucket->ssl_ctx;
}


serf_bucket_t *serf_bucket_ssl_encrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    const serf_ssl_bucket_type_t *type = decide_ssl_bucket_type();
    serf_ssl_bucket_t *ssl_bkt;

    /* If no SSL implementation is available or allowed, we can't create
     a bucket. */
    if (!type)
        return NULL;

    ssl_bkt = serf_bucket_mem_alloc(allocator, sizeof(*ssl_bkt));
    ssl_bkt->allocator = allocator;

    if (!ssl_ctx) {
        ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));
        ssl_ctx->type = type;
        ssl_ctx->refcount = 0;
        ssl_ctx->impl_ctx = NULL;
    }

    ssl_ctx->impl_ctx = type->encrypt_create(&ssl_bkt->bucket,
                                             stream,
                                             ssl_ctx->impl_ctx,
                                             allocator);
    ssl_ctx->refcount++;
    ssl_bkt->ssl_ctx = ssl_ctx;

    return (serf_bucket_t*)ssl_bkt;
}


serf_ssl_context_t *
serf_bucket_ssl_encrypt_context_get(serf_bucket_t *bucket)
{
    serf_ssl_bucket_t *ssl_bucket = (serf_ssl_bucket_t *)bucket;

    return ssl_bucket->ssl_ctx;
}

void
serf_bucket_ssl_destroy_and_data(serf_bucket_t *bucket)
{
    serf_ssl_bucket_t *ssl_bucket = (serf_ssl_bucket_t *)bucket;
    serf_ssl_context_t *ssl_ctx = ssl_bucket->ssl_ctx;

    if (!--ssl_ctx->refcount) {
        serf_bucket_mem_free(ssl_bucket->allocator, ssl_ctx);
    }
}

apr_status_t serf_ssl_use_default_certificates(serf_ssl_context_t *ssl_ctx)
{
    return ssl_ctx->type->use_default_certificates(ssl_ctx->impl_ctx);
}



apr_status_t serf_ssl_trust_cert(serf_ssl_context_t *ssl_ctx,
                                 serf_ssl_certificate_t *cert)
{
    return ssl_ctx->type->trust_cert(ssl_ctx->impl_ctx, cert);
}

/* Create a implementation-independent serf_ssl_certificate_t object */
serf_ssl_certificate_t *
serf__create_certificate(serf_bucket_alloc_t *allocator,
                         const serf_ssl_bucket_type_t *type,
                         void *impl_cert,
                         int depth_of_error)
{
    serf_ssl_certificate_t *cert;

    cert = serf_bucket_mem_alloc(allocator,
                                 sizeof(serf_ssl_certificate_t));
    cert->impl_cert = impl_cert;
    cert->type = type;
    cert->depth_of_error = depth_of_error;

    return cert;
}

/* Functions to read a serf_ssl_certificate structure. */
int serf_ssl_cert_depth(const serf_ssl_certificate_t *cert)
{
    return cert->depth_of_error;
}

apr_hash_t *serf_ssl_cert_issuer(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return cert->type->cert_issuer(cert, pool);
}

apr_hash_t *serf_ssl_cert_subject(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return cert->type->cert_subject(cert, pool);
}

apr_hash_t *serf_ssl_cert_certificate(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return cert->type->cert_certificate(cert, pool);
}

const char *serf_ssl_cert_export(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return cert->type->cert_export(cert, pool);
}

/* Create a implementation-independent serf_ssl_identity_t object */
serf_ssl_identity_t *
serf__create_identity(const serf_ssl_bucket_type_t *type,
                      void *impl_cert,
                      void *impl_pkey,
                      apr_pool_t *pool)
{
    serf_ssl_identity_t *identity;

    identity = apr_palloc(pool, sizeof(serf_ssl_identity_t));
    identity->impl_cert = impl_cert;
    identity->impl_pkey = impl_pkey;
    identity->type = type;

    return identity;
}

apr_status_t serf_ssl_load_identity_from_file(serf_ssl_context_t *ssl_ctx,
                 const serf_ssl_identity_t **identity,
                 const char *file_path,
                 apr_pool_t *pool)
{
    return ssl_ctx->type->load_identity_from_file(ssl_ctx->impl_ctx, identity,
                                                  file_path, pool);
}

apr_status_t serf_ssl_load_CA_cert_from_file(serf_ssl_context_t *ssl_ctx,
                                             serf_ssl_certificate_t **cert,
                                             const char *file_path,
                                             apr_pool_t *pool)
{
    /* The ssl_ctx is not needed to load the certificate, only to determine
       which SSL library we're using. */
    return ssl_ctx->type->load_CA_cert_from_file(cert, file_path, pool);
}

apr_status_t serf_ssl_load_cert_file(serf_ssl_certificate_t **cert,
                                     const char *file_path,
                                     apr_pool_t *pool)
{
    /* ### This is a hack, depends on the SSL implementation type to be 
       always the same during multiple ssl sessions. While that's currently
       the case, it's not guaranteed to stay this way in future versions of
       serf. */
    const serf_ssl_bucket_type_t *type = decide_ssl_bucket_type();

    return type->load_CA_cert_from_file(cert, file_path, pool);
}

/* SSL Session Resumption API's */
void serf_ssl_new_session_callback_set(serf_ssl_context_t *ssl_ctx,
                                       serf_ssl_new_session_t new_session_cb,
                                       void *baton)
{
    ssl_ctx->type->new_session_callback_set(ssl_ctx->impl_ctx,
                                            new_session_cb, baton);
}

apr_status_t serf_ssl_resume_session(serf_ssl_context_t *ssl_ctx,
                                     const serf_ssl_session_t *ssl_session,
                                     apr_pool_t *pool)
{
    return ssl_ctx->type->resume_session(ssl_ctx->impl_ctx, ssl_session,
                                         pool);
}

apr_status_t serf_ssl_session_export(serf_ssl_context_t *ssl_ctx,
                                     void **data,
                                     apr_size_t *len,
                                     const serf_ssl_session_t *ssl_session,
                                     apr_pool_t *pool)
{
    return ssl_ctx->type->session_export(data, len, ssl_session, pool);
}

apr_status_t serf_ssl_session_import(serf_ssl_context_t *ssl_ctx,
                                     const serf_ssl_session_t **ssl_session,
                                     void *data,
                                     apr_size_t len,
                                     apr_pool_t *pool)
{
    return ssl_ctx->type->session_import(ssl_session, data, len, pool);
}

/* Define dummy ssl_decrypt and ssl_encrypt buckets. These are needed because
   they are exported symbols, previously (not anymore) used in the
   SERF_BUCKET_IS_SSL_DECRYPT and SERF_BUCKET_IS_SSL_ENCRYPT macro's. */
const serf_bucket_type_t serf_bucket_type_ssl_decrypt = {
    "ABSTRACT DECRYPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
const serf_bucket_type_t serf_bucket_type_ssl_encrypt = {
    "ABSTRACT ENCRYPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
