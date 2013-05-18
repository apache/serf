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

const serf_ssl_bucket_type_t *decide_ssl_bucket_type(void)
{
#ifdef SERF_HAVE_OPENSSL
    return &serf_ssl_bucket_type_openssl;
#elif defined SERF_HAVE_SECURETRANSPORT
    return &serf_ssl_bucket_type_securetransport;
#else
    return NULL;
#endif
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
    serf_ssl_bucket_t *ssl_bkt = serf_bucket_mem_alloc(allocator,
                                                       sizeof(*ssl_bkt));
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
    serf_ssl_bucket_t *ssl_bkt = serf_bucket_mem_alloc(allocator,
                                                       sizeof(*ssl_bkt));
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

apr_status_t
serf_ssl_show_trust_certificate_dialog(serf_ssl_context_t *ssl_ctx,
                                       const char *message,
                                       const char *ok_button_label,
                                       const char *cancel_button_label)
{
    return ssl_ctx->type->show_trust_certificate_dialog(ssl_ctx->impl_ctx,
                                                        message,
                                                        ok_button_label,
                                                        cancel_button_label);
}

apr_status_t
serf_ssl_show_select_identity_dialog(serf_ssl_context_t *ssl_ctx,
                                     const serf_ssl_identity_t **identity,
                                     const char *message,
                                     const char *ok_button_label,
                                     const char *cancel_button_label,
                                     apr_pool_t *pool)
{
    return ssl_ctx->type->show_select_identity_dialog(ssl_ctx->impl_ctx,
                                                      identity,
                                                      message,
                                                      ok_button_label,
                                                      cancel_button_label,
                                                      pool);
}

apr_status_t
serf_ssl_find_preferred_identity_in_store(serf_ssl_context_t *ssl_ctx,
                                          const serf_ssl_identity_t **identity,
                                          apr_pool_t *pool)
{
    return ssl_ctx->type->find_preferred_identity_in_store(ssl_ctx->impl_ctx,
                                                           identity,
                                                           pool);
}
