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
    
    /** the implementation of this ssl bucket */
    const serf_ssl_bucket_type_t *type;

    /* context shared between encrypt and decrypt ssl_bucket */
    serf_ssl_context_t *ssl_ctx;

    /** the allocator used for this context (needed at destroy time) */
    serf_bucket_alloc_t *allocator;
} serf_ssl_bucket_t;

struct serf_ssl_context_t
{
    /* How many open buckets refer to this context. */
    int refcount;

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
    return 0l;
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
    ssl_bkt->type = type;
    ssl_bkt->allocator = allocator;

    if (!ssl_ctx) {
        ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));
        ssl_ctx->type = type;
        ssl_ctx->refcount = 0;
        ssl_ctx->impl_ctx = 0l;
    }

    ssl_ctx->impl_ctx = ssl_bkt->type->decrypt_create(&ssl_bkt->bucket,
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
    ssl_bkt->type = type;
    ssl_bkt->allocator = allocator;

    if (!ssl_ctx) {
        ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));
        ssl_ctx->type = type;
        ssl_ctx->refcount = 0;
        ssl_ctx->impl_ctx = 0l;
    }

    ssl_ctx->impl_ctx = ssl_bkt->type->encrypt_create(&ssl_bkt->bucket,
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



apr_status_t serf_ssl_trust_cert(
                                 serf_ssl_context_t *ssl_ctx,
                                 serf_ssl_certificate_t *cert)
{
    return ssl_ctx->type->trust_cert(ssl_ctx->impl_ctx, cert);
}


/* TODO: what to do with these? */
apr_status_t serf_ssl_load_cert_file(
                                     serf_ssl_certificate_t **cert,
                                     const char *file_path,
                                     apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_load_cert_file not implemented.\n");

    return APR_ENOTIMPL;
}

/* Functions to read a serf_ssl_certificate structure. */
int serf_ssl_cert_depth(const serf_ssl_certificate_t *cert)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_cert_depth not implemented.\n");

    return 0;
}


apr_hash_t *serf_ssl_cert_issuer(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_cert_issuer not implemented.\n");

    return 0l;
}

apr_hash_t *serf_ssl_cert_subject(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_cert_subject not implemented.\n");

    return 0l;
}


apr_hash_t *serf_ssl_cert_certificate(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_cert_certificate not implemented.\n");

    return 0l;
}


const char *serf_ssl_cert_export(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    serf__log(SSL_VERBOSE, __FILE__,
              "TODO: function serf_ssl_cert_export not implemented.\n");

    return 0l;
}
