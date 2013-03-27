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

void serf_ssl_client_cert_provider_set(
    serf_ssl_context_t *context,
    serf_ssl_need_client_cert_t callback,
    void *data,
    void *cache_pool)
{
    return serf__openssl_client_cert_provider_set(context, callback,
                                                  data, cache_pool);
}


void serf_ssl_client_cert_password_set(
    serf_ssl_context_t *context,
    serf_ssl_need_cert_password_t callback,
    void *data,
    void *cache_pool)
{
    return serf__openssl_client_cert_password_set(context, callback,
                                                  data, cache_pool);
}


void serf_ssl_server_cert_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t callback,
    void *data)
{
    return serf__openssl_server_cert_callback_set(context, callback, data);
}

void serf_ssl_server_cert_chain_callback_set(
    serf_ssl_context_t *context,
    serf_ssl_need_server_cert_t cert_callback,
    serf_ssl_server_cert_chain_cb_t cert_chain_callback,
    void *data)
{
    return serf__openssl_server_cert_chain_callback_set(context, cert_callback,
                                                        cert_chain_callback,
                                                        data);
}

apr_status_t serf_ssl_set_hostname(serf_ssl_context_t *context,
                                   const char * hostname)
{
    return serf__openssl_set_hostname(context, hostname);
}

apr_status_t serf_ssl_use_default_certificates(serf_ssl_context_t *ssl_ctx)
{
    return serf__openssl_use_default_certificates(ssl_ctx);
}

apr_status_t serf_ssl_load_cert_file(
    serf_ssl_certificate_t **cert,
    const char *file_path,
    apr_pool_t *pool)
{
    return serf__openssl_load_cert_file(cert, file_path, pool);
}


apr_status_t serf_ssl_trust_cert(
    serf_ssl_context_t *ssl_ctx,
    serf_ssl_certificate_t *cert)
{
    return serf__openssl_trust_cert(ssl_ctx, cert);
}


serf_bucket_t *serf_bucket_ssl_decrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    return serf_bucket__openssl_decrypt_create(stream, ssl_ctx, allocator);
}


serf_ssl_context_t *serf_bucket_ssl_decrypt_context_get(
     serf_bucket_t *bucket)
{
    return serf_bucket__openssl_decrypt_context_get(bucket);
}


serf_bucket_t *serf_bucket_ssl_encrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    return serf_bucket__openssl_encrypt_create(stream, ssl_ctx, allocator);
}


serf_ssl_context_t *serf_bucket_ssl_encrypt_context_get(
     serf_bucket_t *bucket)
{
    return serf_bucket__openssl_encrypt_context_get(bucket);
}

/* Functions to read a serf_ssl_certificate structure. */
int serf_ssl_cert_depth(const serf_ssl_certificate_t *cert)
{
    return serf__openssl_cert_depth(cert);
}


apr_hash_t *serf_ssl_cert_issuer(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return serf__openssl_cert_issuer(cert, pool);
}

apr_hash_t *serf_ssl_cert_subject(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return serf__openssl_cert_subject(cert, pool);
}


apr_hash_t *serf_ssl_cert_certificate(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return serf__openssl_cert_certificate(cert, pool);
}


const char *serf_ssl_cert_export(
    const serf_ssl_certificate_t *cert,
    apr_pool_t *pool)
{
    return serf__openssl_cert_export(cert, pool);
}
