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

#ifndef _BUCKET_PRIVATE_H_
#define _BUCKET_PRIVATE_H_


/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type_openssl_encrypt;
#define SERF_BUCKET_IS_OPENSSL_ENCRYPT(b) SERF_BUCKET_CHECK((b), openssl_encrypt)

void serf__openssl_client_cert_provider_set(
         serf_ssl_context_t *context,
         serf_ssl_need_client_cert_t callback,
         void *data,
         void *cache_pool);

void serf__openssl_client_cert_password_set(
         serf_ssl_context_t *context,
         serf_ssl_need_cert_password_t callback,
         void *data,
         void *cache_pool);

/**
 * Set a callback to override the default SSL server certificate validation
 * algorithm.
 */
void serf__openssl_server_cert_callback_set(
         serf_ssl_context_t *context,
         serf_ssl_need_server_cert_t callback,
         void *data);

/**
 * Set callbacks to override the default SSL server certificate validation
 * algorithm for the current certificate or the entire certificate chain.
 */
void serf__openssl_server_cert_chain_callback_set(
         serf_ssl_context_t *context,
         serf_ssl_need_server_cert_t cert_callback,
         serf_ssl_server_cert_chain_cb_t cert_chain_callback,
         void *data);

/**
 * Use the default root CA certificates as included with the OpenSSL library.
 */
apr_status_t serf__openssl_use_default_certificates(
                                               serf_ssl_context_t *context);

/**
 * Allow SNI indicators to be sent to the server.
 */
apr_status_t serf__openssl_set_hostname(
                                   serf_ssl_context_t *context, const char *hostname);

/**
 * Return the depth of the certificate.
 */
int serf__openssl_cert_depth(
                        const serf_ssl_certificate_t *cert);

/**
 * Extract the fields of the issuer in a table with keys (E, CN, OU, O, L,
 * ST and C). The returned table will be allocated in @a pool.
 */
apr_hash_t *serf__openssl_cert_issuer(
                                 const serf_ssl_certificate_t *cert,
                                 apr_pool_t *pool);

/**
 * Extract the fields of the subject in a table with keys (E, CN, OU, O, L,
 * ST and C). The returned table will be allocated in @a pool.
 */
apr_hash_t *serf__openssl_cert_subject(
                                  const serf_ssl_certificate_t *cert,
                                  apr_pool_t *pool);

/**
 * Extract the fields of the certificate in a table with keys (sha1, notBefore,
 * notAfter). The returned table will be allocated in @a pool.
 */
apr_hash_t *serf__openssl_cert_certificate(
                                      const serf_ssl_certificate_t *cert,
                                      apr_pool_t *pool);

/**
 * Export a certificate to base64-encoded, zero-terminated string.
 * The returned string is allocated in @a pool. Returns NULL on failure.
 */
const char *serf__openssl_cert_export(
                                 const serf_ssl_certificate_t *cert,
                                 apr_pool_t *pool);

/**
 * Load a CA certificate file from a path @a file_path. If the file was loaded
 * and parsed correctly, a certificate @a cert will be created and returned.
 * This certificate object will be alloced in @a pool.
 */
apr_status_t serf__openssl_load_cert_file(
                                     serf_ssl_certificate_t **cert,
                                     const char *file_path,
                                     apr_pool_t *pool);

/**
 * Adds the certificate @a cert to the list of trusted certificates in
 * @a ssl_ctx that will be used for verification.
 * See also @a serf_ssl_load_cert_file.
 */
apr_status_t serf__openssl_trust_cert(
                                 serf_ssl_context_t *ssl_ctx,
                                 serf_ssl_certificate_t *cert);

/**
 * Enable or disable SSL compression on a SSL session.
 * @a enabled = 1 to enable compression, 0 to disable compression.
 * Default = disabled.
 */
apr_status_t serf__openssl_use_compression(
                                      serf_ssl_context_t *ssl_ctx,
                                      int enabled);

serf_bucket_t *serf_bucket__openssl_encrypt_create(
                                              serf_bucket_t *stream,
                                              serf_ssl_context_t *ssl_context,
                                              serf_bucket_alloc_t *allocator);

serf_ssl_context_t *serf_bucket__openssl_encrypt_context_get(
                                                        serf_bucket_t *bucket);

/* ==================================================================== */


extern const serf_bucket_type_t serf_bucket_type_openssl_decrypt;
#define SERF_BUCKET_IS_OPENSSL_DECRYPT(b) SERF_BUCKET_CHECK((b), openssl_decrypt)

serf_bucket_t *serf_bucket__openssl_decrypt_create(
                                              serf_bucket_t *stream,
                                              serf_ssl_context_t *ssl_context,
                                              serf_bucket_alloc_t *allocator);

serf_ssl_context_t *serf_bucket__openssl_decrypt_context_get(
                                                        serf_bucket_t *bucket);


/* ==================================================================== */


#endif