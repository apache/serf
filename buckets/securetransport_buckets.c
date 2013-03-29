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

typedef struct sectrans_context_t {
    /* How many open buckets refer to this context. */
    int refcount;
    
    SSLContextRef st_ctxr;
} sectrans_context_t;

static sectrans_context_t *
sectrans_init_context(serf_bucket_alloc_t *allocator)
{
    sectrans_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->refcount = 0;
    
    if (SSLNewContext(FALSE, &ctx->st_ctxr))
        return 0l;

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

    return bucket->data;
}

static void *
decrypt_context_get(serf_bucket_t *bucket)
{
    return 0l;
}

static void *
encrypt_context_get(serf_bucket_t *bucket)
{
    return 0l;
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
set_hostname(void *impl_ctx,
                                   const char * hostname)
{
    return APR_ENOTIMPL;
}

static apr_status_t
use_default_certificates(void *impl_ctx)
{
    return APR_ENOTIMPL;
}

static apr_status_t
load_cert_file(serf_ssl_certificate_t **cert,
                                     const char *file_path,
                                     apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}


static apr_status_t trust_cert(void *impl_ctx,
                               serf_ssl_certificate_t *cert)
{
    return APR_ENOTIMPL;
}

static apr_status_t use_compression(void *impl_ctx, int enabled)
{
    return APR_ENOTIMPL;
}

/**** BUCKET API *****/
/*********************/
static apr_status_t
serf_sectrans_read(serf_bucket_t *bucket,
                   apr_size_t requested,
                   const char **data, apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static apr_status_t
serf_sectrans_readline(serf_bucket_t *bucket,
                       int acceptable, int *found,
                       const char **data,
                       apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static apr_status_t
serf_sectrans_peek(serf_bucket_t *bucket,
                   const char **data,
                   apr_size_t *len)
{
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

static void
serf_sectrans_encrypt_destroy_and_data(serf_bucket_t *bucket)
{
    sectrans_context_t *ctx = bucket->data;

    if (!--ctx->refcount) {
        sectrans_free_context(ctx, bucket->allocator);
    }

    serf_bucket_ssl_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type_sectrans_encrypt = {
    "SECURETRANSPORTENCRYPT",
    serf_sectrans_read,
    serf_sectrans_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_sectrans_peek,
    serf_sectrans_encrypt_destroy_and_data,
};

const serf_bucket_type_t serf_bucket_type_sectrans_decrypt = {
    "SECURETRANSPORTDECRYPT",
    serf_sectrans_read,
    serf_sectrans_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_sectrans_peek,
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


