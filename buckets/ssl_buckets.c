/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
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

#include <apr_pools.h>
#include <apr_network_io.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>

struct serf_ssl_context_t {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;

    /* Data we've read but not processed. */
    serf_bucket_t *source;

    /* Pending data to return. */
    serf_bucket_t *sink;

    /* The last thing we did. */
    apr_status_t last_status;
};

typedef struct {
    serf_ssl_context_t *ssl_ctx;
    int own_ssl_ctx;

    serf_bucket_t *stream;

    serf_databuf_t databuf;

} ssl_context_t;


static void free_read_data(void *baton, const char *data)
{
    serf_bucket_mem_free(baton, (char*)data);
}

/* This function reads an encrypted stream and returns the decrypted stream. */
static apr_status_t ssl_decrypt(void *baton, apr_size_t bufsize,
                                char *buf, apr_size_t *len)
{
    ssl_context_t *ctx = baton;
    apr_size_t priv_len;
    apr_status_t status;
    const char *data;
    int read_len;

    status = serf_bucket_read(ctx->stream, bufsize, &data, &priv_len);

    if (!SERF_BUCKET_READ_ERROR(status) && priv_len) {
        int ssl_len;
        apr_status_t agg_status;
        serf_bucket_t *tmp;
        char *data_copy;

        data_copy =
            serf_bucket_mem_alloc(ctx->ssl_ctx->source->allocator, priv_len);
        memcpy(data_copy, data, priv_len);

        tmp = serf_bucket_simple_create(data_copy, priv_len, free_read_data,
                                        ctx->ssl_ctx->source->allocator,
                                        ctx->ssl_ctx->source->allocator);

        serf_bucket_aggregate_append(ctx->ssl_ctx->source, tmp);

        ssl_len = SSL_read(ctx->ssl_ctx->ssl, buf, bufsize);
        if (ssl_len == -1) {
            int ssl_err;

            ssl_err = SSL_get_error(ctx->ssl_ctx->ssl, ssl_len);
            if (ssl_err == SSL_ERROR_SYSCALL) {
                *len = 0;
                return ctx->ssl_ctx->last_status;
            }
            else {
                /* Oh, no. */
                if (ssl_err == SSL_ERROR_WANT_READ) {
                    status = APR_EAGAIN;
                }
            }
            abort();
        }
        *len = ssl_len;
    }
    else {
        *len = 0;
    }
    return status;
}

/* This function reads an decrypted stream and returns an encrypted stream. */
static apr_status_t ssl_encrypt(void *baton, apr_size_t bufsize,
                                char *buf, apr_size_t *len)
{
    const char *data;
    ssl_context_t *ctx = baton;
    apr_status_t status;

    status = serf_bucket_read(ctx->stream, bufsize, &data, len);

    if (!SERF_BUCKET_READ_ERROR(status) && *len) {
        int ssl_len;
        apr_status_t agg_status;

        ssl_len = SSL_write(ctx->ssl_ctx->ssl, data, *len);
        if (ssl_len == -1) {
            int ssl_err;

            ssl_err = SSL_get_error(ctx->ssl_ctx->ssl, ssl_len);
            if (ssl_err == SSL_ERROR_SYSCALL) {
                status = ctx->ssl_ctx->last_status;
                if (SERF_BUCKET_READ_ERROR(status)) {
                    return status;
                }
            }
            else {
                /* Oh, no. */
                if (ssl_err == SSL_ERROR_WANT_READ) {
                    status = APR_EAGAIN;
                }
                else {
                    abort();
                }
            }
            *len = 0;
        }
        else {

            /* We read something! */
            agg_status = serf_bucket_read(ctx->ssl_ctx->sink, ssl_len, &data,
                                          len);
            /* Assert ssl_len == *len */
            memcpy(buf, data, *len);
        }
    }

    return status;
}

static apr_status_t ssl_init_context(
     serf_ssl_context_t *,
     serf_bucket_alloc_t *);

static serf_bucket_t * serf_bucket_ssl_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator,
    const serf_bucket_type_t *type,
    serf_databuf_reader_t databuf_reader)
{
    ssl_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    if (!ssl_ctx) {
        ctx->ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(ssl_context_t));
        ssl_init_context(ctx->ssl_ctx, allocator);
        ctx->own_ssl_ctx = 1;
    }
    else {
        ctx->ssl_ctx = ssl_ctx;
        ctx->own_ssl_ctx = 0;
    }

    serf_databuf_init(&ctx->databuf);
    ctx->databuf.read = databuf_reader;
    ctx->databuf.read_baton = ctx;

    return serf_bucket_create(type, allocator, ctx);
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_ssl_decrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    return serf_bucket_ssl_create(stream, ssl_ctx, allocator,
                                  &serf_bucket_type_ssl_decrypt, ssl_decrypt);

}

SERF_DECLARE(serf_ssl_context_t *) serf_bucket_ssl_decrypt_context_get(
     serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;
    return ctx->ssl_ctx; 
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_ssl_encrypt_create(
    serf_bucket_t *stream,
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    return serf_bucket_ssl_create(stream, ssl_ctx, allocator,
                                 &serf_bucket_type_ssl_encrypt, ssl_encrypt);
}

SERF_DECLARE(serf_ssl_context_t *) serf_bucket_ssl_encrypt_context_get(
     serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;
    return ctx->ssl_ctx;
}

static void serf_ssl_destroy_and_data(serf_bucket_t *bucket)
{
    ssl_context_t *ctx = bucket->data;

    if (ctx->own_ssl_ctx) {
        serf_bucket_mem_free(bucket->allocator, ctx->ssl_ctx);
    }

    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_ssl_read(serf_bucket_t *bucket,
                                  apr_size_t requested,
                                  const char **data, apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_read(&ctx->databuf, requested, data, len);
}

static apr_status_t serf_ssl_readline(serf_bucket_t *bucket,
                                      int acceptable, int *found,
                                      const char **data,
                                      apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_readline(&ctx->databuf, acceptable, found, data, len);
}

static apr_status_t serf_ssl_peek(serf_bucket_t *bucket,
                                  const char **data,
                                  apr_size_t *len)
{
    ssl_context_t *ctx = bucket->data;

    return serf_databuf_peek(&ctx->databuf, data, len);
}

/* Returns the amount read. */
static int bio_bucket_read(BIO *bio, char *in, int inlen)
{
    serf_ssl_context_t *ctx = bio->ptr;
    const char *data;
    apr_status_t status;
    apr_size_t len;

    status = serf_bucket_read(ctx->source, inlen, &data, &len);

    ctx->last_status = status;

    if (!SERF_BUCKET_READ_ERROR(status)) {
        /* Oh suck. */
        if (len) {
            memcpy(in, data, len);
            return len;
        }
        if (APR_STATUS_IS_EOF(status)) {
            ctx->last_status = APR_EAGAIN;
        }
    }

    return -1;
}

/* Returns the amount written. */
static int bio_bucket_write(BIO *bio, const char *in, int inl)
{
    serf_ssl_context_t *ctx = bio->ptr;
    serf_bucket_t *tmp;

    /* Do we need to copy this data? */
    tmp = SERF_BUCKET_SIMPLE_STRING_LEN(in, inl,
                                        ctx->sink->allocator);
    serf_bucket_aggregate_append(ctx->sink, tmp);

    return inl;
}

static int bio_bucket_create(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

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
    /* What to do here? */
    return 1;
}

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

static apr_status_t ssl_init_context(
    serf_ssl_context_t *ssl_ctx,
    serf_bucket_alloc_t *allocator)
{
    /* XXX Only do this ONCE! */
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    /* This is wrong-ish. */
    ssl_ctx->ctx = SSL_CTX_new(SSLv23_client_method());

    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_ALL);

    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    ssl_ctx->bio = BIO_new(&bio_bucket_method);
    ssl_ctx->bio->ptr = ssl_ctx;

    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);

    SSL_set_connect_state(ssl_ctx->ssl);

    ssl_ctx->source = serf_bucket_aggregate_create(allocator);
    ssl_ctx->sink = serf_bucket_aggregate_create(allocator);

    return APR_SUCCESS;
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_ssl_encrypt = {
    "SSLENCRYPT",
    serf_ssl_read,
    serf_ssl_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_ssl_peek,
    serf_ssl_destroy_and_data,
};

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_ssl_decrypt = {
    "SSLDECRYPT",
    serf_ssl_read,
    serf_ssl_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_ssl_peek,
    serf_ssl_destroy_and_data,
};
