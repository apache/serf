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

#define SSL_VERBOSE

struct serf_ssl_context_t {
    int refcount;
    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;

    /* Data we've read but not processed. */
    serf_bucket_t *source;

    /* Pending data to return. */
    serf_bucket_t *sink;

    /* The last thing we wrote. */
    apr_status_t sink_status;

    /* The last thing we read. */
    apr_status_t source_status;
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
    int ssl_len;

    /* Is there some data waiting to be read? */
    ssl_len = SSL_read(ctx->ssl_ctx->ssl, buf, bufsize);
    if (ssl_len > 0) {
#ifdef SSL_VERBOSE
        printf("ssl_decrypt: read %d bytes (%d); bio %d (cached)\n",
               ssl_len, bufsize, BIO_get_retry_flags(ctx->ssl_ctx->bio));
#endif
        *len = ssl_len;
        return APR_SUCCESS;
    }

    status = serf_bucket_read(ctx->stream, bufsize, &data, &priv_len);

    if (!SERF_BUCKET_READ_ERROR(status) && priv_len) {
        apr_status_t agg_status;
        serf_bucket_t *tmp;
        char *data_copy;

#ifdef SSL_VERBOSE
        printf("ssl_decrypt: read %d bytes (%d); status: %d\n", priv_len,
               bufsize, status);
#endif

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
            switch (ssl_err) {
            case SSL_ERROR_SYSCALL:
                *len = 0;
                status = ctx->ssl_ctx->sink_status;
                break;
            case SSL_ERROR_WANT_READ:
                *len = 0;
                status = APR_EAGAIN;
                break;
            default:
                abort();
            }
        }
        else {
            *len = ssl_len;
        }
    }
    else {
        *len = 0;
    }
#ifdef SSL_VERBOSE
    printf("ssl_decrypt: %d %d %d\n", status, *len,
           BIO_get_retry_flags(ctx->ssl_ctx->bio));
#endif
    return status;
}

/* This function reads a decrypted stream and returns an encrypted stream. */
static apr_status_t ssl_encrypt(void *baton, apr_size_t bufsize,
                                char *buf, apr_size_t *len)
{
    const char *data;
    ssl_context_t *ctx = baton;
    apr_status_t status;

    /* Try to read unread data first. */
    status = serf_bucket_read(ctx->ssl_ctx->sink, bufsize, &data, len);
    if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }

    /* Aha, we read something.  Return that now. */
    if (*len) {
        memcpy(buf, data, *len);
        if (APR_STATUS_IS_EOF(status)) {
            status = APR_SUCCESS;
        }
#ifdef SSL_VERBOSE
        printf("ssl_encrypt: %d %d %d\n", status, *len,
               BIO_get_retry_flags(ctx->ssl_ctx->bio));
#endif
        return status;
    }

    if (BIO_should_retry(ctx->ssl_ctx->bio) &&
        BIO_should_write(ctx->ssl_ctx->bio)) {
#ifdef SSL_VERBOSE
        printf("ssl_encrypt: %d %d %d (should write exit)\n", status, *len,
               BIO_get_retry_flags(ctx->ssl_ctx->bio));
#endif
        return APR_EAGAIN;
    }

    /* Oh well, read from our stream now. */
    if (!APR_STATUS_IS_EOF(ctx->ssl_ctx->source_status)) {
        status = serf_bucket_read(ctx->stream, bufsize, &data, len);
    }
    else {
        *len = 0;
        status = APR_EAGAIN;
    }

    if (!SERF_BUCKET_READ_ERROR(status) && *len) {
        int ssl_len;
        apr_status_t agg_status;

#ifdef SSL_VERBOSE
        printf("ssl_encrypt: read %d bytes; status %d\n", *len, status);
#endif
        if (APR_STATUS_IS_EOF(status)) {
            ctx->ssl_ctx->source_status = status;
        }

        ssl_len = SSL_write(ctx->ssl_ctx->ssl, data, *len);
        if (ssl_len == -1) {
            int ssl_err;
            serf_bucket_t *tmp;
            char *data_copy;

            /* Ah, bugger. We need to put that data back. */
            if (!SERF_BUCKET_IS_AGGREGATE(ctx->stream)) {
                tmp = serf_bucket_aggregate_create(ctx->stream->allocator);
                serf_bucket_aggregate_append(tmp, ctx->stream);
                ctx->stream = tmp;
            }

            data_copy =
                serf_bucket_mem_alloc(ctx->stream->allocator, *len);
            memcpy(data_copy, data, *len);

            tmp = serf_bucket_simple_create(data_copy, *len, free_read_data,
                                            ctx->stream->allocator,
                                            ctx->stream->allocator);

            serf_bucket_aggregate_prepend(ctx->stream, tmp);

            ssl_err = SSL_get_error(ctx->ssl_ctx->ssl, ssl_len);
            if (ssl_err == SSL_ERROR_SYSCALL) {
                status = ctx->ssl_ctx->sink_status;
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

    /* We can't send EOF. */
    if (APR_STATUS_IS_EOF(status) && ctx->ssl_ctx->refcount > 1) {
        status = APR_EAGAIN;
    }
#ifdef SSL_VERBOSE
    printf("ssl_encrypt: %d %d %d\n", status, *len,
           BIO_get_retry_flags(ctx->ssl_ctx->bio));
#endif
    return status;
}

static serf_ssl_context_t *ssl_init_context();

static apr_status_t ssl_free_context(serf_ssl_context_t *);

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
        ctx->ssl_ctx = ssl_init_context();
        ctx->own_ssl_ctx = 1;
    }
    else {
        ctx->ssl_ctx = ssl_ctx;
        ctx->own_ssl_ctx = 0;
    }
    ctx->ssl_ctx->refcount++;

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

    if (!--ctx->ssl_ctx->refcount || !ctx->own_ssl_ctx) {
        ssl_free_context(ctx->ssl_ctx);
    }

    serf_bucket_destroy(ctx->stream);

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

#ifdef SSL_VERBOSE
    printf("bio_bucket_read called for %d bytes\n", inlen);
#endif

    BIO_clear_retry_flags(bio);

    status = serf_bucket_read(ctx->source, inlen, &data, &len);

    ctx->sink_status = status;

    if (!SERF_BUCKET_READ_ERROR(status)) {
        /* Oh suck. */
        if (len) {
            memcpy(in, data, len);
            return len;
        }
        if (APR_STATUS_IS_EOF(status)) {
            BIO_set_retry_read(bio);
            return -1;
        }
    }

    return -1;
}

/* Returns the amount written. */
static int bio_bucket_write(BIO *bio, const char *in, int inl)
{
    serf_ssl_context_t *ctx = bio->ptr;
    serf_bucket_t *tmp;
    char *data_copy;

#ifdef SSL_VERBOSE
    printf("bio_bucket_write called for %d bytes\n", inl);
#endif
    BIO_clear_retry_flags(bio);

    data_copy = serf_bucket_mem_alloc(ctx->sink->allocator, inl);
    memcpy(data_copy, in, inl);

    tmp = serf_bucket_simple_create(data_copy, inl, free_read_data,
                                    ctx->sink->allocator,
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
    long ret = 1;

    switch (cmd) {
    default:
        abort();
        break;
    case BIO_CTRL_FLUSH:
        /* At this point we can't force a flush. */
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
        ret = 0;
        break;
    }
    return ret;
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

static serf_ssl_context_t *ssl_init_context()
{
    serf_ssl_context_t *ssl_ctx;
    apr_pool_t *pool;
    serf_bucket_alloc_t *allocator;

    /* XXX Only do this ONCE! */
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    apr_pool_create(&pool, NULL);
    allocator = serf_bucket_allocator_create(pool, NULL, NULL);

    ssl_ctx = serf_bucket_mem_alloc(allocator, sizeof(*ssl_ctx));

    ssl_ctx->refcount = 0;
    ssl_ctx->pool = pool;
    ssl_ctx->allocator = allocator;

    /* This is wrong-ish. */
    ssl_ctx->ctx = SSL_CTX_new(SSLv23_client_method());

    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_ALL);

    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    ssl_ctx->bio = BIO_new(&bio_bucket_method);
    ssl_ctx->bio->ptr = ssl_ctx;

    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);

    SSL_set_connect_state(ssl_ctx->ssl);

    ssl_ctx->source = serf_bucket_aggregate_create(ssl_ctx->allocator);
    ssl_ctx->sink = serf_bucket_aggregate_create(ssl_ctx->allocator);

    ssl_ctx->source_status = APR_SUCCESS;
    ssl_ctx->sink_status = APR_SUCCESS;

    return ssl_ctx;
}

static apr_status_t ssl_free_context(
    serf_ssl_context_t *ssl_ctx)
{
    apr_pool_t *p;

    serf_bucket_destroy(ssl_ctx->source);
    serf_bucket_destroy(ssl_ctx->sink);

    BIO_free(ssl_ctx->bio);
    SSL_free(ssl_ctx->ssl);
    SSL_CTX_free(ssl_ctx->ctx);

    p = ssl_ctx->pool;

    serf_bucket_mem_free(ssl_ctx->allocator, ssl_ctx);
    apr_pool_destroy(p);

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
