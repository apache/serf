/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_portable.h>
#include <apr_poll.h>

#include "serf_filters.h"
#include "serf_buckets.h"
#include "serf.h"

#if !SERF_HAS_OPENSSL
#error Serf must be compiled with OpenSSL support.
#endif

#define OPENSSL_THREAD_DEFINES
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static int started_ssl = 0;

/* FIXME: Make me a hook that serf_initialize runs! */
static void init_openssl(void)
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    started_ssl = 1;
}

static void* init_ssl_context(apr_pool_t *pool, serf_connection_t *conn)
{
    apr_os_sock_t ossock;
    serf_ssl_ctx_t *context;
    int ssl_error;
    apr_pollfd_t *pollfd;

    if (!started_ssl) {
        init_openssl();
    }

    context = apr_pcalloc(pool, sizeof(serf_ssl_ctx_t));

    /* Get the native OS socket. */
    apr_os_sock_get(&ossock, conn->socket);

    /* Create a local context */
    context->ssl_context = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(context->ssl_context, SSL_OP_ALL);
#ifdef SSL_MODE_AUTO_RETRY
    /* Not all OpenSSL versions support this. */
    SSL_CTX_set_options(context->ssl_context, SSL_MODE_AUTO_RETRY);
#endif
    /* If we want to allow partial writes, set the following:
    SSL_CTX_set_mode(context->ssl_context, SSL_MOD_ENABLE_PARTIAL_WRITE);
    */
    /*SSL_CTX_set_default_verify_paths(ssl_socket->ssl_context);*/
    SSL_CTX_load_verify_locations(context->ssl_context, NULL, SERF_SSL_CAPATH);

    /* Initialize the SSL connection */
    context->ssl_connection = SSL_new(context->ssl_context);
    SSL_set_connect_state(context->ssl_connection);
  
    /* Set the descriptors */
    SSL_set_fd(context->ssl_connection, ossock);
    ssl_error = SSL_connect(context->ssl_connection);

    /* Setup the poll so that we can efficiently wait for read handshakes. */
    apr_pollset_create(&context->read_pollset, 1, pool, 0);
    pollfd = apr_pcalloc(pool, sizeof(apr_pollfd_t));
    pollfd->desc_type = APR_POLL_SOCKET;
    pollfd->desc.s = conn->socket;
    pollfd->reqevents = APR_POLLIN;
    apr_pollset_add(context->read_pollset, pollfd);
    
    if (ssl_error)
    {
        int sslError = SSL_get_error(context->ssl_connection, ssl_error);

        switch (sslError)
        {
        case SSL_ERROR_NONE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            /* Treat as okay. */
            break;
        default:
            ERR_print_errors_fp(stderr);
            return NULL;
        }
    }

    return context;
}

static apr_status_t ssl_read_socket_handshake(serf_ssl_ctx_t *context)
{
    char buf[1];
    int buflen = 1, e, sslError;
    apr_int32_t socketsRead;
    apr_status_t rv;
    const apr_pollfd_t *descriptors;

    /* Wait until there is something to read. */
    rv = apr_pollset_poll(context->read_pollset, SERF_SOCKET_TIMEOUT,
                          &socketsRead, &descriptors);

    if (rv != APR_SUCCESS) {
        return rv;
    }
    if (socketsRead != 1) {
        return APR_TIMEUP;
    }

    e = SSL_peek(context->ssl_connection, buf, buflen);
    sslError = SSL_get_error(context->ssl_connection, e);

    switch (sslError)
    {
    case SSL_ERROR_NONE:
        break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    default:
        ERR_print_errors_fp(stderr);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static apr_status_t write_ssl(serf_ssl_ctx_t *context, const char *buf,
                              apr_size_t buflen)
{
    apr_status_t rv;
    int e, sslError;

    /* Returns on error. */
    e = SSL_write(context->ssl_connection, buf, buflen);

    sslError = SSL_get_error(context->ssl_connection, e);
    switch (sslError)
    {
    case SSL_ERROR_NONE:
        break;
    case SSL_ERROR_WANT_READ:
        rv = ssl_read_socket_handshake(context);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        return write_ssl(context, buf, buflen);
    case SSL_ERROR_WANT_WRITE:
        break;
    default:
        ERR_print_errors_fp(stderr);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_ssl_write(apr_bucket_brigade *brigade,
                                          serf_filter_t *filter,
                                          apr_pool_t *pool)
{
    serf_connection_t *conn = filter->ctx;
    if (!conn->ctx) {
        conn->ctx = init_ssl_context(pool, conn);
        if (!conn->ctx) {
            return APR_EGENERAL;
        } 
    }

    while (!APR_BRIGADE_EMPTY(brigade)) {
        apr_bucket *bucket;
        const char *buf;
        apr_size_t length;
        apr_status_t status;

        bucket = APR_BRIGADE_FIRST(brigade);

        status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

        if (status) {
            return status;
        }

        status = write_ssl(conn->ctx, buf, length);        
        if (status) {
            return status;
        }

        apr_bucket_delete(bucket);
    }
    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_ssl_read(apr_bucket_brigade *brigade,
                                         serf_filter_t *filter,
                                         apr_pool_t *pool)
{
    serf_connection_t *conn = filter->ctx;
    apr_bucket *bucket;

    bucket = serf_bucket_ssl_create(conn, brigade->bucket_alloc);

    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}
