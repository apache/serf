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

#include "serf_config.h"
#include "serf_buckets.h"
#include "serf.h"

#if !SERF_HAS_OPENSSL
#error Serf must be compiled with OpenSSL support.
#endif

#define OPENSSL_THREAD_DEFINES
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static apr_status_t read_ssl(serf_ssl_ctx_t *context, char *buf,
                             apr_size_t *buflen)
{       
    apr_status_t rv;
    int e, sslError;
    
    /* Wait until there is something to read. */
    if (SSL_pending(context->ssl_connection) < *buflen) {
        apr_int32_t socketsRead;
        const apr_pollfd_t *descriptors;
        rv = apr_pollset_poll(context->read_pollset, SERF_SOCKET_TIMEOUT,
                              &socketsRead, &descriptors);
        
        if (socketsRead != 1) {
            return APR_TIMEUP;
        }
    }

    e = SSL_read(context->ssl_connection, buf, *buflen);
    sslError = SSL_get_error(context->ssl_connection, e);

    switch (sslError)
    {
    case SSL_ERROR_NONE:
        *buflen = e;
        break;
   case SSL_ERROR_WANT_READ:
        ssl_read_socket(context, buf, buflen);
        break;
    case SSL_ERROR_ZERO_RETURN: /* Peer closed connection. */
        return APR_EOF;
    case SSL_ERROR_SYSCALL: /* Look at errno. */
        if (errno == 0) {
            *buflen = 0;
            return APR_EOF;
        }
        /* Continue through with the error case. */
    case SSL_ERROR_WANT_WRITE:  /* Technically, not an error. */
    default:
        ERR_print_errors_fp(stderr);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static apr_status_t ssl_bucket_read(apr_bucket *a, const char **str,
                                    apr_size_t *len, apr_read_type_e block)
{
    serf_connection_t *c = a->data;
    char *buf;
    apr_status_t rv;
    apr_interval_time_t timeout;

    if (block == APR_NONBLOCK_READ) {
        apr_socket_timeout_get(c->socket, &timeout);
        apr_socket_timeout_set(c->socket, 0);
    }

    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list); /* XXX: check for failure? */

    rv = read_ssl(c->ctx, buf, len);

    if (block == APR_NONBLOCK_READ) {
        apr_socket_timeout_set(c->socket, timeout);
    }

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }
    /*
     * If there's more to read we have to keep the rest of the socket
     * for later. XXX: Note that more complicated bucket types that
     * refer to data not in memory and must therefore have a read()
     * function similar to this one should be wary of copying this
     * code because if they have a destroy function they probably
     * want to migrate the bucket's subordinate structure from the
     * old bucket to a raw new one and adjust it as appropriate,
     * rather than destroying the old one and creating a completely
     * new bucket.
     *
     * Even if there is nothing more to read, don't close the socket here
     * as we have to use it to send any response :)  We could shut it 
     * down for reading, but there is no benefit to doing so.
     */
    if (*len > 0) {
        apr_bucket_heap *h;
        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, serf_bucket_ssl_create(c, a->list));
    }
    else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return APR_SUCCESS;
}

SERF_DECLARE(apr_bucket *) serf_bucket_ssl_make(apr_bucket *b,
                                                serf_connection_t *c)
{
    /*
     * XXX: We rely on a cleanup on some pool or other to actually
     * destroy the socket. We should probably explicitly call apr to
     * destroy it instead.
     *
     * Note that typically the socket is allocated from the connection pool
     * so it will disappear when the connection is finished. 
     */
    b->type        = &serf_bucket_ssl_type;
    b->length      = (apr_size_t)(-1);
    b->start       = -1;
    b->data        = c;

    return b;
}

SERF_DECLARE(apr_bucket *) serf_bucket_ssl_create(serf_connection_t *c,
                                                  apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return serf_bucket_ssl_make(b, c);
}

SERF_DECLARE_DATA const apr_bucket_type_t serf_bucket_ssl_type = {
    "SSL", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    ssl_bucket_read,
    apr_bucket_setaside_notimpl, 
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};
