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

#ifndef SERF_BUCKETS_H
#define SERF_BUCKETS_H

#include <apr_poll.h>
#include <apr_buckets.h>

#include "serf_declare.h"
#include "serf_config.h"

#if SERF_HAS_OPENSSL
#define OPENSSL_THREAD_DEFINES
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

/**
 * @file serf_buckets.h
 * @brief Serf supported buckets in extension to APR buckets
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Represents a request line.
 *
 * On apr_bucket_read, it returns: "METHOD PATH VERSION"
 */
struct serf_bucket_request_line {
    /** Number of buckets using this memory */
    apr_bucket_refcount refcount;
    /** Method */
    const char *method;
    /** Path component */
    const char *path;
    /** Version */
    const char *version;
    /** FULL line (cached) */
    const char *full_line;
};
typedef struct serf_bucket_request_line serf_bucket_request_line;
SERF_DECLARE_DATA extern const apr_bucket_type_t serf_bucket_request_line_type;

/**
 * Determine if a bucket is a request_line bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define SERF_BUCKET_IS_REQUEST_LINE(e) \
     (e->type == &serf_bucket_request_line_type)

/**
 * Make the bucket passed in a request_line bucket
 * @param b The bucket to make into a request_line bucket
 * @param method Method string
 * @param path Path component
 * @param version Version component
 * @param pool A pool to allocate out of
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_request_line_make(apr_bucket *b,
                                                         const char *method,
                                                         const char *path,
                                                         const char *version,
                                                         apr_pool_t *pool);

/**
 * Create a bucket referring to request_line information
 * @param method Method string
 * @param path Path component
 * @param version Version component
 * @param pool A pool to allocate out of
 * @param list The bucket allocator from which to allocate the bucket
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_request_line_create(const char *method,
                                                           const char *path,
                                                           const char *version,
                                                           apr_pool_t *pool,
                                                     apr_bucket_alloc_t *list);

/* Represents a response status code.
 *
 * On apr_bucket_read, it returns: "status_line"
 */
struct serf_bucket_status {
    /** Number of buckets using this memory */
    apr_bucket_refcount refcount;
    /** The status code */
    int status;
    /** The status line */
    const char *status_line;
};
typedef struct serf_bucket_status serf_bucket_status;
SERF_DECLARE_DATA extern const apr_bucket_type_t serf_bucket_status_type;

/**
 * Determine if a bucket is a status bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define SERF_BUCKET_IS_STATUS(e) (e->type == &serf_bucket_status_type)

/**
 * Make the bucket passed in a status bucket
 * @param b The bucket to make into a status bucket
 * @param status Numeric status code
 * @param status_line Textual description of the status code
 * @param pool A pool to allocate out of
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_status_make(apr_bucket *b,
                                                   int status,
                                                   const char *status_line,
                                                   apr_pool_t *pool);

/**
 * Create a bucket referring to status information
 * @param status Numeric status code
 * @param status_line Textual description of the status code
 * @param pool A pool to allocate out of
 * @param list The bucket allocator from which to allocate the bucket
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_status_create(int status,
                                                     const char *status_line,
                                                     apr_pool_t *pool,
                                                     apr_bucket_alloc_t *list);
/* Represents a MIME-header value.
 *
 * Duplicate header key buckets may exist in a brigade. Per RFC2616, these
 * headers are intended to be cumulative, with their values separated by
 * ", ".
 *
 * On apr_bucket_read, it returns: "key: value"
 */
struct serf_bucket_header {
    /** Number of buckets using this memory */
    apr_bucket_refcount refcount;
    /** The MIME-header name */
    const char *key;
    /** The MIME-header value */
    const char *value;
    /** Pool used for allocation for reads */
    apr_pool_t *pool;
};
typedef struct serf_bucket_header serf_bucket_header;
SERF_DECLARE_DATA extern const apr_bucket_type_t serf_bucket_header_type;

/**
 * Determine if a bucket is a header bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define SERF_BUCKET_IS_HEADER(e) (e->type == &serf_bucket_header_type)

/**
 * Make the bucket passed in a header bucket
 * @param b The bucket to make into a header bucket
 * @param key The header name
 * @param value The header value
 * @param pool A pool to allocate out of
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_header_make(apr_bucket *b,
                                                   const char *key,
                                                   const char *value,
                                                   apr_pool_t *pool);

/**
 * Create a bucket referring to header information.
 * @param key The header name
 * @param value The header value
 * @param pool A pool to allocate out of
 * @param list The bucket allocator from which to allocate the bucket
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_header_create(const char *key,
                                                     const char *value,
                                                     apr_pool_t *pool,
                                                     apr_bucket_alloc_t *list);

/* Represents a user-password pair.
 *
 * On apr_bucket_read, it returns: "username:password"
 */
struct serf_bucket_authentication {
    /* Number of buckets using this memory */
    apr_bucket_refcount refcount;
    /* The username */
    const char *user;
    /* The password */
    const char *password;
    /** Pool used for allocation for reads */
    apr_pool_t *pool;
};
typedef struct serf_bucket_authentication serf_bucket_authentication;
SERF_DECLARE_DATA extern const apr_bucket_type_t
                               serf_bucket_authentication_type;

/**
 * Determine if a bucket is an authentication bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define SERF_BUCKET_IS_AUTHENTICATION(e) \
    (e->type == &serf_bucket_authentication_type)

/**
 * Make the bucket passed in an authentication bucket
 * @param b The bucket to make into an authentication bucket
 * @param username The username to store in the bucket
 * @param password The password to store in the bucket
 * @param pool A pool to allocate out of.
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_authentication_make(apr_bucket *b,
                                                           const char *user,
                                                           const char *password,
                                                           apr_pool_t *pool);

/**
 * Create a bucket referring to authentication credentials.
 * @param username The username to store in the bucket
 * @param password The password to store in the bucket
 * @param pool A pool to allocate out of.
 * @param list The bucket allocator from which to allocate the bucket
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_authentication_create(const char *user,
                                                      const char *password,
                                                      apr_pool_t *pool,
                                                      apr_bucket_alloc_t *list);
#if SERF_HAS_OPENSSL

/* Represents a SSL socket.
 *
 * On apr_bucket_read, it returns decrypted socket data
 */

typedef struct serf_ssl_ctx_t serf_ssl_ctx_t;
struct serf_ssl_ctx_t {
    SSL_CTX *ssl_context;
    SSL *ssl_connection;
    apr_pollset_t *read_pollset;
};

struct serf_bucket_ssl {
    /* Number of buckets using this memory */
    apr_bucket_refcount refcount;
    /* Associated connection */
    struct serf_connection_t *connection;
};

typedef struct serf_bucket_ssl serf_bucket_ssl;
SERF_DECLARE_DATA extern const apr_bucket_type_t serf_bucket_ssl_type;

/**
 * Determine if a bucket is a SSL bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define SERF_BUCKET_IS_SSL(e) \
    (e->type == &serf_bucket_ssl_type)

/**
 * Make the bucket passed in a SSL bucket
 * @param b The bucket to make into a SSL bucket
 * @param c Serf connection
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_ssl_make(apr_bucket *b,
                                                struct serf_connection_t *c);

/**
 * Create a bucket referring to SSL connection
 * @param c Serf connection
 * @param list The bucket allocator from which to allocate the bucket
 * @return The new bucket, or NULL if allocation failed
 */
SERF_DECLARE(apr_bucket *) serf_bucket_ssl_create(struct serf_connection_t *c,
                                                  apr_bucket_alloc_t *list);

#endif

#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKETS_H */
