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

/**
 * @file serf_buckets.h
 * @brief Serf supported buckets in extension to APR buckets
 */

#ifdef __cplusplus
extern "C" {
#endif

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

/* Represents a MIME-header value.
 *
 * Duplicate header key buckets may exist in a brigade.
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
};
typedef struct serf_bucket_header serf_bucket_header;

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
};
typedef struct serf_bucket_authentication serf_bucket_authentication;

#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKETS_H */
