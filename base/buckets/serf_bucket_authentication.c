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

#include "serf_buckets.h"

static apr_status_t authentication_bucket_read(apr_bucket *b, const char **str,
                                               apr_size_t *len,
                                               apr_read_type_e block)
{
    serf_bucket_authentication *auth = b->data;
    struct iovec vec[3];
    
    vec[0].iov_base = (void*)auth->user;
    vec[0].iov_len  = strlen(auth->user);
    vec[1].iov_base = (void*)":";
    vec[1].iov_len  = sizeof(":") - 1;
    vec[2].iov_base = (void*)auth->password;
    vec[2].iov_len  = strlen(auth->password);
 
    *str = apr_pstrcatv(auth->pool, vec, 3, len);
    return APR_SUCCESS;
}

static void authentication_bucket_destroy(void *data)
{
    serf_bucket_status *bucket = data;

    if (apr_bucket_shared_destroy(bucket)) {
        apr_bucket_free(bucket);
    }
}

SERF_DECLARE(apr_bucket *) serf_bucket_authentication_make(apr_bucket *b,
                                                           const char *user,
                                                           const char *password,
                                                           apr_pool_t *pool)
{
    serf_bucket_authentication *bucket;

    bucket = apr_bucket_alloc(sizeof(*bucket), b->list);
    bucket->user = (user) ? apr_pstrdup(pool, user) : NULL;
    bucket->password = (password) ? apr_pstrdup(pool, password) : NULL;
    /* FIXME: Make this a subpool? */
    bucket->pool = pool;

    b = apr_bucket_shared_make(b, bucket, 0, 0);
    b->type = &serf_bucket_authentication_type;

    return b;
}

SERF_DECLARE(apr_bucket *) serf_bucket_header_create(const char *user,
                                                     const char *password,
                                                     apr_pool_t *pool,
                                                     apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return serf_bucket_authentication_make(b, user, password, pool);
}

SERF_DECLARE_DATA const apr_bucket_type_t serf_bucket_status_type = {
    "AUTHENTICATION", 5, APR_BUCKET_METADATA,
    authentication_bucket_destroy,
    authentication_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};
