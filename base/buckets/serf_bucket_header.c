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

static apr_status_t header_bucket_read(apr_bucket *b, const char **str,
                                       apr_size_t *len, apr_read_type_e block)
{
    serf_bucket_header *header = b->data;
    struct iovec vec[3];
    
    vec[0].iov_base = (void*)header->key;
    vec[0].iov_len  = strlen(header->key);
    vec[1].iov_base = (void*)": ";
    vec[1].iov_len  = sizeof(": ") - 1;
    vec[2].iov_base = (void*)header->value;
    vec[2].iov_len  = strlen(header->value);
 
    *str = apr_pstrcatv(header->pool, vec, 3, len);
    return APR_SUCCESS;
}

static void header_bucket_destroy(void *data)
{
    serf_bucket_status *bucket = data;

    if (apr_bucket_shared_destroy(bucket)) {
        apr_bucket_free(bucket);
    }
}

SERF_DECLARE(apr_bucket *) serf_bucket_header_make(apr_bucket *b,
                                                   const char *key,
                                                   const char *value,
                                                   apr_pool_t *pool)
{
    serf_bucket_header *bucket;

    bucket = apr_bucket_alloc(sizeof(*bucket), b->list);
    bucket->key = (key) ? apr_pstrdup(pool, key) : NULL;
    bucket->value = (value) ? apr_pstrdup(pool, value) : NULL;
    /* FIXME: Make this a subpool? */
    bucket->pool = pool;

    b = apr_bucket_shared_make(b, bucket, 0, 0);
    b->type = &serf_bucket_header_type;

    return b;
}

SERF_DECLARE(apr_bucket *) serf_bucket_header_create(const char *key,
                                                     const char *value,
                                                     apr_pool_t *pool,
                                                     apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    return serf_bucket_header_make(b, key, value, pool);
}

SERF_DECLARE_DATA const apr_bucket_type_t serf_bucket_header_type = {
    "HEADER", 5, APR_BUCKET_METADATA,
    header_bucket_destroy,
    header_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_shared_copy
};
