/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003 The Apache Software Foundation.  All rights
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

#include "serf.h"


struct serf_bucket_alloc_t {
    apr_allocator_t *allocator;
    apr_pool_t *pool;
};

struct serf_metadata_t {
    apr_hash_t *hash;
};

SERF_DECLARE(serf_bucket_t *) serf_bucket_create(
    const serf_bucket_type_t *type,
    serf_bucket_alloc_t *allocator,
    void *data)
{
    serf_bucket_t *bkt = serf_bucket_mem_alloc(allocator, sizeof(*bkt));

    bkt->type = type;
    bkt->data = data;
    bkt->metadata = serf_bucket_mem_alloc(allocator, sizeof(*bkt->metadata));
    bkt->metadata->hash = NULL;
    bkt->allocator = allocator;

    return bkt;
}

SERF_DECLARE(apr_status_t) serf_default_set_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void *md_value)
{
    apr_hash_t *md_hash;

    md_hash = NULL;

    if (!bucket->metadata->hash) {
        bucket->metadata->hash = apr_hash_make(bucket->allocator->pool);
    }
    else {
        md_hash = apr_hash_get(bucket->metadata->hash, md_type,
                               APR_HASH_KEY_STRING);
    }

    if (!md_hash) {
        md_hash = apr_hash_make(bucket->allocator->pool);
        apr_hash_set(bucket->metadata->hash, md_type, APR_HASH_KEY_STRING,
                     md_hash);
    }

    apr_hash_set(md_hash, md_name, APR_HASH_KEY_STRING, md_value);

    return APR_SUCCESS;
}


SERF_DECLARE(apr_status_t) serf_default_get_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void **md_value)
{
    /* Initialize return value to not being found. */
    *md_value = NULL;

    if (bucket->metadata->hash) {
        apr_hash_t *md_hash;

        md_hash = apr_hash_get(bucket->metadata->hash, md_type,
                               APR_HASH_KEY_STRING);

        if (md_hash) {
            *md_value = apr_hash_get(md_hash, md_name, APR_HASH_KEY_STRING);
        }
    }

    return APR_SUCCESS;
}

SERF_DECLARE(serf_bucket_t *) serf_default_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    return NULL;
}

SERF_DECLARE(void) serf_default_destroy(serf_bucket_t *bucket)
{
    serf_bucket_mem_free(bucket->allocator, bucket->metadata);
    serf_bucket_mem_free(bucket->allocator, bucket);
}


/* ==================================================================== */


SERF_DECLARE(serf_bucket_alloc_t *) serf_bucket_allocator_create(
    apr_allocator_t *allocator, apr_pool_t *pool)
{
    serf_bucket_alloc_t *a = apr_allocator_alloc(allocator, sizeof(*a));

    a->allocator = allocator;
    a->pool = pool;
    /* ### more */

    return a;
}

SERF_DECLARE(void) serf_bucket_allocator_destroy(
    serf_bucket_alloc_t *allocator)
{
    /* We don't (yet) own the pool passed in to our allocator_create. */
    apr_allocator_destroy(allocator->allocator);
}

SERF_DECLARE(void *) serf_bucket_mem_alloc(
    serf_bucket_alloc_t *allocator,
    apr_size_t size)
{
    return apr_allocator_alloc(allocator->allocator, size);
}

SERF_DECLARE(void) serf_bucket_mem_free(
    serf_bucket_alloc_t *allocator,
    void *block)
{
    apr_allocator_free(allocator->allocator, block);
}
