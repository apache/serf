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

#ifndef SERF_BUCKET_UTIL_H
#define SERF_BUCKET_UTILH

/**
 * @file serf_bucket_util.h
 * @brief This header defines a set of functions and other utilities
 * for implementing buckets. It is not needed by users of the bucket
 * system.
 */

#include "serf.h"
#include "serf_declare.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Basic bucket creation function.
 *
 * This function will create a bucket of @a type, allocating the necessary
 * memory from @a allocator. The @a data bucket-private information will
 * be stored into the bucket.
 *
 * The metadata for the bucket will be empty.
 */
SERF_DECLARE(serf_bucket_t *) serf_bucket_create(
    const serf_bucket_type_t *type,
    serf_bucket_alloc_t *allocator,
    void *data);

/**
 * Default implementation to set metadata within a bucket.
 *
 * Stores @a md_value into @a bucket under the metadata type @a md_type
 * and name @a md_name.
 */
SERF_DECLARE(apr_status_t) serf_default_set_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void *md_value);

/**
 * Default implementation to get metadata from @a bucket.
 *
 * The @a md_value for the specified @a md_type and @a md_name will
 * be returned. If the metadata is not present, then NULL will be stored
 * into @a md_value.
 */
SERF_DECLARE(apr_status_t) serf_default_get_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void **md_value);

/**
 * Default implementation of the @see read_iovec functionality.
 *
 * This function will use the @see read function to get a block of memory,
 * then return it in the iovec.
 */
SERF_DECLARE(apr_status_t) serf_default_read_iovec(
    serf_bucket_t *bucket,
    apr_size_t requested,
    int vecs_size,
    struct iovec *vecs,
    int *vecs_used);

/**
 * Default implementation of the @see read_for_sendfile functionality.
 *
 * This function will use the @see read function to get a block of memory,
 * then return it as a header. No file will be returned.
 */
SERF_DECLARE(apr_status_t) serf_default_read_for_sendfile(
    serf_bucket_t *bucket,
    apr_size_t requested,
    apr_hdtr_t *hdtr,
    apr_file_t **file,
    apr_off_t *offset,
    apr_size_t *len);

/**
 * Default implementation of the @see read_bucket functionality.
 *
 * This function will always return NULL, indicating that the @a type
 * of bucket cannot be found within @a bucket.
 */
SERF_DECLARE(serf_bucket_t *) serf_default_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type);

/**
 * Default implementation of the @see destroy functionality.
 *
 * This function will return the @a bucket and its metadata to its allcoator.
 */
SERF_DECLARE(void) serf_default_destroy(serf_bucket_t *bucket);


/**
 * Default implementation of the @see destroy functionality.
 *
 * This function will return the @a bucket, its metadata, and the data
 * member to its allcoator.
 */
SERF_DECLARE(void) serf_default_destroy_and_data(serf_bucket_t *bucket);


SERF_DECLARE(void *) serf_bucket_mem_alloc(
    serf_bucket_alloc_t *allocator,
    apr_size_t size);

SERF_DECLARE(void) serf_bucket_mem_free(
    serf_bucket_alloc_t *allocator,
    void *block);


SERF_DECLARE(void) serf_util_readline(const char **data, apr_size_t *len,
                                      int acceptable, int *found);


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKET_UTIL_H */
