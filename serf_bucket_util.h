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


/**
 * Allocate @a size bytes of memory using @a allocator.
 */
SERF_DECLARE(void *) serf_bucket_mem_alloc(
    serf_bucket_alloc_t *allocator,
    apr_size_t size);

/**
 * Free the memory at @a block, returning it to @a allocator.
 */
SERF_DECLARE(void) serf_bucket_mem_free(
    serf_bucket_alloc_t *allocator,
    void *block);


/**
 * Read data up to a newline.
 *
 * @a acceptable contains the allowed forms of a newline, and @a found
 * will return the particular newline type that was found. If a newline
 * is not found, then SERF_NEWLINE_NONE will be placed in @a found.
 *
 * @a data should contain a pointer to the data to be scanned. @a len
 * should specify the length of that data buffer. On exit, @a data will
 * be advanced past the newline, and @a len will specify the remaining
 * amount of data in the buffer.
 *
 * Given this pattern of behavior, the caller should store the initial
 * value of @a data as the line start. The difference between the
 * returned value of @a data and the saved start is the length of the
 * line.
 *
 * Note that the newline character(s) will remain within the buffer.
 * This function scans at a byte level for the newline characters. Thus,
 * the data buffer may contain NUL characters. As a corollary, this
 * function only works on 8-bit character encodings.
 *
 * If the data is fully consumed (@a len gets set to zero) and a CR
 * character is found at the end and the CRLF sequence is allowed, then
 * this function may store SERF_NEWLINE_CRLF_SPLIT into @a found. The
 * caller should take particular consideration for the CRLF sequence
 * that may be split across data buffer boundaries.
 */
SERF_DECLARE(void) serf_util_readline(const char **data, apr_size_t *len,
                                      int acceptable, int *found);

/** The buffer size used within @see serf_databuf_t. */
#define SERF_DATABUF_BUFSIZE 8000

/**
 * This structure is used as an intermediate data buffer for some "external"
 * source of data. It works as a scratch pad area for incoming data to be
 * stored, and then returned as a ptr/len pair by the bucket read functions.
 *
 * This structure should be initialized by calling @see serf_databuf_init.
 * Users should not bother to zero the structure beforehand.
 */
typedef struct {
    /** The current data position within the buffer. */
    const char *current;

    /** Amount of data remaining in the buffer. */
    apr_size_t remaining;

    /** Callback function which is used to refill the data buffer.
     *
     * The function takes @a baton, which is the @see read_baton value
     * from the serf_databuf_t structure. Data should be placed into
     * a buffer specified by @a buf, which is @a bufsize bytes long.
     * The amount of data read should be returned in @a len.
     *
     * APR_EOF should be returned if no more data is available. APR_EAGAIN
     * should be returned, rather than blocking. In both cases, @a buf
     * should be filled in and @a len set, as appropriate.
     */
    apr_status_t (*read)(void *baton, apr_size_t bufsize,
                         char *buf, apr_size_t *len);

    /** A baton to hold context-specific data. */
    void *read_baton;

    /** Records the status from the last @see read operation. */
    apr_status_t status;

    /** Holds the data until it can be returned. */
    char buf[SERF_DATABUF_BUFSIZE];

} serf_databuf_t;

/**
 * Initialize the @see serf_databuf_t structure specified by @a databuf.
 */
SERF_DECLARE(void) serf_databuf_init(serf_databuf_t *databuf);

/**
 * Implement a bucket-style read function from the @see serf_databuf_t
 * structure given by @a databuf.
 *
 * The @a requested, @a data, and @a len fields are interpreted and used
 * as in the read function of @see serf_bucket_t.
 */
SERF_DECLARE(apr_status_t) serf_databuf_read(serf_databuf_t *databuf,
                                             apr_size_t requested,
                                             const char **data,
                                             apr_size_t *len);

/**
 * Implement a bucket-style readline function from the @see serf_databuf_t
 * structure given by @a databuf.
 *
 * The @a acceptable, @a found, @a data, and @a len fields are interpreted
 * and used as in the read function of @see serf_bucket_t.
 */
SERF_DECLARE(apr_status_t) serf_databuf_readline(serf_databuf_t *databuf,
                                                 int acceptable, int *found,
                                                 const char **data,
                                                 apr_size_t *len);

/**
 * Implement a bucket-style peek function from the @see serf_databuf_t
 * structure given by @a databuf.
 *
 * The @a data, and @a len fields are interpreted and used as in the
 * peek function of @see serf_bucket_t.
 */
SERF_DECLARE(apr_status_t) serf_databuf_peek(serf_databuf_t *databuf,
                                             const char **data,
                                             apr_size_t *len);


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKET_UTIL_H */
