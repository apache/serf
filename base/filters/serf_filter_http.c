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
#include <apr_lib.h>    /* for apr_isxdigit */

#include "serf_filters.h"
#include "serf_buckets.h"
#include "serf.h"

#define HTTP_MAX_HEADER_LENGTH 8192

SERF_DECLARE(apr_status_t) serf_http_status_read(apr_bucket_brigade *brigade,
                                                 serf_filter_t *filter,
                                                 apr_pool_t *pool)
{
    apr_status_t rv;
    char status[HTTP_MAX_HEADER_LENGTH], *status_value;
    apr_size_t status_len = HTTP_MAX_HEADER_LENGTH;
    apr_bucket_brigade *temp_brigade;

    temp_brigade = apr_brigade_create(pool, brigade->bucket_alloc);

    rv = apr_brigade_split_line(temp_brigade, brigade, APR_BLOCK_READ,
                                HTTP_MAX_HEADER_LENGTH);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_brigade_flatten(temp_brigade, status, &status_len);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    /* Search for the ' ' first space. */
    status_value = memchr(status, ' ', status_len);
    if (status_value) {
        apr_int64_t status_code;
        char *end;
        apr_bucket *bucket;

        status_code = apr_strtoi64(++status_value, &end, 10);
        if (end && *end == ' ') {
            end++;
        }
        /* Remove the trailing \r\n */
        status[status_len-2] = '\0';

        /* FIXME: Should it be the entire status line or just the code? */
        bucket = serf_bucket_status_create(status_code, status, pool,
                                           brigade->bucket_alloc); 

        APR_BRIGADE_INSERT_TAIL(brigade, bucket);
    }
    else {
        /* This isn't a HTTP response! */ 
        return APR_EGENERAL;
    }

    apr_brigade_destroy(temp_brigade);

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_http_header_read(apr_bucket_brigade *brigade,
                                                 serf_filter_t *filter,
                                                 apr_pool_t *pool)
{
    apr_bucket_brigade *new_brigade, *temp_brigade;

    new_brigade = apr_brigade_create(pool, brigade->bucket_alloc);
    temp_brigade = apr_brigade_create(pool, brigade->bucket_alloc);

    while (!APR_BRIGADE_EMPTY(brigade)) {
        apr_bucket *bucket;
        apr_status_t rv;
        char header[HTTP_MAX_HEADER_LENGTH], *header_value;
        apr_size_t header_len = HTTP_MAX_HEADER_LENGTH;
        
        rv = apr_brigade_split_line(temp_brigade, brigade, APR_BLOCK_READ,
                                    HTTP_MAX_HEADER_LENGTH);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        rv = apr_brigade_flatten(temp_brigade, header, &header_len);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        /* We found our blank line.  Stop.  */
        if (header_len == 2) {
            break;
        }

        /* Search for the ':' key-value delimiter. */
        header_value = memchr(header, ':', header_len);
        if (header_value) {
            *header_value = '\0';
            if (*(++header_value) == ' ') {
                header_value++;
            }

            /* Remove the trailing \r\n */
            header[header_len-2] = '\0';

            bucket = serf_bucket_header_create(header, header_value, pool,
                                               brigade->bucket_alloc); 
        }
        else {
            /* FIXME: This *could* be a MIME-continuation header.  Eek!  */
            bucket = apr_bucket_transient_create(header, header_len - 2,
                                                 brigade->bucket_alloc);
        }
        APR_BRIGADE_INSERT_TAIL(new_brigade, bucket);
        apr_brigade_cleanup(temp_brigade);
    }

    APR_BRIGADE_CONCAT(brigade, new_brigade);

    apr_brigade_destroy(new_brigade);
    apr_brigade_destroy(temp_brigade);

    return APR_SUCCESS;
}

/**
 * Parse a chunk extension, detect overflow.
 * There are two error cases:
 *  1) If the conversion would require too many bits, a -1 is returned.
 *  2) If the conversion used the correct number of bits, but an overflow
 *     caused only the sign bit to flip, then that negative number is
 *     returned.
 * In general, any negative number can be considered an overflow error.
 */
static long get_chunk_size(char *b)
{
    long chunksize = 0;
    size_t chunkbits = sizeof(long) * 8;

    /* Skip leading zeros */
    while (*b == '0') {
        ++b;
    }

    while (apr_isxdigit(*b) && (chunkbits > 0)) {
        int xvalue = 0;

        if (*b >= '0' && *b <= '9') {
            xvalue = *b - '0';
        }
        else if (*b >= 'A' && *b <= 'F') {
            xvalue = *b - 'A' + 0xa;
        }
        else if (*b >= 'a' && *b <= 'f') {
            xvalue = *b - 'a' + 0xa;
        }

        chunksize = (chunksize << 4) | xvalue;
        chunkbits -= 4;
        ++b;
    }
    if (apr_isxdigit(*b) && (chunkbits <= 0)) {
        /* overflow */
        return -1;
    }

    return chunksize;
}

SERF_DECLARE(apr_status_t) serf_http_dechunk(apr_bucket_brigade *brigade,
                                             serf_filter_t *filter,
                                             apr_pool_t *pool)
{
    apr_bucket *bucket;
    apr_bucket_brigade *new_brigade, *temp_brigade;
    apr_status_t rv;
    int dechunk = 0;

    new_brigade = apr_brigade_create(pool, brigade->bucket_alloc);
    temp_brigade = apr_brigade_create(pool, brigade->bucket_alloc);

    /* Search to see if the server has sent us back the right header. */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) { 
        if (SERF_BUCKET_IS_HEADER(bucket)) {
            serf_bucket_header *hdr = bucket->data;

            if (strcasecmp(hdr->key, "Transfer-Encoding") == 0) {
                /* FIXME: Add token support! */
                if (strcasecmp(hdr->value, "chunked") == 0) {
                    dechunk = 1;
                }                            
            }                                
        }
    }

    if (!dechunk) {
        return APR_SUCCESS;
    }

    while (1) {
        char chunk[HTTP_MAX_HEADER_LENGTH];
        apr_size_t chunk_len = HTTP_MAX_HEADER_LENGTH;
        long chunk_length;

        rv = apr_brigade_split_line(temp_brigade, brigade, APR_BLOCK_READ,
                                    HTTP_MAX_HEADER_LENGTH);

        if (rv != APR_SUCCESS) {
            return rv;
        }
     
        rv = apr_brigade_flatten(temp_brigade, chunk, &chunk_len);

        if (rv != APR_SUCCESS) {
            return rv;
        }

        chunk_length = get_chunk_size(chunk);

        if (chunk_length < 0) {
            /* Overflow! */
            return APR_EGENERAL;
        }

        if (chunk_length == 0) {
            /* We can cheat because we know that the HTTP header filter
             * above doesn't need a context.
             */
            rv = serf_http_header_read(brigade, NULL, pool);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            break;
        }

        rv = apr_brigade_partition(brigade, chunk_length, &bucket);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        temp_brigade = apr_brigade_split(brigade, bucket);
        APR_BRIGADE_CONCAT(new_brigade, brigade);
        APR_BRIGADE_CONCAT(brigade, temp_brigade);

        /* Have to throw the CRLF after the chunk away. */
        rv = apr_brigade_split_line(temp_brigade, brigade, APR_BLOCK_READ,
                                    HTTP_MAX_HEADER_LENGTH);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        apr_brigade_cleanup(temp_brigade);
    }

    APR_BRIGADE_PREPEND(brigade, new_brigade);

    apr_brigade_destroy(new_brigade);
    apr_brigade_destroy(temp_brigade);

    return APR_SUCCESS;
}
