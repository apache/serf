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

#include "serf_filters.h"
#include "serf_buckets.h"
#include "serf.h"
#include "serf_config.h"

#if !SERF_HAS_ZLIB
#error Deflate filters can not be compiled without zlib!
#endif

#include "zlib.h"
#ifdef HAVE_ZUTIL_H
#include "zutil.h"
#endif

SERF_DECLARE(apr_status_t) serf_deflate_send_header(apr_bucket_brigade *brigade,
                                                    serf_filter_t *filter,
                                                    apr_pool_t *pool)
{
    apr_bucket *bucket;

    bucket = serf_bucket_header_create("Accept-Encoding",
                                       "gzip",
                                       pool, brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

/* magic header */
static char deflate_magic[2] = { '\037', '\213' };

static const int DEFLATE_WINDOW_SIZE = -15;
static const int DEFLATE_MEMLEVEL = 9; 
static const int DEFLATE_BUFFER_SIZE = 8096;

/* Context. */
typedef struct deflate_ctx_t
{
    z_stream stream;
    unsigned char *buffer;
    unsigned long crc;
    int windowSize;
    int memLevel;
    int bufferSize;
    apr_bucket_brigade *brigade, *proc_brigade;
} deflate_ctx_t;

/* Inputs a string and returns a long.
 */
static unsigned long getLong(unsigned char *string)
{
    return ((unsigned long)string[0])
          | (((unsigned long)string[1]) << 8)
          | (((unsigned long)string[2]) << 16)
          | (((unsigned long)string[3]) << 24);
}

SERF_DECLARE(apr_status_t) serf_deflate_read(apr_bucket_brigade *brigade,
                                             serf_filter_t *filter,
                                             apr_pool_t *pool)
{
    apr_bucket_brigade *new_brigade, *temp_brigade;
    apr_bucket *bucket;
    deflate_ctx_t *ctx = filter->ctx;
    int zRC;
    char deflate_hdr[10];
    apr_size_t deflate_hdr_len;
    apr_status_t rv;

    if (!ctx) {
        int use_inflate = 0;

        /* Search to see if the server has sent us back the right header. */
        for (bucket = APR_BRIGADE_FIRST(brigade);
             bucket != APR_BRIGADE_SENTINEL(brigade);
            bucket = APR_BUCKET_NEXT(bucket)) {
            if (SERF_BUCKET_IS_HEADER(bucket)) {
                serf_bucket_header *hdr = bucket->data;
 
                if (strcasecmp(hdr->key, "Content-Encoding") == 0) {
                    /* FIXME: Add token support! */
                    if (strcasecmp(hdr->value, "gzip") == 0) {
                        use_inflate = 1;
                        break;
                    }
                }
            }
        }

        if (!use_inflate) {
            return APR_SUCCESS;
        }

        filter->ctx = ctx = apr_pcalloc(pool, sizeof(deflate_ctx_t));
        /* FIXME: Need a way to allow user customization of these! */
        ctx->windowSize = DEFLATE_WINDOW_SIZE;
        ctx->memLevel = DEFLATE_MEMLEVEL;
        ctx->bufferSize = DEFLATE_BUFFER_SIZE;

        ctx->buffer = apr_palloc(pool, ctx->bufferSize);
    }

    /* Create the temporary brigades. */
    new_brigade = apr_brigade_create(pool, brigade->bucket_alloc);

    /* Read the deflate header info. */
    deflate_hdr_len = 10;
    rv = apr_brigade_partition(brigade, deflate_hdr_len, &bucket);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    temp_brigade = apr_brigade_split(brigade, bucket);
    APR_BRIGADE_CONCAT(new_brigade, brigade);
    APR_BRIGADE_CONCAT(brigade, temp_brigade);

    rv = apr_brigade_flatten(new_brigade, deflate_hdr, &deflate_hdr_len);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    if (deflate_hdr_len != 10 ||
        deflate_hdr[0] != deflate_magic[0] ||
        deflate_hdr[1] != deflate_magic[1]) {
        return APR_EGENERAL;
    } 

    if (deflate_hdr[3] != 0) {
        return APR_EGENERAL;
    }

    apr_brigade_cleanup(new_brigade);

    zRC = inflateInit2(&ctx->stream, ctx->windowSize);

    if (zRC != Z_OK) {
        filter->ctx = NULL;
        return APR_EGENERAL;
    }

    ctx->stream.next_out = ctx->buffer;
    ctx->stream.avail_out = ctx->bufferSize;

    /* For everything in the brigade not a METADATA, deflate it. */
    while (!APR_BRIGADE_EMPTY(brigade)) {
        const char *data;
        apr_size_t len;

        bucket = APR_BRIGADE_FIRST(brigade);

        /* If we actually see metadata, that means we screwed up! */
        if (APR_BUCKET_IS_METADATA(bucket)) {
            return APR_EGENERAL;
        }

        apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
        ctx->stream.next_in = (unsigned char*)data;
        ctx->stream.avail_in = len;
        zRC = Z_OK;
        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {
                apr_bucket *tmp_heap;
                ctx->stream.next_out = ctx->buffer;
                len = ctx->bufferSize - ctx->stream.avail_out;
               
                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len,
                                                  NULL, brigade->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(new_brigade, tmp_heap);
                ctx->stream.avail_out = ctx->bufferSize;
            }
            zRC = inflate(&ctx->stream, Z_NO_FLUSH);

            if (zRC == Z_STREAM_END) {
                break;
            }
            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }
        }

        if (zRC == Z_STREAM_END) {
            apr_bucket *tmp_heap;

            len = ctx->bufferSize - ctx->stream.avail_out;
            ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
            tmp_heap = apr_bucket_heap_create(ctx->buffer, len, NULL,
                                              brigade->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(new_brigade, tmp_heap);
            ctx->stream.avail_out = ctx->bufferSize;

            /* Are the remaining 8 bytes already in the avail stream? */
            if (ctx->stream.avail_in >= 8) {
                /* Do the checksum computation. */
                unsigned long compCRC, compLen;
                compCRC = getLong(ctx->stream.next_in);
                if (ctx->crc != compCRC) {
                    return APR_EGENERAL;
                }
                ctx->stream.next_in += 4;
                compLen = getLong(ctx->stream.next_in);
                if (ctx->stream.total_out != compLen) {
                    return APR_EGENERAL;
                }
            }
            else {
                /* FIXME: We need to grab the 8 verification bytes
                 * from the wire! */
                return APR_EGENERAL;
            }
            inflateEnd(&ctx->stream);

            apr_bucket_delete(bucket);

            APR_BRIGADE_PREPEND(brigade, new_brigade);
            break;
        }

        apr_bucket_delete(bucket);

    }

    return APR_SUCCESS;
}

