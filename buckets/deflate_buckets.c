/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <apr_strings.h>

#include <zlib.h>

/* This conditional isn't defined anywhere yet. */
#ifdef HAVE_ZUTIL_H
#include <zutil.h>
#endif

#include "serf.h"
#include "serf_bucket_util.h"

/* magic header */
static char deflate_magic[2] = { '\037', '\213' };
#define DEFLATE_MAGIC_SIZE 10
#define DEFLATE_VERIFY_SIZE 8
#define DEFLATE_BUFFER_SIZE 8096

static const int DEFLATE_WINDOW_SIZE = -15;
static const int DEFLATE_MEMLEVEL = 9; 

typedef struct {
    serf_bucket_t *stream;
    serf_bucket_t *inflate_stream;

    enum {
        STATE_READING_HEADER,   /* reading the deflate header */
        STATE_HEADER,           /* read the deflate header */
        STATE_INFLATE,          /* inflating the content now */
        STATE_READING_VERIFY,   /* reading the final CRC */
        STATE_VERIFY,           /* verifying the final CRC */
        STATE_DONE,             /* body is done; we've returned EOF */
    } state;

    z_stream zstream;
    char hdr_buffer[DEFLATE_MAGIC_SIZE];
    unsigned char buffer[DEFLATE_BUFFER_SIZE];
    unsigned long crc;
    int windowSize;
    int memLevel;
    int bufferSize;

    /* How much of the chunk, or the terminator, do we have left to read? */
    apr_int64_t stream_left;

    /* How much are we supposed to read? */
    apr_int64_t stream_size;

} deflate_context_t;

/* Inputs a string and returns a long.  */
static unsigned long getLong(unsigned char *string)
{
    return ((unsigned long)string[0])
          | (((unsigned long)string[1]) << 8)
          | (((unsigned long)string[2]) << 16)
          | (((unsigned long)string[3]) << 24);
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_deflate_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator)
{
    deflate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->inflate_stream = serf_bucket_aggregate_create(allocator);
    ctx->state = STATE_READING_HEADER;

    /* Initial size of ZLIB header. */
    ctx->stream_left = ctx->stream_size = DEFLATE_MAGIC_SIZE;

    ctx->windowSize = DEFLATE_WINDOW_SIZE;
    ctx->memLevel = DEFLATE_MEMLEVEL;
    ctx->bufferSize = DEFLATE_BUFFER_SIZE;

    return serf_bucket_create(&serf_bucket_type_deflate, allocator, ctx);
}

static void serf_deflate_destroy_and_data(serf_bucket_t *bucket)
{
    deflate_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->inflate_stream);

    serf_default_destroy_and_data(bucket);
}

static apr_status_t serf_deflate_read(serf_bucket_t *bucket,
                                      apr_size_t requested,
                                      const char **data, apr_size_t *len)
{
    deflate_context_t *ctx = bucket->data;
    unsigned long compCRC, compLen;
    apr_status_t status;
    int zRC;

    while (1) {
        switch (ctx->state) {
        case STATE_READING_HEADER:
        case STATE_READING_VERIFY:
            status = serf_bucket_read(ctx->stream, ctx->stream_left,
                                      data, len);

            if (SERF_BUCKET_READ_ERROR(status)) {
                return status;
            }

            memcpy(ctx->hdr_buffer + (ctx->stream_size - ctx->stream_left),
                   data, *len);

            ctx->stream_left -= *len;
            /* Don't let our caller think we read anything. */
            *len = 0;

            if (ctx->stream_left == 0) {
                ctx->state++;
            }
            if (status) {
                return status;
            }
            break;
        case STATE_HEADER:
            if (ctx->hdr_buffer[0] != deflate_magic[0] ||
                ctx->hdr_buffer[1] != deflate_magic[1]) {
                return APR_EGENERAL;
            }
            if (ctx->hdr_buffer[3] != 0) {
                return APR_EGENERAL;
            }
            zRC = inflateInit2(&ctx->zstream, ctx->windowSize);
            if (zRC != Z_OK) {
                return APR_EGENERAL;
            }
            ctx->zstream.next_out = ctx->buffer;
            ctx->zstream.avail_out = ctx->bufferSize;
            ctx->state++;
            break;
        case STATE_VERIFY:
            /* Do the checksum computation. */
            compCRC = getLong(ctx->zstream.next_in);
            if (ctx->crc != compCRC) {
                return APR_EGENERAL;
            }
            ctx->zstream.next_in += 4;
            compLen = getLong(ctx->zstream.next_in);
            if (ctx->zstream.total_out != compLen) {
                return APR_EGENERAL;
            }

            inflateEnd(&ctx->zstream);
            ctx->state++;
            break;
        case STATE_INFLATE:
            /* FIXME: We need to try inflate_stream first. */
            status = serf_bucket_read(ctx->stream, ctx->bufferSize, data, len);

            if (SERF_BUCKET_READ_ERROR(status)) {
                return status;
            }

            ctx->zstream.next_in = (unsigned char*)*data;
            ctx->zstream.avail_in = *len;
            zRC = Z_OK;
            while (ctx->zstream.avail_in != 0) {
                /* We're full, clear out our buffer, reset, and return. */
                if (ctx->zstream.avail_out == 0) {
                    serf_bucket_t *tmp;
                    ctx->zstream.next_out = ctx->buffer;
                    *len = ctx->bufferSize - ctx->zstream.avail_out;

                    ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer,
                                     *len);

                    /* FIXME: There probably needs to be a free func. */
                    tmp = SERF_BUCKET_SIMPLE_STRING_LEN((char *)ctx->buffer,
                                                        *len,
                                                        bucket->allocator);

                    serf_bucket_aggregate_append(ctx->inflate_stream, tmp);
                    ctx->zstream.avail_out = ctx->bufferSize;
                    break;
                }
                zRC = inflate(&ctx->zstream, Z_NO_FLUSH);

                if (zRC == Z_STREAM_END) {
                    serf_bucket_t *tmp;

                    *len = ctx->bufferSize - ctx->zstream.avail_out;
                    ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer,
                                     *len);
                    /* FIXME: There probably needs to be a free func. */
                    tmp = SERF_BUCKET_SIMPLE_STRING_LEN((char *)ctx->buffer,
                                                        *len,
                                                        bucket->allocator);
                    serf_bucket_aggregate_append(ctx->inflate_stream, tmp);

                    ctx->zstream.avail_out = ctx->bufferSize;
                    ctx->state++;
                    ctx->stream_left = ctx->stream_size = DEFLATE_VERIFY_SIZE;
                    break;
                }
                if (zRC != Z_OK) {
                    return APR_EGENERAL;
                }
            }
            /* Okay, we've inflated.  Try to read. */
            status = serf_bucket_read(ctx->inflate_stream, requested, data,
                                      len);
            if (SERF_BUCKET_READ_ERROR(status)) {
                return status;
            }

            if (zRC == Z_STREAM_END && !status) {
                continue;
            }
            return status;
        case STATE_DONE:
            return APR_EOF;
        default:
            abort();
        }
    }

    return APR_SUCCESS;
}

/* ### need to implement */
#define serf_deflate_readline NULL
#define serf_deflate_read_iovec NULL
#define serf_deflate_read_for_sendfile NULL
#define serf_deflate_peek NULL

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_deflate = {
    "DEFLATE",
    serf_deflate_read,
    serf_deflate_readline,
    serf_deflate_read_iovec,
    serf_deflate_read_for_sendfile,
    serf_default_read_bucket,
    serf_deflate_peek,
    serf_deflate_destroy_and_data,
};

