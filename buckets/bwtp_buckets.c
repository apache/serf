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

#include <apr_pools.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_bucket_types.h"

#include <stdlib.h>

/* This is an implementation of Bidirectional Web Transfer Protocol (BWTP)
 * See:
 *   http://bwtp.wikidot.com/
 */

typedef struct {
    int channel;
    int open;
    const char *type;
    const char *uri;
    serf_bucket_t *headers;

    char req_line[1000];
} bwtp_frame_context_t;

SERF_DECLARE(serf_bucket_t *) serf_bucket_bwtp_frame_create(
    serf_bucket_t *bkt,
    serf_bucket_alloc_t *allocator)
{
    /* TODO do magic of peek'ing for BWH or BWM */
    abort();
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_bwtp_channel_close(
    int channel,
    serf_bucket_alloc_t *allocator)
{
    bwtp_frame_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->type = "BWH";
    ctx->open = 0;
    ctx->channel = channel;
    ctx->uri = "CLOSED";
    ctx->headers = serf_bucket_headers_create(allocator);

    return serf_bucket_create(&serf_bucket_type_bwtp_frame, allocator, ctx);
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_bwtp_channel_open(
    int channel,
    const char *uri,
    serf_bucket_alloc_t *allocator)
{
    bwtp_frame_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->type = "BWH";
    ctx->open = 1;
    ctx->channel = channel;
    ctx->uri = uri;
    ctx->headers = serf_bucket_headers_create(allocator);

    return serf_bucket_create(&serf_bucket_type_bwtp_frame, allocator, ctx);
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_bwtp_header_create(
    int channel,
    const char *phrase,
    serf_bucket_alloc_t *allocator)
{
    bwtp_frame_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->type = "BWH";
    ctx->open = 0;
    ctx->channel = channel;
    ctx->uri = phrase;
    ctx->headers = serf_bucket_headers_create(allocator);

    return serf_bucket_create(&serf_bucket_type_bwtp_frame, allocator, ctx);
}

SERF_DECLARE(serf_bucket_t *) serf_bucket_bwtp_frame_get_headers(
    serf_bucket_t *bucket)
{
    bwtp_frame_context_t *ctx = bucket->data;

    return ctx->headers;
}

static int count_size(void *baton, const char *key, const char *value)
{
    apr_size_t *c = baton;
    /* TODO Deal with folding.  Yikes. */

    /* Add in ": " and CRLF - so an extra four bytes. */
    *c += strlen(key) + strlen(value) + 4;

    return 0;
}

static apr_size_t calc_header_size(serf_bucket_t *hdrs)
{
    apr_size_t size = 0;

    serf_bucket_headers_do(hdrs, count_size, &size);

    return size;
}

static void serialize_data(serf_bucket_t *bucket)
{
    bwtp_frame_context_t *ctx = bucket->data;
    serf_bucket_t *new_bucket;
    apr_size_t req_len;

    /* Serialize the request-line and headers into one mother string,
     * and wrap a bucket around it.
     */
    req_len = apr_snprintf(ctx->req_line, sizeof(ctx->req_line),
                           "%s %d " "%" APR_UINT64_T_HEX_FMT " %s%s\r\n",
                           ctx->type,
                           ctx->channel, calc_header_size(ctx->headers),
                           (ctx->open ? "OPEN " : ""),
                           ctx->uri);
    new_bucket = serf_bucket_simple_copy_create(ctx->req_line, req_len,
                                                bucket->allocator);

    /* Build up the new bucket structure.
     *
     * Note that self needs to become an aggregate bucket so that a
     * pointer to self still represents the "right" data.
     */
    serf_bucket_aggregate_become(bucket);

    /* Insert the two buckets. */
    serf_bucket_aggregate_append(bucket, new_bucket);
    serf_bucket_aggregate_append(bucket, ctx->headers);

    /* Our private context is no longer needed, and is not referred to by
     * any existing bucket. Toss it.
     */
    serf_bucket_mem_free(bucket->allocator, ctx);
}

static apr_status_t serf_bwtp_frame_read(serf_bucket_t *bucket,
                                         apr_size_t requested,
                                         const char **data, apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the read. */
    return serf_bucket_read(bucket, requested, data, len);
}

static apr_status_t serf_bwtp_frame_readline(serf_bucket_t *bucket,
                                             int acceptable, int *found,
                                             const char **data, apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the readline. */
    return serf_bucket_readline(bucket, acceptable, found, data, len);
}

static apr_status_t serf_bwtp_frame_read_iovec(serf_bucket_t *bucket,
                                               apr_size_t requested,
                                               int vecs_size,
                                               struct iovec *vecs,
                                               int *vecs_used)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the read. */
    return serf_bucket_read_iovec(bucket, requested,
                                  vecs_size, vecs, vecs_used);
}

static apr_status_t serf_bwtp_frame_peek(serf_bucket_t *bucket,
                                         const char **data,
                                         apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the peek. */
    return serf_bucket_peek(bucket, data, len);
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_bwtp_frame = {
    "BWTP-FRAME",
    serf_bwtp_frame_read,
    serf_bwtp_frame_readline,
    serf_bwtp_frame_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_bwtp_frame_peek,
    serf_default_destroy_and_data,
    serf_default_snapshot,
    serf_default_restore_snapshot,
    serf_default_is_snapshot_set,
};

