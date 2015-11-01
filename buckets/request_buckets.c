/* ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

#include <apr_pools.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"


typedef struct request_context_t {
    const char *method;
    const char *uri;
    serf_bucket_t *headers;
    serf_bucket_t *body;
    apr_int64_t len;
    serf_config_t *config;
} request_context_t;

#define LENGTH_UNKNOWN ((apr_int64_t)-1)


serf_bucket_t *serf_bucket_request_create(
    const char *method,
    const char *URI,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator)
{
    request_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->method = method;
    ctx->uri = URI;
    ctx->headers = serf_bucket_headers_create(allocator);
    ctx->body = body;
    ctx->len = LENGTH_UNKNOWN;
    ctx->config = NULL;

    return serf_bucket_create(&serf_bucket_type_request, allocator, ctx);
}

void serf_bucket_request_set_CL(
    serf_bucket_t *bucket,
    apr_int64_t len)
{
    request_context_t *ctx = (request_context_t *)bucket->data;

    ctx->len = len;
}

serf_bucket_t *serf_bucket_request_get_headers(
    serf_bucket_t *bucket)
{
    return ((request_context_t *)bucket->data)->headers;
}

void serf__bucket_request_read(serf_bucket_t *request_bucket,
                               serf_bucket_t **body_bkt,
                               const char **uri,
                               const char **method)
{
    request_context_t *ctx = request_bucket->data;

    if (body_bkt)
        *body_bkt = ctx->body;
    if (uri)
        *uri = ctx->uri;
    if (method)
        *method = ctx->method;
}


void serf_bucket_request_set_root(
    serf_bucket_t *bucket,
    const char *root_url)
{
    request_context_t *ctx = (request_context_t *)bucket->data;

    /* If uri is already absolute, don't change it. */
    if (ctx->uri[0] != '/')
        return;

    /* If uri is '/' replace it with root_url. */
    if (ctx->uri[1] == '\0')
        ctx->uri = root_url;
    else
        ctx->uri =
            apr_pstrcat(serf_bucket_allocator_get_pool(bucket->allocator),
                        root_url,
                        ctx->uri,
                        NULL);
}

static void serialize_data(serf_bucket_t *bucket)
{
    request_context_t *ctx = bucket->data;
    serf_bucket_t *new_bucket;
    struct iovec iov[4];

    /* Create a bucket for the request-line. */
    iov[0].iov_base = (char*)ctx->method;
    iov[0].iov_len = strlen(ctx->method);
    iov[1].iov_base = " ";
    iov[1].iov_len = sizeof(" ") - 1;
    iov[2].iov_base = (char*)ctx->uri;
    iov[2].iov_len = strlen(ctx->uri);
    iov[3].iov_base = " HTTP/1.1\r\n";
    iov[3].iov_len = sizeof(" HTTP/1.1\r\n") - 1;

    new_bucket = serf_bucket_iovec_create(iov, 4, bucket->allocator);

    /* Build up the new bucket structure with the request-line and the headers.
     *
     * Note that self needs to become an aggregate bucket so that a
     * pointer to self still represents the "right" data.
     */
    serf_bucket_aggregate_become(bucket);
    serf_bucket_set_config(bucket, ctx->config);

    /* Insert the two buckets. */
    serf_bucket_aggregate_append(bucket, new_bucket);
    serf_bucket_aggregate_append(bucket, ctx->headers);

    /* If we know the length, then use C-L and the raw body. Otherwise,
       use chunked encoding for the request.  */
    if (ctx->len != LENGTH_UNKNOWN) {
        char buf[30];
        sprintf(buf, "%" APR_INT64_T_FMT, ctx->len);
        serf_bucket_headers_set(ctx->headers, "Content-Length", buf);
        if (ctx->body != NULL)
            serf_bucket_aggregate_append(bucket, ctx->body);
    }
    else if (ctx->body != NULL) {
        /* Morph the body bucket to a chunked encoding bucket for now. */
        serf_bucket_headers_setn(ctx->headers, "Transfer-Encoding", "chunked");
        ctx->body = serf_bucket_chunk_create(ctx->body, bucket->allocator);
        serf_bucket_aggregate_append(bucket, ctx->body);
    }

    /* Our private context is no longer needed, and is not referred to by
     * any existing bucket. Toss it.
     */
    serf_bucket_mem_free(bucket->allocator, ctx);
}

static apr_status_t serf_request_read(serf_bucket_t *bucket,
                                      apr_size_t requested,
                                      const char **data, apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the read. */
    return serf_bucket_read(bucket, requested, data, len);
}

static apr_status_t serf_request_readline(serf_bucket_t *bucket,
                                          int acceptable, int *found,
                                          const char **data, apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the readline. */
    return serf_bucket_readline(bucket, acceptable, found, data, len);
}

static apr_status_t serf_request_read_iovec(serf_bucket_t *bucket,
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

static serf_bucket_t * serf_request_read_bucket(serf_bucket_t *bucket,
                                                const serf_bucket_type_t *type)
{
    /* Luckily we don't have to be affraid for bucket_v2 tests here */
    serialize_data(bucket);

    return serf_bucket_read_bucket(bucket, type);
}

static apr_status_t serf_request_peek(serf_bucket_t *bucket,
                                      const char **data,
                                      apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the peek. */
    return serf_bucket_peek(bucket, data, len);
}

/* Note that this function is only called when serialize_data()
   hasn't been called on the bucket */
static void serf_request_destroy(serf_bucket_t *bucket)
{
    request_context_t *ctx = bucket->data;

    serf_bucket_destroy(ctx->headers);

    if (ctx->body) {
        serf_bucket_destroy(ctx->body);
    }

    serf_default_destroy_and_data(bucket);
}

void serf_bucket_request_become(
    serf_bucket_t *bucket,
    const char *method,
    const char *uri,
    serf_bucket_t *body)
{
    request_context_t *ctx;

    ctx = serf_bucket_mem_alloc(bucket->allocator, sizeof(*ctx));
    ctx->method = method;
    ctx->uri = uri;
    ctx->headers = serf_bucket_headers_create(bucket->allocator);
    ctx->body = body;

    bucket->type = &serf_bucket_type_request;
    bucket->data = ctx;

    /* The allocator remains the same. */
}

static apr_status_t serf_request_set_config(serf_bucket_t *bucket,
                                            serf_config_t *config)
{
    request_context_t *ctx = bucket->data;

    ctx->config = config;

    return serf_bucket_set_config(ctx->headers, config);
}

const serf_bucket_type_t serf_bucket_type_request = {
    "REQUEST",
    serf_request_read,
    serf_request_readline,
    serf_request_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_request_peek,
    serf_request_destroy,
    serf_request_read_bucket,
    serf_default_get_remaining,
    serf_request_set_config,
};

