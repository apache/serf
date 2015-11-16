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
#include <apr_date.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

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
    return bucket->type->read(bucket, requested, data, len);
}

static apr_status_t serf_request_readline(serf_bucket_t *bucket,
                                          int acceptable, int *found,
                                          const char **data, apr_size_t *len)
{
    /* Seralize our private data into a new aggregate bucket. */
    serialize_data(bucket);

    /* Delegate to the "new" aggregate bucket to do the readline. */
    return bucket->type->readline(bucket, acceptable, found, data, len);
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
    return bucket->type->read_iovec(bucket, requested,
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

typedef enum incoming_rq_status_t
{
    STATE_INIT,
    STATE_HEADERS,
    STATE_PREBODY,
    STATE_BODY,
    STATE_TRAILERS,
    STATE_DONE
} incoming_rq_status_t;

typedef struct incoming_request_context_t {
    const char *method;
    const char *path_raw;
    int version;

    serf_bucket_t *stream;
    serf_bucket_t *headers;
    serf_bucket_t *body;

    incoming_rq_status_t state;
    bool expect_trailers;

    /* Buffer for accumulating a line from the response. */
    serf_linebuf_t linebuf;

} incoming_request_context_t;

serf_bucket_t *serf_bucket_incoming_request_create(
                      serf_bucket_t *stream,
                      serf_bucket_alloc_t *allocator)
{
    incoming_request_context_t *ctx;

    ctx = serf_bucket_mem_calloc(allocator, sizeof(*ctx));

    ctx->stream = stream;
    ctx->state = STATE_INIT;
    ctx->headers = serf_bucket_headers_create(allocator);
    serf_linebuf_init(&ctx->linebuf);

    return serf_bucket_create(&serf_bucket_type_incoming_request,
                              allocator, ctx);
}

static apr_status_t serf_incoming_rq_parse_rqline(serf_bucket_t *bucket)
{
    incoming_request_context_t *ctx = bucket->data;
    const char *spc, *spc2;
    int res;

    if (ctx->linebuf.used == 0) {
        return SERF_ERROR_TRUNCATED_STREAM;
    }

    /* ### This may need some security review if this is used in production
            code */
    spc = memchr(ctx->linebuf.line, ' ', ctx->linebuf.used);

    if (spc)
        ctx->method = serf_bstrmemdup(bucket->allocator, ctx->linebuf.line,
                                      spc - ctx->linebuf.line);
    else
        return SERF_ERROR_TRUNCATED_STREAM;

    spc2 = memchr(spc + 1, ' ', ctx->linebuf.used - (ctx->linebuf.line - spc)
                                - 1);

    if (spc2)
        ctx->path_raw = serf_bstrmemdup(bucket->allocator, spc + 1,
                                        (spc2 - spc-1));
    else
        return SERF_ERROR_TRUNCATED_STREAM;

    spc2++;
    /* spc2 should now be of form 'HTTP/1.1'
       NOTE: Since r1699995 linebuf.line is always NUL terminated string. */
    res = apr_date_checkmask(spc2, "HTTP/#.#");
    if (!res) {
        /* Not an HTTP response?  Well, at least we won't understand it. */
        return SERF_ERROR_TRUNCATED_STREAM;
    }

    ctx->version = SERF_HTTP_VERSION(spc2[5] - '0',
                                     spc2[7] - '0');
    ctx->state++;

    return APR_SUCCESS;
}

static apr_status_t serf_incoming_rq_parse_headerline(serf_bucket_t *bucket)
{
    incoming_request_context_t *ctx = bucket->data;
    const char *split;

    if (ctx->linebuf.used == 0) {
        ctx->state++;
        return APR_SUCCESS;
    }

    split = memchr(ctx->linebuf.line, ':', ctx->linebuf.used);

    serf_bucket_headers_setx(ctx->headers,
                             ctx->linebuf.line, (split - ctx->linebuf.line),
                             TRUE /* copy */,
                             split + 2,
                             ctx->linebuf.used - (split - ctx->linebuf.line) - 2,
                             TRUE /* copy */);

    return APR_SUCCESS;
}

static apr_status_t serf_incoming_rq_wait_for(serf_bucket_t *bucket,
                                              incoming_rq_status_t wait_for)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    if (ctx->state == STATE_TRAILERS && wait_for == STATE_BODY) {
        /* We are done with the body, but not with the request.
           Can't return EOF yet */
        wait_for = STATE_DONE;
    }

    while (ctx->state < wait_for) {
        switch (ctx->state) {
            case STATE_INIT:
                status = serf_linebuf_fetch(&ctx->linebuf, ctx->stream,
                                            SERF_NEWLINE_ANY);
                if (status)
                    return status;

                status = serf_incoming_rq_parse_rqline(bucket);
                if (status)
                    return status;
                break;
            case STATE_HEADERS:
            case STATE_TRAILERS:
                status = serf_linebuf_fetch(&ctx->linebuf, ctx->stream,
                                            SERF_NEWLINE_ANY);
                if (status)
                    return status;

                status = serf_incoming_rq_parse_headerline(bucket);
                if (status)
                    return status;
                break;
            case STATE_PREBODY:
                /* TODO: Determine the body type.. Wrap bucket if necessary,
                         etc.*/

                /* What kind of body do we expect */
                {
                    const char *te;

                    ctx->body = ctx->stream;
                    te = serf_bucket_headers_get(ctx->headers, "Transfer-Encoding");

                    if (te && strcasecmp(te, "chunked") == 0) {
                        ctx->body = serf_bucket_dechunk_create(ctx->stream,
                                                               bucket->allocator);
                        ctx->expect_trailers = true;
                    }
                    else {
                        const char *cl;

                        cl = serf_bucket_headers_get(ctx->headers, "Content-Length");

                        if (cl) {
                            apr_uint64_t length;
                            length = apr_strtoi64(cl, NULL, 10);
                            if (errno == ERANGE) {
                                return APR_FROM_OS_ERROR(ERANGE);
                            }
                            ctx->body = serf_bucket_response_body_create(
                                          ctx->body, length, bucket->allocator);
                        }
                    }
                    ctx->state++;
                }
                break;
            case STATE_DONE:
                break;
            default:
                return APR_EGENERAL; /* Should never happen */
        }
    }

    return (ctx->state == STATE_DONE) ? APR_EOF : APR_SUCCESS;
}

static apr_status_t serf_incoming_rq_read(serf_bucket_t *bucket,
                                          apr_size_t requested,
                                          const char **data,
                                          apr_size_t *len)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_incoming_rq_wait_for(bucket, STATE_BODY);
    if (status || !ctx->body) {
        *len = 0;
        return status ? status : APR_EOF;
    }

    status = serf_bucket_read(ctx->body, requested, data, len);
    if (APR_STATUS_IS_EOF(status) && ctx->expect_trailers) {
        ctx->state = STATE_TRAILERS;
        status = APR_SUCCESS;
    }
    return status;
}

static apr_status_t serf_incoming_rq_readline(serf_bucket_t *bucket, int acceptable,
                                              int *found,
                                              const char **data, apr_size_t *len)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_incoming_rq_wait_for(bucket, STATE_BODY);
    if (status || !ctx->body) {
        *found = 0;
        *len = 0;
        return status ? status : APR_EOF;
    }

    status = serf_bucket_readline(ctx->body, acceptable, found, data, len);
    if (APR_STATUS_IS_EOF(status) && ctx->expect_trailers) {
        ctx->state = STATE_TRAILERS;
        status = APR_SUCCESS;
    }
    return status;
}

static apr_status_t serf_incoming_rq_read_iovec(serf_bucket_t *bucket,
                                                apr_size_t requested,
                                                int vecs_size,
                                                struct iovec *vecs,
                                                int *vecs_used)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_incoming_rq_wait_for(bucket, STATE_BODY);
    if (status || !ctx->body) {
        *vecs_used = 0;
        return status ? status : APR_EOF;
    }

    status = serf_bucket_read_iovec(ctx->body, requested, vecs_size,
                                    vecs, vecs_used);
    if (APR_STATUS_IS_EOF(status) && ctx->expect_trailers) {
        ctx->state = STATE_TRAILERS;
        status = APR_SUCCESS;
    }
    return status;
}

static apr_status_t serf_incoming_rq_peek(serf_bucket_t *bucket,
                                          const char **data,
                                          apr_size_t *len)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_incoming_rq_wait_for(bucket, STATE_BODY);
    if (status || !ctx->body) {
        *len = 0;

        if (SERF_BUCKET_READ_ERROR(status))
            return status;
        else if (APR_STATUS_IS_EOF(status))
            return SERF_ERROR_TRUNCATED_STREAM;

        return status ? APR_SUCCESS : APR_EOF;
    }

    status = serf_bucket_peek(ctx->body, data, len);
    if (APR_STATUS_IS_EOF(status) && ctx->expect_trailers) {
        ctx->state = STATE_TRAILERS;
        status = APR_SUCCESS;
    }
    return status;
}

static void serf_incoming_rq_destroy(serf_bucket_t *bucket)
{
    incoming_request_context_t *ctx = bucket->data;

    if (ctx->method)
        serf_bucket_mem_free(bucket->allocator, (void*)ctx->method);
    if (ctx->path_raw)
        serf_bucket_mem_free(bucket->allocator, (void*)ctx->path_raw);
    if (ctx->headers)
        serf_bucket_destroy(ctx->headers);
    if (ctx->body)
        serf_bucket_destroy(ctx->body);
    else if (ctx->stream)
      serf_bucket_destroy(ctx->stream);

    serf_default_destroy_and_data(bucket);
}

apr_status_t serf_bucket_incoming_request_read(
                  serf_bucket_t **headers,
                  const char **method,
                  const char **path,
                  int *http_version,
                  serf_bucket_t *bucket)
{
    incoming_request_context_t *ctx = bucket->data;
    apr_status_t status;

    status = serf_incoming_rq_wait_for(bucket, STATE_BODY);
    if (status) {
        if (headers)
            *headers = NULL;
        if (method)
            *method = NULL;
        if (path)
            *path = NULL;
        if (http_version)
            *http_version = 0;

        return status;
    }

    if (headers)
        *headers = ctx->headers;
    if (method)
        *method = ctx->method;
    if (path)
        *path = ctx->path_raw;
    if (http_version)
        *http_version = ctx->version;

    return APR_SUCCESS;
}

apr_status_t serf_bucket_incoming_request_wait_for_headers(
                  serf_bucket_t *bucket)
{
    return serf_incoming_rq_wait_for(bucket, STATE_BODY);
}


const serf_bucket_type_t serf_bucket_type_incoming_request = {
    "INCOMING-REQUEST",
    serf_incoming_rq_read,
    serf_incoming_rq_readline,
    serf_incoming_rq_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_incoming_rq_peek,
    serf_incoming_rq_destroy,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_default_ignore_config
};
