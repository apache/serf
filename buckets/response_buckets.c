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

#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_date.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

typedef struct response_context_t {
    serf_bucket_t *stream;
    serf_bucket_t *body;        /* Pointer to the stream wrapping the body. */
    serf_bucket_t *incoming_headers;     /* holds parsed headers */
    serf_bucket_t *fetch_headers;        /* the current set of headers */

    enum {
        STATE_STATUS_LINE,      /* reading status line */
        STATE_NEXT_STATUS_LINE,
        STATE_PRE_HEADERS,
        STATE_HEADERS,          /* reading headers */
        STATE_PRE_BODY,
        STATE_BODY,             /* reading body */
        STATE_TRAILERS,         /* reading trailers */
        STATE_DONE              /* we've sent EOF */
    } state;

    serf_status_line sl;

    int chunked;                /* Do we need to read trailers? */
    int head_req;               /* Was this a HEAD request? */
    int decode_content;         /* Do we want to decode 'Content-Encoding' */

    serf_config_t *config;

    /* Buffer for accumulating a line from the response. */
    serf_linebuf_t linebuf;

    /* Error status that will be returned instead of APR_EOF when the response
       body was read completely. */
    apr_status_t error_on_eof;

} response_context_t;

/* Returns 1 if according to RFC2626 this response can have a body, 0 if it
   must not have a body. */
static int expect_body(response_context_t *ctx)
{
    if (ctx->head_req)
        return 0;

    /* 204 No Content */
    if (ctx->sl.code == 204)
        return 0;

    /* 205? */

    /* 304 Not Modified */
    if (ctx->sl.code == 304)
        return 0;

    return 1;
}

serf_bucket_t *serf_bucket_response_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator)
{
    response_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->body = NULL;
    ctx->incoming_headers = NULL;
    ctx->fetch_headers = NULL;
    ctx->state = STATE_STATUS_LINE;
    ctx->chunked = 0;
    ctx->head_req = 0;
    ctx->decode_content = TRUE;
    ctx->error_on_eof = 0;
    ctx->config = NULL;
    ctx->sl.reason = NULL;

    serf_linebuf_init(&ctx->linebuf);

    return serf_bucket_create(&serf_bucket_type_response, allocator, ctx);
}

void serf_bucket_response_set_head(
    serf_bucket_t *bucket)
{
    response_context_t *ctx = bucket->data;

    ctx->head_req = 1;
}

void serf_bucket_response_decode_content(serf_bucket_t *bucket,
                                         int decode)
{
    response_context_t *ctx = bucket->data;

    ctx->decode_content = decode;
}

serf_bucket_t *serf_bucket_response_get_headers(serf_bucket_t *bucket)
{
    response_context_t *ctx = bucket->data;

    if (!ctx->fetch_headers) {

        if (!ctx->incoming_headers) {
            ctx->incoming_headers = serf_bucket_headers_create(
                                                        bucket->allocator);
        }

        ctx->fetch_headers = ctx->incoming_headers;
    }

    return ctx->fetch_headers;
}


static void serf_response_destroy_and_data(serf_bucket_t *bucket)
{
    response_context_t *ctx = bucket->data;

    if (ctx->sl.reason) {
        serf_bucket_mem_free(bucket->allocator, (void*)ctx->sl.reason);
    }

    serf_bucket_destroy(ctx->stream);
    if (ctx->body != NULL)
        serf_bucket_destroy(ctx->body);

    if (ctx->incoming_headers)
      serf_bucket_destroy(ctx->incoming_headers);
    if (ctx->fetch_headers && ctx->fetch_headers != ctx->incoming_headers)
      serf_bucket_destroy(ctx->fetch_headers);

    serf_default_destroy_and_data(bucket);
}

static apr_status_t fetch_line(response_context_t *ctx, int acceptable)
{
    return serf_linebuf_fetch(&ctx->linebuf, ctx->stream, acceptable);
}

static apr_status_t parse_status_line(response_context_t *ctx,
                                      serf_bucket_alloc_t *allocator)
{
    int res;
    char *reason; /* ### stupid APR interface makes this non-const */

    if (ctx->sl.reason) {
      serf_bucket_mem_free(allocator, (void*)ctx->sl.reason);
      ctx->sl.reason = NULL;
    }

    /* ctx->linebuf.line should be of form: 'HTTP/1.1 200 OK',
       but we also explicitly allow the forms 'HTTP/1.1 200' (no reason)
       and 'HTTP/1.1 401.1 Logon failed' (iis extended error codes)
       NOTE: Since r1699995 linebuf.line is always NUL terminated string. */
    res = apr_date_checkmask(ctx->linebuf.line, "HTTP/#.# ###*");
    if (!res) {
        /* Not an HTTP response?  Well, at least we won't understand it. */
        return SERF_ERROR_BAD_HTTP_RESPONSE;
    }

    ctx->sl.version = SERF_HTTP_VERSION(ctx->linebuf.line[5] - '0',
                                        ctx->linebuf.line[7] - '0');
    ctx->sl.code = apr_strtoi64(ctx->linebuf.line + 8, &reason, 10);
    if (errno == ERANGE || reason == ctx->linebuf.line + 8)
        return SERF_ERROR_BAD_HTTP_RESPONSE;

    /* Skip leading spaces for the reason string. */
    while (apr_isspace(*reason)) {
        reason++;
    }

    /* Copy the reason value out of the line buffer. */
    ctx->sl.reason = serf_bstrmemdup(allocator, reason,
                                     ctx->linebuf.used
                                     - (reason - ctx->linebuf.line));

    return APR_SUCCESS;
}

/* This code should be replaced with header buckets. */
static apr_status_t fetch_headers(serf_bucket_t *bkt, response_context_t *ctx)
{
    apr_status_t status;

    /* RFC 2616 says that CRLF is the only line ending, but we can easily
     * accept any kind of line ending.
     */
    status = fetch_line(ctx, SERF_NEWLINE_ANY);
    /* Convert generic 'line too long' error to specific one. */
    if (status == SERF_ERROR_LINE_TOO_LONG) {
        return SERF_ERROR_RESPONSE_HEADER_TOO_LONG;
    } else if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }
    /* Something was read. Process it. */

    if (ctx->linebuf.state == SERF_LINEBUF_READY && ctx->linebuf.used) {
        const char *end_key;
        const char *c;

        end_key = c = memchr(ctx->linebuf.line, ':', ctx->linebuf.used);
        if (!c) {
            /* Bad headers? */
            return SERF_ERROR_BAD_HTTP_RESPONSE;
        }

        /* Skip over initial ':' */
        c++;

        /* And skip all whitespaces. */
        for(; c < ctx->linebuf.line + ctx->linebuf.used; c++)
        {
            if (!apr_isspace(*c))
            {
              break;
            }
        }

        /* Always copy the headers (from the linebuf into new mem). */
        /* ### we should be able to optimize some mem copies */
        serf_bucket_headers_setx(
            ctx->incoming_headers,
            ctx->linebuf.line, end_key - ctx->linebuf.line, 1,
            c, ctx->linebuf.line + ctx->linebuf.used - c, 1);
    }

    return status;
}

/* Perform one iteration of the state machine.
 *
 * Will return when one the following conditions occurred:
 *  1) a state change
 *  2) an error
 *  3) the stream is not ready or at EOF
 *  4) APR_SUCCESS, meaning the machine can be run again immediately
 */
static apr_status_t run_machine(serf_bucket_t *bkt, response_context_t *ctx)
{
    apr_status_t status = APR_SUCCESS; /* initialize to avoid gcc warnings */

    switch (ctx->state) {
    case STATE_STATUS_LINE:
    case STATE_NEXT_STATUS_LINE:
        /* RFC 2616 says that CRLF is the only line ending, but we can easily
         * accept any kind of line ending.
         */
        status = fetch_line(ctx, SERF_NEWLINE_ANY);

        /* Convert generic 'line too long' error to specific one. */
        if (status == SERF_ERROR_LINE_TOO_LONG)
            return SERF_ERROR_STATUS_LINE_TOO_LONG;
        else if (SERF_BUCKET_READ_ERROR(status))
            return status;

        if (ctx->linebuf.state == SERF_LINEBUF_READY) {
            /* The Status-Line is in the line buffer. Process it. */
            status = parse_status_line(ctx, bkt->allocator);
            if (status)
                return status;

            /* Good times ahead: we're switching protocols! */
            if (ctx->sl.code == 101) {
                ctx->body =
                    serf_bucket_barrier_create(ctx->stream, bkt->allocator);
                ctx->state = STATE_DONE;
                break;
            }

            /* Okay... move on to reading the headers. */
            ctx->state = STATE_PRE_HEADERS;
        }
        else {
            /* The connection closed before we could get the next
             * response.  Treat the request as lost so that our upper
             * end knows the server never tried to give us a response.
             */
            if (APR_STATUS_IS_EOF(status)) {
                return SERF_ERROR_REQUEST_LOST;
            }
        }
        break;
    case STATE_PRE_HEADERS:
        {
            serf_bucket_t *read_hdrs;

            ctx->state = STATE_HEADERS;

            /* Perhaps we can just read a headers bucket? */
            read_hdrs = serf_bucket_read_bucket(ctx->stream,
                                                &serf_bucket_type_headers);

            if (read_hdrs) {
                if (ctx->incoming_headers)
                    serf_bucket_destroy(ctx->incoming_headers);

                ctx->incoming_headers = read_hdrs;

                ctx->state = STATE_PRE_BODY;
            }
            else if (!ctx->incoming_headers) {
                ctx->incoming_headers =
                    serf_bucket_headers_create(bkt->allocator);
            }

            if (!ctx->fetch_headers)
                ctx->fetch_headers = ctx->incoming_headers;
        }
        break;

    case STATE_HEADERS:
        status = fetch_headers(bkt, ctx);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* If an empty line was read, then we hit the end of the headers.
         * Move on to the body.
         */
        if (ctx->linebuf.state != SERF_LINEBUF_READY || ctx->linebuf.used)
            break;

        /* Advance the state. */
        ctx->state = STATE_PRE_BODY;
        /* fall through */

    case STATE_PRE_BODY:
        {
            const char *v;
            int chunked = 0;
            int gzip = 0;

            if (ctx->fetch_headers != ctx->incoming_headers) {
              /* We now only have one interesting set of headers remaining */
              serf_bucket_destroy(ctx->fetch_headers);
              ctx->fetch_headers = ctx->incoming_headers;
            }

            if (ctx->sl.code >= 100 && ctx->sl.code < 200) {
                /* We received a set of informational headers.

                   Prepare for the next set */
                ctx->incoming_headers = serf_bucket_headers_create(
                                            bkt->allocator);
                ctx->state = STATE_NEXT_STATUS_LINE;
                break;
            }
            /* Advance the state. */
            ctx->state = STATE_BODY;

            /* If this is a response to a HEAD request, or 204 or 304
               then we don't receive a real body. */
            if (!expect_body(ctx)) {
                ctx->body = serf_bucket_simple_create(NULL, 0, NULL, NULL,
                                                      bkt->allocator);
                ctx->state = STATE_BODY;
                break;
            }

            ctx->body =
                serf_bucket_barrier_create(ctx->stream, bkt->allocator);

            /* Are we chunked, C-L, or conn close? */
            v = serf_bucket_headers_get(ctx->fetch_headers,
                                        "Transfer-Encoding");

            /* Need a copy cuz we're going to write NUL characters into the
               string.  */
            if (v) {
                char *attrs = serf_bstrdup(bkt->allocator, v);
                char *at = attrs;
                char *next = NULL;

                while ((v = apr_strtok(at, ", ", &next))) {
                  at = NULL;

                  if (!strcasecmp(v, "chunked"))
                      chunked = 1;
                  else if (!strcasecmp(v, "gzip"))
                      gzip = 1;
                  /* ### Others? */
                }
                serf_bucket_mem_free(bkt->allocator, attrs);
            }

            if (chunked) {
                ctx->chunked = 1;
                ctx->body = serf_bucket_dechunk_create(ctx->body,
                                                       bkt->allocator);
                serf_bucket_set_config(ctx->body, ctx->config);
            }
            else {
                /* RFC 7231 specifies that we should determine the message
                   length via Transfer-Encoding chunked, when both chunked
                   and Content-Length are passed */

                v = serf_bucket_headers_get(ctx->fetch_headers,
                                            "Content-Length");
                if (v) {
                    apr_uint64_t length;
                    length = apr_strtoi64(v, NULL, 10);
                    if (errno == ERANGE) {
                        return APR_FROM_OS_ERROR(ERANGE);
                    }
                    ctx->body = serf_bucket_response_body_create(
                                  ctx->body, length, bkt->allocator);
                }
            }

            /* Transfer encodings are handled by the transport, while content
               encoding is part of the data itself. */
            if (gzip) {
                ctx->body =
                    serf_bucket_deflate_create(ctx->body, bkt->allocator,
                                               SERF_DEFLATE_GZIP);
                serf_bucket_set_config(ctx->body, ctx->config);
            }

            v = serf_bucket_headers_get(ctx->fetch_headers,
                                        "Content-Encoding");
            if (v && ctx->decode_content) {
                /* Need to handle multiple content-encoding. */
                if (v && strcasecmp("gzip", v) == 0) {
                    ctx->body =
                        serf_bucket_deflate_create(ctx->body, bkt->allocator,
                                                   SERF_DEFLATE_GZIP);
                    serf_bucket_set_config(ctx->body, ctx->config);
                }
                else if (v && strcasecmp("deflate", v) == 0) {
                    ctx->body =
                        serf_bucket_deflate_create(ctx->body, bkt->allocator,
                                                   SERF_DEFLATE_DEFLATE);
                    serf_bucket_set_config(ctx->body, ctx->config);
                }
            }
        }
        break;
    case STATE_BODY:
        /* Don't do anything. */
        break;
    case STATE_TRAILERS:
        status = fetch_headers(bkt, ctx);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /* If an empty line was read, then we're done. */
        if (ctx->linebuf.state == SERF_LINEBUF_READY && !ctx->linebuf.used) {
            ctx->state = STATE_DONE;
            return APR_EOF;
        }
        break;
    case STATE_DONE:
        return APR_EOF;
    default:
        /* Not reachable */
        return APR_EGENERAL;
    }

    return status;
}

static apr_status_t wait_for_body(serf_bucket_t *bkt, response_context_t *ctx)
{
    apr_status_t status;

    /* Keep reading and moving through states if we aren't at the BODY */
    while (ctx->state != STATE_BODY) {
        status = run_machine(bkt, ctx);

        /* Anything other than APR_SUCCESS means that we cannot immediately
         * read again (for now).
         */
        if (status)
            return status;
    }
    /* in STATE_BODY */

    return APR_SUCCESS;
}

apr_status_t serf_bucket_response_wait_for_headers(
    serf_bucket_t *bucket)
{
    response_context_t *ctx = bucket->data;

    return wait_for_body(bucket, ctx);
}

apr_status_t serf_bucket_response_wait_for_some_headers(
    serf_bucket_t *bucket,
     int wait_for_next)
{
    response_context_t *ctx = bucket->data;

    if (ctx->incoming_headers != ctx->fetch_headers) {
        /* We have a good set of informational
           headers */

        if (!wait_for_next)
          return APR_SUCCESS;

        /* We stop caring about a previous set, if there is one */
        serf_bucket_destroy(ctx->fetch_headers);
        ctx->fetch_headers = ctx->incoming_headers;

        /* And fixup the state if we just read this one to avoid
           theoretically returning success again */
        if (ctx->state == STATE_NEXT_STATUS_LINE)
            ctx->state = STATE_STATUS_LINE;
    }

    /* Keep reading and moving until we are in BODY or
       STATE_NEXT_STATUS_LINE */
    while (ctx->state != STATE_BODY
           && ctx->state != STATE_NEXT_STATUS_LINE) {

        apr_status_t status = run_machine(bucket, ctx);

        /* Anything other than APR_SUCCESS means that we cannot immediately
        * read again (for now).
        */
        if (status)
          return status;
    }

    /* in STATE_BODY or STATE_NEXT_STATUS_LINE */
    return APR_SUCCESS;
}

apr_status_t serf_bucket_response_status(
    serf_bucket_t *bkt,
    serf_status_line *sline)
{
    response_context_t *ctx = bkt->data;
    apr_status_t status;

    if (ctx->state != STATE_STATUS_LINE) {
        /* We already read it and moved on. Just return it. */
        *sline = ctx->sl;
        return APR_SUCCESS;
    }

    /* Running the state machine once will advance the machine, or state
     * that the stream isn't ready with enough data. There isn't ever a
     * need to run the machine more than once to try and satisfy this. We
     * have to look at the state to tell whether it advanced, though, as
     * it is quite possible to advance *and* to return APR_EAGAIN.
     */
    status = run_machine(bkt, ctx);
    if (ctx->state != STATE_STATUS_LINE) {
        *sline = ctx->sl;
    }
    else {
        /* Indicate that we don't have the information yet. */
        sline->version = 0;
    }

    return status;
}

static apr_status_t serf_response_read(serf_bucket_t *bucket,
                                       apr_size_t requested,
                                       const char **data, apr_size_t *len)
{
    response_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_body(bucket, ctx);
    if (status) {
        /* It's not possible to have read anything yet! */
        *len = 0;
        goto fake_eof;
    }

    status = serf_bucket_read(ctx->body, requested, data, len);
    if (SERF_BUCKET_READ_ERROR(status))
        return status;

    if (APR_STATUS_IS_EOF(status)) {
        if (ctx->chunked) {
            ctx->state = STATE_TRAILERS;
            /* Mask the result. */
            status = APR_SUCCESS;
        } else {
            ctx->state = STATE_DONE;
        }
    }

fake_eof:
    if (APR_STATUS_IS_EOF(status) && ctx->error_on_eof)
        return ctx->error_on_eof;

    return status;
}

static apr_status_t serf_response_readline(serf_bucket_t *bucket,
                                           int acceptable, int *found,
                                           const char **data, apr_size_t *len)
{
    response_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_body(bucket, ctx);
    if (status) {
        *len = 0;
        goto fake_eof;
    }

    /* Delegate to the stream bucket to do the readline. */
    status = serf_bucket_readline(ctx->body, acceptable, found, data, len);

    if (APR_STATUS_IS_EOF(status)) {
        if (ctx->chunked) {
            ctx->state = STATE_TRAILERS;
            /* Mask the result. */
            status = APR_SUCCESS;
        }
        else {
            ctx->state = STATE_DONE;
        }
    }

fake_eof:
    if (APR_STATUS_IS_EOF(status) && ctx->error_on_eof)
        return ctx->error_on_eof;

    return status;
}

static apr_status_t serf_response_read_iovec(serf_bucket_t *bucket,
                                             apr_size_t requested,
                                             int vecs_size,
                                             struct iovec *vecs,
                                             int *vecs_used)
{
    response_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_body(bucket, ctx);
    if (status) {
        *vecs_used = 0;
        goto fake_eof;
    }

    status = serf_bucket_read_iovec(ctx->body, requested, vecs_size,
                                    vecs, vecs_used);

    if (APR_STATUS_IS_EOF(status)) {
        if (ctx->chunked) {
            ctx->state = STATE_TRAILERS;
            /* Mask the result. */
            status = APR_SUCCESS;
        }
        else {
            ctx->state = STATE_DONE;
        }
    }

fake_eof:
    if (APR_STATUS_IS_EOF(status) && ctx->error_on_eof)
        return ctx->error_on_eof;

    return status;
}

static apr_status_t serf_response_peek(serf_bucket_t *bucket,
                                       const char **data,
                                       apr_size_t *len)
{
    response_context_t *ctx = bucket->data;
    apr_status_t status;

    status = wait_for_body(bucket, ctx);
    if (status) {
        *data = NULL;
        *len = 0;

        if (SERF_BUCKET_READ_ERROR(status))
            return status;
        else
            return APR_SUCCESS;
    }

    status = serf_bucket_peek(ctx->body, data, len);
    if (APR_STATUS_IS_EOF(status) && ctx->error_on_eof)
        return ctx->error_on_eof;

    return status;
}

apr_status_t serf_response_full_become_aggregate(serf_bucket_t *bucket)
{
    response_context_t *ctx = bucket->data;
    serf_bucket_t *bkt;
    char buf[256];
    int size;

    serf_bucket_aggregate_become(bucket);

    /* Add reconstructed status line. */
    size = apr_snprintf(buf, 256, "HTTP/%d.%d %d ",
                        SERF_HTTP_VERSION_MAJOR(ctx->sl.version),
                        SERF_HTTP_VERSION_MINOR(ctx->sl.version),
                        ctx->sl.code);
    bkt = serf_bucket_simple_copy_create(buf, size,
                                         bucket->allocator);
    serf_bucket_aggregate_append(bucket, bkt);
    bkt = serf_bucket_simple_copy_create(ctx->sl.reason, strlen(ctx->sl.reason),
                                         bucket->allocator);
    serf_bucket_aggregate_append(bucket, bkt);
    bkt = SERF_BUCKET_SIMPLE_STRING_LEN("\r\n", 2,
                                        bucket->allocator);
    serf_bucket_aggregate_append(bucket, bkt);

    /* Add headers and stream buckets in order. */
    serf_bucket_aggregate_append(bucket, ctx->fetch_headers);
    serf_bucket_aggregate_append(bucket, ctx->stream);

    if (ctx->body != NULL)
        serf_bucket_destroy(ctx->body);
    serf_bucket_mem_free(bucket->allocator, (void*)ctx->sl.reason);
    serf_bucket_mem_free(bucket->allocator, ctx);

    return APR_SUCCESS;
}

static apr_status_t serf_response_set_config(serf_bucket_t *bucket,
                                             serf_config_t *config)
{
    response_context_t *ctx = bucket->data;

    ctx->config = config;

    return serf_bucket_set_config(ctx->stream, config);
}

void serf__bucket_response_set_error_on_eof(serf_bucket_t *bucket,
                                            apr_status_t error)
{
    response_context_t *ctx = bucket->data;
    ctx->error_on_eof = error;
}

const serf_bucket_type_t serf_bucket_type_response = {
    "RESPONSE",
    serf_response_read,
    serf_response_readline,
    serf_response_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_response_peek,
    serf_response_destroy_and_data,
    serf_default_read_bucket,
    serf_default_get_remaining,
    serf_response_set_config,
};
