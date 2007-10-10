/* Copyright 2002-2007 Justin Erenkrantz and Greg Stein
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

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_version.h>

#include "serf.h"

#include "test_serf.h"

#define CRLF "\r\n"

typedef struct {
    serf_response_acceptor_t acceptor;
    void *acceptor_baton;

    serf_response_handler_t handler;

    apr_array_header_t *sent_requests;
    apr_array_header_t *accepted_requests;
    apr_array_header_t *handled_requests;
    int req_id;

    const char *method;
    const char *path;
    BOOL done;
} handler_baton_t;

static serf_bucket_t* accept_response(serf_request_t *request,
                                      serf_bucket_t *stream,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;
    handler_baton_t *ctx = acceptor_baton;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    APR_ARRAY_PUSH(ctx->accepted_requests, int) = ctx->req_id;

    return serf_bucket_response_create(c, bkt_alloc);
}

static apr_status_t handle_response(serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;

    while (1) {
        apr_status_t status;
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(response, 2048, &data, &len);
        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        if (APR_STATUS_IS_EOF(status)) {
            APR_ARRAY_PUSH(ctx->handled_requests, int) = ctx->req_id;
            ctx->done = TRUE;
            return APR_EOF;
        }

    }

    return APR_SUCCESS;
}

static apr_status_t setup_request(serf_request_t *request,
                                  void *setup_baton,
                                  serf_bucket_t **req_bkt,
                                  serf_response_acceptor_t *acceptor,
                                  void **acceptor_baton,
                                  serf_response_handler_t *handler,
                                  void **handler_baton,
                                  apr_pool_t *pool)
{
    handler_baton_t *ctx = setup_baton;
    serf_bucket_t *body_bkt;

    /* create a simple body text */
    const char *str = apr_psprintf(pool, "%d", ctx->req_id);
    body_bkt = serf_bucket_simple_create(str, strlen(str), NULL, NULL,
                                         serf_request_get_alloc(request));
    *req_bkt = serf_bucket_request_create(ctx->method, ctx->path, body_bkt,
                                      serf_request_get_alloc(request));

    APR_ARRAY_PUSH(ctx->sent_requests, int) = ctx->req_id;

    *acceptor = ctx->acceptor;
    *acceptor_baton = ctx;
    *handler = ctx->handler;
    *handler_baton = ctx;

    return APR_SUCCESS;
}


/* Validate that requests are sent and completed in the order of creation. */
void test_serf_connection_request_create(CuTest *tc)
{
    test_baton_t *tb;
    serf_request_t *request1, *request2;
    handler_baton_t handler_ctx, handler2_ctx;
    apr_status_t status;
    apr_pool_t *iter_pool;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    int i;
    test_server_action_t action_list[] = {
        {SERVER_RECV,
        "GET / HTTP/1.1" CRLF
        "Transfer-Encoding: chunked" CRLF
        CRLF
        "1" CRLF
        "1" CRLF
        "0" CRLF
        CRLF
        "GET / HTTP/1.1" CRLF
        "Transfer-Encoding: chunked" CRLF
        "" CRLF
        "1" CRLF
        "2" CRLF
        "0" CRLF
        CRLF
        },
        {SERVER_SEND,
        "HTTP/1.1 200 OK" CRLF
        "Transfer-Encoding: chunked" CRLF
        CRLF
        "0" CRLF
        CRLF
        "HTTP/1.1 200 OK" CRLF
        "Transfer-Encoding: chunked" CRLF
        CRLF
        "0" CRLF
        CRLF
        }
    };

    accepted_requests = apr_array_make(test_pool, 2, sizeof(int));
    sent_requests = apr_array_make(test_pool, 2, sizeof(int));
    handled_requests = apr_array_make(test_pool, 2, sizeof(int));

    /* Set up a test context with a server */
    status = test_server_create(&tb, action_list, 2, 0, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    handler_ctx.method = "GET";
    handler_ctx.path = "/";
    handler_ctx.done = FALSE;

    handler_ctx.acceptor = accept_response;
    handler_ctx.acceptor_baton = NULL;
    handler_ctx.handler = handle_response;
    handler_ctx.req_id = 1;
    handler_ctx.accepted_requests = accepted_requests;
    handler_ctx.sent_requests = sent_requests;
    handler_ctx.handled_requests = handled_requests;

    request1 = serf_connection_request_create(tb->connection,
                                              setup_request,
                                              &handler_ctx);

    handler2_ctx = handler_ctx;
    handler2_ctx.req_id = 2;

    request2 = serf_connection_request_create(tb->connection,
                                              setup_request,
                                              &handler2_ctx);

    apr_pool_create(&iter_pool, test_pool);

    while (!handler_ctx.done && !handler2_ctx.done)
    {
        apr_pool_clear(iter_pool);

        status = test_server_run(tb, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = serf_context_run(tb->context, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        /* Debugging purposes only! */
        serf_debug__closed_conn(tb->bkt_alloc);
    }
    apr_pool_destroy(iter_pool);

    /* Check that all requests were received */
    CuAssertIntEquals(tc, 2, sent_requests->nelts);
    CuAssertIntEquals(tc, 2, accepted_requests->nelts);
    CuAssertIntEquals(tc, 2, handled_requests->nelts);

    /* Check that the requests were sent in the order we created them */
    for (i = 0; i < sent_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(sent_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    /* Check that the requests were received in the order we created them */
    for (i = 0; i < handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    test_server_destroy(tb, test_pool);
}

/* Validate that priority requests are sent and completed before normal 
   requests. */
void test_serf_connection_priority_request_create(CuTest *tc)
{
    test_baton_t *tb;
    serf_request_t *request1, *request2, *request3;
    handler_baton_t handler_ctx, handler2_ctx, handler3_ctx;
    apr_status_t status;
    apr_pool_t *iter_pool;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    int i;
    test_server_action_t action_list[] = {
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
         CHUNCKED_REQUEST(1, "2")
         CHUNCKED_REQUEST(1, "3")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
        }
    };

    accepted_requests = apr_array_make(test_pool, 3, sizeof(int));
    sent_requests = apr_array_make(test_pool, 3, sizeof(int));
    handled_requests = apr_array_make(test_pool, 3, sizeof(int));

    /* Set up a test context with a server */
    status = test_server_create(&tb, action_list, 2, 0, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    handler_ctx.method = "GET";
    handler_ctx.path = "/";
    handler_ctx.done = FALSE;

    handler_ctx.acceptor = accept_response;
    handler_ctx.acceptor_baton = NULL;
    handler_ctx.handler = handle_response;
    handler_ctx.req_id = 2;
    handler_ctx.accepted_requests = accepted_requests;
    handler_ctx.sent_requests = sent_requests;
    handler_ctx.handled_requests = handled_requests;

    request1 = serf_connection_request_create(tb->connection,
                                              setup_request,
                                              &handler_ctx);

    handler2_ctx = handler_ctx;
    handler2_ctx.req_id = 3;

    request2 = serf_connection_request_create(tb->connection,
                                              setup_request,
                                              &handler2_ctx);
    handler3_ctx = handler_ctx;
    handler3_ctx.req_id = 1;

    request3 = serf_connection_priority_request_create(tb->connection,
                                                       setup_request,
                                                       &handler3_ctx);

    apr_pool_create(&iter_pool, test_pool);

    while (!handler_ctx.done && !handler2_ctx.done && !handler3_ctx.done)
    {
        apr_pool_clear(iter_pool);

        status = test_server_run(tb, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = serf_context_run(tb->context, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        /* Debugging purposes only! */
        serf_debug__closed_conn(tb->bkt_alloc);
    }
    apr_pool_destroy(iter_pool);

    /* Check that all requests were received */
    CuAssertIntEquals(tc, 3, sent_requests->nelts);
    CuAssertIntEquals(tc, 3, accepted_requests->nelts);
    CuAssertIntEquals(tc, 3, handled_requests->nelts);

    /* Check that the requests were sent in the order we created them */
    for (i = 0; i < sent_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(sent_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    /* Check that the requests were received in the order we created them */
    for (i = 0; i < handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    test_server_destroy(tb, test_pool);
}

#define NUM_REQUESTS 10
void test_serf_closed_connection(CuTest *tc)
{
    apr_pool_t *child_pool;
    test_baton_t *tb;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    apr_status_t status;
    handler_baton_t handler_ctx[NUM_REQUESTS];
    int done = FALSE, i;

    test_server_action_t action_list[] = {
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
         CHUNCKED_REQUEST(1, "2")
         CHUNCKED_REQUEST(1, "3")
         CHUNCKED_REQUEST(1, "4")
         CHUNCKED_REQUEST(1, "5")
         CHUNCKED_REQUEST(1, "6")
         CHUNCKED_REQUEST(1, "7")
         CHUNCKED_REQUEST(1, "8")
         CHUNCKED_REQUEST(1, "9")
         CHUNCKED_REQUEST(2, "10")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         "HTTP/1.1 200 OK" CRLF\
         "Transfer-Encoding: chunked" CRLF\
         "Connection: close" CRLF\
         CRLF\
         "0" CRLF\
         CRLF
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         "HTTP/1.1 200 OK" CRLF\
         "Transfer-Encoding: chunked" CRLF\
         "Connection: close" CRLF\
         CRLF\
         "0" CRLF\
         CRLF
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
        }
    };

    accepted_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    sent_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    handled_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));

    /* Set up a test context with a server. */
    status = test_server_create(&tb, action_list, 2, 0, test_pool);

    for (i = 0 ; i < NUM_REQUESTS ; i++) {
        /* Send some requests on the connections */
        handler_ctx[i].method = "GET";
        handler_ctx[i].path = "/";
        handler_ctx[i].done = FALSE;

        handler_ctx[i].acceptor = accept_response;
        handler_ctx[i].acceptor_baton = NULL;
        handler_ctx[i].handler = handle_response;
        handler_ctx[i].req_id = i+1;
        handler_ctx[i].accepted_requests = accepted_requests;
        handler_ctx[i].sent_requests = sent_requests;
        handler_ctx[i].handled_requests = handled_requests;

        serf_connection_request_create(tb->connection,
                                       setup_request,
                                       &handler_ctx[i]);
    }

    while (1) {
        status = test_server_run(tb, 0, test_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = serf_context_run(tb->context, 0, test_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        /* Debugging purposes only! */
        serf_debug__closed_conn(tb->bkt_alloc);

        done = TRUE;
        for (i = 0 ; i < NUM_REQUESTS ; i++)
            if (handler_ctx[i].done == FALSE) {
                done = FALSE;
                break;
            }
        if (done)
            break;
    }

    /* Check that all requests were received */
    CuAssertIntEquals(tc, NUM_REQUESTS, sent_requests->nelts);
    CuAssertIntEquals(tc, NUM_REQUESTS, accepted_requests->nelts);
    CuAssertIntEquals(tc, NUM_REQUESTS, handled_requests->nelts);

    /* Cleanup */
    test_server_destroy(tb, test_pool);
}
#undef NUM_REQUESTS

CuSuite *test_context(void)
{
    CuSuite *suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_serf_connection_request_create);
    SUITE_ADD_TEST(suite, test_serf_connection_priority_request_create);
    SUITE_ADD_TEST(suite, test_serf_closed_connection);

    return suite;
}
