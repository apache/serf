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
    int done;

    const char *server_root;
    int use_proxy;

    test_baton_t *tb;
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
    *req_bkt = 
        serf_request_bucket_request_create(request, 
                                           ctx->method, ctx->path, 
                                           body_bkt,
                                           serf_request_get_alloc(request));

    APR_ARRAY_PUSH(ctx->sent_requests, int) = ctx->req_id;

    *acceptor = ctx->acceptor;
    *acceptor_baton = ctx;
    *handler = ctx->handler;
    *handler_baton = ctx;

    return APR_SUCCESS;
}

static apr_status_t handle_response(serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;

    if (! response) {
        serf_connection_request_create(ctx->tb->connection,
                                       setup_request,
                                       ctx);
        return APR_SUCCESS;
    }

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

/* Validate that requests are sent and completed in the order of creation. */
static void test_serf_connection_request_create(CuTest *tc)
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
    status = test_server_create(&tb, action_list, 2, 0, NULL, NULL, NULL,
                                test_pool);
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
    handler_ctx.use_proxy = FALSE;
    handler_ctx.server_root = NULL;

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
static void test_serf_connection_priority_request_create(CuTest *tc)
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
    status = test_server_create(&tb, action_list, 2, 0, NULL, NULL, NULL,
                                test_pool);
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
    handler_ctx.use_proxy = FALSE;
    handler_ctx.server_root = NULL;

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

/* Test that serf correctly handles the 'Connection:close' header when the
   server is planning to close the connection. */
#define NUM_REQUESTS 10
static void test_serf_closed_connection(CuTest *tc)
{
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
         "HTTP/1.1 200 OK" CRLF
         "Transfer-Encoding: chunked" CRLF
         "Connection: close" CRLF
         CRLF
         "0" CRLF
         CRLF
        },
        {SERVER_KILL_CONNECTION},
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         "HTTP/1.1 200 OK" CRLF
         "Transfer-Encoding: chunked" CRLF
         "Connection: close" CRLF
         CRLF
         "0" CRLF
         CRLF
        },
        {SERVER_KILL_CONNECTION},
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
        },
    };

    accepted_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    sent_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    handled_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));

    /* Set up a test context with a server. */
    status = test_server_create(&tb, action_list, 6, 0, NULL, NULL, NULL,
                                test_pool);

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
        handler_ctx[i].tb = tb;
        handler_ctx[i].use_proxy = FALSE;
        handler_ctx[i].server_root = NULL;

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
    CuAssertTrue(tc, sent_requests->nelts >= NUM_REQUESTS);
    CuAssertIntEquals(tc, NUM_REQUESTS, accepted_requests->nelts);
    CuAssertIntEquals(tc, NUM_REQUESTS, handled_requests->nelts);

    /* Cleanup */
    test_server_destroy(tb, test_pool);
}
#undef NUM_REQUESTS

/* Test if serf is sending the request to the proxy, not to the server
   directly. */
static void test_serf_setup_proxy(CuTest *tc)
{
    test_baton_t *tb_server, *tb_proxy;
    serf_request_t *request;
    handler_baton_t handler_ctx;
    apr_status_t status;
    apr_pool_t *iter_pool;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    int i;
    int numrequests = 1;
    apr_sockaddr_t *proxy_address;
    test_server_action_t *action_list_server = NULL;
    test_server_action_t action_list_proxy[] = {
        {SERVER_RECV,
         "GET http://localhost:" SERV_PORT_STR " HTTP/1.1" CRLF\
         "Transfer-Encoding: chunked" CRLF\
         "Host: localhost" CRLF\
         CRLF\
         "1" CRLF\
         "1" CRLF\
         "0" CRLF\
         CRLF
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        }
    };

    accepted_requests = apr_array_make(test_pool, numrequests, sizeof(int));
    sent_requests = apr_array_make(test_pool, numrequests, sizeof(int));
    handled_requests = apr_array_make(test_pool, numrequests, sizeof(int));

    /* Set up a test context with a server */
    status = test_server_create(&tb_server, action_list_server, 2, 0,
                                "http://localhost:" SERV_PORT_STR, NULL,
                                NULL, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Set up another test context for the proxy server */
    status = apr_sockaddr_info_get(&proxy_address,
                                   "localhost", APR_INET, 21212, 0,
                                   test_pool);
    status = test_server_create(&tb_proxy, action_list_proxy, 2, 0,
                                NULL, proxy_address, NULL,
                                test_pool);

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
    handler_ctx.use_proxy = TRUE;
    handler_ctx.server_root = "http://localhost:" SERV_PORT_STR;

    /* Configure serf to use the proxy server */
    serf_config_proxy(tb_server->context, proxy_address);

    request = serf_connection_request_create(tb_server->connection,
                                             setup_request,
                                             &handler_ctx);

    apr_pool_create(&iter_pool, test_pool);

    while (!handler_ctx.done)
    {
        apr_pool_clear(iter_pool);

        status = test_server_run(tb_server, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = test_server_run(tb_proxy, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = serf_context_run(tb_server->context, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        /* Debugging purposes only! */
        serf_debug__closed_conn(tb_server->bkt_alloc);
    }
    apr_pool_destroy(iter_pool);

    /* Check that all requests were received */
    CuAssertIntEquals(tc, numrequests, sent_requests->nelts);
    CuAssertIntEquals(tc, numrequests, accepted_requests->nelts);
    CuAssertIntEquals(tc, numrequests, handled_requests->nelts);

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

    test_server_destroy(tb_server, test_pool);
}

/*****************************************************************************
 * Test if we can make serf send requests one by one.
 *****************************************************************************/

/* Resend the first request 4 times by reducing the pipeline bandwidth to
   one request at a time, and by adding the first request again at the start of
   the outgoing queue. */
static apr_status_t
handle_response_keepalive_limit(serf_request_t *request,
                                serf_bucket_t *response,
                                void *handler_baton,
                                apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;

    if (! response) {
        return APR_SUCCESS;
    }

    while (1) {
        apr_status_t status;
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(response, 2048, &data, &len);
        if (SERF_BUCKET_READ_ERROR(status)) {
            return status;
        }

        if (APR_STATUS_IS_EOF(status)) {
            APR_ARRAY_PUSH(ctx->handled_requests, int) = ctx->req_id;
            ctx->done = TRUE;
            if (ctx->req_id == 1 && ctx->handled_requests->nelts < 3) {
                serf_connection_priority_request_create(ctx->tb->connection,
                                                        setup_request,
                                                        ctx);
                ctx->done = FALSE;
            }
            return APR_EOF;
        }
    }

    return APR_SUCCESS;
}

#define SEND_REQUESTS 5
#define RCVD_REQUESTS 7
static void test_keepalive_limit_one_by_one(CuTest *tc)
{
    test_baton_t *tb;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    apr_status_t status;
    handler_baton_t handler_ctx[SEND_REQUESTS];
    int done = FALSE, i;

    test_server_action_t action_list[] = {
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "2")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "3")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "4")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "5")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
    };

    accepted_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));
    sent_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));
    handled_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));

    /* Set up a test context with a server. */
    status = test_server_create(&tb, action_list, 14, 0, NULL, NULL, NULL,
                                test_pool);

    for (i = 0 ; i < SEND_REQUESTS ; i++) {
        /* Send some requests on the connections */
        handler_ctx[i].method = "GET";
        handler_ctx[i].path = "/";
        handler_ctx[i].done = FALSE;

        handler_ctx[i].acceptor = accept_response;
        handler_ctx[i].acceptor_baton = NULL;
        handler_ctx[i].handler = handle_response_keepalive_limit;
        handler_ctx[i].req_id = i+1;
        handler_ctx[i].accepted_requests = accepted_requests;
        handler_ctx[i].sent_requests = sent_requests;
        handler_ctx[i].handled_requests = handled_requests;
        handler_ctx[i].tb = tb;
        handler_ctx[i].use_proxy = FALSE;
        handler_ctx[i].server_root = NULL;

        serf_connection_request_create(tb->connection,
                                       setup_request,
                                       &handler_ctx[i]);
        serf_connection_set_max_outstanding_requests(tb->connection, 1);
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
        for (i = 0 ; i < SEND_REQUESTS ; i++)
            if (handler_ctx[i].done == FALSE) {
                done = FALSE;
                break;
            }
        if (done)
            break;
    }

    /* Check that all requests were received */
    CuAssertIntEquals(tc, RCVD_REQUESTS, sent_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, accepted_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, handled_requests->nelts);

    /* Cleanup */
    test_server_destroy(tb, test_pool);
}
#undef SEND_REQUESTS
#undef RCVD_REQUESTS

/*****************************************************************************
 * Test if we can make serf first send requests one by one, and then change
 * back to burst mode.
 *****************************************************************************/
#define SEND_REQUESTS 5
#define RCVD_REQUESTS 7
/* Resend the first request 4 times by reducing the pipeline bandwidth to
   one request at a time, and by adding the first request again at the start of
   the outgoing queue. */
static apr_status_t
handle_response_keepalive_limit_burst(serf_request_t *request,
                                      serf_bucket_t *response,
                                      void *handler_baton,
                                      apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;

    if (! response) {
        return APR_SUCCESS;
    }

    while (1) {
        apr_status_t status;
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(response, 2048, &data, &len);
        if (SERF_BUCKET_READ_ERROR(status)) {
            return status;
        }

        if (APR_STATUS_IS_EOF(status)) {
            APR_ARRAY_PUSH(ctx->handled_requests, int) = ctx->req_id;
            ctx->done = TRUE;
            if (ctx->req_id == 1 && ctx->handled_requests->nelts < 3) {
                serf_connection_priority_request_create(ctx->tb->connection,
                                                        setup_request,
                                                        ctx);
                ctx->done = FALSE;
            }
            else  {
                /* No more one-by-one. */
                serf_connection_set_max_outstanding_requests(ctx->tb->connection,
                                                             0);
            }
            return APR_EOF;
        }
    }

    return APR_SUCCESS;
}

static void test_keepalive_limit_one_by_one_and_burst(CuTest *tc)
{
    test_baton_t *tb;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    apr_status_t status;
    handler_baton_t handler_ctx[SEND_REQUESTS];
    int done = FALSE, i;

    test_server_action_t action_list[] = {
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
        },
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "2")
         CHUNCKED_REQUEST(1, "3")
         CHUNCKED_REQUEST(1, "4")
         CHUNCKED_REQUEST(1, "5")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
        },
    };

    accepted_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));
    sent_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));
    handled_requests = apr_array_make(test_pool, RCVD_REQUESTS, sizeof(int));

    /* Set up a test context with a server. */
    status = test_server_create(&tb, action_list, 8, 0, NULL, NULL, NULL, 
                                test_pool);

    for (i = 0 ; i < SEND_REQUESTS ; i++) {
        /* Send some requests on the connections */
        handler_ctx[i].method = "GET";
        handler_ctx[i].path = "/";
        handler_ctx[i].done = FALSE;

        handler_ctx[i].acceptor = accept_response;
        handler_ctx[i].acceptor_baton = NULL;
        handler_ctx[i].handler = handle_response_keepalive_limit_burst;
        handler_ctx[i].req_id = i+1;
        handler_ctx[i].accepted_requests = accepted_requests;
        handler_ctx[i].sent_requests = sent_requests;
        handler_ctx[i].handled_requests = handled_requests;
        handler_ctx[i].tb = tb;
        handler_ctx[i].use_proxy = FALSE;
        handler_ctx[i].server_root = NULL;

        serf_connection_request_create(tb->connection,
                                       setup_request,
                                       &handler_ctx[i]);
        serf_connection_set_max_outstanding_requests(tb->connection, 1);
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
        for (i = 0 ; i < SEND_REQUESTS ; i++)
            if (handler_ctx[i].done == FALSE) {
                done = FALSE;
                break;
            }
        if (done)
            break;
    }

    /* Check that all requests were received */
    CuAssertIntEquals(tc, RCVD_REQUESTS, sent_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, accepted_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, handled_requests->nelts);

    /* Cleanup */
    test_server_destroy(tb, test_pool);
}
#undef SEND_REQUESTS
#undef RCVD_REQUESTS

#define NUM_REQUESTS 5
typedef struct {
  apr_off_t read;
  apr_off_t written;
} progress_baton_t;

static void
progress_cb(void *progress_baton, apr_off_t read, apr_off_t written)
{
    test_baton_t *tb = progress_baton;
    progress_baton_t *pb = tb->user_baton;

    pb->read = read;
    pb->written = written;
}

static serf_bucket_t* progress_conn_setup(apr_socket_t *skt,
                                          void *setup_baton,
                                          apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    return serf_context_bucket_socket_create(tb->context, skt, tb->bkt_alloc);
}

static void test_serf_progress_callback(CuTest *tc)
{
    test_baton_t *tb;
    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;
    apr_status_t status;
    handler_baton_t handler_ctx[NUM_REQUESTS];
    int done = FALSE, i;
    progress_baton_t *pb;

    test_server_action_t action_list[] = {
        {SERVER_RECV,
         CHUNCKED_REQUEST(1, "1")
         CHUNCKED_REQUEST(1, "2")
         CHUNCKED_REQUEST(1, "3")
         CHUNCKED_REQUEST(1, "4")
         CHUNCKED_REQUEST(1, "5")
        },
        {SERVER_SEND,
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_RESPONSE(1, "2")
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
         CHUNKED_EMPTY_RESPONSE
        },
    };

    accepted_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    sent_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));
    handled_requests = apr_array_make(test_pool, NUM_REQUESTS, sizeof(int));

    /* Set up a test context with a server. */
    status = test_server_create(&tb, action_list, 2, 0, NULL, NULL, 
                                progress_conn_setup, test_pool);
    
    /* Set up the progress callback. */
    pb = apr_pcalloc(test_pool, sizeof(*pb));
    tb->user_baton = pb;
    serf_context_set_progress_cb(tb->context, progress_cb, tb);

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
        handler_ctx[i].tb = tb;
        handler_ctx[i].use_proxy = FALSE;
        handler_ctx[i].server_root = NULL;

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
    CuAssertTrue(tc, sent_requests->nelts >= NUM_REQUESTS);
    CuAssertIntEquals(tc, NUM_REQUESTS, accepted_requests->nelts);
    CuAssertIntEquals(tc, NUM_REQUESTS, handled_requests->nelts);

    /* Check that progress was reported. */
    CuAssertTrue(tc, pb->written > 0);
    CuAssertTrue(tc, pb->read > 0);

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
    SUITE_ADD_TEST(suite, test_serf_setup_proxy);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one_and_burst);
    SUITE_ADD_TEST(suite, test_serf_progress_callback);

    return suite;
}
