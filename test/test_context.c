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
#include "server/test_server.h"

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

    test_baton_t *tb;
} handler_baton_t;

/* These defines are used with the test_baton_t result_flags variable. */
#define TEST_RESULT_CERTCB_CALLED      0x0001
#define TEST_RESULT_CERTCHAINCB_CALLED 0x0002

/* Helper function, runs the client and server context loops and validates
   that no errors were encountered, and all messages were sent and received. */
static apr_status_t
test_helper_run_requests_no_check(CuTest *tc, test_baton_t *tb,
                                  int num_requests,
                                  handler_baton_t handler_ctx[],
                                  apr_pool_t *pool)
{
    apr_pool_t *iter_pool;
    int i, done = 0;
    apr_status_t status;

    apr_pool_create(&iter_pool, pool);

    while (!done)
    {
        apr_pool_clear(iter_pool);

        status = test_server_run(tb->serv_ctx, 0, iter_pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
            SERF_BUCKET_READ_ERROR(status))
            return status;

        status = serf_context_run(tb->context, 0, iter_pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
            SERF_BUCKET_READ_ERROR(status))
            return status;

        done = 1;
        for (i = 0; i < num_requests; i++)
            done &= handler_ctx[i].done;
    }
    apr_pool_destroy(iter_pool);

    return APR_SUCCESS;
}

static void
test_helper_run_requests_expect_ok(CuTest *tc, test_baton_t *tb,
                                   int num_requests,
                                   handler_baton_t handler_ctx[],
                                   apr_pool_t *pool)
{
    apr_status_t status;

    status = test_helper_run_requests_no_check(tc, tb, num_requests,
                                               handler_ctx, pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that all requests were received */
    CuAssertIntEquals(tc, num_requests, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

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

        if (APR_STATUS_IS_EAGAIN(status)) {
            return status;
        }

    }

    return APR_SUCCESS;
}

static void setup_handler(test_baton_t *tb, handler_baton_t *handler_ctx,
                          const char *method, const char *path,
                          int req_id,
                          serf_response_handler_t handler)
{
    handler_ctx->method = method;
    handler_ctx->path = path;
    handler_ctx->done = FALSE;

    handler_ctx->acceptor = accept_response;
    handler_ctx->acceptor_baton = NULL;
    handler_ctx->handler = handler ? handler : handle_response;
    handler_ctx->req_id = req_id;
    handler_ctx->accepted_requests = tb->accepted_requests;
    handler_ctx->sent_requests = tb->sent_requests;
    handler_ctx->handled_requests = tb->handled_requests;
    handler_ctx->tb = tb;
}

static void create_new_prio_request(test_baton_t *tb,
                                    handler_baton_t *handler_ctx,
                                    const char *method, const char *path,
                                    int req_id)
{
    setup_handler(tb, handler_ctx, method, path, req_id, NULL);
    serf_connection_priority_request_create(tb->connection,
                                            setup_request,
                                            handler_ctx);
}

static void create_new_request(test_baton_t *tb,
                               handler_baton_t *handler_ctx,
                               const char *method, const char *path,
                               int req_id)
{
    setup_handler(tb, handler_ctx, method, path, req_id, NULL);
    serf_connection_request_create(tb->connection,
                                   setup_request,
                                   handler_ctx);
}

static void
create_new_request_with_resp_hdlr(test_baton_t *tb,
                                  handler_baton_t *handler_ctx,
                                  const char *method, const char *path,
                                  int req_id,
                                  serf_response_handler_t handler)
{
    setup_handler(tb, handler_ctx, method, path, req_id, handler);
    serf_connection_request_create(tb->connection,
                                   setup_request,
                                   handler_ctx);
}

/* Validate that requests are sent and completed in the order of creation. */
static void test_serf_connection_request_create(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    int i;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server */
    status = test_server_setup(&tb,
                               message_list, num_requests,
                               action_list, num_requests, 0, NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 2);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);

    /* Check that the requests were sent in the order we created them */
    for (i = 0; i < tb->sent_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->sent_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    /* Check that the requests were received in the order we created them */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
}

/* Validate that priority requests are sent and completed before normal
   requests. */
static void test_serf_connection_priority_request_create(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[3];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    int i;

    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
        {CHUNKED_REQUEST(1, "3")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server */
    status = test_server_setup(&tb,
                               message_list, num_requests,
                               action_list, num_requests, 0, NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 2);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 3);
    create_new_prio_request(tb, &handler_ctx[2], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);

    /* Check that the requests were sent in the order we created them */
    for (i = 0; i < tb->sent_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->sent_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    /* Check that the requests were received in the order we created them */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
}

/* Test that serf correctly handles the 'Connection:close' header when the
   server is planning to close the connection. */
static void test_serf_closed_connection(CuTest *tc)
{
    test_baton_t *tb;
    apr_status_t status;
    handler_baton_t handler_ctx[10];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int done = FALSE, i;

    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
        {CHUNKED_REQUEST(1, "3")},
        {CHUNKED_REQUEST(1, "4")},
        {CHUNKED_REQUEST(1, "5")},
        {CHUNKED_REQUEST(1, "6")},
        {CHUNKED_REQUEST(1, "7")},
        {CHUNKED_REQUEST(1, "8")},
        {CHUNKED_REQUEST(1, "9")},
        {CHUNKED_REQUEST(2, "10")}
        };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND,
         "HTTP/1.1 200 OK" CRLF
         "Transfer-Encoding: chunked" CRLF
         "Connection: close" CRLF
         CRLF
         "0" CRLF
         CRLF
        },
        {SERVER_IGNORE_AND_KILL_CONNECTION},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND,
         "HTTP/1.1 200 OK" CRLF
         "Transfer-Encoding: chunked" CRLF
         "Connection: close" CRLF
         CRLF
         "0" CRLF
         CRLF
        },
        {SERVER_IGNORE_AND_KILL_CONNECTION},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server. */
    status = test_server_setup(&tb,
                               message_list, num_requests,
                               action_list, 12,
                               0,
                               NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    while (1) {
        status = test_server_run(tb->serv_ctx, 0, test_pool);
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
        for (i = 0 ; i < num_requests ; i++)
            if (handler_ctx[i].done == FALSE) {
                done = FALSE;
                break;
            }
        if (done)
            break;
    }

   /* Check that all requests were received */
   CuAssertTrue(tc, tb->sent_requests->nelts >= num_requests);
   CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
   CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

/* Test if serf is sending the request to the proxy, not to the server
   directly. */
static void test_serf_setup_proxy(CuTest *tc)
{
    test_baton_t *tb;
    int i;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_pool_t *iter_pool;
    apr_status_t status;

    test_server_message_t message_list[] = {
        {"GET http://localhost:" SERV_PORT_STR " HTTP/1.1" CRLF\
         "Host: localhost:" SERV_PORT_STR CRLF\
         "Transfer-Encoding: chunked" CRLF\
         CRLF\
         "1" CRLF\
         "1" CRLF\
         "0" CRLF\
         CRLF}
    };

    test_server_action_t action_list_proxy[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server, no messages expected. */
    status = test_server_proxy_setup(&tb,
                                     /* server messages and actions */
                                     NULL, 0,
                                     NULL, 0,
                                     /* server messages and actions */
                                     message_list, 1,
                                     action_list_proxy, 1,
                                     0,
                                     NULL, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    apr_pool_create(&iter_pool, test_pool);

    while (!handler_ctx[0].done)
    {
        apr_pool_clear(iter_pool);

        status = test_server_run(tb->serv_ctx, 0, iter_pool);
        if (APR_STATUS_IS_TIMEUP(status))
            status = APR_SUCCESS;
        CuAssertIntEquals(tc, APR_SUCCESS, status);

        status = test_server_run(tb->proxy_ctx, 0, iter_pool);
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
    CuAssertIntEquals(tc, num_requests, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);


    /* Check that the requests were sent in the order we created them */
    for (i = 0; i < tb->sent_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->sent_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }

    /* Check that the requests were received in the order we created them */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
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
    apr_status_t status;
    handler_baton_t handler_ctx[SEND_REQUESTS];
    int done = FALSE, i;

    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
        {CHUNKED_REQUEST(1, "3")},
        {CHUNKED_REQUEST(1, "4")},
        {CHUNKED_REQUEST(1, "5")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server. */
    status = test_server_setup(&tb,
                               message_list, RCVD_REQUESTS,
                               action_list, RCVD_REQUESTS, 0, NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    for (i = 0 ; i < SEND_REQUESTS ; i++) {
        create_new_request_with_resp_hdlr(tb, &handler_ctx[i], "GET", "/", i+1,
                                          handle_response_keepalive_limit);
        /* TODO: don't think this needs to be done in the loop. */
        serf_connection_set_max_outstanding_requests(tb->connection, 1);
    }

    while (1) {
        status = test_server_run(tb->serv_ctx, 0, test_pool);
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
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->handled_requests->nelts);
}
#undef SEND_REQUESTS
#undef RCVD_REQUESTS

/*****************************************************************************
 * Test if we can make serf first send requests one by one, and then change
 * back to burst mode.
 *****************************************************************************/
#define SEND_REQUESTS 5
#define RCVD_REQUESTS 7
/* Resend the first request 2 times by reducing the pipeline bandwidth to
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

        if (APR_STATUS_IS_EAGAIN(status)) {
            return status;
        }
    }

    return APR_SUCCESS;
}

static void test_keepalive_limit_one_by_one_and_burst(CuTest *tc)
{
    test_baton_t *tb;
        apr_status_t status;
    handler_baton_t handler_ctx[SEND_REQUESTS];
    int done = FALSE, i;

    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
        {CHUNKED_REQUEST(1, "3")},
        {CHUNKED_REQUEST(1, "4")},
        {CHUNKED_REQUEST(1, "5")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server. */
    status = test_server_setup(&tb,
                               message_list, RCVD_REQUESTS,
                               action_list, RCVD_REQUESTS, 0, NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    for (i = 0 ; i < SEND_REQUESTS ; i++) {
        create_new_request_with_resp_hdlr(tb, &handler_ctx[i], "GET", "/", i+1,
                                          handle_response_keepalive_limit_burst);
        serf_connection_set_max_outstanding_requests(tb->connection, 1);
    }

    while (1) {
        status = test_server_run(tb->serv_ctx, 0, test_pool);
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
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->handled_requests->nelts);
}
#undef SEND_REQUESTS
#undef RCVD_REQUESTS

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

static apr_status_t progress_conn_setup(apr_socket_t *skt,
                                          serf_bucket_t **input_bkt,
                                          serf_bucket_t **output_bkt,
                                          void *setup_baton,
                                          apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    *input_bkt = serf_context_bucket_socket_create(tb->context, skt, tb->bkt_alloc);
    return APR_SUCCESS;
}

static void test_serf_progress_callback(CuTest *tc)
{
    test_baton_t *tb;
    apr_status_t status;
    handler_baton_t handler_ctx[5];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;
    progress_baton_t *pb;

    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {CHUNKED_REQUEST(1, "2")},
        {CHUNKED_REQUEST(1, "3")},
        {CHUNKED_REQUEST(1, "4")},
        {CHUNKED_REQUEST(1, "5")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_RESPONSE(1, "2")},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    apr_pool_t *test_pool = tc->testBaton;
    
    /* Set up a test context with a server. */
    status = test_server_setup(&tb,
                               message_list, num_requests,
                               action_list, num_requests, 0,
                               progress_conn_setup, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Set up the progress callback. */
    pb = apr_pcalloc(test_pool, sizeof(*pb));
    tb->user_baton = pb;
    serf_context_set_progress_cb(tb->context, progress_cb, tb);

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);

    /* Check that progress was reported. */
    CuAssertTrue(tc, pb->written > 0);
    CuAssertTrue(tc, pb->read > 0);
}


/*****************************************************************************
 * Issue #91: test that serf correctly handle an incoming 4xx reponse while
 * the outgoing request wasn't written completely yet.
 *****************************************************************************/

#define REQUEST_PART1 "PROPFIND / HTTP/1.1" CRLF\
"Host: lgo-ubuntu.local" CRLF\
"User-Agent: SVN/1.8.0-dev (x86_64-apple-darwin11.4.2) serf/2.0.0" CRLF\
"Content-Type: text/xml" CRLF\
"Transfer-Encoding: chunked" CRLF \
CRLF\
"12d" CRLF\
"<?xml version=""1.0"" encoding=""utf-8""?><propfind xmlns=""DAV:""><prop>"

#define REQUEST_PART2 \
"<resourcetype xmlns=""DAV:""/><getcontentlength xmlns=""DAV:""/>"\
"<deadprop-count xmlns=""http://subversion.tigris.org/xmlns/dav/""/>"\
"<version-name xmlns=""DAV:""/><creationdate xmlns=""DAV:""/>"\
"<creator-displayname xmlns=""DAV:""/></prop></propfind>" CRLF\
"0" CRLF \
CRLF

#define RESPONSE_408 "HTTP/1.1 408 Request Time-out" CRLF\
"Date: Wed, 14 Nov 2012 19:50:35 GMT" CRLF\
"Server: Apache/2.2.17 (Ubuntu)" CRLF\
"Vary: Accept-Encoding" CRLF\
"Content-Length: 305" CRLF\
"Connection: close" CRLF\
"Content-Type: text/html; charset=iso-8859-1" CRLF \
CRLF\
"<!DOCTYPE HTML PUBLIC ""-//IETF//DTD HTML 2.0//EN""><html><head>"\
"<title>408 Request Time-out</title></head><body><h1>Request Time-out</h1>"\
"<p>Server timeout waiting for the HTTP request from the client.</p><hr>"\
"<address>Apache/2.2.17 (Ubuntu) Server at lgo-ubuntu.local Port 80</address>"\
"</body></html>"


static apr_status_t detect_eof(void *baton, serf_bucket_t *aggregate_bucket)
{
    serf_bucket_t *body_bkt;
    handler_baton_t *ctx = baton;

    if (ctx->done) {
        body_bkt = serf_bucket_simple_create(REQUEST_PART1, strlen(REQUEST_PART2),
                                             NULL, NULL,
                                             ctx->tb->bkt_alloc);
        serf_bucket_aggregate_append(aggregate_bucket, body_bkt);
    }

    return APR_EAGAIN;
}

static apr_status_t setup_request_timeout(
                                  serf_request_t *request,
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

    *req_bkt = serf__bucket_stream_create(serf_request_get_alloc(request),
                                          detect_eof,
                                          ctx);

    /* create a simple body text */
    body_bkt = serf_bucket_simple_create(REQUEST_PART1, strlen(REQUEST_PART1),
                                         NULL, NULL,
                                         serf_request_get_alloc(request));
    serf_bucket_aggregate_append(*req_bkt, body_bkt);

    APR_ARRAY_PUSH(ctx->sent_requests, int) = ctx->req_id;

    *acceptor = ctx->acceptor;
    *acceptor_baton = ctx;
    *handler = ctx->handler;
    *handler_baton = ctx;

    return APR_SUCCESS;
}

static apr_status_t handle_response_timeout(
                                    serf_request_t *request,
                                    serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;
    serf_status_line sl;
    apr_status_t status;

    if (! response) {
        serf_connection_request_create(ctx->tb->connection,
                                       setup_request,
                                       ctx);
        return APR_SUCCESS;
    }

    if (serf_request_is_written(request) != APR_EBUSY) {
        return APR_EGENERAL;
    }


    status = serf_bucket_response_status(response, &sl);
    if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }
    if (!sl.version && (APR_STATUS_IS_EOF(status) ||
                        APR_STATUS_IS_EAGAIN(status))) {
        return status;
    }
    if (sl.code == 408) {
        APR_ARRAY_PUSH(ctx->handled_requests, int) = ctx->req_id;
        ctx->done = TRUE;
    }

    /* discard the rest of the body */
    while (1) {
        const char *data;
        apr_size_t len;

        status = serf_bucket_read(response, 2048, &data, &len);
        if (SERF_BUCKET_READ_ERROR(status) ||
            APR_STATUS_IS_EAGAIN(status) ||
            APR_STATUS_IS_EOF(status))
            return status;
    }

    return APR_SUCCESS;
}

static void test_serf_request_timeout(CuTest *tc)
{
    test_baton_t *tb;
        apr_status_t status;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);

    test_server_message_t message_list[] = {
        {REQUEST_PART1},
        {REQUEST_PART2},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, RESPONSE_408},
    };

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server. */
    status = test_server_setup(&tb,
                               message_list, 2,
                               action_list, 1, 0,
                               NULL, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Send some requests on the connection */
    handler_ctx[0].method = "PROPFIND";
    handler_ctx[0].path = "/";
    handler_ctx[0].done = FALSE;

    handler_ctx[0].acceptor = accept_response;
    handler_ctx[0].acceptor_baton = NULL;
    handler_ctx[0].handler = handle_response_timeout;
    handler_ctx[0].req_id = 1;
    handler_ctx[0].accepted_requests = tb->accepted_requests;
    handler_ctx[0].sent_requests = tb->sent_requests;
    handler_ctx[0].handled_requests = tb->handled_requests;
    handler_ctx[0].tb = tb;

    serf_connection_request_create(tb->connection,
                                   setup_request_timeout,
                                   &handler_ctx[0]);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);
}

static const char *create_large_response_message(apr_pool_t *pool)
{
    const char *response = "HTTP/1.1 200 OK" CRLF
                     "Transfer-Encoding: chunked" CRLF
                     CRLF;
    struct iovec vecs[500];
    const int num_vecs = 500;
    int i, j;
    apr_size_t len;

    vecs[0].iov_base = (char *)response;
    vecs[0].iov_len = strlen(response);

    for (i = 1; i < num_vecs; i++)
    {
        int chunk_len = 10 * i * 3;

        /* end with empty chunk */
        if (i == num_vecs - 1)
            chunk_len = 0;

        char *chunk, *buf = apr_pcalloc(pool, chunk_len + 1);
        for (j = 0; j < chunk_len; j += 10)
            memcpy(buf + j, "0123456789", 10);

        chunk = apr_pstrcat(pool,
                            apr_psprintf(pool, "%x", chunk_len),
                            CRLF, buf, CRLF, NULL);
        vecs[i].iov_base = chunk;
        vecs[i].iov_len = strlen(chunk);
    }

    return apr_pstrcatv(pool, vecs, num_vecs, &len);
}

/* Validate reading a large chunked response. */
static void test_serf_connection_large_response(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };
    test_server_action_t action_list[1];

    apr_pool_t *test_pool = tc->testBaton;

    /* create large chunked response message */
    const char *response = create_large_response_message(test_pool);
    action_list[0].kind = SERVER_RESPOND;
    action_list[0].text = response;

    /* Set up a test context with a server */
    status = test_server_setup(&tb,
                               message_list, num_requests,
                               action_list, num_requests, 0, NULL,
                               test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);
}

/*****************************************************************************
 * SSL handshake tests
 *****************************************************************************/
static const char *server_certs[] = {
    "test/server/serfservercert.pem",
    "test/server/serfcacert.pem",
    NULL };

static apr_status_t validate_servercert(const serf_ssl_certificate_t *cert,
                                        apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("Serf Server",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Test Suite Server",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("serfserver@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;

    return APR_SUCCESS;
}

static apr_status_t validate_cacert(const serf_ssl_certificate_t *cert,
                                    apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("Serf CA",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Test Suite CA",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("serfca@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;

    return APR_SUCCESS;
}

static apr_status_t validate_rootcacert(const serf_ssl_certificate_t *cert,
                                        apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("Serf Root CA",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Test Suite Root CA",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;
    if (strcmp("serfrootca@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return APR_EGENERAL;

    return APR_SUCCESS;
}

static apr_status_t
ssl_server_cert_cb_expect_failures(void *baton, int failures,
                                   const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    tb->result_flags |= TEST_RESULT_CERTCB_CALLED;

    /* We expect an error from the certificate validation function. */
    if (failures)
        return APR_SUCCESS;
    else
        return APR_EGENERAL;
}

static apr_status_t
ssl_server_cert_cb_expect_allok(void *baton, int failures,
                                const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    tb->result_flags |= TEST_RESULT_CERTCB_CALLED;

    /* No error expected, certificate is valid. */
    if (failures)
        return APR_EGENERAL;
    else
        return APR_SUCCESS;
}

/* Validate that we can connect successfully to an https server. */
static void test_serf_ssl_handshake(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    static const char *server_cert[] = { "test/server/serfservercert.pem",
        NULL };


    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;
    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     NULL, /* default conn setup */
                                     "test/server/serfserverkey.pem",
                                     server_cert,
                                     NULL, /* no client cert */
                                     ssl_server_cert_cb_expect_failures,
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);
}

/* Set up the ssl context with the CA and root CA certificates needed for
   successful valiation of the server certificate. */
static apr_status_t
https_set_root_ca_conn_setup(apr_socket_t *skt,
                             serf_bucket_t **input_bkt,
                             serf_bucket_t **output_bkt,
                             void *setup_baton,
                             apr_pool_t *pool)
{
    serf_ssl_certificate_t *rootcacert;
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = default_https_conn_setup(skt, input_bkt, output_bkt,
                                      setup_baton, pool);
    if (status)
        return status;

    status = serf_ssl_load_cert_file(&rootcacert,
                                     "test/server/serfrootcacert.pem",
                                     pool);
    if (status)
        return status;
    status = serf_ssl_trust_cert(tb->ssl_context, rootcacert);
    if (status)
        return status;

    return status;
}

/* Validate that server certificate validation is ok when we
   explicitly trust our self-signed root ca. */
static void test_serf_ssl_trust_rootca(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;
    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     https_set_root_ca_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     ssl_server_cert_cb_expect_allok,
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests, handler_ctx,
                                       test_pool);
}

/* Validate that when the application rejects the cert, the context loop
   bails out with an error. */
static void test_serf_ssl_application_rejects_cert(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    /* The certificate is valid, but we tell serf to reject it by using the
       ssl_server_cert_cb_expect_failures callback. */
    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     https_set_root_ca_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     ssl_server_cert_cb_expect_failures,
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = test_helper_run_requests_no_check(tc, tb, num_requests,
                                               handler_ctx, test_pool);
    /* We expect an error from the certificate validation function. */
    CuAssert(tc, "Application told serf the certificate should be rejected,"
                 " expected error!", status != APR_SUCCESS);
}

/* Test for ssl certificate chain callback. */
static apr_status_t
cert_chain_cb(void *baton,
              int failures,
              int error_depth,
              const serf_ssl_certificate_t * const * certs,
              apr_size_t certs_len)
{
    test_baton_t *tb = baton;
    apr_status_t status;

    tb->result_flags |= TEST_RESULT_CERTCHAINCB_CALLED;

    if (failures)
        return APR_EGENERAL;

    if (certs_len != 3)
        return APR_EGENERAL;

    status = validate_rootcacert(certs[2], tb->pool);
    if (status)
        return status;

    status = validate_cacert(certs[1], tb->pool);
    if (status)
        return status;

    status = validate_servercert(certs[0], tb->pool);
    if (status)
        return status;

    return APR_SUCCESS;
}

static apr_status_t
chain_callback_conn_setup(apr_socket_t *skt,
                          serf_bucket_t **input_bkt,
                          serf_bucket_t **output_bkt,
                          void *setup_baton,
                          apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = https_set_root_ca_conn_setup(skt, input_bkt, output_bkt,
                                          setup_baton, pool);
    if (status)
        return status;

    serf_ssl_server_cert_chain_callback_set(tb->ssl_context,
                                            ssl_server_cert_cb_expect_allok,
                                            cert_chain_cb,
                                            tb);

    return APR_SUCCESS;
}

static void test_serf_ssl_certificate_chain(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };

    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     chain_callback_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     ssl_server_cert_cb_expect_allok,
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests,
                                       handler_ctx, test_pool);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_CERTCB_CALLED);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_CERTCHAINCB_CALLED);
}

/* Validate that the ssl handshake succeeds if no application callbacks
   are set, and the ssl server certificate chains is ok. */
static void test_serf_ssl_no_servercert_callback_allok(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };
    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    apr_status_t status;

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     https_set_root_ca_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     NULL, /* No server cert callback */
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests,
                                       handler_ctx, test_pool);
}

/* Validate that the ssl handshake fails if no application callbacks
 are set, and the ssl server certificate chains is NOT ok. */
static void test_serf_ssl_no_servercert_callback_fail(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };
    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    apr_status_t status;

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     NULL, /* default conn setup, no certs */
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     NULL, /* No server cert callback */
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = test_helper_run_requests_no_check(tc, tb, num_requests,
                                               handler_ctx, test_pool);
    /* We expect an error from the certificate validation function. */
    CuAssertIntEquals(tc, SERF_ERROR_SSL_CERT_FAILED, status);
}

/* Similar to test_serf_connection_large_response, validate reading a large
   chunked response over SSL. */
static void test_serf_ssl_large_response(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };
    test_server_action_t action_list[1];
    apr_status_t status;

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     https_set_root_ca_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     server_certs,
                                     NULL, /* no client cert */
                                     NULL, /* No server cert callback */
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* create large chunked response message */
    const char *response = create_large_response_message(test_pool);
    action_list[0].kind = SERVER_RESPOND;
    action_list[0].text = response;

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests,
                                       handler_ctx, test_pool);
}

apr_status_t client_cert_cb(void *data,
                            const char **cert_path)
{
    *cert_path = "test/server/serfclientcert.p12";

    return APR_SUCCESS;
}

apr_status_t client_cert_pw_cb(void *data,
                               const char *cert_path,
                               const char **password)
{
    if (strcmp(cert_path, "test/server/serfclientcert.p12") == 0)
    {
        *password = "serftest";
        return APR_SUCCESS;
    }

    return APR_EGENERAL;
}

static apr_status_t
client_cert_conn_setup(apr_socket_t *skt,
                       serf_bucket_t **input_bkt,
                       serf_bucket_t **output_bkt,
                       void *setup_baton,
                       apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = https_set_root_ca_conn_setup(skt, input_bkt, output_bkt,
                                          setup_baton, pool);
    if (status)
        return status;

    serf_ssl_client_cert_provider_set(tb->ssl_context,
                                      client_cert_cb,
                                      NULL,
                                      pool);

    serf_ssl_client_cert_password_set(tb->ssl_context,
                                      client_cert_pw_cb,
                                      NULL,
                                      pool);

    return APR_SUCCESS;
}

static const char *all_server_certs[] = {
    "test/server/serfservercert.pem",
    "test/server/serfcacert.pem",
    "test/server/serfrootcacert.pem",
    NULL };

static void test_serf_ssl_client_certificate(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
    };
    test_server_action_t action_list[] = {
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    apr_status_t status;

    /* Set up a test context with a server */
    apr_pool_t *test_pool = tc->testBaton;

    /* The SSL server the complete certificate chain to validate the client
       certificate. */
    status = test_https_server_setup(&tb,
                                     message_list, num_requests,
                                     action_list, num_requests, 0,
                                     client_cert_conn_setup,
                                     "test/server/serfserverkey.pem",
                                     all_server_certs,
                                     "Serf Client",
                                     NULL, /* No server cert callback */
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    test_helper_run_requests_expect_ok(tc, tb, num_requests,
                                       handler_ctx, test_pool);
}

/*****************************************************************************/
CuSuite *test_context(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_serf_connection_request_create);
    SUITE_ADD_TEST(suite, test_serf_connection_priority_request_create);
    SUITE_ADD_TEST(suite, test_serf_closed_connection);
    SUITE_ADD_TEST(suite, test_serf_setup_proxy);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one_and_burst);
    SUITE_ADD_TEST(suite, test_serf_progress_callback);
    SUITE_ADD_TEST(suite, test_serf_request_timeout);
    SUITE_ADD_TEST(suite, test_serf_connection_large_response);
    SUITE_ADD_TEST(suite, test_serf_ssl_handshake);
    SUITE_ADD_TEST(suite, test_serf_ssl_trust_rootca);
    SUITE_ADD_TEST(suite, test_serf_ssl_application_rejects_cert);
    SUITE_ADD_TEST(suite, test_serf_ssl_certificate_chain);
    SUITE_ADD_TEST(suite, test_serf_ssl_no_servercert_callback_allok);
    SUITE_ADD_TEST(suite, test_serf_ssl_no_servercert_callback_fail);
    SUITE_ADD_TEST(suite, test_serf_ssl_large_response);
    SUITE_ADD_TEST(suite, test_serf_ssl_client_certificate);

    return suite;
}
