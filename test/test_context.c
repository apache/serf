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

#include <stdlib.h>

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_version.h>

#include "serf.h"

#include "test_serf.h"

/* Validate that requests are sent and completed in the order of creation. */
static void test_serf_connection_request_create(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 2);

    status = run_client_and_mock_servers_loops(tb, num_requests,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server in the order
       we created them */
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify

    /* Check that the responses were received in the order we created them */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
}

/* Validate that priority requests are sent and completed before normal
   requests. */
static void test_serf_connection_priority_request_create(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[3];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"),
                 HeaderEqualTo("Host", tb->serv_host))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"),
                 HeaderEqualTo("Host", tb->serv_host))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 2);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 3);
    create_new_prio_request(tb, &handler_ctx[2], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);

    /* Check that the responses were received in the order we created them */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
}

/* Test that serf correctly handles the 'Connection:close' header when the
   server is planning to close the connection. */
static void test_closed_connection(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[10];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* We will send 10 requests to the mock server, close connection after the
       4th and the 8th response */
    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("4"))
        Respond(WithCode(200), WithRequestBody,
                WithConnectionCloseHeader)
      /* All messages from hereon can potentially be sent (but not responded to)
         twice */
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("5"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("6"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("7"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("8"))
        Respond(WithCode(200), WithRequestBody,
                WithConnectionCloseHeader)
      /* All messages from hereon can potentially be sent (but not responded to)
         three times */
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("9"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("10"))
    EndGiven

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server */
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify
    CuAssertTrue(tc, tb->sent_requests->nelts >= num_requests);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

/* Default implementation of a serf_connection_setup_t callback. */
static apr_status_t http_conn_setup_mock_socket(apr_socket_t *skt,
                                                serf_bucket_t **input_bkt,
                                                serf_bucket_t **output_bkt,
                                                void *setup_baton,
                                                apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    serf_bucket_t *skt_bkt = serf_context_bucket_socket_create(tb->context,
                                                               skt,
                                                               tb->bkt_alloc);
    *input_bkt = serf_bucket_mock_sock_create(skt_bkt,
                                              tb->user_baton_l,
                                              tb->bkt_alloc);

    return APR_SUCCESS;
}

static void
send_more_requests_than_keepalive_of_server(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[10];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;
    apr_status_t status;

    /* We will send 10 requests to the mock server, close connection after the
       4th and the 8th response */
    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("4"))
        Respond(WithCode(200), WithRequestBody)
        CloseConnection
      /* All messages from hereon can potentially be sent (but not responded to)
         twice */
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("5"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("6"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("7"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("8"))
        Respond(WithCode(200), WithRequestBody)
        CloseConnection
      /* All messages from hereon can potentially be sent (but not responded to)
         three times */
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("9"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("10"))
    EndGiven

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server */
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify
    CuAssertTrue(tc, tb->sent_requests->nelts >= num_requests);
    CuAssertTrue(tc, tb->accepted_requests->nelts >= num_requests);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);

}

/* Test that serf correctly handles suddenly closed connections (where the last
   response didn't have a Connection: close header). It should be handled as a
   normal connection closure. */
static void test_eof_connection(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    send_more_requests_than_keepalive_of_server(tc);
}

/* The same test as test_eof_connection, but with the authn callback set.
   This makes serf follow a slightly different code path in handle_response(). */
static void test_eof_connection_with_authn_cb(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_credentials_callback(tb->context, dummy_authn_callback);
    send_more_requests_than_keepalive_of_server(tc);
}

/* Test that serf correctly handles aborted connections. This can happen
   on Windows when the server (cleanly) closes the connection, and where it
   happens between responses, it should be handled as a normal connection
   closure. */
static void test_aborted_connection(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. Use the mock socket to return
       APR_ECONNABORTED instead of APR_EOF. */
    setup_test_mock_server(tb);
    tb->user_baton_l = APR_ECONNABORTED;
    status = setup_test_client_context(tb, http_conn_setup_mock_socket,
                                       tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    send_more_requests_than_keepalive_of_server(tc);
}

/* The same test as test_aborted_connection, but with the authn callback set.
   This makes serf follow a slightly different code path in handle_response(). */
static void test_aborted_connection_with_authn_cb(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. Use the mock socket to return
     APR_ECONNABORTED instead of APR_EOF. */
    setup_test_mock_server(tb);
    tb->user_baton_l = APR_ECONNABORTED;
    status = setup_test_client_context(tb, http_conn_setup_mock_socket,
                                       tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_credentials_callback(tb->context, dummy_authn_callback);
    send_more_requests_than_keepalive_of_server(tc);
}

/* The same test as test_aborted_connection, but with APR_ECONNRESET instead
   of APR_ECONNABORTED. */
static void test_reset_connection(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. Use the mock socket to return
       APR_ECONNRESET instead of APR_EOF. */
    setup_test_mock_server(tb);
    tb->user_baton_l = APR_ECONNRESET;
    status = setup_test_client_context(tb, http_conn_setup_mock_socket,
                                       tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    send_more_requests_than_keepalive_of_server(tc);
}

/* The same test as test_reset_connection, but with the authn callback set.
   This makes serf follow a slightly different code path in handle_response(). */
static void test_reset_connection_with_authn_cb(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;

    /* Set up a test context with a server. Use the mock socket to return
       APR_ECONNRESET instead of APR_EOF. */
    setup_test_mock_server(tb);
    tb->user_baton_l = APR_ECONNRESET;
    status = setup_test_client_context(tb, http_conn_setup_mock_socket,
                                       tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_credentials_callback(tb->context, dummy_authn_callback);
    send_more_requests_than_keepalive_of_server(tc);
}

/* Test if serf is sending the request to the proxy, not to the server
   directly. */
static void test_setup_proxy(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context with a proxy */
    setup_test_mock_server(tb);
    status = setup_test_mock_proxy(tb);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    status = setup_test_client_context_with_proxy(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      RequestsReceivedByProxy
        GETRequest(
            URLEqualTo(apr_psprintf(tb->pool, "http://%s", tb->serv_host)),
            HeaderEqualTo("Host", tb->serv_host),
            ChunkedBodyEqualTo("1"))
          Respond(WithCode(200), WithChunkedBody(""))
    EndGiven
    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/*****************************************************************************
 * Test if we can make serf send requests one by one.
 *****************************************************************************/

/* Resend the first request 2 more times as priority requests. */
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

#define SENT_REQUESTS 5
#define RCVD_REQUESTS 7
static void test_keepalive_limit_one_by_one(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[RCVD_REQUESTS];
    int i;


    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Reduce the bandwidth to one at a time. The first request will be resend
       twice as priority requests, so iff the bandwidth reduction is in effect
       these should be sent before all other requests. */
    serf_connection_set_max_outstanding_requests(tb->connection, 1);

    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("4"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("5"))
    EndGiven

    for (i = 0 ; i < SENT_REQUESTS ; i++) {
        create_new_request_ex(tb, &handler_ctx[i], "GET", "/", i+1,
                              NULL, handle_response_keepalive_limit);
    }

    /* The two retries of request 1 both also have req_id=1, which means that
       we can't expected RECV_REQUESTS # of requests here, because the done flag
       of these 2 request will not be registered correctly. */
    status = run_client_and_mock_servers_loops(tb, SENT_REQUESTS, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
    EndVerify

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
#define SENT_REQUESTS 5
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
    test_baton_t *tb = tc->testBaton;
        apr_status_t status;
    handler_baton_t handler_ctx[SENT_REQUESTS];
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_connection_set_max_outstanding_requests(tb->connection, 1);

    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("4"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("5"))
    EndGiven

    for (i = 0 ; i < SENT_REQUESTS ; i++) {
        create_new_request_ex(tb, &handler_ctx[i], "GET", "/", i+1,
                              NULL, handle_response_keepalive_limit_burst);
    }

    /* The two retries of request 1 both also have req_id=1, which means that
       we can't expected RECV_REQUESTS # of requests here, because the done flag
       of these 2 request will not be registered correctly. */
    status = run_client_and_mock_servers_loops(tb, SENT_REQUESTS, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
    EndVerify

    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, RCVD_REQUESTS, tb->handled_requests->nelts);
}
#undef SEND_REQUESTS
#undef RCVD_REQUESTS

typedef struct progress_baton_t {
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
    *input_bkt = serf_context_bucket_socket_create(tb->context, skt,
                                                   tb->bkt_alloc);
    return APR_SUCCESS;
}

static void test_progress_callback(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[5];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;
    progress_baton_t *pb;


    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, progress_conn_setup, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Set up the progress callback. */
    pb = apr_pcalloc(tb->pool, sizeof(*pb));
    tb->user_baton = pb;
    serf_context_set_progress_cb(tb->context, progress_cb, tb);

    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("3"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("4"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("5"))
    EndGiven

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);

    /* Check that progress was reported. */
    CuAssertTrue(tc, pb->written > 0);
    CuAssertTrue(tc, pb->read > 0);
}

/* Test that username:password components in url are ignored. */
static void test_connection_userinfo_in_url(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"))
    EndGiven

    /* Create a connection using user:password@hostname syntax */
    tb->serv_url = apr_psprintf(tb->pool, "http://user:password@localhost:%d",
                                tb->serv_port);

    use_new_connection(tb, tb->pool);

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/", i+1);
    }

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/*****************************************************************************
 * Issue #91: test that serf correctly handle an incoming 4xx reponse while
 * the outgoing request wasn't written completely yet.
 *****************************************************************************/

#define REQUEST_BODY_PART1\
    "<?xml version=""1.0"" encoding=""utf-8""?><propfind xmlns=""DAV:""><prop>"

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


static apr_status_t queue_part2(void *baton, serf_bucket_t *aggregate_bucket)
{
    serf_bucket_t *body_bkt;
    handler_baton_t *ctx = baton;

    if (ctx->done) {
        body_bkt = serf_bucket_simple_create(REQUEST_PART2, strlen(REQUEST_PART2),
                                             NULL, NULL,
                                             aggregate_bucket->allocator);
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

    *req_bkt = serf_bucket_aggregate_create(serf_request_get_alloc(request));

    /* create a simple body text */
    body_bkt = serf_bucket_simple_create(REQUEST_PART1, strlen(REQUEST_PART1),
                                         NULL, NULL,
                                         serf_request_get_alloc(request));
    serf_bucket_aggregate_append(*req_bkt, body_bkt);

    /* When REQUEST_PART1 runs out, we will queue up PART2.  */
    serf_bucket_aggregate_hold_open(*req_bkt, queue_part2, ctx);

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
        return REPORT_TEST_SUITE_ERROR();
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

static void test_request_timeout(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      HTTPRequest(MethodEqualTo("PROPFIND"),
                  URLEqualTo("/"),
                  IncompleteBodyEqualTo(REQUEST_BODY_PART1))
        Respond(WithRawData(RESPONSE_408, strlen(RESPONSE_408)))
    EndGiven

    /* Send a incomplete requesta on the connection */
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

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/* Validate reading a large chunked response. */
static void test_connection_large_response(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;


    /* create large chunked response message */
    const char *response = create_large_response_message(tb->pool);

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
        Respond(WithRawData(response, strlen(response)))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/* Validate sending a large chunked response. */
static void test_connection_large_request(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    const char *request, *body;
    apr_status_t status;


    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* create large chunked request message */
    body = create_large_request_message_body(tb->pool);
    request = create_large_request_message(tb->pool, body);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), RawBodyEqualTo(body))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    handler_ctx[0].request = request;

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

static void test_max_keepalive_requests(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[200];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int i;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    InitMockServers(tb->mh)
      ConfigServerWithID("server", WithMaxKeepAliveRequests(4))
    EndInit

    /* We will NUM_REQUESTS requests to the mock server, close connection after
       every 4th response. */
    Given(tb->mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/index.html"))
    EndGiven

    /* Send some requests on the connections */
    for (i = 0 ; i < num_requests ; i++) {
        create_new_request(tb, &handler_ctx[i], "GET", "/index.html", i+1);
    }

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server */
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
      CuAssertIntEquals(tc, num_requests, VerifyStats->requestsResponded);
    EndVerify
    CuAssertTrue(tc, tb->sent_requests->nelts >= num_requests);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

/* Implements test_request_setup_t */
static apr_status_t setup_request_err(serf_request_t *request,
                                      void *setup_baton,
                                      serf_bucket_t **req_bkt,
                                      apr_pool_t *pool)
{
    static mockbkt_action actions[] = {
        { 1, "a", APR_SUCCESS },
        /* Return an error after first successful read. */
        { 1, "", APR_EINVAL }
    };
    handler_baton_t *ctx = setup_baton;
    serf_bucket_alloc_t *alloc;
    serf_bucket_t *mock_bkt;

    alloc = serf_request_get_alloc(request);
    mock_bkt = serf_bucket_mock_create(actions, 2, alloc);
    *req_bkt = serf_request_bucket_request_create(request,
                                                  ctx->method, ctx->path,
                                                  mock_bkt, alloc);
    return APR_SUCCESS;
}

static void test_outgoing_request_err(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    apr_status_t status;

    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Setup an outgoing request with the body bucket returning an error. */
    create_new_request_ex(tb, &handler_ctx[0], "POST", "/", 1,
                          setup_request_err, NULL);

    status = run_client_and_mock_servers_loops(tb, 1, handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_EINVAL, status);
    CuAssertIntEquals(tc, 1, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, 0, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, 0, tb->handled_requests->nelts);
}

/*****************************************************************************/
CuSuite *test_context(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_serf_connection_request_create);
    SUITE_ADD_TEST(suite, test_serf_connection_priority_request_create);
    SUITE_ADD_TEST(suite, test_closed_connection);
    SUITE_ADD_TEST(suite, test_eof_connection);
    SUITE_ADD_TEST(suite, test_eof_connection_with_authn_cb);
    SUITE_ADD_TEST(suite, test_aborted_connection);
    SUITE_ADD_TEST(suite, test_aborted_connection_with_authn_cb);
    SUITE_ADD_TEST(suite, test_reset_connection);
    SUITE_ADD_TEST(suite, test_reset_connection_with_authn_cb);
    SUITE_ADD_TEST(suite, test_setup_proxy);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one);
    SUITE_ADD_TEST(suite, test_keepalive_limit_one_by_one_and_burst);
    SUITE_ADD_TEST(suite, test_progress_callback);
    SUITE_ADD_TEST(suite, test_connection_userinfo_in_url);
    SUITE_ADD_TEST(suite, test_request_timeout);
    SUITE_ADD_TEST(suite, test_connection_large_response);
    SUITE_ADD_TEST(suite, test_connection_large_request);
    SUITE_ADD_TEST(suite, test_max_keepalive_requests);
    SUITE_ADD_TEST(suite, test_outgoing_request_err);

    return suite;
}
