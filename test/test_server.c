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

static apr_status_t client_setup(apr_socket_t *skt,
                                 serf_bucket_t **read_bkt,
                                 serf_bucket_t **write_bkt,
                                 void *setup_baton,
                                 apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    *read_bkt = serf_bucket_socket_create(skt, tb->bkt_alloc);
    return APR_SUCCESS;
}

static apr_status_t client_closed(serf_incoming_t *client,
                                  void *closed_baton,
                                  apr_status_t why,
                                  apr_pool_t *pool)
{
    return APR_ENOTIMPL;
}

static apr_status_t client_request_handler(serf_incoming_request_t *req,
                                           serf_bucket_t *request,
                                           void *handler_baton,
                                           apr_pool_t *pool)
{
    const char *data;
    apr_size_t len;
    apr_status_t status;

    do
    {
        status = serf_bucket_read(request, SERF_READ_ALL_AVAIL, &data, &len);
    } while (status == APR_SUCCESS);

    return status;
}

static apr_status_t client_generate_response(serf_bucket_t **resp_bkt,
                                             serf_incoming_request_t *req,
                                             void *setup_baton,
                                             serf_bucket_alloc_t *allocator,
                                             apr_pool_t *pool)
{
    serf_bucket_t *tmp;
#define CRLF "\r\n"

    tmp = SERF_BUCKET_SIMPLE_STRING("HTTP/1.1 200 OK" CRLF
                                    "Content-Length: 4" CRLF
                                    CRLF
                                    "OK" CRLF,
                                    allocator);

    *resp_bkt = tmp;
    return APR_SUCCESS;
}

static apr_status_t client_request_acceptor(serf_bucket_t **req_bkt,
                                            serf_bucket_t *stream,
                                            serf_incoming_request_t *req,
                                            void *request_baton,
                                            serf_incoming_request_handler_t *handler,
                                            void **handler_baton,
                                            serf_incoming_response_setup_t *response,
                                            void **response_baton,
                                            apr_pool_t *pool)
{
    test_baton_t *tb = request_baton;
    *req_bkt = serf_bucket_incoming_request_create(stream, stream->allocator);

    *handler = client_request_handler;
    *handler_baton = tb;

    *response = client_generate_response;
    *response_baton = tb;

    return APR_SUCCESS;
}

static apr_status_t client_acceptor(serf_context_t *ctx,
                                    serf_listener_t *l,
                                    void *accept_baton,
                                    apr_socket_t *insock,
                                    apr_pool_t *pool)
{
    serf_incoming_t *incoming;
    test_baton_t *tb = accept_baton;

    return serf_incoming_create2(&incoming, ctx, insock,
                                 client_setup, tb,
                                 client_closed, tb,
                                 client_request_acceptor, tb,
                                 pool);
}

void setup_test_server(test_baton_t *tb)
{
    serf_listener_t *listener;
    apr_status_t status;
    apr_port_t listen_port = 47080;

    if (!tb->mh)    /* TODO: move this to test_setup */
        tb->mh = mhInit();

    tb->context = serf_context_create(tb->pool);

    while ((status = serf_listener_create(&listener, tb->context,
                                          "localhost", listen_port,
                                          tb, client_acceptor,
                                          tb->pool)) != APR_SUCCESS)
    {
        listen_port++;
    }

    tb->serv_port = listen_port;
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost",
                                 tb->serv_port);
    tb->serv_url = apr_psprintf(tb->pool, "http://%s", tb->serv_host);
}

static apr_status_t
run_client_server_loop(test_baton_t *tb,
                       int num_requests,
                       handler_baton_t handler_ctx[],
                       apr_pool_t *pool)
{
    apr_pool_t *iter_pool;
    int i, done = 0;
    apr_status_t status;
    apr_time_t finish_time = apr_time_now() + apr_time_from_sec(15);

    apr_pool_create(&iter_pool, pool);

    while (!done)
    {
        apr_pool_clear(iter_pool);

        /* run client event loop */
        status = serf_context_run(tb->context, 0, iter_pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
            SERF_BUCKET_READ_ERROR(status))
            return status;

        done = 1;
        for (i = 0; i < num_requests; i++)
            done &= handler_ctx[i].done;

        if (!done && (apr_time_now() > finish_time))
            return APR_ETIMEDOUT;
    }
    apr_pool_destroy(iter_pool);

    return APR_SUCCESS;
}

static apr_status_t connection_setup_http2(apr_socket_t *skt,
                                           serf_bucket_t **read_bkt,
                                           serf_bucket_t **write_bkt,
                                           void *setup_baton,
                                           apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    /* Would be nice to be able to call default_http_conn_setup */
    *read_bkt = serf_bucket_socket_create(skt, tb->bkt_alloc);

    serf_connection_set_framing_type(tb->connection,
                                     SERF_CONNECTION_FRAMING_TYPE_HTTP2);

    return APR_SUCCESS;
}
void test_listen_http(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx) / sizeof(handler_ctx[0]);

    setup_test_server(tb);

    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 2);

    status = run_client_server_loop(tb, num_requests,
                                    handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
}

void test_listen_http2(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_status_t status;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx) / sizeof(handler_ctx[0]);

    setup_test_server(tb);

    status = setup_test_client_context(tb, connection_setup_http2,
                                       tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    create_new_request(tb, &handler_ctx[1], "GET", "/", 2);

    status = run_client_server_loop(tb, num_requests,
                                    handler_ctx, tb->pool);
    CuAssertIntEquals(tc, SERF_ERROR_HTTP2_PROTOCOL_ERROR, status);
}

/*****************************************************************************/
CuSuite *test_server(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_listen_http);
    SUITE_ADD_TEST(suite, test_listen_http2);

    return suite;
}
