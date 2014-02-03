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

#include "apr.h"
#include "apr_pools.h"
#include <apr_strings.h>

#include <stdlib.h>

#include "serf.h"

#include "test_serf.h"
#include "server/test_server.h"

/*****************************************************************************/
/* Server setup function(s)
 */

#define HTTP_SERV_URL  "http://localhost:" SERV_PORT_STR
#define HTTPS_SERV_URL "https://localhost:" SERV_PORT_STR

/* cleanup for conn */
static apr_status_t cleanup_conn(void *baton)
{
    serf_connection_t *conn = baton;

    serf_connection_close(conn);

    return APR_SUCCESS;
}

static apr_status_t default_server_address(apr_sockaddr_t **address,
                                           apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_UNSPEC, SERV_PORT, 0,
                                 pool);
}

static apr_status_t default_proxy_address(apr_sockaddr_t **address,
                                          apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_UNSPEC, PROXY_PORT, 0,
                                 pool);
}

/* Default implementation of a serf_connection_closed_t callback. */
static void default_closed_connection(serf_connection_t *conn,
                                      void *closed_baton,
                                      apr_status_t why,
                                      apr_pool_t *pool)
{
    if (why) {
        abort();
    }
}

/* Default implementation of a serf_connection_setup_t callback. */
static apr_status_t default_http_conn_setup(apr_socket_t *skt,
                                            serf_bucket_t **input_bkt,
                                            serf_bucket_t **output_bkt,
                                            void *setup_baton,
                                            apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    *input_bkt = serf_bucket_socket_create(skt, tb->bkt_alloc);
    return APR_SUCCESS;
}

/* This function makes serf use SSL on the connection. */
apr_status_t default_https_conn_setup(apr_socket_t *skt,
                                      serf_bucket_t **input_bkt,
                                      serf_bucket_t **output_bkt,
                                      void *setup_baton,
                                      apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;

    *input_bkt = serf_bucket_socket_create(skt, tb->bkt_alloc);
    *input_bkt = serf_bucket_ssl_decrypt_create(*input_bkt, NULL,
                                                tb->bkt_alloc);
    tb->ssl_context = serf_bucket_ssl_encrypt_context_get(*input_bkt);

    if (output_bkt) {
        *output_bkt = serf_bucket_ssl_encrypt_create(*output_bkt,
                                                     tb->ssl_context,
                                                     tb->bkt_alloc);
    }

    if (tb->server_cert_cb)
        serf_ssl_server_cert_callback_set(tb->ssl_context,
                                          tb->server_cert_cb,
                                          tb);

    serf_ssl_set_hostname(tb->ssl_context, "localhost");

    return APR_SUCCESS;
}

apr_status_t use_new_connection(test_baton_t *tb,
                                apr_pool_t *pool)
{
    apr_uri_t url;
    apr_status_t status;

    if (tb->connection)
        cleanup_conn(tb->connection);
    tb->connection = NULL;

    status = apr_uri_parse(pool, tb->serv_url, &url);
    if (status != APR_SUCCESS)
        return status;

    status = serf_connection_create2(&tb->connection, tb->context,
                                     url,
                                     tb->conn_setup,
                                     tb,
                                     default_closed_connection,
                                     tb,
                                     pool);

    apr_pool_cleanup_register(pool, tb->connection, cleanup_conn,
                              apr_pool_cleanup_null);

    return status;
}

static test_baton_t *initTestCtx(apr_pool_t *pool)
{
    test_baton_t *tb;
    tb = apr_pcalloc(pool, sizeof(*tb));
    tb->pool = pool;
    tb->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    tb->accepted_requests = apr_array_make(pool, 10, sizeof(int));
    tb->sent_requests = apr_array_make(pool, 10, sizeof(int));
    tb->handled_requests = apr_array_make(pool, 10, sizeof(int));
    return tb;
}

/* Setup the client context, ready to connect and send requests to a
   server.*/
static apr_status_t setup(test_baton_t **tb_p,
                          serf_connection_setup_t conn_setup,
                          const char *serv_url,
                          int use_proxy,
                          apr_size_t message_count,
                          apr_pool_t *pool)
{
    test_baton_t *tb;
    apr_status_t status;

    *tb_p = tb = initTestCtx(pool);

    tb->context = serf_context_create(pool);

    tb->serv_url = serv_url;
    tb->serv_port = SERV_PORT;
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost", tb->serv_port);

    tb->conn_setup = conn_setup;

    status = default_server_address(&tb->serv_addr, pool);
    if (status != APR_SUCCESS)
        return status;

    if (use_proxy) {
        status = default_proxy_address(&tb->proxy_addr, pool);
        if (status != APR_SUCCESS)
            return status;

        /* Configure serf to use the proxy server */
        serf_config_proxy(tb->context, tb->proxy_addr);
    }

    status = use_new_connection(tb, pool);

    return status;
}

/* Setup an https server and the client context to connect to that server */
apr_status_t test_https_server_setup(test_baton_t **tb_p,
                                     test_server_message_t *message_list,
                                     apr_size_t message_count,
                                     test_server_action_t *action_list,
                                     apr_size_t action_count,
                                     apr_int32_t options,
                                     serf_connection_setup_t conn_setup,
                                     const char *keyfile,
                                     const char **certfiles,
                                     const char *client_cn,
                                     serf_ssl_need_server_cert_t server_cert_cb,
                                     apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup ? conn_setup : default_https_conn_setup,
                   HTTPS_SERV_URL,
                   FALSE,
                   message_count,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;
    tb->server_cert_cb = server_cert_cb;

    /* Prepare a server. */
    setup_https_test_server(&tb->serv_ctx, tb->serv_addr,
                            message_list, message_count,
                            action_list, action_count, options,
                            keyfile, certfiles, client_cn,
                            pool);
    status = start_test_server(tb->serv_ctx);

    return status;
}

/* Setup an http server and the client context to connect to that server */
apr_status_t test_http_server_setup(test_baton_t **tb_p,
                                    test_server_message_t *message_list,
                                    apr_size_t message_count,
                                    test_server_action_t *action_list,
                                    apr_size_t action_count,
                                    apr_int32_t options,
                                    serf_connection_setup_t conn_setup,
                                    apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup ? conn_setup : default_http_conn_setup,
                   HTTP_SERV_URL,
                   FALSE,
                   message_count,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;

    /* Prepare a server. */
    setup_test_server(&tb->serv_ctx, tb->serv_addr,
                      message_list, message_count,
                      action_list, action_count, options,
                      pool);
    status = start_test_server(tb->serv_ctx);

    return status;
}

/* Setup a proxy server and an http server and the client context to connect to
   that proxy server */
apr_status_t
test_server_proxy_setup(test_baton_t **tb_p,
                        test_server_message_t *serv_message_list,
                        apr_size_t serv_message_count,
                        test_server_action_t *serv_action_list,
                        apr_size_t serv_action_count,
                        test_server_message_t *proxy_message_list,
                        apr_size_t proxy_message_count,
                        test_server_action_t *proxy_action_list,
                        apr_size_t proxy_action_count,
                        apr_int32_t options,
                        serf_connection_setup_t conn_setup,
                        apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup ? conn_setup : default_http_conn_setup,
                   HTTP_SERV_URL,
                   TRUE,
                   serv_message_count,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;

    /* Prepare the server. */
    setup_test_server(&tb->serv_ctx, tb->serv_addr,
                      serv_message_list, serv_message_count,
                      serv_action_list, serv_action_count,
                      options,
                      pool);
    status = start_test_server(tb->serv_ctx);
    if (status != APR_SUCCESS)
        return status;

    /* Prepare the proxy. */
    setup_test_server(&tb->proxy_ctx, tb->proxy_addr,
                      proxy_message_list, proxy_message_count,
                      proxy_action_list, proxy_action_count,
                      options,
                      pool);
    status = start_test_server(tb->proxy_ctx);

    return status;
}

/* Setup a proxy server and a https server and the client context to connect to
   that proxy server */
apr_status_t
test_https_server_proxy_setup(test_baton_t **tb_p,
                              test_server_message_t *serv_message_list,
                              apr_size_t serv_message_count,
                              test_server_action_t *serv_action_list,
                              apr_size_t serv_action_count,
                              test_server_message_t *proxy_message_list,
                              apr_size_t proxy_message_count,
                              test_server_action_t *proxy_action_list,
                              apr_size_t proxy_action_count,
                              apr_int32_t options,
                              serf_connection_setup_t conn_setup,
                              const char *keyfile,
                              const char **certfiles,
                              const char *client_cn,
                              serf_ssl_need_server_cert_t server_cert_cb,
                              apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup ? conn_setup : default_https_conn_setup,
                   HTTPS_SERV_URL,
                   TRUE, /* use proxy */
                   serv_message_count,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;
    tb->server_cert_cb = server_cert_cb;

    /* Prepare a https server. */
    setup_https_test_server(&tb->serv_ctx, tb->serv_addr,
                            serv_message_list, serv_message_count,
                            serv_action_list, serv_action_count,
                            options,
                            keyfile, certfiles, client_cn,
                            pool);
    status = start_test_server(tb->serv_ctx);

    /* Prepare the proxy. */
    setup_test_server(&tb->proxy_ctx, tb->proxy_addr,
                      proxy_message_list, proxy_message_count,
                      proxy_action_list, proxy_action_count,
                      options,
                      pool);
    status = start_test_server(tb->proxy_ctx);

    return status;
}

/* Helper function, runs the client and server context loops and validates
 that no errors were encountered, and all messages were sent and received. */
apr_status_t
test_helper_run_requests_no_check(CuTest *tc, test_baton_t *tb,
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

        /* run server event loop */
        status = run_test_server(tb->serv_ctx, 0, iter_pool);
        if (!APR_STATUS_IS_TIMEUP(status) &&
            SERF_BUCKET_READ_ERROR(status))
            return status;

        /* run proxy event loop */
        if (tb->proxy_ctx) {
            status = run_test_server(tb->proxy_ctx, 0, iter_pool);
            if (!APR_STATUS_IS_TIMEUP(status) &&
                SERF_BUCKET_READ_ERROR(status))
                return status;
        }

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

void
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

serf_bucket_t* accept_response(serf_request_t *request,
                               serf_bucket_t *stream,
                               void *acceptor_baton,
                               apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;
    handler_baton_t *ctx = acceptor_baton;
    serf_bucket_t *response;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    APR_ARRAY_PUSH(ctx->accepted_requests, int) = ctx->req_id;

    response = serf_bucket_response_create(c, bkt_alloc);

    if (strcasecmp(ctx->method, "HEAD") == 0)
      serf_bucket_response_set_head(response);

    return response;
}

apr_status_t setup_request(serf_request_t *request,
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

    if (ctx->request)
    {
        /* Create a raw request bucket. */
        *req_bkt = serf_bucket_simple_create(ctx->request, strlen(ctx->request),
                                             NULL, NULL,
                                             serf_request_get_alloc(request));
    }
    else
    {
        if (ctx->req_id >= 0) {
            /* create a simple body text */
            const char *str = apr_psprintf(pool, "%d", ctx->req_id);

            body_bkt = serf_bucket_simple_create(
                                        str, strlen(str), NULL, NULL,
                                        serf_request_get_alloc(request));
        }
        else
            body_bkt = NULL;

        *req_bkt =
        serf_request_bucket_request_create(request,
                                           ctx->method, ctx->path,
                                           body_bkt,
                                           serf_request_get_alloc(request));
    }

    APR_ARRAY_PUSH(ctx->sent_requests, int) = ctx->req_id;

    *acceptor = ctx->acceptor;
    *acceptor_baton = ctx;
    *handler = ctx->handler;
    *handler_baton = ctx;

    return APR_SUCCESS;
}

apr_status_t handle_response(serf_request_t *request,
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

void setup_handler(test_baton_t *tb, handler_baton_t *handler_ctx,
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
    handler_ctx->request = NULL;
}

void create_new_prio_request(test_baton_t *tb,
                             handler_baton_t *handler_ctx,
                             const char *method, const char *path,
                             int req_id)
{
    setup_handler(tb, handler_ctx, method, path, req_id, NULL);
    serf_connection_priority_request_create(tb->connection,
                                            setup_request,
                                            handler_ctx);
}

void create_new_request(test_baton_t *tb,
                        handler_baton_t *handler_ctx,
                        const char *method, const char *path,
                        int req_id)
{
    setup_handler(tb, handler_ctx, method, path, req_id, NULL);
    serf_connection_request_create(tb->connection,
                                   setup_request,
                                   handler_ctx);
}

void
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

/*****************************************************************************/
/* Test utility functions, to be used with the MockHTTPinC framework         */
/*****************************************************************************/

apr_status_t
setup_test_client_context(test_baton_t *tb,
                          serf_connection_setup_t conn_setup,
                          apr_pool_t *pool)
{
    apr_status_t status;

    tb->context = serf_context_create(pool);
    tb->conn_setup = conn_setup ? conn_setup :
                                  default_http_conn_setup;
    status = use_new_connection(tb, pool);

    return status;
}

apr_status_t
setup_test_client_https_context(test_baton_t *tb,
                                serf_connection_setup_t conn_setup,
                                serf_ssl_need_server_cert_t server_cert_cb,
                                apr_pool_t *pool)
{
    apr_status_t status;

    status = setup_test_client_context(tb,
                                       conn_setup ? conn_setup:
                                                    default_https_conn_setup,
                                       pool);
    tb->server_cert_cb = server_cert_cb;

    return status;
}

apr_status_t
setup_test_client_context_with_proxy(test_baton_t *tb,
                                     serf_connection_setup_t conn_setup,
                                     apr_pool_t *pool)
{
    apr_status_t status;

    tb->context = serf_context_create(pool);
    tb->conn_setup = conn_setup ? conn_setup :
                                  default_http_conn_setup;

    /* Configure serf to use the proxy server */
    serf_config_proxy(tb->context, tb->proxy_addr);

    status = use_new_connection(tb, pool);

    return status;
}

apr_status_t
setup_serf_https_context_with_proxy(test_baton_t *tb,
                                    serf_connection_setup_t conn_setup,
                                    serf_ssl_need_server_cert_t server_cert_cb,
                                    apr_pool_t *pool)
{
    apr_status_t status;

    status = setup_test_client_context_with_proxy(tb,
                                                  conn_setup ? conn_setup:
                                                  default_https_conn_setup,
                                                  pool);
    tb->server_cert_cb = server_cert_cb;

    return status;
}

apr_status_t
run_client_and_mock_servers_loops(test_baton_t *tb,
                                  int num_requests,
                                  handler_baton_t handler_ctx[],
                                  apr_pool_t *pool)
{
    apr_pool_t *iter_pool;
    int i, done = 0;
    MockHTTP *mh = tb->mh;
    apr_status_t status;
    apr_time_t finish_time = apr_time_now() + apr_time_from_sec(15);

    apr_pool_create(&iter_pool, pool);

    while (!done)
    {
        mhError_t err;
        apr_pool_clear(iter_pool);

        /* run server event loop */
        err = mhRunServerLoop(mh);
        if (err == MOCKHTTP_TEST_FAILED)
            return SERF_ERROR_ISSUE_IN_TESTSUITE;

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

void
run_client_and_mock_servers_loops_expect_ok(CuTest *tc, test_baton_t *tb,
                                            int num_requests,
                                            handler_baton_t handler_ctx[],
                                            apr_pool_t *pool)
{
    apr_status_t status;

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server in the order
     we created them */
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify

    CuAssertIntEquals(tc, num_requests, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

void setup_test_mock_server(test_baton_t *tb)
{
    if (!tb->mh)    /* TODO: move this to test_setup */
        tb->mh = mhInit();

    InitMockServers(tb->mh)
      SetupServer(WithHTTP, WithPort(30080))
    EndInit
    tb->serv_port = mhServerPortNr(tb->mh);
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost", tb->serv_port);
    tb->serv_url = apr_psprintf(tb->pool, "http://%s", tb->serv_host);
}

apr_status_t setup_test_mock_proxy(test_baton_t *tb)
{
    if (!tb->mh)
        tb->mh = mhInit();

    InitMockServers(tb->mh)
      SetupProxy(WithHTTP, WithPort(PROXY_PORT))
    EndInit
    tb->proxy_port = mhProxyPortNr(tb->mh);
    return apr_sockaddr_info_get(&tb->proxy_addr,
                                 "localhost", APR_UNSPEC,
                                 mhProxyPortNr(tb->mh), 0,
                                 tb->pool);
}

void setup_test_mock_https_server(test_baton_t *tb,
                                  const char *keyfile,
                                  const char **certfiles,
                                  const char *client_cn) /* TODO: remove arg */
{
    if (!tb->mh)
        tb->mh = mhInit();

    InitMockServers(tb->mh)
      SetupServer(WithHTTPS, WithPort(30080),
                  WithCertificateKeyFile(keyfile),
                  WithCertificateFileArray(certfiles),
                  WithClientCertificate)
    EndInit
    tb->serv_port = mhServerPortNr(tb->mh);
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost", tb->serv_port);
    tb->serv_url = apr_psprintf(tb->pool, "https://%s", tb->serv_host);
}

void *test_setup(void *dummy)
{
    apr_pool_t *test_pool;
    apr_pool_create(&test_pool, NULL);
    return initTestCtx(test_pool);
}

void *test_teardown(void *baton)
{
    test_baton_t *tb = baton;
    if (tb->mh)
        mhCleanup(tb->mh);
    apr_pool_destroy(tb->pool);      /* tb is now an invalid pointer */
    return NULL;
}

/*****************************************************************************/
/* Logging functions                                                         */
/*****************************************************************************/
static void log_time()
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void test__log(int verbose_flag, const char *filename, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void test__log_nopref(int verbose_flag, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

void test__log_skt(int verbose_flag, const char *filename, apr_socket_t *skt,
                   const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        apr_sockaddr_t *sa;
        log_time();

        if (skt) {
            /* Log local and remote ip address:port */
            fprintf(stderr, "[l:");
            if (apr_socket_addr_get(&sa, APR_LOCAL, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, " r:");
            if (apr_socket_addr_get(&sa, APR_REMOTE, skt) == APR_SUCCESS) {
                char buf[32];
                apr_sockaddr_ip_getbuf(buf, 32, sa);
                fprintf(stderr, "%s:%d", buf, sa->port);
            }
            fprintf(stderr, "] ");
        }

        if (filename)
            fprintf(stderr, "%s: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}
