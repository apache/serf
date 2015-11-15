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

#ifndef TEST_SERF_H
#define TEST_SERF_H

#include "CuTest.h"

#include <apr.h>
#include <apr_pools.h>
#include <apr_uri.h>

#include "serf.h"

#include "MockHTTPinC/MockHTTP.h"

/* Test logging facilities, set flag to 1 to enable console logging for
   the test suite. */
#define TEST_VERBOSE 0

/* Preferred proxy port */
#define PROXY_PORT 23456

/** These macros are provided by APR itself from version 1.3.
 * Definitions are provided here for when using older versions of APR.
 */

/** index into an apr_array_header_t */
#ifndef APR_ARRAY_IDX
#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif

/** easier array-pushing syntax */
#ifndef APR_ARRAY_PUSH
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

/* CuTest declarations */
CuSuite *getsuite(void);

CuSuite *test_context(void);
CuSuite *test_buckets(void);
CuSuite *test_ssl(void);
CuSuite *test_auth(void);
CuSuite *test_internal(void);
CuSuite *test_server(void);
CuSuite *test_mock_bucket(void);

/* Test setup declarations */
#define CRLF "\r\n"
#define CR "\r"
#define LF "\n"

typedef struct test_baton_t {
    /* Pool for resource allocation. */
    apr_pool_t *pool;

    serf_context_t *context;
    serf_connection_t *connection;
    serf_bucket_alloc_t *bkt_alloc;

    apr_port_t serv_port;
    const char *serv_host; /* "localhost:30080" */

    apr_sockaddr_t *proxy_addr;
    apr_port_t proxy_port;

    /* Cache connection params here so it gets user for a test to switch to a
       new connection. */
    const char *serv_url;
    serf_connection_setup_t conn_setup;

    /* Extra batons which can be freely used by tests. */
    void *user_baton;
    long user_baton_l;

    /* Flags that can be used to report situations, e.g. that a callback was
       called. */
    int result_flags;

    apr_array_header_t *accepted_requests, *handled_requests, *sent_requests;

    serf_ssl_context_t *ssl_context;
    serf_ssl_need_server_cert_t server_cert_cb;
    int enable_ocsp_stapling;

    /* Context for the MockHTTP library */
    MockHTTP *mh;
} test_baton_t;

typedef enum test_verify_clientcert_t {
    test_clientcert_none,
    test_clientcert_optional,
    test_clientcert_mandatory,
} test_verify_clientcert_t;

apr_status_t default_https_conn_setup(apr_socket_t *skt,
                                      serf_bucket_t **input_bkt,
                                      serf_bucket_t **output_bkt,
                                      void *setup_baton,
                                      apr_pool_t *pool);

apr_status_t use_new_connection(test_baton_t *tb,
                                apr_pool_t *pool);

void *test_setup(void *baton);
void *test_teardown(void *baton);

typedef struct handler_baton_t {
    serf_response_acceptor_t acceptor;
    void *acceptor_baton;

    serf_response_handler_t handler;

    apr_array_header_t *sent_requests;
    apr_array_header_t *accepted_requests;
    apr_array_header_t *handled_requests;
    int req_id;

    const char *method;
    const char *path;
    /* Use this for a raw request message */
    const char *request;
    int done;

    test_baton_t *tb;
} handler_baton_t;

/* These defines are used with the test_baton_t result_flags variable. */
#define TEST_RESULT_SERVERCERTCB_CALLED      0x0001
#define TEST_RESULT_SERVERCERTCHAINCB_CALLED 0x0002
#define TEST_RESULT_CLIENT_CERTCB_CALLED     0x0004
#define TEST_RESULT_CLIENT_CERTPWCB_CALLED   0x0008
#define TEST_RESULT_AUTHNCB_CALLED           0x0010
#define TEST_RESULT_HANDLE_RESPONSECB_CALLED 0x0020
#define TEST_RESULT_OCSP_CHECK_SUCCESSFUL    0x0040

serf_bucket_t* accept_response(serf_request_t *request,
                               serf_bucket_t *stream,
                               void *acceptor_baton,
                               apr_pool_t *pool);
apr_status_t setup_request(serf_request_t *request,
                           void *setup_baton,
                           serf_bucket_t **req_bkt,
                           serf_response_acceptor_t *acceptor,
                           void **acceptor_baton,
                           serf_response_handler_t *handler,
                           void **handler_baton,
                           apr_pool_t *pool);
apr_status_t handle_response(serf_request_t *request,
                             serf_bucket_t *response,
                             void *handler_baton,
                             apr_pool_t *pool);
void setup_handler(test_baton_t *tb, handler_baton_t *handler_ctx,
                   const char *method, const char *path,
                   int req_id,
                   serf_response_handler_t handler);
void create_new_prio_request(test_baton_t *tb,
                             handler_baton_t *handler_ctx,
                             const char *method, const char *path,
                             int req_id);
void create_new_request(test_baton_t *tb,
                        handler_baton_t *handler_ctx,
                        const char *method, const char *path,
                        int req_id);
void
create_new_request_with_resp_hdlr(test_baton_t *tb,
                                  handler_baton_t *handler_ctx,
                                  const char *method, const char *path,
                                  int req_id,
                                  serf_response_handler_t handler);

const char *create_large_response_message(apr_pool_t *pool);
const char *create_large_request_message_body(apr_pool_t *pool);
const char *create_large_request_message(apr_pool_t *pool, const char *body);
apr_status_t dummy_authn_callback(char **username,
                                  char **password,
                                  serf_request_t *request, void *baton,
                                  int code, const char *authn_type,
                                  const char *realm,
                                  apr_pool_t *pool);


/* Mock bucket type and constructor */
typedef struct mockbkt_action {
    int times;
    const char *data;
    apr_status_t status;
} mockbkt_action;

void read_and_check_bucket(CuTest *tc, serf_bucket_t *bkt,
                           const char *expected);
void readlines_and_check_bucket(CuTest *tc, serf_bucket_t *bkt,
                                int acceptable,
                                const char *expected,
                                int expected_nr_of_lines);

extern const serf_bucket_type_t serf_bucket_type_mock_socket;
#define SERF_BUCKET_IS_MOCK_SOCKET(b) SERF_BUCKET_CHECK((b), mock_socket)

serf_bucket_t *serf_bucket_mock_create(mockbkt_action *actions,
                                       int len,
                                       serf_bucket_alloc_t *allocator);
apr_status_t serf_bucket_mock_more_data_arrived(serf_bucket_t *bucket);

extern const serf_bucket_type_t serf_bucket_type_mock;
#define SERF_BUCKET_IS_MOCK(b) SERF_BUCKET_CHECK((b), mock)

serf_bucket_t *serf_bucket_mock_sock_create(serf_bucket_t *stream,
                                            apr_status_t eof_status,
                                            serf_bucket_alloc_t *allocator);

/*****************************************************************************/
/* Test utility functions, to be used with the MockHTTPinC framework         */
/*****************************************************************************/

/* Initiate a serf context configured to connect to the mock http server */
apr_status_t setup_test_client_context(test_baton_t *tb,
                                       serf_connection_setup_t conn_setup,
                                       apr_pool_t *pool);

/* Initiate a serf context configured to connect to the mock https server */
apr_status_t
setup_test_client_https_context(test_baton_t *tb,
                                serf_connection_setup_t conn_setup,
                                serf_ssl_need_server_cert_t server_cert_cb,
                                apr_pool_t *pool);

/* Initiate a serf context configured to connect to a http server over a
   proxy */
apr_status_t
setup_test_client_context_with_proxy(test_baton_t *tb,
                                     serf_connection_setup_t conn_setup,
                                     apr_pool_t *pool);

/* Initiate a serf context configured to connect to a https server over a
   proxy */
apr_status_t
setup_serf_https_context_with_proxy(test_baton_t *tb,
                                    serf_connection_setup_t conn_setup,
                                    serf_ssl_need_server_cert_t server_cert_cb,
                                    apr_pool_t *pool);

/* Setup a mock test server on localhost on the default port. The actual port
   will be stored in tb->port. */
void setup_test_mock_server(test_baton_t *tb);

void setup_test_mock_https_server(test_baton_t *tb,
                                  const char *keyfile,
                                  const char **certfiles,
                                  test_verify_clientcert_t t);

apr_status_t setup_test_mock_proxy(test_baton_t *tb);

/* Helper function, runs the client and server context loops. */
apr_status_t
run_client_and_mock_servers_loops(test_baton_t *tb,
                                  int num_requests,
                                  handler_baton_t handler_ctx[],
                                  apr_pool_t *pool);

/* Helper function, runs the client and server context loops and validates
   that no errors were encountered, and all messages were sent and received
   in order. */
void
run_client_and_mock_servers_loops_expect_ok(CuTest *tc, test_baton_t *tb,
                                            int num_requests,
                                            handler_baton_t handler_ctx[],
                                            apr_pool_t *pool);

/* Logs a test suite error with its code location, and return status 
   SERF_ERROR_ISSUE_IN_TESTSUITE. */
#define REPORT_TEST_SUITE_ERROR()\
     test__report_suite_error(__FILE__, __LINE__)
apr_status_t test__report_suite_error(const char *filename, long line);

/* Logs a standard event, with filename & timestamp header */
void test__log(int verbose_flag, const char *filename, const char *fmt, ...);

/* Logs a socket event, add local and remote ip address:port */
void test__log_skt(int verbose_flag, const char *filename, apr_socket_t *skt,
                   const char *fmt, ...);
/* Logs a standard event, but without prefix. This is useful to build up
 log lines in parts. */
void test__log_nopref(int verbose_flag, const char *fmt, ...);

/* Create serf_bucket_allocator() with configured unfreed callback
 * to report unfreed memory during test execution. */
serf_bucket_alloc_t *
test__create_bucket_allocator(CuTest *tc, apr_pool_t *pool);

/* Helper to get a file relative to our source directory by looking at
 * 'srcdir' env variable. */
const char * get_srcdir_file(apr_pool_t *pool, const char * file);

#endif /* TEST_SERF_H */
