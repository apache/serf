/* Copyright 2013 Justin Erenkrantz and Greg Stein
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

#include "serf.h"
#include "test_serf.h"


static apr_status_t
basic_authn_callback(char **username,
                     char **password,
                     serf_request_t *request, void *baton,
                     int code, const char *authn_type,
                     const char *realm,
                     apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (code != 401)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;
    if (strcmp("Basic", authn_type) != 0)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;
    if (strcmp("<http://localhost:12345> Test Suite", realm) != 0)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;

    *username = "serf";
    *password = "serftest";

    return APR_SUCCESS;
}

static void test_basic_authentication(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[2];
    int num_requests_sent, num_requests_recvd;

    /* Expected string relies on strict order of headers, which is not
       guaranteed. c2VyZjpzZXJmdGVzdA== is base64 encoded serf:serftest . */
    test_server_message_t message_list[] = {
        {CHUNKED_REQUEST(1, "1")},
        {"GET / HTTP/1.1" CRLF
            "Host: localhost:12345" CRLF
            "Authorization: Basic c2VyZjpzZXJmdGVzdA==" CRLF
            "Transfer-Encoding: chunked" CRLF
            CRLF
            "1" CRLF
            "1" CRLF
            "0" CRLF CRLF},
        {"GET / HTTP/1.1" CRLF
            "Host: localhost:12345" CRLF
            "Authorization: Basic c2VyZjpzZXJmdGVzdA==" CRLF
            "Transfer-Encoding: chunked" CRLF
            CRLF
            "1" CRLF
            "2" CRLF
            "0" CRLF CRLF}, };
    test_server_action_t action_list[] = {
        {SERVER_RESPOND, "HTTP/1.1 401 Unauthorized" CRLF
            "Transfer-Encoding: chunked" CRLF
            "WWW-Authenticate: Basic realm=""Test Suite""" CRLF
            CRLF
            "1" CRLF CRLF
            "0" CRLF CRLF},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server */
    status = test_http_server_setup(&tb,
                                    message_list, 3,
                                    action_list, 3, 0, NULL,
                                    test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC);
    serf_config_credentials_callback(tb->context, basic_authn_callback);

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;
    num_requests_recvd = 2;

    status = test_helper_run_requests_no_check(tc, tb, num_requests_sent,
                                               handler_ctx, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertIntEquals(tc, num_requests_recvd, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests_recvd, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);

    /* Test that credentials were cached by asserting that the authn callback
       wasn't called again. */
    tb->result_flags = 0;

    create_new_request(tb, &handler_ctx[0], "GET", "/", 2);
    status = test_helper_run_requests_no_check(tc, tb, num_requests_sent,
                                               handler_ctx, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertTrue(tc, !(tb->result_flags & TEST_RESULT_AUTHNCB_CALLED));
}

static apr_status_t
digest_authn_callback(char **username,
                      char **password,
                      serf_request_t *request, void *baton,
                      int code, const char *authn_type,
                      const char *realm,
                      apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (code != 401)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;
    if (strcmp("Digest", authn_type) != 0)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;
    if (strcmp("<http://localhost:12345> Test Suite", realm) != 0)
        return SERF_ERROR_ISSUE_IN_TESTSUITE;

    *username = "serf";
    *password = "serftest";

    return APR_SUCCESS;
}

static void test_digest_authentication(CuTest *tc)
{
    test_baton_t *tb;
    handler_baton_t handler_ctx[2];
    int num_requests_sent, num_requests_recvd;

    /* Expected string relies on strict order of headers and attributes of
       Digest, both are not guaranteed.
       6ff0d4cc201513ce970d5c6b25e1043b is encoded as: 
         md5hex(md5hex("serf:Test Suite:serftest") & ":" &
                md5hex("ABCDEF1234567890") & ":" &
                md5hex("GET:/test/index.html"))
     */
    const test_server_message_t message_list[] = {
        {CHUNKED_REQUEST_URI("/test/index.html", 1, "1")},
        {"GET /test/index.html HTTP/1.1" CRLF
            "Host: localhost:12345" CRLF
            "Authorization: Digest realm=\"Test Suite\", username=\"serf\", "
            "nonce=\"ABCDEF1234567890\", uri=\"/test/index.html\", "
            "response=\"6ff0d4cc201513ce970d5c6b25e1043b\", opaque=\"myopaque\", "
            "algorithm=\"MD5\"" CRLF
            "Transfer-Encoding: chunked" CRLF
            CRLF
            "1" CRLF
            "1" CRLF
            "0" CRLF CRLF}, };
    const test_server_action_t action_list[] = {
        {SERVER_RESPOND, "HTTP/1.1 401 Unauthorized" CRLF
            "Transfer-Encoding: chunked" CRLF
            "WWW-Authenticate: Digest realm=\"Test Suite\","
            "nonce=\"ABCDEF1234567890\",opaque=\"myopaque\","
            "algorithm=\"MD5\",qop-options=\"auth\"" CRLF
            CRLF
            "1" CRLF CRLF
            "0" CRLF CRLF},
        {SERVER_RESPOND, CHUNKED_EMPTY_RESPONSE},
    };
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;

    /* Set up a test context with a server */
    status = test_http_server_setup(&tb,
                                    message_list, 2,
                                    action_list, 2, 0, NULL,
                                    test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Add both Basic and Digest here, should use Digest only. */
    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC | SERF_AUTHN_DIGEST);
    serf_config_credentials_callback(tb->context, digest_authn_callback);

    create_new_request(tb, &handler_ctx[0], "GET", "/test/index.html", 1);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;
    num_requests_recvd = 2;

    status = test_helper_run_requests_no_check(tc, tb, num_requests_sent,
                                               handler_ctx, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertIntEquals(tc, num_requests_recvd, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests_recvd, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

/*****************************************************************************/
CuSuite *test_auth(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_basic_authentication);
    SUITE_ADD_TEST(suite, test_digest_authentication);

    return suite;
}
