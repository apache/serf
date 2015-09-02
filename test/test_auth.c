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

#include <apr_strings.h>

#include "serf.h"
#include "test_serf.h"

static apr_status_t
authn_callback_expect_not_called(char **username,
                                 char **password,
                                 serf_request_t *request, void *baton,
                                 int code, const char *authn_type,
                                 const char *realm,
                                 apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    /* Should not have been called. */
    return REPORT_TEST_SUITE_ERROR();
}

/* Tests that authn fails if all authn schemes are disabled. */
static void test_authentication_disabled(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    apr_status_t status;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_NONE);
    serf_config_credentials_callback(tb->context,
                                     authn_callback_expect_not_called);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
        Respond(WithCode(401), WithChunkedBody("1"),
                WithHeader("WWW-Authenticate", "Basic realm=\"Test Suite\""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    status = run_client_and_mock_servers_loops(tb, 1,
                                               handler_ctx, tb->pool);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
    CuAssertIntEquals(tc, SERF_ERROR_AUTHN_NOT_SUPPORTED, status);
    CuAssertTrue(tc, !(tb->result_flags & TEST_RESULT_AUTHNCB_CALLED));
}

/* Tests that authn fails if encountered an unsupported scheme. */
static void test_unsupported_authentication(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    apr_status_t status;


    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_ALL);
    serf_config_credentials_callback(tb->context,
                                     authn_callback_expect_not_called);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
        Respond(WithCode(401), WithChunkedBody("1"),
                WithHeader("WWW-Authenticate",
                           "NotExistent realm=\"Test Suite\""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    status = run_client_and_mock_servers_loops(tb, 1,
                                               handler_ctx, tb->pool);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
    CuAssertIntEquals(tc, SERF_ERROR_AUTHN_NOT_SUPPORTED, status);
    CuAssertTrue(tc, !(tb->result_flags & TEST_RESULT_AUTHNCB_CALLED));
}

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
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Basic", authn_type) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp(apr_psprintf(pool, "<http://localhost:%d> Test Suite",
                            tb->serv_port), realm) != 0)
        return REPORT_TEST_SUITE_ERROR();

    *username = "serf";
    *password = "serftest";

    return APR_SUCCESS;
}

/* Test template, used for KeepAlive Off and KeepAlive On test */
static void basic_authentication(CuTest *tc, int close_conn)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[2];
    int num_requests_sent;
    apr_status_t status;


    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC);
    serf_config_credentials_callback(tb->context, basic_authn_callback);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;

    /* c2VyZjpzZXJmdGVzdA== is base64 encoded serf:serftest . */
    /* Use non-standard case WWW-Authenticate header and scheme name to test
       for case insensitive comparisons. */
    Given(tb->mh)
      GETRequest(URLEqualTo("/"), HeaderNotSet("Authorization"))
        Respond(WithCode(401),WithChunkedBody("1"),
                WithHeader("www-Authenticate", "bAsIc realm=\"Test Suite\""),
                OnConditionThat(close_conn, WithConnectionCloseHeader))
      GETRequest(URLEqualTo("/"),
                 HeaderEqualTo("Authorization", "Basic c2VyZjpzZXJmdGVzdA=="))
        Respond(WithCode(200),WithChunkedBody(""))
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify

    /* Test that credentials were cached by asserting that the authn callback
       wasn't called again. */
    Given(tb->mh)
      GETRequest(URLEqualTo("/"),
                 HeaderEqualTo("Authorization", "Basic c2VyZjpzZXJmdGVzdA=="))
        Respond(WithCode(200), WithChunkedBody(""))
    Expect
      AllRequestsReceivedInOrder
    EndGiven
    tb->result_flags = 0;

    create_new_request(tb, &handler_ctx[0], "GET", "/", 2);
    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertTrue(tc, !(tb->result_flags & TEST_RESULT_AUTHNCB_CALLED));
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify
}

static void test_basic_authentication(CuTest *tc)
{
    basic_authentication(tc, 0 /* don't close connection */);
}

static void test_basic_authentication_keepalive_off(CuTest *tc)
{
    basic_authentication(tc, 1);
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
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Digest", authn_type) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp(apr_psprintf(pool, "<http://localhost:%d> Test Suite",
                            tb->serv_port), realm) != 0)
        return REPORT_TEST_SUITE_ERROR();

    *username = "serf";
    *password = "serftest";

    return APR_SUCCESS;
}

/* Test template, used for KeepAlive Off and KeepAlive On test */
static void digest_authentication(CuTest *tc, int close_conn)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[2];
    int num_requests_sent;
    apr_status_t status;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Add both Basic and Digest here, should use Digest only. */
    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC | SERF_AUTHN_DIGEST);
    serf_config_credentials_callback(tb->context, digest_authn_callback);

    create_new_request(tb, &handler_ctx[0], "GET", "/test/index.html", 1);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;

    
    /* Expected string relies on strict order of attributes of Digest, which are
       not guaranteed.
       6ff0d4cc201513ce970d5c6b25e1043b is encoded as: 
         md5hex(md5hex("serf:Test Suite:serftest") & ":" &
                md5hex("ABCDEF1234567890") & ":" &
                md5hex("GET:/test/index.html"))
     */
    Given(tb->mh)
      GETRequest(URLEqualTo("/test/index.html"), HeaderNotSet("Authorization"))
        Respond(WithCode(401), WithChunkedBody("1"),
                WithHeader("www-Authenticate", "Digest realm=\"Test Suite\","
                           "nonce=\"ABCDEF1234567890\",opaque=\"myopaque\","
                           "algorithm=\"MD5\",qop-options=\"auth\""),
                OnConditionThat(close_conn, WithConnectionCloseHeader))
      GETRequest(URLEqualTo("/test/index.html"),
                 HeaderEqualTo("Authorization", "Digest realm=\"Test Suite\", "
                               "username=\"serf\", nonce=\"ABCDEF1234567890\", "
                               "uri=\"/test/index.html\", "
                               "response=\"6ff0d4cc201513ce970d5c6b25e1043b\", "
                               "opaque=\"myopaque\", algorithm=\"MD5\""))
        Respond(WithCode(200),WithChunkedBody(""))
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

static void test_digest_authentication(CuTest *tc)
{
    digest_authentication(tc, 0 /* don't close connection */);
}

static void test_digest_authentication_keepalive_off(CuTest *tc)
{
    /* Add the Connection: close header to the response with the Digest headers.
       This to test that the Digest headers will be added to the retry of the
       request on the new connection. */
    digest_authentication(tc, 1);
}

static apr_status_t
switched_realm_authn_callback(char **username,
                              char **password,
                              serf_request_t *request, void *baton,
                              int code, const char *authn_type,
                              const char *realm,
                              apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;
    const char *exp_realm = tb->user_baton;

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (code != 401)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp(exp_realm, realm) != 0)
        return REPORT_TEST_SUITE_ERROR();

    if (strcmp(apr_psprintf(pool, "<http://localhost:%d> Test Suite",
                            tb->serv_port), realm) == 0) {
        *username = "serf";
        *password = "serftest";
    } else {
        *username = "serf_newrealm";
        *password = "serftest";
    }

    return APR_SUCCESS;
}

/* Test template, used for both Basic and Digest switch realms test */
static void authentication_switch_realms(CuTest *tc,
                                         const char *scheme,
                                         const char *authn_attr,
                                         const char *authz_attr_test_suite,
                                         const char *authz_attr_wrong_realm,
                                         const char *authz_attr_new_realm)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[2];
    int num_requests_sent;
    apr_status_t status;

    const char *exp_authz_test_suite = apr_psprintf(tb->pool, "%s %s", scheme,
                                                    authz_attr_test_suite);
    const char *exp_authz_wrong_realm = apr_psprintf(tb->pool, "%s %s", scheme,
                                                     authz_attr_wrong_realm);
    const char *exp_authz_new_realm = apr_psprintf(tb->pool, "%s %s", scheme,
                                                   authz_attr_new_realm);

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC | SERF_AUTHN_DIGEST);
    serf_config_credentials_callback(tb->context,
                                     switched_realm_authn_callback);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    tb->user_baton = apr_psprintf(tb->pool, "<http://localhost:%d> Test Suite",
                                  mhServerPortNr(tb->mh));
    num_requests_sent = 1;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderNotSet("Authorization"))
        Respond(WithCode(401), WithChunkedBody("1"),
                WithHeader("WWW-Authenticate",
                           apr_psprintf(tb->pool, "%s realm=\"Test Suite\"%s",
                                        scheme, authn_attr)))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Authorization", exp_authz_test_suite))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);

    /* Test that credentials were cached by asserting that the authn callback
       wasn't called again. */
    tb->result_flags = 0;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("2"),
                 HeaderEqualTo("Authorization", exp_authz_test_suite))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 2);
    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
    CuAssertTrue(tc, !(tb->result_flags & TEST_RESULT_AUTHNCB_CALLED));

    /* Switch realms. Test that serf asks the application for new
       credentials. */
    tb->result_flags = 0;
    tb->user_baton = apr_psprintf(tb->pool, "<http://localhost:%d> New Realm",
                                  mhServerPortNr(tb->mh));

    Given(tb->mh)
      GETRequest(URLEqualTo("/newrealm/index.html"), ChunkedBodyEqualTo("3"),
                 HeaderEqualTo("Authorization", exp_authz_wrong_realm))
        Respond(WithCode(401), WithChunkedBody("1"),
                WithHeader("WWW-Authenticate",
                           apr_psprintf(tb->pool, "%s realm=\"New Realm\"%s",
                                        scheme, authn_attr)))
    GETRequest(URLEqualTo("/newrealm/index.html"), ChunkedBodyEqualTo("3"),
               HeaderEqualTo("Authorization", exp_authz_new_realm))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/newrealm/index.html", 3);
    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

static void test_basic_switch_realms(CuTest *tc)
{
    authentication_switch_realms(tc, "Basic", "", "c2VyZjpzZXJmdGVzdA==",
                                 "c2VyZjpzZXJmdGVzdA==",
                                 "c2VyZl9uZXdyZWFsbTpzZXJmdGVzdA==");
}

static void test_digest_switch_realms(CuTest *tc)
{
    authentication_switch_realms(tc, "Digest", ",nonce=\"ABCDEF1234567890\","
 "opaque=\"myopaque\", algorithm=\"MD5\",qop-options=\"auth\"",
 /* response hdr attribute for Test Suite realm, uri / */
 "realm=\"Test Suite\", username=\"serf\", nonce=\"ABCDEF1234567890\", "
 "uri=\"/\", response=\"3511a71fec5c02ab1c9212711a8baa58\", "
 "opaque=\"myopaque\", algorithm=\"MD5\"",
 /* response hdr attribute for Test Suite realm, uri /newrealm/index.html */
 "realm=\"Test Suite\", username=\"serf\", nonce=\"ABCDEF1234567890\", "
 "uri=\"/newrealm/index.html\", response=\"c6b673cf44ad16ef379930856b607344\", "
 "opaque=\"myopaque\", algorithm=\"MD5\"",
 /* response hdr attribute for New Realm realm, uri /newrealm/index.html */
 "realm=\"New Realm\", username=\"serf_newrealm\", nonce=\"ABCDEF1234567890\", "
 "uri=\"/newrealm/index.html\", response=\"f93f07d1412e53c421f66741a89198cb\", "
 "opaque=\"myopaque\", algorithm=\"MD5\"");
}

static void test_auth_on_HEAD(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    int num_requests_sent;
    apr_status_t status;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC);
    serf_config_credentials_callback(tb->context, basic_authn_callback);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;

    Given(tb->mh)
      HEADRequest(URLEqualTo("/"), BodyEqualTo(""),
                  HeaderNotSet("Authorization"))
        Respond(WithCode(401), WithBody(""),
                WithHeader("WWW-Authenticate", "Basic Realm=\"Test Suite\""))
      HEADRequest(URLEqualTo("/"), BodyEqualTo(""),
                  HeaderEqualTo("Authorization", "Basic c2VyZjpzZXJmdGVzdA=="))
        Respond(WithCode(200), WithBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "HEAD", "/", -1);

    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);
    Verify(tb->mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

/*****************************************************************************/
CuSuite *test_auth(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_authentication_disabled);
    SUITE_ADD_TEST(suite, test_unsupported_authentication);
    SUITE_ADD_TEST(suite, test_basic_authentication);
    SUITE_ADD_TEST(suite, test_basic_authentication_keepalive_off);
    SUITE_ADD_TEST(suite, test_digest_authentication);
    SUITE_ADD_TEST(suite, test_digest_authentication_keepalive_off);
    SUITE_ADD_TEST(suite, test_basic_switch_realms);
    SUITE_ADD_TEST(suite, test_digest_switch_realms);
    SUITE_ADD_TEST(suite, test_auth_on_HEAD);

    return suite;
}
