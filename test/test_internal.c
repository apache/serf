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

#include <apr_version.h>
#include <apr_strings.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>

#if APR_VERSION_MAJOR < 2
#include <apu_version.h>
#endif


#include "serf.h"
#include "test_serf.h"

/* These test cases have access to internal functions. */
#include "serf_private.h"
#include "serf_bucket_util.h"

#define PER_CONN_UNKNOWN_KEY    SERF_CONFIG_PER_CONNECTION | 0xFF0001
/* #define PER_HOST_UNKNOWN_KEY    SERF_CONFIG_PER_HOST | 0xFF0002 */
#define PER_CONTEXT_UNKNOWN_KEY SERF_CONFIG_PER_CONTEXT | 0xFF0003
#define PER_CONN_TEST_KEY       SERF_CONFIG_PER_CONNECTION | 0xFFFFFF
#define PER_HOST_TEST_KEY       SERF_CONFIG_PER_HOST | 0xFFFFFF
#define PER_CONTEXT_TEST_KEY    SERF_CONFIG_PER_CONTEXT | 0xFFFFFF

static void test_config_store_per_context(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_config_t *cfg;

    serf_context_t *ctx = serf_context_create(tb->pool);

    /* The config store is empty initially, so we can play all we want */

    /* We don't have a serf connection yet, so only the per context config
       should be available to read and write */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_ctx_config(ctx, &cfg, tb->pool));
    CuAssertPtrEquals(tc, NULL, cfg->per_conn);
    CuAssertPtrEquals(tc, NULL, cfg->per_host);
    CuAssertPtrNotNull(tc, cfg->per_context);

    /* Get a non-existing key, value should be NULL */
    {
        const char *actual;

        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_config_get_string(cfg, PER_CONTEXT_UNKNOWN_KEY,
                                                 &actual));
        CuAssertPtrEquals(tc, NULL, actual);
    }

    /* Store and retrieve a string value for a per-context key */
    {
        const char *actual;

        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_config_set_string(cfg, PER_CONTEXT_TEST_KEY,
                                                 "test_value"));
        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_config_get_string(cfg, PER_CONTEXT_TEST_KEY,
                                                 &actual));
        CuAssertStrEquals(tc, "test_value", actual);
    }
}

/* Empty implementations, they won't be called. */
static void conn_closed(serf_connection_t *conn, void *closed_baton,
                        apr_status_t why, apr_pool_t *pool)
{
}

static apr_status_t conn_setup(apr_socket_t *skt,
                               serf_bucket_t **input_bkt,
                               serf_bucket_t **output_bkt,
                               void *setup_baton,
                               apr_pool_t *pool)
{
    return APR_SUCCESS;
}

static void test_config_store_per_connection_different_host(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_config_t *cfg1, *cfg2;
    apr_uri_t url;
    const char *actual;

    serf_context_t *ctx = serf_context_create(tb->pool);
    serf_connection_t *conn1, *conn2;

    /* Create two connections conn1 and conn2 to a different host */
    apr_uri_parse(tb->pool, "http://localhost:12345", &url);
    serf_connection_create2(&conn1, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, tb->pool);
    apr_uri_parse(tb->pool, "http://localhost:54321", &url);
    serf_connection_create2(&conn2, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, tb->pool);

    /* Test 1: This should return a config object with per_context, per_host and
       per_connection hash_table's initialized. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_conn_config(conn1, &cfg1,
                                                            tb->pool));
    CuAssertPtrNotNull(tc, cfg1->per_context);
    CuAssertPtrNotNull(tc, cfg1->per_host);
    CuAssertPtrNotNull(tc, cfg1->per_conn);
    /* Get a config object for the other connection also. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_conn_config(conn2, &cfg2,
                                                            tb->pool));

    /* Test 2: Get a non-existing per connection key, value should be NULL */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_CONN_UNKNOWN_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 3: Store and retrieve a string value for a per-connection key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg1, PER_CONN_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_CONN_TEST_KEY, &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was set in the config for the first connection only. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg2, PER_CONN_TEST_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 4: Store and retrieve a string value for a per-host key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg1, PER_HOST_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_HOST_TEST_KEY, &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was NOT set in the config for the second connection,
       since they are to a different host. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg2, PER_HOST_TEST_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);
}

static void test_config_store_per_connection_same_host(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_config_t *cfg1, *cfg2;
    apr_uri_t url;
    const char *actual;

    serf_context_t *ctx = serf_context_create(tb->pool);
    serf_connection_t *conn1, *conn2;

    /* Create two connections conn1 and conn2 to the same host */
    apr_uri_parse(tb->pool, "http://localhost:12345", &url);
    serf_connection_create2(&conn1, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, tb->pool);
    serf_connection_create2(&conn2, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, tb->pool);

    /* Test 1: This should return a config object with per_context, per_host and
     per_connection hash_table's initialized. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_conn_config(conn1, &cfg1,
                                                            tb->pool));
    CuAssertPtrNotNull(tc, cfg1->per_context);
    CuAssertPtrNotNull(tc, cfg1->per_host);
    CuAssertPtrNotNull(tc, cfg1->per_conn);
    /* Get a config object for the other connection also. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_conn_config(conn2, &cfg2,
                                                            tb->pool));

    /* Test 2: Get a non-existing per connection key, value should be NULL */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_CONN_UNKNOWN_KEY,
                                             &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 3: Store and retrieve a string value for a per-connection key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg1, PER_CONN_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_CONN_TEST_KEY, &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was set in the config for the first connection only. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg2, PER_CONN_TEST_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 4: Store and retrieve a string value for a per-host key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg1, PER_HOST_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg1, PER_HOST_TEST_KEY, &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was also set in the config for the second connection,
       since they are the same host. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg2, PER_HOST_TEST_KEY, &actual));
    CuAssertStrEquals(tc, "test_value", actual);
}

static void test_config_store_error_handling(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_config_t *cfg;
    const char *actual;
    void *actual_obj;

    serf_context_t *ctx = serf_context_create(tb->pool);

    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_ctx_config(ctx, &cfg,
                                                           tb->pool));

    /* Config only has per-context keys, check for no crashes when getting
       per-connection and per-host keys. */
    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_get_string(cfg, PER_HOST_TEST_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_get_string(cfg, PER_CONN_TEST_KEY, &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_set_string(cfg, PER_CONN_TEST_KEY,
                                             "test_value"));

    /* The same tests with objects instead of strings */
    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_get_object(cfg, PER_HOST_TEST_KEY, &actual_obj));
    CuAssertPtrEquals(tc, NULL, actual_obj);

    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_get_object(cfg, PER_CONN_TEST_KEY, &actual_obj));
    CuAssertPtrEquals(tc, NULL, actual_obj);

    CuAssertIntEquals(tc, APR_EINVAL,
                      serf_config_set_object(cfg, PER_CONN_TEST_KEY, stderr));
}

static void test_config_store_remove_objects(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_config_t *cfg;
    serf_connection_t *conn;
    apr_uri_t url;
    const char *actual;

    serf_context_t *ctx = serf_context_create(tb->pool);

    /* Create a connection conn */
    apr_uri_parse(tb->pool, "http://localhost:12345", &url);
    serf_connection_create2(&conn, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, tb->pool);

    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf__config_store_create_conn_config(conn, &cfg,
                                                            tb->pool));

    /* Add and remove a key per-context */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg, PER_CONTEXT_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_remove_value(cfg, PER_CONTEXT_TEST_KEY));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg, PER_CONTEXT_TEST_KEY,
                                             &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Add and remove a key per-context */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg, PER_HOST_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_remove_value(cfg, PER_HOST_TEST_KEY));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg, PER_HOST_TEST_KEY,
                                             &actual));
    CuAssertPtrEquals(tc, NULL, actual);


    /* Add and remove a key per-context */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_set_string(cfg, PER_CONN_TEST_KEY,
                                             "test_value"));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_remove_value(cfg, PER_CONN_TEST_KEY));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_config_get_string(cfg, PER_CONN_TEST_KEY,
                                             &actual));
    CuAssertPtrEquals(tc, NULL, actual);
}

/* Add and remove some headers from the headers bucket. */
/* Note: serf__bucket_headers_remove is an internal function */
static void test_header_buckets_remove(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_bucket_alloc_t *alloc = test__create_bucket_allocator(tc, tb->pool);
    const char *cur;

    serf_bucket_t *hdrs = serf_bucket_headers_create(alloc);
    CuAssertTrue(tc, hdrs != NULL);

    /* empty bucket, delete header */
    serf__bucket_headers_remove(hdrs, "Content-Length");

    /* bucket with one header, delete a non-existant header */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf__bucket_headers_remove(hdrs, "Content-Length");
    cur = "Content-Type: text/plain" CRLF CRLF;
    read_and_check_bucket(tc, hdrs, cur);

    serf_bucket_destroy(hdrs);
    hdrs = serf_bucket_headers_create(alloc);

    /* bucket with one header, delete it */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf__bucket_headers_remove(hdrs, "Content-Type");
    cur = CRLF;
    read_and_check_bucket(tc, hdrs, cur);

    serf_bucket_destroy(hdrs);
    hdrs = serf_bucket_headers_create(alloc);

    /* bucket with two headers, delete the first */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf_bucket_headers_set(hdrs, "Content-Length", "100");
    serf__bucket_headers_remove(hdrs, "Content-Type");
    cur = "Content-Length: 100" CRLF CRLF;
    read_and_check_bucket(tc, hdrs, cur);

    serf_bucket_destroy(hdrs);
    hdrs = serf_bucket_headers_create(alloc);

    /* bucket with two headers, delete the second */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf_bucket_headers_set(hdrs, "Content-Length", "100");
    serf__bucket_headers_remove(hdrs, "Content-Length");
    cur = "Content-Type: text/plain" CRLF CRLF;
    read_and_check_bucket(tc, hdrs, cur);

    serf_bucket_destroy(hdrs);
    hdrs = serf_bucket_headers_create(alloc);

    /* bucket with more headers, delete one in the middle */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf_bucket_headers_set(hdrs, "Content-Location", "/");
    serf_bucket_headers_set(hdrs, "Content-Length", "100");
    serf__bucket_headers_remove(hdrs, "Content-Location");
    cur = "Content-Type: text/plain" CRLF
    "Content-Length: 100" CRLF CRLF;
    read_and_check_bucket(tc, hdrs, cur);

    serf_bucket_destroy(hdrs);
    hdrs = serf_bucket_headers_create(alloc);

    /* bucket with more headers, delete more in the middle */
    serf_bucket_headers_set(hdrs, "Content-Type", "text/plain");
    serf_bucket_headers_set(hdrs, "Content-Location", "/");
    serf_bucket_headers_set(hdrs, "Content-Location", "/bla");
    serf_bucket_headers_set(hdrs, "Content-Length", "100");
    serf_bucket_headers_set(hdrs, "Content-Location", "/blub");
    serf__bucket_headers_remove(hdrs, "Content-Location");
    cur = "Content-Type: text/plain" CRLF
    "Content-Length: 100" CRLF CRLF;
    read_and_check_bucket(tc, hdrs, cur);
    serf_bucket_destroy(hdrs);
}

static void test_runtime_versions(CuTest *tc)
{
  apr_version_t version_of_apr;
#if APR_MAJOR_VERSION < 2
  apr_version_t version_of_aprutil;
#endif

  apr_version(&version_of_apr);

  CuAssertIntEquals(tc, APR_MAJOR_VERSION, version_of_apr.major);
  CuAssertTrue(tc, version_of_apr.minor >= APR_MINOR_VERSION);

  if (version_of_apr.minor == APR_MINOR_VERSION)
    CuAssertTrue(tc, version_of_apr.patch >= APR_PATCH_VERSION);

#if APR_MAJOR_VERSION < 2
  apu_version(&version_of_aprutil);

  CuAssertIntEquals(tc, APU_MAJOR_VERSION, version_of_aprutil.major);
  CuAssertTrue(tc, version_of_aprutil.minor >= APU_MINOR_VERSION);

  if (version_of_aprutil.minor == APU_MINOR_VERSION)
    CuAssertTrue(tc, version_of_aprutil.patch >= APU_PATCH_VERSION);

  CuAssertIntEquals(tc, APR_MAJOR_VERSION, APU_MAJOR_VERSION);
#endif
}

CuSuite *test_internal(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_config_store_per_context);
    SUITE_ADD_TEST(suite, test_config_store_per_connection_different_host);
    SUITE_ADD_TEST(suite, test_config_store_per_connection_same_host);
    SUITE_ADD_TEST(suite, test_config_store_error_handling);
    SUITE_ADD_TEST(suite, test_config_store_remove_objects);
    SUITE_ADD_TEST(suite, test_header_buckets_remove);
    SUITE_ADD_TEST(suite, test_runtime_versions);

    return suite;
}
