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

/* These test cases have access to internal functions. */
#include "serf_private.h"
#include "serf_bucket_util.h"

static void test_config_store_per_context(CuTest *tc)
{
    apr_pool_t *test_pool = tc->testBaton;
    serf_config_t *cfg;

    serf_context_t *ctx = serf_context_create(test_pool);

    /* The config store is empty initially, so we can play all we want */

    /* We don't have a serf connection yet, so only the per context config
       should be available to read and write */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_from_store(ctx, NULL, &cfg, test_pool));
    CuAssertPtrEquals(tc, NULL, cfg->per_conn);
    CuAssertPtrEquals(tc, NULL, cfg->per_host);
    CuAssertPtrNotNull(tc, cfg->per_context);

    /* Get a non-existing key, value should be NULL */
    {
        char *actual;

        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_get_config_string(cfg, SERF_CONFIG_PER_CONTEXT,
                                                 "unknown_key", &actual));
        CuAssertPtrEquals(tc, NULL, actual);
    }

    /* Store and retrieve a string value for a per-context key */
    {
        char *actual;

        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_set_config_string(cfg, SERF_CONFIG_PER_CONTEXT,
                              "test_key", "test_value", SERF_CONFIG_NO_COPIES));
        CuAssertIntEquals(tc, APR_SUCCESS,
                          serf_get_config_string(cfg, SERF_CONFIG_PER_CONTEXT,
                                                 "test_key", &actual));
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
    apr_pool_t *test_pool = tc->testBaton;
    serf_config_t *cfg1, *cfg2;
    apr_uri_t url;
    char *actual;

    serf_context_t *ctx = serf_context_create(test_pool);
    serf_connection_t *conn1, *conn2;

    /* Create two connections conn1 and conn2 to a different host */
    apr_uri_parse(test_pool, "http://localhost:12345", &url);
    serf_connection_create2(&conn1, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, test_pool);
    apr_uri_parse(test_pool, "http://localhost:54321", &url);
    serf_connection_create2(&conn2, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, test_pool);

    /* Test 1: This should return a config object with per_context, per_host and
       per_connection hash_table's initialized. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_from_store(ctx, conn1, &cfg1, test_pool));
    CuAssertPtrNotNull(tc, cfg1->per_context);
    CuAssertPtrNotNull(tc, cfg1->per_host);
    CuAssertPtrNotNull(tc, cfg1->per_conn);
    /* Get a config object for the other connection also. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_from_store(ctx, conn2, &cfg2, test_pool));

    /* Test 2: Get a non-existing per connection key, value should be NULL */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                                             "unknown_key", &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 3: Store and retrieve a string value for a per-connection key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_set_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                          "test_key", "test_value", SERF_CONFIG_NO_COPIES));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                                             "test_key", &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was set in the config for the first connection only. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg2, SERF_CONFIG_PER_CONNECTION,
                                             "test_key", &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 4: Store and retrieve a string value for a per-host key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_set_config_string(cfg1, SERF_CONFIG_PER_HOST,
                          "test_key", "test_value", SERF_CONFIG_NO_COPIES));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_HOST,
                          "test_key", &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was NOT set in the config for the second connection,
       since they are to a different host. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg2, SERF_CONFIG_PER_HOST,
                          "test_key", &actual));
    CuAssertPtrEquals(tc, NULL, actual);
}

static void test_config_store_per_connection_same_host(CuTest *tc)
{
    apr_pool_t *test_pool = tc->testBaton;
    serf_config_t *cfg1, *cfg2;
    apr_uri_t url;
    char *actual;

    serf_context_t *ctx = serf_context_create(test_pool);
    serf_connection_t *conn1, *conn2;

    /* Create two connections conn1 and conn2 to the same host */
    apr_uri_parse(test_pool, "http://localhost:12345", &url);
    serf_connection_create2(&conn1, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, test_pool);
    serf_connection_create2(&conn2, ctx, url, conn_setup, NULL,
                            conn_closed, NULL, test_pool);

    /* Test 1: This should return a config object with per_context, per_host and
     per_connection hash_table's initialized. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_from_store(ctx, conn1, &cfg1, test_pool));
    CuAssertPtrNotNull(tc, cfg1->per_context);
    CuAssertPtrNotNull(tc, cfg1->per_host);
    CuAssertPtrNotNull(tc, cfg1->per_conn);
    /* Get a config object for the other connection also. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_from_store(ctx, conn2, &cfg2, test_pool));

    /* Test 2: Get a non-existing per connection key, value should be NULL */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                                             "unknown_key", &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 3: Store and retrieve a string value for a per-connection key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_set_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                          "test_key", "test_value", SERF_CONFIG_NO_COPIES));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_CONNECTION,
                                             "test_key", &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was set in the config for the first connection only. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg2, SERF_CONFIG_PER_CONNECTION,
                                             "test_key", &actual));
    CuAssertPtrEquals(tc, NULL, actual);

    /* Test 4: Store and retrieve a string value for a per-host key */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_set_config_string(cfg1, SERF_CONFIG_PER_HOST,
                          "test_key", "test_value", SERF_CONFIG_NO_COPIES));
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg1, SERF_CONFIG_PER_HOST,
                                             "test_key", &actual));
    CuAssertStrEquals(tc, "test_value", actual);

    /* Test that the key was also set in the config for the second connection,
       since they are the same host. */
    CuAssertIntEquals(tc, APR_SUCCESS,
                      serf_get_config_string(cfg2, SERF_CONFIG_PER_HOST,
                                             "test_key", &actual));
    CuAssertStrEquals(tc, "test_value", actual);
}


CuSuite *test_internal(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_config_store_per_context);
    SUITE_ADD_TEST(suite, test_config_store_per_connection_different_host);
    SUITE_ADD_TEST(suite, test_config_store_per_connection_same_host);

    return suite;
}
