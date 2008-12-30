/* Copyright 2008 Justin Erenkrantz and Greg Stein
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

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_types.h"

#include "test_serf.h"

#if defined(WIN32) && defined(_DEBUG)
/* Include this file to allow running a Debug build of serf with a Release
   build of OpenSSL. */
#include <openssl/applink.c>
#endif

/* Test that loading a custom CA certificate file works. */
static void test_ssl_load_cert_file(CuTest *tc)
{
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status = serf_ssl_load_cert_file(&cert, "test/serftestca.pem",
                                                  test_pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);
}

/* Test that reading a custom CA certificate file works. */
static void test_ssl_cert_subject(CuTest *tc)
{
    apr_pool_t *subpool;
    apr_hash_t *subject;
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status;

    apr_pool_create(&subpool, test_pool);
    status = serf_ssl_load_cert_file(&cert, "test/serftestca.pem", subpool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    subject = serf_ssl_cert_subject(cert, subpool);
    CuAssertStrEquals(tc, "Test Suite", 
                      apr_hash_get(subject, "OU", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "In Serf we trust, Inc.", 
                      apr_hash_get(subject, "O", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Mechelen", 
                      apr_hash_get(subject, "L", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Antwerp", 
                      apr_hash_get(subject, "ST", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "BE", 
                      apr_hash_get(subject, "C", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "serf@example.com", 
                      apr_hash_get(subject, "E", APR_HASH_KEY_STRING));

    apr_pool_destroy(subpool);
}

CuSuite *test_ssl(void)
{
    CuSuite *suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_ssl_load_cert_file);
    SUITE_ADD_TEST(suite, test_ssl_cert_subject);

    return suite;
}
