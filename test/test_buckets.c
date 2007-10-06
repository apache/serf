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

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

#include "serf.h"
#include "test_serf.h"

#define CRLF "\r\n"

static void test_simple_bucket(CuTest *tc)
{
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(test_pool, NULL, NULL);
    apr_status_t status;
    serf_bucket_t *bkt;
    const char *data;
    int found;
    apr_size_t len;

    bkt = SERF_BUCKET_SIMPLE_STRING(
        "line1" CRLF
        "line2",
        alloc);

    /* Initialize parameters to check that they will be initialized. */
    len = 0x112233;
    data = 0;
    status = serf_bucket_readline(bkt, SERF_NEWLINE_CRLF, &found, &data, &len);

    CuAssertIntEquals(tc, status, APR_SUCCESS);
    CuAssertIntEquals(tc, found, SERF_NEWLINE_CRLF);
    CuAssertIntEquals(tc, len, 7);
    CuAssert(tc, data, strncmp("line1" CRLF, data, len) == 0);

    /* Initialize parameters to check that they will be initialized. */
    len = 0x112233;
    data = 0;
    status = serf_bucket_readline(bkt, SERF_NEWLINE_CRLF, &found, &data, &len);

    CuAssertIntEquals(tc, status, APR_EOF);
    CuAssertIntEquals(tc, found, SERF_NEWLINE_NONE);
    CuAssertIntEquals(tc, len, 5);
    CuAssert(tc, data, strncmp("line2", data, len) == 0);
}

CuSuite *test_buckets(void)
{
    CuSuite *suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_simple_bucket);

    return suite;
}