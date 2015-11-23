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

#include "apr.h"
#include "apr_pools.h"
#include <apr_signal.h>

#include "test_serf.h"
#include <stdlib.h>

static const struct testlist {
    const char *testname;
    CuSuite *(*func)(void);
} tests[] = {
    {"context",     test_context},
    {"buckets",     test_buckets},
    {"ssl",         test_ssl},
    {"auth",        test_auth},
    {"internal",    test_internal},
    {"server",      test_server},
#if 0
    /* internal test for the mock bucket. */
    {"mock",    test_mock_bucket},
#endif
    {"LastTest", NULL}
};

int main(int argc, char *argv[])
{
    CuSuite *alltests = NULL;
    CuString *output = CuStringNew();
    int i;
    int list_provided = 0;
    int exit_code;

    apr_initialize();
    atexit(apr_terminate);

#ifdef SIGPIPE
    /* Disable SIGPIPE generation for the platforms that have it. */
    apr_signal(SIGPIPE, SIG_IGN);
#endif

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) {
            continue;
        }
        if (!strcmp(argv[i], "-l")) {
            for (i = 0; tests[i].func != NULL; i++) {
                CuSuite *suite;
                int j = 0;

                printf("%s\n", tests[i].testname);
                suite = tests[i].func();

                for (j = 0; j < suite->count; j++) {
                    printf("  %3d - %s\n", j+1, suite->list[j]->name);
                }

                printf("\n");
            }
            exit(0);
        }
        if (argv[i][0] == '-') {
            fprintf(stderr, "invalid option: `%s'\n", argv[i]);
            exit(1);
        }
        list_provided = 1;
    }

    alltests = CuSuiteNew();
    if (!list_provided) {
        /* add everything */
        for (i = 0; tests[i].func != NULL; i++) {
            CuSuite *st = tests[i].func();
            CuSuiteAddSuite(alltests, st);
            CuSuiteFree(st);
        }
    }
    else {
        /* add only the tests listed */
        for (i = 1; i < argc; i++) {
            int j;
            int found = 0;
            const char *sh;
            apr_size_t len;

            if (argv[i][0] == '-') {
                continue;
            }

            sh = strchr(argv[i], '#');
            if (!sh)
                len = strlen(argv[i]);
            else {
                len = sh - argv[i];
                sh++;
            }

            for (j = 0; tests[j].func != NULL; j++) {

                if (strncmp(argv[i], tests[j].testname, len) == 0
                    && tests[j].testname[len] == '\0')
                {
                    CuSuite *suite = tests[j].func();

                    if (sh) {
                        int k, m = 0;

                        for (k = 0; k < suite->count; k++) {
                            if (!strcmp(suite->list[k]->name, sh)) {
                                suite->list[m++] = suite->list[k];
                            }
                            else
                                CuTestFree(suite->list[k]);
                        }
                        suite->count = m;
                    }

                    if (suite->count) {
                        CuSuiteAddSuite(alltests, suite);
                        found = 1;
                    }
                }
            }
            if (!found) {
                fprintf(stderr, "invalid test name: `%s'\n", argv[i]);
                exit(1);
            }
        }
    }

    CuSuiteRun2(alltests, TRUE);
    /* CuSuiteSummary(alltests, output); */
    CuSuiteDetails(alltests, output);
    printf("%s\n", output->buffer);

    exit_code = alltests->failCount > 0 ? 1 : 0;

    CuSuiteFreeDeep(alltests);
    CuStringFree(output);

    return exit_code;
}
