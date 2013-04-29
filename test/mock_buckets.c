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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "test_serf.h"

/* This bucket uses a list of count - data/len - status actions (provided by the
   test case), to control the read / read_iovec operations. */
typedef struct {
    mockbkt_action *actions;
    int len;
    const char *current_data;
    int remaining_data;
    int current_action;
    int current_remaining;
} mockbkt_context_t;

serf_bucket_t *serf_bucket_mock_create(mockbkt_action *actions,
                                       int len,
                                       serf_bucket_alloc_t *allocator)
{
    mockbkt_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->actions = actions;
    ctx->len = len;
    ctx->current_data = 0l;
    ctx->remaining_data = -1;
    ctx->current_action = 0;
    ctx->current_remaining = -1;

    return serf_bucket_create(&serf_bucket_type_mock, allocator, ctx);
}

static apr_status_t next_action(mockbkt_context_t *ctx)
{
    mockbkt_action *action;

    while (1)
    {
        if (ctx->current_action >= ctx->len)
            return APR_EOF;

        action = &ctx->actions[ctx->current_action];

        if (ctx->current_remaining == 0) {
            ctx->current_action++;
            ctx->current_remaining = -1;
            ctx->remaining_data = 0;
            continue;
        }

        if (ctx->current_remaining == -1) {
            ctx->current_data = action->data;
            ctx->current_remaining = action->times;
            ctx->remaining_data = action->len;
        }

        return APR_SUCCESS;
    }
}

static apr_status_t serf_mock_readline(serf_bucket_t *bucket,
                                       int acceptable, int *found,
                                       const char **data, apr_size_t *len)
{
    mockbkt_context_t *ctx = bucket->data;
    mockbkt_action *action;
    apr_status_t status;

    status = next_action(ctx);
    if (status)
        return status;

    action = &ctx->actions[ctx->current_action];
    *data = ctx->current_data;
    *len = ctx->remaining_data;

    ctx->current_remaining--;

    serf_util_readline(data, len,
                       acceptable, found);

    /* See how much ctx->current moved forward. */
    *len = *data - ctx->current_data;
    *data = ctx->current_data;
    ctx->remaining_data -= *len;

    return ctx->remaining_data ? APR_SUCCESS : action->status;
}

static apr_status_t serf_mock_read(serf_bucket_t *bucket,
                                   apr_size_t requested,
                                   const char **data, apr_size_t *len)
{
    mockbkt_context_t *ctx = bucket->data;
    mockbkt_action *action;
    apr_status_t status;

    status = next_action(ctx);
    if (status)
        return status;

    action = &ctx->actions[ctx->current_action];
    *len = action->len;
    *data = action->data;
    ctx->current_remaining--;

    return action->status;
}

static apr_status_t serf_mock_peek(serf_bucket_t *bucket,
                                   const char **data,
                                   apr_size_t *len)
{
    mockbkt_context_t *ctx = bucket->data;
    mockbkt_action *action;
    apr_status_t status;

    status = next_action(ctx);
    if (status)
        return status;

    action = &ctx->actions[ctx->current_action];
    *len = action->len;
    *data = action->data;

    /* peek only returns an error, APR_EOF or APR_SUCCESS.
       APR_EAGAIN is returned as APR_SUCCESS. */
    if (SERF_BUCKET_READ_ERROR(action->status))
        return status;

    return action->status == APR_EOF ? APR_EOF : APR_SUCCESS;
}

const serf_bucket_type_t serf_bucket_type_mock = {
    "MOCK",
    serf_mock_read,
    serf_mock_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_mock_peek,
    serf_default_destroy_and_data,
};


/* internal test for the mock buckets */
static void test_basic_mock_bucket(CuTest *tc)
{
    serf_bucket_t *mock_bkt;
    apr_pool_t *test_pool = test_setup();
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(test_pool, NULL,
                                                              NULL);

    /* read one line */
    {
        mockbkt_action actions[]= {
            { 1, "HTTP/1.1 200 OK" CRLF, 17, APR_EOF },
        };
        mock_bkt = serf_bucket_mock_create(actions, 1, alloc);
        read_and_check_bucket(tc, mock_bkt,
                              "HTTP/1.1 200 OK" CRLF);

        mock_bkt = serf_bucket_mock_create(actions, 1, alloc);
        readlines_and_check_bucket(tc, mock_bkt, SERF_NEWLINE_CRLF,
                                   "HTTP/1.1 200 OK" CRLF, 1);
    }
    /* read multiple lines */
    {
        mockbkt_action actions[]= {
            { 1, "HTTP/1.1 200 OK" CRLF, 17, APR_SUCCESS },
            { 1, "Content-Type: text/plain" CRLF, 26, APR_EOF },
        };
        mock_bkt = serf_bucket_mock_create(actions, 2, alloc);
        readlines_and_check_bucket(tc, mock_bkt, SERF_NEWLINE_CRLF,
                                   "HTTP/1.1 200 OK" CRLF
                                   "Content-Type: text/plain" CRLF, 2);
    }
    /* read empty line */
    {
        mockbkt_action actions[]= {
            { 1, "HTTP/1.1 200 OK" CRLF, 17, APR_SUCCESS },
            { 1, "", 0, APR_EAGAIN },
            { 1, "Content-Type: text/plain" CRLF, 26, APR_EOF },
        };
        mock_bkt = serf_bucket_mock_create(actions, 3, alloc);
        read_and_check_bucket(tc, mock_bkt,
                              "HTTP/1.1 200 OK" CRLF
                              "Content-Type: text/plain" CRLF);
        mock_bkt = serf_bucket_mock_create(actions, 3, alloc);
        readlines_and_check_bucket(tc, mock_bkt, SERF_NEWLINE_CRLF,
                                   "HTTP/1.1 200 OK" CRLF
                                   "Content-Type: text/plain" CRLF, 2);
    }

    /* read empty line */
    {
        mockbkt_action actions[]= {
            { 1, "HTTP/1.1 200 OK" CR, 16, APR_SUCCESS },
            { 1, "", 0, APR_EAGAIN },
            { 1, LF, 1, APR_EOF },
        };
        mock_bkt = serf_bucket_mock_create(actions,
                                           sizeof(actions)/sizeof(actions[0]),
                                           alloc);
        read_and_check_bucket(tc, mock_bkt,
                              "HTTP/1.1 200 OK" CRLF);

        mock_bkt = serf_bucket_mock_create(actions,
                                           sizeof(actions)/sizeof(actions[0]),
                                           alloc);
        readlines_and_check_bucket(tc, mock_bkt, SERF_NEWLINE_CRLF,
                                   "HTTP/1.1 200 OK" CRLF, 1);
    }

    test_teardown(test_pool);
}

CuSuite *test_mock_bucket(void)
{
    CuSuite *suite = CuSuiteNew();

    SUITE_ADD_TEST(suite, test_basic_mock_bucket);

    return suite;
}
