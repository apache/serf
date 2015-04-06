/* Copyright 2014 Justin Erenkrantz and Greg Stein
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
#include "serf_bucket_util.h"

#include "test/test_serf.h"

typedef struct mock_sock_context_t {
    apr_status_t eof_status;
    serf_bucket_t *stream;
} mock_sock_context_t;

serf_bucket_t *serf_bucket_mock_sock_create(serf_bucket_t *stream,
                                            apr_status_t eof_status,
                                            serf_bucket_alloc_t *allocator)
{
    mock_sock_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->stream = stream;
    ctx->eof_status = eof_status;

    return serf_bucket_create(&serf_bucket_type_mock_socket, allocator, ctx);
}

static apr_status_t serf_mock_sock_readline(serf_bucket_t *bucket,
                                            int acceptable, int *found,
                                            const char **data, apr_size_t *len)
{
    mock_sock_context_t *ctx = bucket->data;
    apr_status_t status = serf_bucket_readline(ctx->stream, acceptable, found,
                                               data, len);
    if (status == APR_EOF)
        status = ctx->eof_status;
    return status;
}

static apr_status_t serf_mock_sock_read(serf_bucket_t *bucket,
                                        apr_size_t requested,
                                        const char **data, apr_size_t *len)
{
    mock_sock_context_t *ctx = bucket->data;
    apr_status_t status = serf_bucket_read(ctx->stream, requested, data, len);
    if (status == APR_EOF)
        status = ctx->eof_status;
    return status;
}

static apr_status_t serf_mock_sock_peek(serf_bucket_t *bucket,
                                        const char **data,
                                        apr_size_t *len)
{
    mock_sock_context_t *ctx = bucket->data;
    apr_status_t status = serf_bucket_peek(ctx->stream, data, len);
    if (status == APR_EOF)
        status = ctx->eof_status;
    return status;
}

static apr_status_t serf_mock_sock_set_config(serf_bucket_t *bucket,
                                              serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
       it along to our wrapped bucket. */
    mock_sock_context_t *ctx = bucket->data;

    return serf_bucket_set_config(ctx->stream, config);
}

const serf_bucket_type_t serf_bucket_type_mock_socket = {
    "MOCK_SOCKET",
    serf_mock_sock_read,
    serf_mock_sock_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_mock_sock_peek,
    serf_default_destroy_and_data,
    serf_default_read_bucket,
    serf_mock_sock_set_config,
};
