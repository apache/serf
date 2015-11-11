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

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

typedef apr_status_t(*serf_bucket_event_callback_t)(void *baton);

typedef struct event_context_t
{
    void *baton;
    serf_bucket_event_callback_t eof_cb;
    serf_bucket_event_callback_t destroy_cb;
} event_context_t;

serf_bucket_t *serf__bucket_event_create(
                          void *baton,
                          serf_bucket_event_callback_t eof_cb,
                          serf_bucket_event_callback_t destroy_cb,
                          serf_bucket_alloc_t *allocator)
{
    event_context_t *ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->baton = baton;
    ctx->eof_cb = eof_cb;
    ctx->destroy_cb = destroy_cb;

    return serf_bucket_create(&serf_bucket_type__event, allocator, ctx);
}

static apr_status_t serf_event_read(serf_bucket_t *bucket,
                                    apr_size_t requested,
                                    const char **data,
                                    apr_size_t *len)
{
    event_context_t *ctx = bucket->data;
    apr_status_t status = APR_EOF;
    *data = NULL;
    *len = 0;

    if (ctx->eof_cb)
        status = ctx->eof_cb(ctx->baton);

    return status ? status : APR_EOF;
}

static apr_status_t serf_event_readline(serf_bucket_t *bucket,
                                        int acceptable, int *found,
                                        const char **data, apr_size_t *len)
{
    event_context_t *ctx = bucket->data;
    apr_status_t status = APR_EOF;
    *found = 0;
    *data = NULL;
    *len = 0;

    if (ctx->eof_cb)
        status = ctx->eof_cb(ctx->baton);

    return status ? status : APR_EOF;
}

static apr_status_t serf_event_read_iovec(serf_bucket_t *bucket,
                                          apr_size_t requested,
                                          int vecs_size,
                                          struct iovec *vecs,
                                          int *vecs_used)
{
    event_context_t *ctx = bucket->data;
    apr_status_t status = APR_EOF;
    *vecs_used = 0;

    if (ctx->eof_cb)
        status = ctx->eof_cb(ctx->baton);

    return status ? status : APR_EOF;
}

static apr_status_t serf_event_peek(serf_bucket_t *bucket,
                                    const char **data,
                                    apr_size_t *len)
{
    event_context_t *ctx = bucket->data;
    apr_status_t status = APR_EOF;
    *data = NULL;
    *len = 0;

    if (ctx->eof_cb)
        status = ctx->eof_cb(ctx->baton);

    if (APR_STATUS_IS_EAGAIN(status))
        return APR_SUCCESS;
    else
        return status ? status : APR_EOF;
}

static apr_uint64_t serf_event_get_remaining(serf_bucket_t *bucket)
{
    return 0;
}

static void serf_event_destroy(serf_bucket_t *bucket)
{
    event_context_t *ctx = bucket->data;

    if (ctx->destroy_cb)
        (void)ctx->destroy_cb(ctx->baton);

    serf_default_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type__event = {
    "EVENT",
    serf_event_read,
    serf_event_readline,
    serf_event_read_iovec,
    serf_default_read_for_sendfile,
    serf_buckets_are_v2,
    serf_event_peek,
    serf_event_destroy,
    serf_default_read_bucket,
    serf_default_readline2,
    serf_event_get_remaining,
    serf_default_ignore_config,
};
