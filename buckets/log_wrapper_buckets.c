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
#include "serf_private.h"
#include "serf_bucket_util.h"

/* TODO: don't use SOCK[_MSG]_VERBOSE directly, but get a log category in
   from the config object. */

typedef struct {
    const serf_bucket_type_t *old_type;
    const char *prefix;
    apr_socket_t *skt;
    serf_config_t *config;
} log_wrapped_context_t;

/* Extended serf_bucket_t. */
typedef struct {
    /* This must be the first member to ensure that this bucket can be cast
       to a serf_bucket_t */
    serf_bucket_t wrapped_bkt;

    /* stored data for the log wrapper */
    log_wrapped_context_t *more_data;
} serf_log_wrapped_bucket_t;


static apr_status_t
serf_log_wrapped_readline(serf_bucket_t *bucket,
                          int acceptable, int *found,
                          const char **data, apr_size_t *len)
{
    serf_log_wrapped_bucket_t *lwbkt = (serf_log_wrapped_bucket_t *)bucket;
    log_wrapped_context_t *ctx = lwbkt->more_data;

    apr_status_t status = ctx->old_type->readline(bucket, acceptable, found,
                                                  data, len);

    if (SERF_BUCKET_READ_ERROR(status))
        serf__log_skt(LOGLVL_ERROR, ctx->prefix, ctx->skt,
                      "Error %d while reading.\n", status);

    if (*len) {
        serf__log_skt(SOCK_VERBOSE || SOCK_MSG_VERBOSE, ctx->prefix, ctx->skt,
                      "--- %d bytes. --\n", *len);
        serf__log_skt(SOCK_MSG_VERBOSE, ctx->prefix, ctx->skt, "%.*s\n",
                      *len, *data);
    }

    return status;
}

static apr_status_t
serf_log_wrapped_read_iovec(serf_bucket_t *bucket,
                            apr_size_t requested,
                            int vecs_size,
                            struct iovec *vecs,
                            int *vecs_used)
{
    serf_log_wrapped_bucket_t *lwbkt = (serf_log_wrapped_bucket_t *)bucket;
    log_wrapped_context_t *ctx = lwbkt->more_data;
    apr_size_t len;
    int i;

    apr_status_t status = ctx->old_type->read_iovec(bucket, requested, vecs_size,
                                                    vecs, vecs_used);

    if (SERF_BUCKET_READ_ERROR(status))
        serf__log_skt(LOGLVL_ERROR, ctx->prefix, ctx->skt,
                      "Error %d while reading.\n", status);

    for (i = 0, len = 0; i < *vecs_used; i++)
        len += vecs[i].iov_len;
    serf__log_skt(SOCK_VERBOSE || SOCK_MSG_VERBOSE, ctx->prefix, ctx->skt,
                  "--- %d bytes. --\n", len);

    for (i = 0; i < *vecs_used; i++) {
        serf__log_nopref(SOCK_MSG_VERBOSE, "%.*s",
                         vecs[i].iov_len,
                         vecs[i].iov_base);
    }
    serf__log_nopref(SOCK_MSG_VERBOSE, "\n");

    return status;
}

static apr_status_t
serf_log_wrapped_read(serf_bucket_t *bucket, apr_size_t requested,
                      const char **data, apr_size_t *len)
{
    serf_log_wrapped_bucket_t *lwbkt = (serf_log_wrapped_bucket_t *)bucket;
    log_wrapped_context_t *ctx = lwbkt->more_data;

    apr_status_t status = ctx->old_type->read(bucket, requested, data, len);

    if (SERF_BUCKET_READ_ERROR(status))
        serf__log_skt(LOGLVL_ERROR, ctx->prefix, ctx->skt,
                      "Error %d while reading.\n", status);

    if (*len) {
        serf__log_skt(SOCK_VERBOSE || SOCK_MSG_VERBOSE, ctx->prefix, ctx->skt,
                  "--- %d bytes. --\n", *len);
        serf__log_skt(SOCK_MSG_VERBOSE, ctx->prefix, ctx->skt,
                      "%.*s\n", *len, *data);
    }

    return status;
}

static void serf_log_wrapped_destroy(serf_bucket_t *bucket)
{
    serf_log_wrapped_bucket_t *lwbkt = (serf_log_wrapped_bucket_t *)bucket;
    const serf_bucket_type_t *bkt_type = lwbkt->more_data->old_type;

    serf_bucket_mem_free(bucket->allocator, lwbkt->more_data);
    bkt_type->destroy(bucket);
}

static apr_status_t serf_log_wrapped_set_config(serf_bucket_t *bucket,
                                                serf_config_t *config)
{
    serf_log_wrapped_bucket_t *lwbkt = (serf_log_wrapped_bucket_t *)bucket;
    log_wrapped_context_t *ctx = lwbkt->more_data;

    ctx->config = config;

    return ctx->old_type->set_config(bucket, config);
}

serf_bucket_t *serf__bucket_log_wrapper_create(serf_bucket_t *wrapped,
                                               const char *prefix,
                                               /* need configuration here */
                                               apr_socket_t *skt,
                                               serf_bucket_alloc_t *alloc)
{
#if SOCK_VERBOSE || SOCK_MSG_VERBOSE
    serf_log_wrapped_bucket_t *bkt = serf_bucket_mem_alloc(alloc, sizeof(*bkt));
    log_wrapped_context_t *ctx = serf_bucket_mem_alloc(alloc, sizeof(*ctx));
    serf_bucket_type_t *bkt_type = serf_bucket_mem_alloc(alloc, sizeof(*bkt_type));

    /* Construct the new bucket type based on the wrapped bucket type, but
       replace all read functions with the logging wrappers. */
    bkt_type->name = wrapped->type->name;
    bkt_type->peek = wrapped->type->peek;
    /* These read functions are not used by serf, so no need to add logging. */
    bkt_type->read_bucket = wrapped->type->read_bucket;
    bkt_type->read_for_sendfile = wrapped->type->read_for_sendfile;
    if (wrapped->type->read_bucket == serf_buckets_are_v2) {
        bkt_type->read_bucket_v2 = wrapped->type->read_bucket_v2;
        bkt_type->get_remaining = wrapped->type->get_remaining;
    }

    /* Wrap these functions */
    bkt_type->destroy = serf_log_wrapped_destroy;
    bkt_type->read = serf_log_wrapped_read;
    bkt_type->readline = serf_log_wrapped_readline;
    bkt_type->read_iovec = serf_log_wrapped_read_iovec;
    bkt_type->set_config = serf_log_wrapped_set_config;

    ctx->old_type = wrapped->type;
    ctx->prefix = prefix;
    ctx->skt = skt;

    /* Construct the new extended bucket. */
    bkt->wrapped_bkt.type = bkt_type;
    bkt->wrapped_bkt.data = wrapped->data;
    bkt->wrapped_bkt.allocator = wrapped->allocator;
    bkt->more_data = ctx;

    /* We have created a new extended bucket and copied over the data from the
       wrapped bucket, so we can delete the wrapped bucket now. */
    serf_default_destroy(wrapped);

    return (serf_bucket_t *)bkt;
#else
    return wrapped;
#endif
}
