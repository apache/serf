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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"


serf_bucket_t *serf_bucket_barrier_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator)
{
    return serf_bucket_create(&serf_bucket_type_barrier, allocator, stream);
}

static apr_status_t serf_barrier_read(serf_bucket_t *bucket,
                                     apr_size_t requested,
                                     const char **data, apr_size_t *len)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_read(stream, requested, data, len);
}

static apr_status_t serf_barrier_read_iovec(serf_bucket_t *bucket,
                                            apr_size_t requested,
                                            int vecs_size, struct iovec *vecs,
                                            int *vecs_used)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_read_iovec(stream, requested, vecs_size, vecs, vecs_used);
}

static apr_status_t serf_barrier_read_for_sendfile(serf_bucket_t *bucket,
                                                   apr_size_t requested,
                                                   apr_hdtr_t *hdtr,
                                                   apr_file_t **file,
                                                   apr_off_t *offset,
                                                   apr_size_t *len)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_read_for_sendfile(stream, requested, hdtr, file,
                                         offset, len);
}

static apr_status_t serf_barrier_readline(serf_bucket_t *bucket,
                                         int acceptable, int *found,
                                         const char **data, apr_size_t *len)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_readline(stream, acceptable, found, data, len);
}

static apr_status_t serf_barrier_readline2(serf_bucket_t *bucket,
                                           int acceptable, apr_size_t requested,
                                           int *found,
                                           const char **data, apr_size_t *len)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_readline2(stream, acceptable, requested,
                                 found, data, len);
}


static apr_status_t serf_barrier_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_peek(stream, data, len);
}

static void serf_barrier_destroy(serf_bucket_t *bucket)
{
    /* The intent of this bucket is not to let our wrapped buckets be
     * destroyed. */

    /* The option is for us to go ahead and 'eat' this bucket now,
     * or just ignore the deletion entirely.
     */
    serf_default_destroy(bucket);
}

static apr_uint64_t serf_barrier_get_remaining(serf_bucket_t *bucket)
{
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_get_remaining(stream);
}

static apr_status_t serf_barrier_set_config(serf_bucket_t *bucket,
                                            serf_config_t *config)
{
    /* This bucket doesn't need/update any shared config, but we need to pass
     it along to our wrapped bucket. */
    serf_bucket_t *stream = bucket->data;

    return serf_bucket_set_config(stream, config);
}

const serf_bucket_type_t serf_bucket_type_barrier = {
    "BARRIER",
    serf_barrier_read,
    serf_barrier_readline,
    serf_barrier_read_iovec,
    serf_barrier_read_for_sendfile,
    serf_buckets_are_v2,
    serf_barrier_peek,
    serf_barrier_destroy,
    serf_default_read_bucket, /* ### TODO? */
    serf_barrier_readline2,
    serf_barrier_get_remaining,
    serf_barrier_set_config,
};
