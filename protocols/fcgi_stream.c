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

#include <stdlib.h>

#include <apr_pools.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

#include "protocols/fcgi_buckets.h"
#include "protocols/fcgi_protocol.h"

struct serf_fcgi_stream_data_t
{
    int dummy;
};

serf_fcgi_stream_t *
serf_fcgi__stream_create(serf_fcgi_protocol_t *h2,
                          apr_int32_t streamid,
                          apr_uint32_t lr_window,
                          apr_uint32_t rl_window,
                          serf_bucket_alloc_t *alloc)
{
    serf_fcgi_stream_t *stream = serf_bucket_mem_alloc(alloc,
                                                        sizeof(*stream));

    stream->h2 = h2;
    stream->alloc = alloc;

    stream->next = stream->prev = NULL;

    /* Delay creating this? */
    stream->data = serf_bucket_mem_alloc(alloc, sizeof(*stream->data));

    return stream;
}
