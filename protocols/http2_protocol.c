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
#include <apr_poll.h>
#include <apr_version.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

static apr_status_t
http2_protocol_read(serf_connection_t *conn);

static apr_status_t
http2_protocol_write(serf_connection_t *conn);

static apr_status_t
http2_protocol_hangup(serf_connection_t *conn);

static void
http2_protocol_teardown(serf_connection_t *conn);

typedef struct serf_http2_procotol_state_t
{
  apr_pool_t *pool;

} serf_http2_procotol_state_t;

static apr_status_t
http2_protocol_cleanup(void *state)
{
  serf_connection_t *conn = state;
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  conn->protocol_baton = NULL;
  return APR_SUCCESS;
}

void serf__http2_protocol_init(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx;
  apr_pool_t *protocol_pool;

  apr_pool_create(&protocol_pool, conn->pool);

  ctx = apr_pcalloc(protocol_pool, sizeof(*ctx));
  ctx->pool = protocol_pool;

  apr_pool_cleanup_register(protocol_pool, conn, http2_protocol_cleanup,
                            apr_pool_cleanup_null);

  conn->perform_read = http2_protocol_read;
  conn->perform_write = http2_protocol_write;
  conn->perform_hangup = http2_protocol_hangup;
  conn->perform_teardown = http2_protocol_teardown;
  conn->protocol_baton = ctx;
}

static apr_status_t
http2_protocol_read(serf_connection_t *conn)
{
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  return APR_EGENERAL;
}

static apr_status_t
http2_protocol_write(serf_connection_t *conn)
{
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  return APR_EGENERAL;
}

static apr_status_t
http2_protocol_hangup(serf_connection_t *conn)
{
  /* serf_http2_procotol_state_t *ctx = conn->protocol_baton; */

  return APR_EGENERAL;
}

static void
http2_protocol_teardown(serf_connection_t *conn)
{
  serf_http2_procotol_state_t *ctx = conn->protocol_baton;

  apr_pool_destroy(ctx->pool);
  conn->protocol_baton = NULL;
}
