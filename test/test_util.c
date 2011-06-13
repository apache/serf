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

#include "apr.h"
#include "apr_pools.h"
#include <stdlib.h>

#include "serf.h"

#include "test_serf.h"
#include "server/test_server.h"


/*****************************************************************************/
/* Server setup function(s)
 */

static apr_status_t get_server_address(apr_sockaddr_t **address,
                                       apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_INET, SERV_PORT, 0,
                                 pool);
}

/* Default implementation of a serf_connection_closed_t callback. */
static void default_closed_connection(serf_connection_t *conn,
                                      void *closed_baton,
                                      apr_status_t why,
                                      apr_pool_t *pool)
{
    if (why) {
        abort();
    }
}

/* Default implementation of a serf_connection_setup_t callback. */
static apr_status_t default_conn_setup(apr_socket_t *skt,
                                       serf_bucket_t **input_bkt,
                                       serf_bucket_t **output_bkt,
                                       void *setup_baton,
                                       apr_pool_t *pool)
{
    test_baton_t *ctx = setup_baton;

    *input_bkt = serf_bucket_socket_create(skt, ctx->bkt_alloc);
    return APR_SUCCESS;
}

apr_status_t test_server_setup(test_baton_t **tb_p,
                               test_server_message_t *message_list,
                               apr_size_t message_count,
                               test_server_action_t *action_list,
                               apr_size_t action_count,
                               apr_int32_t options,
                               const char *host_url,
                               apr_sockaddr_t *servaddr,
                               serf_connection_setup_t conn_setup,
                               apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    tb = apr_pcalloc(pool, sizeof(*tb));
    *tb_p = tb;

    if (!servaddr) {
        status = get_server_address(&servaddr, pool);
        if (status != APR_SUCCESS)
          return status;
    }

    tb->pool = pool;
    tb->context = serf_context_create(pool);
    tb->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    if (host_url) {
        apr_uri_t url;
        status = apr_uri_parse(pool, host_url, &url);
        if (status != APR_SUCCESS)
            return status;

        status = serf_connection_create2(&tb->connection, tb->context,
                                         url,
                                         conn_setup ? conn_setup :
                                             default_conn_setup,
                                         tb,
                                         default_closed_connection,
                                         tb,
                                         pool);
        if (status != APR_SUCCESS)
          return status;
    } else {
        tb->connection = serf_connection_create(tb->context,
                                                servaddr,
                                                conn_setup ? conn_setup :
                                                    default_conn_setup,
                                                tb,
                                                default_closed_connection,
                                                tb,
                                                pool);
    }

    /* Prepare a server. */
    status = test_start_server(&tb->servctx, servaddr,
                               message_list, message_count,
                               action_list, action_count, options, pool);
    if (status != APR_SUCCESS)
      return status;

    return APR_SUCCESS;
}

apr_status_t test_server_teardown(test_baton_t *tb, apr_pool_t *pool)
{
    serf_connection_close(tb->connection);

    test_server_destroy(tb->servctx, pool);

    return APR_SUCCESS;
}

apr_pool_t *test_setup()
{
    apr_pool_t *test_pool;
    apr_pool_create(&test_pool, NULL);
    return test_pool;
}

void test_teardown(apr_pool_t *test_pool)
{
    apr_pool_destroy(test_pool);
}
