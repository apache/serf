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

#define SERV_URL "http://localhost:" SERV_PORT_STR

static apr_status_t default_server_address(apr_sockaddr_t **address,
                                           apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_UNSPEC, SERV_PORT, 0,
                                 pool);
}

static apr_status_t default_proxy_address(apr_sockaddr_t **address,
                                          apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_UNSPEC, PROXY_PORT, 0,
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


static apr_status_t setup(test_baton_t **tb_p,
                          serf_connection_setup_t conn_setup,
                          int use_proxy,
                          apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;
    apr_uri_t url;

    tb = apr_pcalloc(pool, sizeof(*tb));
    *tb_p = tb;

    tb->pool = pool;
    tb->context = serf_context_create(pool);
    tb->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);

    status = default_server_address(&tb->serv_addr, pool);
    if (status != APR_SUCCESS)
        return status;

    if (use_proxy) {
        status = default_proxy_address(&tb->proxy_addr, pool);
        if (status != APR_SUCCESS)
            return status;

        /* Configure serf to use the proxy server */
        serf_config_proxy(tb->context, tb->proxy_addr);
    }

    status = apr_uri_parse(pool, SERV_URL, &url);
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

    return status;
}



apr_status_t test_server_setup(test_baton_t **tb_p,
                               test_server_message_t *message_list,
                               apr_size_t message_count,
                               test_server_action_t *action_list,
                               apr_size_t action_count,
                               apr_int32_t options,
                               serf_connection_setup_t conn_setup,
                               apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup,
                   FALSE,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;

    /* Prepare a server. */
    status = test_start_server(&tb->serv_ctx, tb->serv_addr,
                               message_list, message_count,
                               action_list, action_count, options, pool);

    return status;
}

apr_status_t
test_server_proxy_setup(test_baton_t **tb_p,
                        test_server_message_t *serv_message_list,
                        apr_size_t serv_message_count,
                        test_server_action_t *serv_action_list,
                        apr_size_t serv_action_count,
                        test_server_message_t *proxy_message_list,
                        apr_size_t proxy_message_count,
                        test_server_action_t *proxy_action_list,
                        apr_size_t proxy_action_count,
                        apr_int32_t options,
                        serf_connection_setup_t conn_setup,
                        apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    status = setup(tb_p,
                   conn_setup,
                   TRUE,
                   pool);
    if (status != APR_SUCCESS)
        return status;

    tb = *tb_p;

    /* Prepare the server. */
    status = test_start_server(&tb->serv_ctx, tb->serv_addr,
                               serv_message_list, serv_message_count,
                               serv_action_list, serv_action_count,
                               options, pool);
    if (status != APR_SUCCESS)
        return status;

    /* Prepare the proxy. */
    status = test_start_server(&tb->proxy_ctx, tb->proxy_addr,
                               proxy_message_list, proxy_message_count,
                               proxy_action_list, proxy_action_count,
                               options, pool);

    return status;
}

apr_status_t test_server_teardown(test_baton_t *tb, apr_pool_t *pool)
{
    serf_connection_close(tb->connection);

    if (tb->serv_ctx)
        test_server_destroy(tb->serv_ctx, pool);
    if (tb->proxy_ctx)
        test_server_destroy(tb->proxy_ctx, pool);

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
