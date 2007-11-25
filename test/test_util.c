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
#include <apr_poll.h>
#include <stdlib.h>

#include "serf.h"

#include "test_serf.h"

/*****************************************************************************/
/* Server setup functions
 */

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
static serf_bucket_t* default_conn_setup(apr_socket_t *skt,
                                         void *setup_baton,
                                         apr_pool_t *pool)
{
    test_baton_t *ctx = setup_baton;

    return serf_bucket_socket_create(skt, ctx->bkt_alloc);
}

static apr_status_t get_server_address(apr_sockaddr_t **address,
                                       apr_pool_t *pool)
{
    return apr_sockaddr_info_get(address,
                                 "localhost", APR_INET, SERV_PORT, 0,
                                 pool);
}

static void next_action(test_baton_t *tb)
{
    tb->cur_action++;
    tb->action_buf_pos = 0;
}

static apr_status_t replay(test_baton_t *tb,
                           apr_pool_t *pool)
{
    apr_status_t status = APR_SUCCESS;
    test_server_action_t *action;

    if (tb->cur_action >= tb->action_count) {
        /* we're out of actions! */
        printf("Received more requests than expected\n");

        return APR_EGENERAL;
    }

    if (tb->action_list == NULL)
    {
        /* we're not expecting any requests to reach this server! */
        printf("Received request where none was expected\n");

        return APR_EGENERAL;
    }

    action = &tb->action_list[tb->cur_action];

    if (action->kind == SERVER_RECV)
    {
        apr_size_t msg_len, len;
        char buf[128];

        msg_len = strlen(action->text);

        len = msg_len - tb->action_buf_pos;
        if (len > sizeof(buf))
            len = sizeof(buf);

        status = apr_socket_recv(tb->client_sock, buf, &len);

        if (tb->options & TEST_SERVER_DUMP)
            fwrite(buf, len, 1, stdout);

        if (strncmp(buf, action->text + tb->action_buf_pos, len) != 0) {
            /* ## TODO: Better diagnostics. */
            printf("Expected: (\n");
            fwrite(action->text + tb->action_buf_pos, len, 1, stdout);
            printf(")\n");
            printf("Actual: (\n");
            fwrite(buf, len, 1, stdout);
            printf(")\n");

            return APR_EGENERAL;
        }

        tb->action_buf_pos += len;

        if (tb->action_buf_pos >= msg_len)
            next_action(tb);
    }
    else if (action->kind == SERVER_SEND) {
        apr_size_t msg_len;
        apr_size_t len;

        msg_len = strlen(action->text);
        len = msg_len - tb->action_buf_pos;

        status = apr_socket_send(tb->client_sock,
                                 action->text + tb->action_buf_pos, &len);

        if (tb->options & TEST_SERVER_DUMP)
            fwrite(action->text + tb->action_buf_pos, len, 1, stdout);

        tb->action_buf_pos += len;

        if (tb->action_buf_pos >= msg_len)
            next_action(tb);
    }
    else if (action->kind == SERVER_KILL_CONNECTION) {
        apr_socket_close(tb->client_sock);
        tb->client_sock = NULL;
        next_action(tb);
    }
    else {
        abort();
    }

    return status;
}

apr_status_t test_server_run(test_baton_t *tb,
                             apr_short_interval_time_t duration,
                             apr_pool_t *pool)
{
    apr_status_t status;
    apr_pollset_t *pollset;
    apr_int32_t num;
    const apr_pollfd_t *desc;

    /* create a new pollset */
    status = apr_pollset_create(&pollset, 32, pool, 0);
    if (status != APR_SUCCESS)
        return status;

    /* Don't accept new connection while processing client connection. At
       least for present time.*/
    if (tb->client_sock) {
        apr_pollfd_t pfd = { pool, APR_POLL_SOCKET, APR_POLLIN | APR_POLLOUT, 0,
                             { NULL }, NULL };
        pfd.desc.s = tb->client_sock;
        status = apr_pollset_add(pollset, &pfd);
        if (status != APR_SUCCESS)
            return status;
    }
    else {
        apr_pollfd_t pfd = { pool, APR_POLL_SOCKET, APR_POLLIN, 0,
                             { NULL }, NULL };
        pfd.desc.s = tb->serv_sock;
        status = apr_pollset_add(pollset, &pfd);
        if (status != APR_SUCCESS)
            return status;
    }

    status = apr_pollset_poll(pollset, APR_USEC_PER_SEC >> 1, &num, &desc);
    if (status != APR_SUCCESS)
        return status;

    while (num--) {
        if (desc->desc.s == tb->serv_sock) {
            status = apr_socket_accept(&tb->client_sock, tb->serv_sock,
                                       tb->pool);
            if (status != APR_SUCCESS)
              return status;

            apr_socket_opt_set(tb->client_sock, APR_SO_NONBLOCK, 1);
            apr_socket_timeout_set(tb->client_sock, 0);

            return APR_SUCCESS;
        }

        if (desc->desc.s == tb->client_sock) {
            /* Replay data to socket. */
            status = replay(tb, pool);

            if (APR_STATUS_IS_EOF(status)) {
                apr_socket_close(tb->client_sock);
                tb->client_sock = NULL;
            }
            else if (APR_STATUS_IS_EAGAIN(status)) {
                status = APR_SUCCESS;
            }
            else if (status != APR_SUCCESS) {
                /* Real error. */
                return status;
            }
        }

        desc++;
    }

    return APR_SUCCESS;
}

/* Start a TCP server on port SERV_PORT in thread THREAD. srv_replay is a array
   of action to replay when connection started. replay_count is count of
   actions in srv_replay. */
static apr_status_t prepare_server(test_baton_t *tb,
                                   apr_pool_t *pool)
{
    apr_status_t status;
    apr_socket_t *serv_sock;

    /* create server socket */
    status = apr_socket_create(&serv_sock, APR_INET, SOCK_STREAM, 0, pool);
    if (status != APR_SUCCESS)
        return status;

    apr_socket_opt_set(serv_sock, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set(serv_sock, 0);
    apr_socket_opt_set(serv_sock, APR_SO_REUSEADDR, 1);

    status = apr_socket_bind(serv_sock, tb->serv_addr);
    if (status != APR_SUCCESS)
        return status;

    /* Start replay from first action. */
    tb->cur_action = 0;
    tb->action_buf_pos = 0;

    /* listen for clients */
    apr_socket_listen(serv_sock, SOMAXCONN);
    if (status != APR_SUCCESS)
        return status;

    tb->serv_sock = serv_sock;
    tb->client_sock = NULL;
    return APR_SUCCESS;
}

/*****************************************************************************/

apr_status_t test_server_create(test_baton_t **tb_p,
                                test_server_action_t *action_list,
                                apr_size_t action_count,
                                apr_int32_t options,
                                apr_sockaddr_t *address,
                                apr_pool_t *pool)
{
    apr_status_t status;
    test_baton_t *tb;

    tb = apr_palloc(pool, sizeof(*tb));
    *tb_p = tb;

    if (address) { 
        tb->serv_addr = address;
    }
    else {
        status = get_server_address(&tb->serv_addr, pool);
        if (status != APR_SUCCESS)
          return status;
    }

    tb->pool = pool;
    tb->options = options;
    tb->context = serf_context_create(pool);
    tb->bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    tb->connection = serf_connection_create(tb->context,
                                            tb->serv_addr,
                                            default_conn_setup,
                                            tb,
                                            default_closed_connection,
                                            tb,
                                            pool);
    tb->action_list = action_list;
    tb->action_count = action_count;

    /* Prepare a server. */
    status = prepare_server(tb, pool);
    if (status != APR_SUCCESS)
      return status;

    return APR_SUCCESS;
}

apr_status_t test_server_destroy(test_baton_t *tb, apr_pool_t *pool)
{
    serf_connection_close(tb->connection);

    apr_socket_close(tb->serv_sock);

    if (tb->client_sock) {
        apr_socket_close(tb->client_sock);
    }

    return APR_SUCCESS;
}
