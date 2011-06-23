/* Copyright 2011 Justin Erenkrantz and Greg Stein
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
#include <apr_version.h>
#include <stdlib.h>

#include "serf.h"

#include "test_server.h"

struct serv_ctx_t {
    /* Pool for resource allocation. */
    apr_pool_t *pool;

    apr_int32_t options;

    /* Array of actions which server will replay when client connected. */
    test_server_action_t *action_list;
    /* Size of action_list array. */
    apr_size_t action_count;
    /* Index of current action. */
    apr_size_t cur_action;

    /* Array of messages the server will receive from the client. */
    test_server_message_t *message_list;
    /* Size of message_list array. */
    apr_size_t message_count;
    /* Index of current message. */
    apr_size_t cur_message;

    /* Number of messages received that the server didn't respond to yet. */
    apr_size_t outstanding_responses;

    /* Position in message buffer (incoming messages being read). */
    apr_size_t message_buf_pos;

    /* Position in action buffer. (outgoing messages being sent). */
    apr_size_t action_buf_pos;

    /* Address for server binding. */
    apr_sockaddr_t *serv_addr;
    apr_socket_t *serv_sock;

    /* Accepted client socket. NULL if there is no client socket. */
    apr_socket_t *client_sock;

};

/* Replay support functions */
static void next_message(serv_ctx_t *servctx)
{
    servctx->cur_message++;
}

static void next_action(serv_ctx_t *servctx)
{
    servctx->cur_action++;
    servctx->action_buf_pos = 0;
}

/* Verify received requests and take the necessary actions
   (return a response, kill the connection ...) */
static apr_status_t replay(serv_ctx_t *servctx,
                           apr_int16_t rtnevents,
                           apr_pool_t *pool)
{
    apr_status_t status = APR_SUCCESS;
    test_server_action_t *action;

    if (rtnevents & APR_POLLIN) {
        if (servctx->message_list == NULL) {
            /* we're not expecting any requests to reach this server! */
            printf("Received request where none was expected\n");

            return APR_EGENERAL;
        }

        if (servctx->cur_action >= servctx->action_count) {
            char buf[128];
            apr_size_t len = sizeof(buf);

            status = apr_socket_recv(servctx->client_sock, buf, &len);
            if (! APR_STATUS_IS_EAGAIN(status)) {
                /* we're out of actions! */
                printf("Received more requests than expected.\n");

                return APR_EGENERAL;
            }
            return status;
        }

        action = &servctx->action_list[servctx->cur_action];

        if (action->kind == SERVER_IGNORE_AND_KILL_CONNECTION) {
            char buf[128];
            apr_size_t len = sizeof(buf);

            status = apr_socket_recv(servctx->client_sock, buf, &len);

            if (status == APR_EOF) {
                apr_socket_close(servctx->client_sock);
                servctx->client_sock = NULL;
                next_action(servctx);
                return APR_SUCCESS;
            }

            return status;
        }
        else if (action->kind == SERVER_RECV ||
                 (action->kind == SERVER_RESPOND &&
                  servctx->outstanding_responses == 0)) {
            apr_size_t msg_len, len;
            char buf[128];
            test_server_message_t *message;

            message = &servctx->message_list[servctx->cur_message];
            msg_len = strlen(message->text);

            len = msg_len - servctx->message_buf_pos;
            if (len > sizeof(buf))
                len = sizeof(buf);

            status = apr_socket_recv(servctx->client_sock, buf, &len);
            if (status != APR_SUCCESS)
                return status;

            if (servctx->options & TEST_SERVER_DUMP)
                fwrite(buf, len, 1, stdout);

            if (strncmp(buf, message->text + servctx->message_buf_pos, len) != 0) {
                /* ## TODO: Better diagnostics. */
                printf("Expected: (\n");
                fwrite(message->text + servctx->message_buf_pos, len, 1, stdout);
                printf(")\n");
                printf("Actual: (\n");
                fwrite(buf, len, 1, stdout);
                printf(")\n");

                return APR_EGENERAL;
            }

            servctx->message_buf_pos += len;

            if (servctx->message_buf_pos >= msg_len) {
                next_message(servctx);
                servctx->message_buf_pos -= msg_len;
                if (action->kind == SERVER_RESPOND)
                    servctx->outstanding_responses++;
                if (action->kind == SERVER_RECV)
                    next_action(servctx);
            }
        }
    }
    if (rtnevents & APR_POLLOUT) {
        action = &servctx->action_list[servctx->cur_action];

        if (action->kind == SERVER_RESPOND && servctx->outstanding_responses) {
            apr_size_t msg_len;
            apr_size_t len;

            msg_len = strlen(action->text);
            len = msg_len - servctx->action_buf_pos;

            status = apr_socket_send(servctx->client_sock,
                                     action->text + servctx->action_buf_pos, &len);
            if (status != APR_SUCCESS)
                return status;

            if (servctx->options & TEST_SERVER_DUMP)
                fwrite(action->text + servctx->action_buf_pos, len, 1, stdout);

            servctx->action_buf_pos += len;

            if (servctx->action_buf_pos >= msg_len) {
                next_action(servctx);
                servctx->outstanding_responses--;
            }
        }
        else if (action->kind == SERVER_KILL_CONNECTION ||
                 action->kind == SERVER_IGNORE_AND_KILL_CONNECTION) {
            apr_socket_close(servctx->client_sock);
            servctx->client_sock = NULL;
            next_action(servctx);
        }
    }
    else if (rtnevents & APR_POLLIN) {
        /* ignore */
    }
    else {
        printf("Unknown rtnevents: %d\n", rtnevents);
        abort();
    }

    return status;
}

apr_status_t test_server_run(serv_ctx_t *servctx,
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
    if (servctx->client_sock) {
        apr_pollfd_t pfd = { pool, APR_POLL_SOCKET, APR_POLLIN | APR_POLLOUT, 0,
                             { NULL }, NULL };
        pfd.desc.s = servctx->client_sock;
        status = apr_pollset_add(pollset, &pfd);
        if (status != APR_SUCCESS)
            goto cleanup;
    }
    else {
        apr_pollfd_t pfd = { pool, APR_POLL_SOCKET, APR_POLLIN, 0,
                             { NULL }, NULL };
        pfd.desc.s = servctx->serv_sock;
        status = apr_pollset_add(pollset, &pfd);
        if (status != APR_SUCCESS)
            goto cleanup;
    }

    status = apr_pollset_poll(pollset, APR_USEC_PER_SEC >> 1, &num, &desc);
    if (status != APR_SUCCESS)
        goto cleanup;

    while (num--) {
        if (desc->desc.s == servctx->serv_sock) {
            status = apr_socket_accept(&servctx->client_sock, servctx->serv_sock,
                                       servctx->pool);
            if (status != APR_SUCCESS)
                goto cleanup;

            apr_socket_opt_set(servctx->client_sock, APR_SO_NONBLOCK, 1);
            apr_socket_timeout_set(servctx->client_sock, 0);

            status = APR_SUCCESS;
            goto cleanup;
        }

        if (desc->desc.s == servctx->client_sock) {
            /* Replay data to socket. */
            status = replay(servctx, desc->rtnevents, pool);

            if (APR_STATUS_IS_EOF(status)) {
                apr_socket_close(servctx->client_sock);
                servctx->client_sock = NULL;
            }
            else if (APR_STATUS_IS_EAGAIN(status)) {
                status = APR_SUCCESS;
            }
            else if (status != APR_SUCCESS) {
                /* Real error. */
                goto cleanup;
            }
        }

        desc++;
    }

cleanup:
    apr_pollset_destroy(pollset);

    return status;
}

/* Start a TCP server on port SERV_PORT in thread THREAD. srv_replay is a array
   of action to replay when connection started. replay_count is count of
   actions in srv_replay. */
apr_status_t test_start_server(serv_ctx_t **servctx_p,
                               apr_sockaddr_t *address,
                               test_server_message_t *message_list,
                               apr_size_t message_count,
                               test_server_action_t *action_list,
                               apr_size_t action_count,
                               apr_int32_t options,
                               apr_pool_t *pool)
{
    apr_status_t status;
    apr_socket_t *serv_sock;
    serv_ctx_t *servctx;

    servctx = apr_pcalloc(pool, sizeof(*servctx));
    *servctx_p = servctx;

    servctx->serv_addr = address;
    servctx->options = options;
    servctx->pool = pool;
    servctx->message_list = message_list;
    servctx->message_count = message_count;
    servctx->action_list = action_list;
    servctx->action_count = action_count;

    /* create server socket */
#if APR_VERSION_AT_LEAST(1, 0, 0)
    status = apr_socket_create(&serv_sock, APR_UNSPEC, SOCK_STREAM, 0, pool);
#else
    status = apr_socket_create(&serv_sock, APR_UNSPEC, SOCK_STREAM, pool);
#endif

    if (status != APR_SUCCESS)
        return status;

    apr_socket_opt_set(serv_sock, APR_SO_NONBLOCK, 1);
    apr_socket_timeout_set(serv_sock, 0);
    apr_socket_opt_set(serv_sock, APR_SO_REUSEADDR, 1);

    status = apr_socket_bind(serv_sock, servctx->serv_addr);
    if (status != APR_SUCCESS)
        return status;

    /* Start replay from first action. */
    servctx->cur_action = 0;
    servctx->action_buf_pos = 0;
    servctx->outstanding_responses = 0;

    /* listen for clients */
    apr_socket_listen(serv_sock, SOMAXCONN);
    if (status != APR_SUCCESS)
        return status;

    servctx->serv_sock = serv_sock;
    servctx->client_sock = NULL;
    return APR_SUCCESS;
}

apr_status_t test_server_destroy(serv_ctx_t *servctx, apr_pool_t *pool)
{
    apr_socket_close(servctx->serv_sock);

    if (servctx->client_sock) {
        apr_socket_close(servctx->client_sock);
    }

    return APR_SUCCESS;
}
