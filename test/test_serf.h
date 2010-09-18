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

#ifndef TEST_SERF_H
#define TEST_SERF_H

#include "CuTest.h"

#include <apr.h>
#include <apr_pools.h>
#include <apr_uri.h>

#include "serf.h"

/** These macros are provided by APR itself from version 1.3.
 * Definitions are provided here for when using older versions of APR.
 */

/** index into an apr_array_header_t */
#ifndef APR_ARRAY_IDX
#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif

/** easier array-pushing syntax */
#ifndef APR_ARRAY_PUSH
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

/* CuTest declarations */
CuSuite *getsuite(void);

CuSuite *test_context(void);
CuSuite *test_buckets(void);
CuSuite *test_ssl(void);

/* Test setup declarations */

#define CRLF "\r\n"

#define CHUNCKED_REQUEST(len, body)\
        "GET / HTTP/1.1" CRLF\
        "Transfer-Encoding: chunked" CRLF\
        CRLF\
        #len CRLF\
        body CRLF\
        "0" CRLF\
        CRLF

#define CHUNKED_RESPONSE(len, body)\
        "HTTP/1.1 200 OK" CRLF\
        "Transfer-Encoding: chunked" CRLF\
        CRLF\
        #len CRLF\
        body CRLF\
        "0" CRLF\
        CRLF

#define CHUNKED_EMPTY_RESPONSE\
        "HTTP/1.1 200 OK" CRLF\
        "Transfer-Encoding: chunked" CRLF\
        CRLF\
        "0" CRLF\
        CRLF

typedef struct
{
    enum {
        SERVER_RECV,
        SERVER_SEND,
        SERVER_RESPOND,
        SERVER_IGNORE_AND_KILL_CONNECTION,
        SERVER_KILL_CONNECTION
    } kind;

    const char *text;
} test_server_action_t;

typedef struct
{
    const char *text;
} test_server_message_t;

typedef struct {
    /* Pool for resource allocation. */
    apr_pool_t *pool;

    serf_context_t *context;
    serf_connection_t *connection;
    serf_bucket_alloc_t *bkt_alloc;
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

    /* An extra baton which can be freely used by tests. */
    void *user_baton;

} test_baton_t;

#define TEST_SERVER_DUMP 1

/* Default port for our test server. */
#define SERV_PORT 12345
#define SERV_PORT_STR "12345"

apr_status_t test_server_create(test_baton_t **tb,
                                test_server_message_t *message_list,
                                apr_size_t message_count,
                                test_server_action_t *action_list,
                                apr_size_t action_count,
                                apr_int32_t options,
                                const char *host_url,
                                apr_sockaddr_t *address,
                                serf_connection_setup_t conn_setup,
                                apr_pool_t *pool);

apr_status_t test_server_run(test_baton_t *tb,
                             apr_short_interval_time_t duration,
                             apr_pool_t *pool);

apr_status_t test_server_destroy(test_baton_t *tb, apr_pool_t *pool);

apr_pool_t *test_setup();
void test_teardown(apr_pool_t *test_pool);

#ifndef APR_VERSION_AT_LEAST /* Introduced in APR 1.3.0 */
#define APR_VERSION_AT_LEAST(major,minor,patch)                  \
(((major) < APR_MAJOR_VERSION)                                       \
 || ((major) == APR_MAJOR_VERSION && (minor) < APR_MINOR_VERSION)    \
 || ((major) == APR_MAJOR_VERSION && (minor) == APR_MINOR_VERSION && \
     (patch) <= APR_PATCH_VERSION))
#endif /* APR_VERSION_AT_LEAST */

#endif /* TEST_SERF_H */
