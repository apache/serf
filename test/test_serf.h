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

extern apr_pool_t *test_pool;

/* CuTest declarations */
CuSuite *getsuite(void);

CuSuite *test_context(void);

typedef struct
{
    enum {
        SERVER_RECV,
        SERVER_SEND
    } kind;

    const char *text;
} test_server_action_t;

/* Test setup declarations */
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
    
    /* Position in action buffer. */
    apr_size_t action_buf_pos;

    /* Address for server binding. */
    apr_sockaddr_t *serv_addr;
    apr_socket_t *serv_sock;
    
    /* Accepted client socket. NULL if there is no client socket. */
    apr_socket_t *client_sock;
} test_baton_t;

#define TEST_SERVER_DUMP 1

apr_status_t test_server_create(test_baton_t **tb,
                                test_server_action_t *action_list,
                                apr_size_t action_count,
                                apr_int32_t options,
                                apr_pool_t *pool);

apr_status_t test_server_run(test_baton_t *tb,
                             apr_short_interval_time_t duration,
                             apr_pool_t *pool);

apr_status_t test_server_destroy(test_baton_t *tb, apr_pool_t *pool);

#endif /* TEST_SERF_H */
