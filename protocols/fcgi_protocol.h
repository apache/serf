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

#ifndef SERF_PROTOCOL_FCGI_PROTOCOL_H
#define SERF_PROTOCOL_FCGI_PROTOCOL_H

#include "serf_bucket_types.h"

#ifdef _DEBUG
#include <assert.h>
#define SERF_FCGI_assert(x) assert(x)
#else
#define SERF_FCGI_assert(x) ((void)0)
#endif

#define SERF_LOGFCGI \
    SERF_LOGCOMP_PROTOCOL, (__FILE__ ":" APR_STRINGIFY(__LINE__))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serf_fcgi_protocol_t serf_fcgi_protocol_t;
typedef struct serf_fcgi_stream_data_t serf_fcgi_stream_data_t;

#define FCGI_FRAMETYPE(version, type)                           \
             (  ( (apr_uint16_t)(unsigned char)(version) << 8)  \
              | ( (apr_uint16_t)(unsigned char)(type)))

#define FCGI_V1     0x1

#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)


typedef struct serf_fcgi_stream_t
{
    struct serf_fcgi_protocol_t *h2;
    serf_bucket_alloc_t *alloc;

    /* Opaque implementation details */
    serf_fcgi_stream_data_t *data;

    /* Linked list of currently existing streams */
    struct serf_fcgi_stream_t *next;
    struct serf_fcgi_stream_t *prev;
} serf_fcgi_stream_t;

typedef apr_status_t(*serf_fcgi_processor_t)(void *baton,
                                             serf_fcgi_protocol_t *fcgi,
                                             serf_bucket_t *body);



#ifdef __cplusplus
}
#endif

#endif /* !SERF_PROTOCOL_FCGI_PROTOCOL_H */


