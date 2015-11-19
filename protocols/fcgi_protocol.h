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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serf_fcgi_protocol_t serf_fcgi_protocol_t;
typedef struct serf_fcgi_stream_data_t serf_fcgi_stream_data_t;

#define FCGI_FRAMETYPE(version, type)                           \
             (  ( (apr_uint16_t)(unsigned char)(version) << 8)  \
              | ( (apr_uint16_t)(unsigned char)(type)))

#define FCGI_V1     0x1

/* From protocol specs */
/*
* Listening socket file number
*/
#define FCGI_LISTENSOCK_FILENO 0

typedef struct FCGI_Header {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;

/*
 * Number of bytes in a FCGI_Header.  Future versions of the protocol
 * will not reduce this number.
 */
#define FCGI_HEADER_LEN  8

/*
 * Value for version component of FCGI_Header
 */
#define FCGI_VERSION_1           1

/*
 * Values for type component of FCGI_Header
 */
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

/*
* Value for requestId component of FCGI_Header
*/
#define FCGI_NULL_REQUEST_ID     0

typedef struct FCGI_BeginRequestBody {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;

typedef struct FCGI_BeginRequestRecord {
    FCGI_Header header;
    FCGI_BeginRequestBody body;
} FCGI_BeginRequestRecord;

/*
 * Mask for flags component of FCGI_BeginRequestBody
 */
#define FCGI_KEEP_CONN  1

/*
 * Values for role component of FCGI_BeginRequestBody
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct FCGI_EndRequestBody {
    unsigned char appStatusB3;
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;
    unsigned char reserved[3];
} FCGI_EndRequestBody;

typedef struct FCGI_EndRequestRecord {
    FCGI_Header header;
    FCGI_EndRequestBody body;
} FCGI_EndRequestRecord;

/*
* Values for protocolStatus component of FCGI_EndRequestBody
*/
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

/*
* Variable names for FCGI_GET_VALUES / FCGI_GET_VALUES_RESULT records
*/
#define FCGI_MAX_CONNS  "FCGI_MAX_CONNS"
#define FCGI_MAX_REQS   "FCGI_MAX_REQS"
#define FCGI_MPXS_CONNS "FCGI_MPXS_CONNS"

typedef struct FCGI_UnknownTypeBody {
    unsigned char type;
    unsigned char reserved[7];
} FCGI_UnknownTypeBody;

typedef struct FCGI_UnknownTypeRecord {
    FCGI_Header header;
    FCGI_UnknownTypeBody body;
} FCGI_UnknownTypeRecord;


/**************************************************/

typedef struct serf_fcgi_stream_t
{
    struct serf_fcgi_protocol_t *fcgi;
    serf_bucket_alloc_t *alloc;

    apr_uint16_t streamid;
    apr_uint16_t role;

    /* Opaque implementation details */
    serf_fcgi_stream_data_t *data;

    /* Linked list of currently existing streams */
    struct serf_fcgi_stream_t *next;
    struct serf_fcgi_stream_t *prev;
} serf_fcgi_stream_t;

typedef apr_status_t(*serf_fcgi_processor_t)(void *baton,
                                             serf_fcgi_protocol_t *fcgi,
                                             serf_bucket_t *body);


/* From fcgi_protocol.c */
serf_fcgi_stream_t * serf_fcgi__stream_get(serf_fcgi_protocol_t *fcgi,
                                           apr_uint16_t streamid,
                                           bool create);


apr_status_t serf_fcgi__setup_incoming_request(
    serf_incoming_request_t **in_request,
    serf_incoming_request_setup_t *req_setup,
    void **req_setup_baton,
    serf_fcgi_protocol_t *fcgi);

apr_status_t serf_fcgi__enqueue_frame(serf_fcgi_protocol_t *fcgi,
                                      serf_bucket_t *frame,
                                      bool flush);

void serf_fcgi__close_stream(serf_fcgi_protocol_t *fcgi,
                             serf_fcgi_stream_t *stream);


/* From fcgi_stream.c */
serf_fcgi_stream_t * serf_fcgi__stream_create(serf_fcgi_protocol_t *fcgi,
                                              apr_uint16_t streamid,
                                              serf_bucket_alloc_t *alloc);

apr_status_t serf_fcgi__stream_processor(void *baton,
                                         serf_fcgi_protocol_t *fcgi,
                                         serf_bucket_t *body);

serf_bucket_t * serf_fcgi__stream_handle_params(serf_fcgi_stream_t *stream,
                                                serf_bucket_t *body,
                                                serf_config_t *config,
                                                serf_bucket_alloc_t *alloc);

serf_bucket_t * serf_fcgi__stream_handle_stdin(serf_fcgi_stream_t *stream,
                                               serf_bucket_t *body,
                                               serf_config_t *config,
                                               serf_bucket_alloc_t *alloc);

void serf_fcgi__stream_destroy(serf_fcgi_stream_t *stream);


#ifdef __cplusplus
}
#endif

#endif /* !SERF_PROTOCOL_FCGI_PROTOCOL_H */


