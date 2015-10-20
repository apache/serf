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

#ifndef SERF_PROTOCOL_HTTP2_PRIVATE_H
#define SERF_PROTOCOL_HTTP2_PRIVATE_H


#ifdef __cplusplus
extern "C" {
#endif

/* ********** HTTP2 Frame types ********** */

/* The standard maximum framesize. Always supported */
#define HTTP2_DEFAULT_MAX_FRAMESIZE 16384

/* Frame type is an 8 bit unsigned integer */

/* http://tools.ietf.org/html/rfc7540#section-11.2 */
#define HTTP2_FRAME_TYPE_DATA           0x00
#define HTTP2_FRAME_TYPE_HEADERS        0x01
#define HTTP2_FRAME_TYPE_PRIORITY       0x02
#define HTTP2_FRAME_TYPE_RST_STREAM     0x03
#define HTTP2_FRAME_TYPE_SETTINGS       0x04
#define HTTP2_FRAME_TYPE_PUSH_PROMISE   0x05
#define HTTP2_FRAME_TYPE_PING           0x06
#define HTTP2_FRAME_TYPE_GOAWAY         0x07
#define HTTP2_FRAME_TYPE_WINDOW_UPDATE  0x08
#define HTTP2_FRAME_TYPE_CONTINUATION   0x09
/* https://httpwg.github.io/http-extensions/alt-svc.html
   documents that frame 0x0A will most likely be assigned
   to ALT-SVC */

/* ********** HTTP2 Flags ********** */

/* Flags are currently unique over all frame types, but perhaps this
   may change in future specs */


/* Defined on DATA and HEADERS */
#define HTTP2_FLAG_END_STREAM     0x01
/* Defined on HEADERS and CONTINUATION */
#define HTTP2_FLAG_END_HEADERS    0x04
/* Defined on DATA and HEADERS */
#define HTTP2_FLAG_PADDED         0x08
/* Defined on HEADERS */
#define HTTP2_FLAG_PRIORITY       0x20


/* ********** HTTP2 Settings ********** */

/* Settings are 16 bit unsigned integers*/
#define HTTP2_SETTING_HEADER_TABLE_SIZE       0x0001  /* default: 4096 */
#define HTTP2_SETTING_ENABLE_PUSH             0x0002  /* default: 1 */
#define HTTP2_SETTING_MAX_CONCURRENT_STREAMS  0x0003  /* default: (infinite) */
#define HTTP2_SETTING_INITIAL_WINDOW_SIZE     0x0004  /* default: 65535 */
#define HTTP2_SETTING_MAX_FRAME_SIZE          0x0005  /* default: 16384 */
#define HTTP2_SETTING_MAX_HEADER_LIST_SIZE    0x0006  /* default: (infinite) */

/* https://tools.ietf.org/html/rfc7540#section-3.5 */
#define HTTP2_CONNECTION_PREFIX "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


#ifdef __cplusplus
}
#endif

#endif
