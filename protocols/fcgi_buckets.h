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

#ifndef SERF_PROTOCOL_FCGI_BUCKETS_H
#define SERF_PROTOCOL_FCGI_BUCKETS_H

#include "serf_bucket_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const serf_bucket_type_t serf_bucket_type__fcgi_unframe;
#define SERF__BUCKET_IS_FCGI_UNFRAME(b) SERF_BUCKET_CHECK((b), _fcgi_unframe)

typedef apr_status_t (*serf_bucket_end_of_frame_t)(
                                    void *baton,
                                    serf_bucket_t *unframe_bucket);

/* Creates a bucket that reads a single fcgi frame from stream.  Note that
   unlike many other buckets destroying the unframe bucket doesn't destroy the
   underlying stream.

   The frame header information can be obtained by calling
   serf__bucket_fcgi_unframe_read_info().

   After the header has been read the remaining payload size can be retrieved
   using serf_bucket_get_remaining()
 */
serf_bucket_t * serf__bucket_fcgi_unframe_create(serf_bucket_t *stream,
                                                 serf_bucket_alloc_t *allocator);

/* Sets the end of frame handler on the frame, which will be called as soon as
   the whole frame has been read from the contained stream */
void serf__bucket_fcgi_unframe_set_eof(serf_bucket_t *bucket,
                                       serf_bucket_end_of_frame_t end_of_frame,
                                       void *end_of_frame_baton);


/* Obtains the frame header state, reading from the bucket if necessary.
   If the header was read successfully (or was already read before calling)
   the *stream_id, * frame_type and *flags values (when not pointing to NULL)
   will be set to the requested values.

   returns APR_SUCCESS when the header was already read before calling this,
   function. Otherwise it will return the result of reading. */
apr_status_t serf__bucket_fcgi_unframe_read_info(serf_bucket_t *bucket,
                                                 apr_uint16_t *stream_id,
                                                 apr_uint16_t *frame_type);

/* ==================================================================== */
extern const serf_bucket_type_t serf_bucket_type__fcgi_params_decode;
#define SERF__BUCKET_IS_FCGI_PARAMS_DECODE(b)               \
            SERF_BUCKET_CHECK((b), _fcgi_params_decode)

serf_bucket_t *
serf__bucket_fcgi_params_decode_create(serf_bucket_t *stream,
                                       serf_bucket_alloc_t *alloc);

/* ==================================================================== */
extern const serf_bucket_type_t serf_bucket_type__fcgi_frame;

#define SERF__BUCKET_IS_FCGI_FRAME(b) SERF_BUCKET_CHECK((b), _fcgi_frame)

serf_bucket_t *
serf__bucket_fcgi_frame_create(serf_bucket_t *stream,
                               apr_uint16_t stream_id,
                               apr_uint16_t frame_type,
                               serf_bucket_alloc_t *alloc);

#ifdef __cplusplus
}
#endif

#endif /* !SERF_PROTOCOL_FCGI_BUCKETS_H */

