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

#ifndef SERF_PROTOCOL_HTTP2_BUCKETS_H
#define SERF_PROTOCOL_HTTP2_BUCKETS_H

#include "serf_bucket_types.h"

/**
 * @file serf_bucket_types.h
 * @brief serf-supported bucket types
 */
/* ### this whole file needs docco ... */

#ifdef __cplusplus
extern "C" {
#endif

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type__http2_unframe;
#define SERF__BUCKET_IS_HTTP2_UNFRAME(b) SERF_BUCKET_CHECK((b), _http2_unframe)

/* Creates a bucket that reads a single http2 frame from stream. If
   DESTROY_STREAM is true STREAM will be destroyed with the bucket, otherwise
   it won't.

   The frame header information can be obtained by calling
   serf__bucket_http2_unframe_read_info().

   After the header has been read the remaining payload size can be retrieved
   using serf_bucket_get_remaining()
 */
serf_bucket_t *
serf__bucket_http2_unframe_create(serf_bucket_t *stream,
                                  int destroy_stream,
                                  apr_size_t max_payload_size,
                                  serf_bucket_alloc_t *allocator);

/* Sets the end of frame handler on the frame, which will be called as soon as
   the whole frame has been read from the contained stream */
void
serf__bucket_http2_unframe_set_eof(serf_bucket_t *bucket,
                                   apr_status_t (*eof_callback)(
                                                    void *baton,
                                                    serf_bucket_t *bucket),
                                   void *eof_callback_baton);


/* Obtains the frame header state, reading from the bucket if necessary.
   If the header was read successfully (or was already read before calling)
   the *stream_id, * frame_type and *flags values (when not pointing to NULL)
   will be set to the requested values.

   returns APR_SUCCESS when the header was already read before calling this,
   function. Otherwise it will return the result of reading. */
apr_status_t
serf__bucket_http2_unframe_read_info(serf_bucket_t *bucket,
                                     apr_int32_t *stream_id,
                                     unsigned char *frame_type,
                                     unsigned char *flags);

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type__http2_unpad;
#define SERF__BUCKET_IS_HTTP2_UNPAD(b) SERF_BUCKET_CHECK((b), _http2_unpad)

serf_bucket_t *
serf__bucket_http2_unpad_create(serf_bucket_t *stream,
                                int destroy_stream,
                                serf_bucket_alloc_t *allocator);

/* ==================================================================== */

extern const serf_bucket_type_t serf_bucket_type__hpack;
#define SERF_BUCKET_IS_HPACK(b) SERF_BUCKET_CHECK((b), _hpack)

typedef struct serf_hpack_table_t serf_hpack_table_t;

serf_bucket_t *
serf__bucket_hpack_create(serf_hpack_table_t *hpack_table,
                          serf_bucket_alloc_t *allocator);

/**
 * Set, copies: header and value copied.
 *
 * Copy the specified @a header and @a value into the bucket, using space
 * from this bucket's allocator.
 */
void serf__bucket_hpack_setc(serf_bucket_t *hpack_bucket,
                             const char *key,
                             const char *value);

/**
 * Set, extended: fine grained copy control of key and value.
 *
 * Set the specified @a key, with length @a key_size with the
 * @a value, and length @a value_size, into the bucket. The header will
 * be copied if @a header_copy is set, and the value is copied if
 * @a value_copy is set. If the values are not copied, then they should
 * remain in scope at least as long as the bucket.
 *
 * If @a headers_bucket already contains a header with the same name
 * as @a header, then append @a value to the existing value,
 * separating with a comma (as per RFC 2616, section 4.2).  In this
 * case, the new value must be allocated and the header re-used, so
 * behave as if @a value_copy were true and @a header_copy false.
 */
void
serf__bucket_hpack_setx(serf_bucket_t *hpack_bucket,
                        const char *key,
                        apr_size_t key_size,
                        int header_copy,
                        const char *value,
                        apr_size_t value_size,
                        int value_copy,
                        int dont_index,
                        int never_index);

const char *
serf__bucket_hpack_getc(serf_bucket_t *hpack_bucket,
                        const char *key);

/**
 * @param baton opaque baton as passed to @see serf_bucket_hpack_do
 * @param key The header key from this iteration through the table
 * @param value The header value from this iteration through the table
 */
typedef int (serf_bucket_hpack_do_callback_fn_t)(void *baton,
                                                 const char *key,
                                                 apr_size_t keylen,
                                                 const char *value,
                                                 apr_size_t value_len);

/**
 * Iterates over all headers of the message and invokes the callback 
 * function with header key and value. Stop iterating when no more
 * headers are available or when the callback function returned a 
 * non-0 value.
 *
 * @param headers_bucket headers to iterate over
 * @param func callback routine to invoke for every header in the bucket
 * @param baton baton to pass on each invocation to func
 */
void
serf__bucket_hpack_do(serf_bucket_t *hpack_bucket,
                     serf_bucket_hpack_do_callback_fn_t func,
                     void *baton);

serf_hpack_table_t *
serf__hpack_table_create(int for_http2,
                         apr_size_t default_max_table_size,
                         apr_pool_t *result_pool);

void
serf__hpack_table_set_max_table_size(serf_hpack_table_t *hpack_tbl,
                                     apr_size_t max_decoder_size,
                                     apr_size_t max_encoder_size);


/* ==================================================================== */
extern const serf_bucket_type_t serf_bucket_type__hpack_decode;
#define SERF_BUCKET_IS_HPACK_DECODE(b) SERF_BUCKET_CHECK((b), hpack_decode)

/* If ITEM_CALLBACK is not null calls it for every item while reading, and
   the bucket will just return no data and APR_EAGAIN until done.

   If ITEM_CALLBACK is NULL, the bucket will read as a HTTP/1 like header block,
   starting with a status line and ending with "\r\n\r\n", which allows using
   the result as the start of the result for a response_bucket.
 */
serf_bucket_t *
serf__bucket_hpack_decode_create(serf_bucket_t *stream,
                                 apr_status_t(*item_callback)(
                                                  void *baton,
                                                  const char *key,
                                                  apr_size_t key_size,
                                                  const char *value,
                                                  apr_size_t value_size),
                                 void *item_baton,
                                 apr_size_t max_entry_size,
                                 serf_hpack_table_t *hpack_table,
                                 serf_bucket_alloc_t *alloc);

/* ==================================================================== */
extern const serf_bucket_type_t serf_bucket_type__http2_frame;

#define SERF__BUCKET_IS_HTTP2_FRAME(b) SERF_BUCKET_CHECK((b), _http2_frame)

serf_bucket_t *
serf__bucket_http2_frame_create(serf_bucket_t *stream,
                                unsigned char frame_type,
                                unsigned char flags,
                                apr_int32_t *stream_id,
                                void(*stream_id_alloc)(
                                      void *baton,
                                      apr_int32_t *stream_id),
                                void *stream_id_baton,
                                apr_size_t max_payload_size,
                                apr_int32_t(*alloc_window)(
                                      void *baton,
                                      unsigned char frametype,
                                      apr_int32_t stream_id,
                                      apr_size_t requested,
                                      int peek),
                                void *alloc_window_baton,
                                serf_bucket_alloc_t *alloc);

int
serf__bucket_http2_frame_within_frame(serf_bucket_t *bucket);

/* ==================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* !SERF_PROTOCOL_HTTP2_BUCKETS_H */

