/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
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

#ifndef SERF_BUCKET_TYPES_H
#define SERF_BUCKET_TYPES_H

#include <apr_mmap.h>

/* this header and serf.h refer to each other, so take a little extra care */
#ifndef SERF_H
#include "serf.h"
#endif

#include "serf_declare.h"


/**
 * @file serf_bucket_types.h
 * @brief serf-supported bucket types
 */
/* ### this whole file needs docco ... */

#ifdef __cplusplus
extern "C" {
#endif

/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_request;
#define SERF_BUCKET_IS_REQUEST(b) SERF_BUCKET_CHECK((b), request)

SERF_DECLARE(serf_bucket_t *) serf_bucket_request_create(
    const char *method,
    const char *URI,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator);

SERF_DECLARE(serf_bucket_t *) serf_bucket_request_get_headers(
    serf_bucket_t *request);

/* Metadata key for get/set_metadata */
#define SERF_REQUEST_HEADERS "REQUESTHEADERS"


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_response;
#define SERF_BUCKET_IS_RESPONSE(b) SERF_BUCKET_CHECK((b), response)

SERF_DECLARE(serf_bucket_t *) serf_bucket_response_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);

#define SERF_HTTP_VERSION(major, minor)  ((major) * 1000 + (minor))
#define SERF_HTTP_11 SERF_HTTP_VERSION(1, 1)
#define SERF_HTTP_10 SERF_HTTP_VERSION(1, 0)

typedef struct {
    int version;
    int code;
    const char *reason;
} serf_status_line;

/**
 * Return the Status-Line information, if available. This function
 * works like other bucket read functions: it may return APR_EAGAIN or
 * APR_EOF to signal the state of the bucket for reading. A return
 * value of APR_SUCCESS will always indicate that status line
 * information was returned; for other return values the caller must
 * check the version field in @a sline. A value of 0 means that the
 * data is not (yet) present.
 */
SERF_DECLARE(apr_status_t) serf_bucket_response_status(
    serf_bucket_t *bkt,
    serf_status_line *sline);

/* Metadata key for get/set_metadata */
#define SERF_RESPONSE_HEADERS "RESPONSEHEADERS"

/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_aggregate;
#define SERF_BUCKET_IS_AGGREGATE(b) SERF_BUCKET_CHECK((b), aggregate)

SERF_DECLARE(serf_bucket_t *) serf_bucket_aggregate_create(
    serf_bucket_alloc_t *allocator);

/** Transform @a bucket in-place into an aggregate bucket. */
SERF_DECLARE(void) serf_bucket_aggregate_become(serf_bucket_t *bucket);

SERF_DECLARE(void) serf_bucket_aggregate_prepend(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *prepend_bucket);

SERF_DECLARE(void) serf_bucket_aggregate_append(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *append_bucket);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_file;
#define SERF_BUCKET_IS_FILE(b) SERF_BUCKET_CHECK((b), file)

SERF_DECLARE(serf_bucket_t *) serf_bucket_file_create(
    apr_file_t *file,
    serf_bucket_alloc_t *allocator);

SERF_DECLARE(apr_file_t *) serf_bucket_file_borrow(serf_bucket_t *bkt);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_socket;
#define SERF_BUCKET_IS_SOCKET(b) SERF_BUCKET_CHECK((b), socket)

SERF_DECLARE(serf_bucket_t *) serf_bucket_socket_create(
    apr_socket_t *skt,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_simple;
#define SERF_BUCKET_IS_SIMPLE(b) SERF_BUCKET_CHECK((b), simple)

typedef void (*serf_simple_freefunc_t)(void *baton, const char *data);

SERF_DECLARE(serf_bucket_t *) serf_bucket_simple_create(
    const char *data, apr_size_t len,
    serf_simple_freefunc_t freefunc,
    void *freefunc_baton,
    serf_bucket_alloc_t *allocator);

#define SERF_BUCKET_SIMPLE_STRING(s,a) \
    serf_bucket_simple_create(s, strlen(s), NULL, NULL, a);

#define SERF_BUCKET_SIMPLE_STRING_LEN(s,l,a) \
    serf_bucket_simple_create(s, l, NULL, NULL, a);

/* ==================================================================== */


/* Note: apr_mmap_t is always defined, but if APR doesn't have mmaps, then
   the caller can never create an apr_mmap_t to pass to this function. */

SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_mmap;
#define SERF_BUCKET_IS_MMAP(b) SERF_BUCKET_CHECK((b), mmap)

SERF_DECLARE(serf_bucket_t *) serf_bucket_mmap_create(
    apr_mmap_t *mmap,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_headers;
#define SERF_BUCKET_IS_HEADERS(b) SERF_BUCKET_CHECK((b), headers)

SERF_DECLARE(serf_bucket_t *) serf_bucket_headers_create(
    serf_bucket_alloc_t *allocator);

/**
 * Set the specified @a header within the bucket, copying the @a value
 * into space from this bucket's allocator. The header is NOT copied,
 * so it should remain in scope at least as long as the bucket.
 */
SERF_DECLARE(void) serf_bucket_headers_set(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

/**
 * Copy the specified @a header and @a value into the bucket, using space
 * from this bucket's allocator.
 */
SERF_DECLARE(void) serf_bucket_headers_setc(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

/**
 * Set the specified @a header and @a value into the bucket, without
 * copying either attribute. Both attributes should remain in scope at
 * least as long as the bucket.
 */
SERF_DECLARE(void) serf_bucket_headers_setn(
    serf_bucket_t *headers_bucket,
    const char *header,
    const char *value);

SERF_DECLARE(const char *) serf_bucket_headers_get(
    serf_bucket_t *headers_bucket,
    const char *header);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_dechunk;
#define SERF_BUCKET_IS_DECHUNK(b) SERF_BUCKET_CHECK((b), dechunk)

SERF_DECLARE(serf_bucket_t *) serf_bucket_dechunk_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */

/* ### do we need a PIPE bucket type? they are simple apr_file_t objects */


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKET_TYPES_H */
