/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#ifndef SERF_BUCKET_TYPES_H
#define SERF_BUCKET_TYPES_H


/* this header and serf.h refer to each other, so take a little extra care */
#ifndef SERF_H
#include "serf.h"
#endif

#include "serf_declare.h"


/**
 * @file serf_bucket_types.h
 * @brief serf-supported bucket types
 */

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


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_response;
#define SERF_BUCKET_IS_RESPONSE(b) SERF_BUCKET_CHECK((b), response)

SERF_DECLARE(serf_bucket_t *) serf_bucket_response_create(
    serf_bucket_t *stream,
    serf_bucket_alloc_t *allocator);

/* ### hmm. these need to return APR_EAGAIN somehow. maybe 0 for the
   ### integer functions and NULL for the reason? hmm. should probably
   ### switch to apr_status_t so that we can return *any* network-related
   ### error. (or parsing error or whatever)
*/
SERF_DECLARE(int) serf_bucket_response_status(serf_bucket_t *bkt);

SERF_DECLARE(const char *) serf_bucket_response_reason(serf_bucket_t *bkt);

SERF_DECLARE(int) serf_bucket_response_protocol(serf_bucket_t *bkt);


/* ==================================================================== */


SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_aggregate;
#define SERF_BUCKET_IS_AGGREGATE(b) SERF_BUCKET_CHECK((b), aggregate)

SERF_DECALRE(serf_bucket_t *) serf_bucket_aggregate_create(
    serf_bucket_alloc_t *allocator);

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
    apr_socket_t *socket,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


/* ### we probably don't need all three here. our memory model is a bit
   ### special, so it may simply be that we have a bucket type that refers
   ### to externally-managed memory
*/

SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_immortal;
#define SERF_BUCKET_IS_IMMORTAL(b) SERF_BUCKET_CHECK((b), immortal)

SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_heap;
#define SERF_BUCKET_IS_HEAP(b) SERF_BUCKET_CHECK((b), heap)

SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_pool;
#define SERF_BUCKET_IS_POOL(b) SERF_BUCKET_CHECK((b), pool)


/* ==================================================================== */


/* Note: this is always defined, but if APR doesn't have mmaps, then
   the caller can never create an apr_mmap_t to pass to this function. */

SERF_DECLARE_DATA extern const serf_bucket_type_t serf_bucket_type_mmap;
#define SERF_BUCKET_IS_MMAP(b) SERF_BUCKET_CHECK((b), mmap)

SERF_DECLARE(serf_bucket_t *) serf_bucket_mmap_create(
    apr_mmap_t *mmap,
    serf_bucket_alloc_t *allocator);


/* ==================================================================== */


/* ### do we need a PIPE bucket type? they are simple apr_file_t objects */


#ifdef __cplusplus
}
#endif

#endif	/* !SERF_BUCKET_TYPES_H */
