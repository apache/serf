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

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"

typedef enum serf_request_state_t {
    UNREAD,
    READING_STATUS,
    READING_HEADERS,
    READING_BODY,
    EXHAUSTED
} serf_request_state_t;

typedef struct serf_request_context_t {
    const char *method;
    const char *uri;
    serf_bucket_t *body;
    serf_request_state_t state;
} serf_request_context_t;

SERF_DECLARE(serf_bucket_t *) serf_bucket_request_create(
    const char *method,
    const char *uri,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator)
{
    serf_request_context_t *req_context;

    serf_bucket_mem_alloc(allocator, sizeof(*req_context));

    /* Theoretically, we *could* store this in the metadata of our bucket,
     * but that'd be ridiculously slow.
     */
    req_context->method = method;
    req_context->uri = uri;
    req_context->body = body;
    req_context->state = UNREAD;

    return serf_bucket_create(serf_bucket_type_request, allocator, data);
}

static apr_status_t serf_request_read(serf_bucket_t *bucket,
                                      apr_size_t requested,
                                      const char **data, apr_size_t *len)
{
    serf_request_context_t *req_context;
    serf_bucket_t *new_bucket;
    const char *new_data;

    req_context = (serf_request_context_t*)bucket->data;
    new_bucket = NULL;

    /* We'll store whatever we generate into a new bucket and update our
     * state accordingly.
     */
    switch (req_context->state) {
    case UNREAD:
        /* Store method line. */
        /* ARGH.  Allocator needs to be public? */
        new_data = apr_pstrcat(bucket->allocator->pool,
                               req_context->method, " ",
                               req_context->uri, " HTTP/1.1", NULL);
        /* heap, pool, whatever. */
        new_bucket = serf_bucket_pool_create(bucket->allocator, new_data);
        req_context->state = READ_STATUS;
        break;
    case READ_STATUS:
        /* Store method line. */
        req_context->state = READ_HEADERS;
        break;
    case READ_HEADERS:
        /* Return all headers. */
        req_context->state = READ_BODY;
        break;
    case READ_BODY:
        /* Just read from the body at this point! */
        req_context->state = READ_EXHAUSTED;
        break;
    case EXHAUSTED:
        /* Hmm.  How did we get here? */
        break;
    }

    if (!new_bucket) {
        *len = 0;
        return APR_SUCCESS;
    }

    /* Okay, so we created a bucket.  Pass the 'hard' stuff to that bucket. */
    /* This better have the semantics we want in that bucket is pushed down. */
    serf_bucket_aggregate_become(bucket);
    serf_bucket_aggregate_prepend(bucket, new_bucket);
    return serf_bucket_read(bucket, data, len);
}

static apr_status_t serf_request_readline(serf_bucket_t *bucket,
                                          int acceptable, int *found,
                                          const char **data, apr_size_t *len)
{
    return APR_ENOTIMPL;
}

static apr_status_t serf_request_peek(serf_bucket_t *bucket,
                                      const char **data,
                                      apr_size_t *len)
{
    return APR_ENOTIMPL;
}

SERF_DECLARE_DATA serf_bucket_type_t serf_bucket_type_request {
    "REQUEST",
    serf_request_read,
    serf_request_readline,
    serf_request_peek,
    serf_default_read_bucket,
    serf_default_set_metadata,
    serf_default_get_metadata,
    serf_default_destroy,
};
