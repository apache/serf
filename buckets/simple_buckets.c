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


typedef struct {
    const char *original;
    const char *current;
    apr_size_t remaining;

    serf_simple_freefunc_t freefunc;
    void *baton;

} simple_context_t;


SERF_DECLARE(serf_bucket_t *) serf_bucket_simple_create(
    const char *data, apr_size_t len,
    serf_simple_freefunc_t freefunc,
    void *freefunc_baton,
    serf_bucket_alloc_t *allocator)
{
    simple_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->original = ctx->current = data;
    ctx->remaining = len;
    ctx->freefunc = freefunc;
    ctx->baton = freefunc_baton;

    return serf_bucket_create(&serf_bucket_type_simple, allocator, ctx);
}

static apr_status_t serf_simple_read(serf_bucket_t *bucket,
                                     apr_size_t requested,
                                     const char **data, apr_size_t *len)
{
    simple_context_t *ctx = bucket->data;

    if (requested == SERF_READ_ALL_AVAIL || requested > ctx->remaining)
        requested = ctx->remaining;

    *data = ctx->current;
    *len = requested;

    ctx->current += requested;
    ctx->remaining -= requested;

    return APR_SUCCESS;
}

static apr_status_t serf_simple_readline(serf_bucket_t *bucket,
                                         int acceptable, int *found,
                                         const char **data, apr_size_t *len)
{
    /* ### need our utility function... */
    return APR_ENOTIMPL;
}

static apr_status_t serf_simple_peek(serf_bucket_t *bucket,
                                     const char **data,
                                     apr_size_t *len)
{
    simple_context_t *ctx = bucket->data;

    /* return whatever we have left */
    *data = ctx->current;
    *len = ctx->remaining;

    return APR_SUCCESS;
}

static void serf_simple_destroy(serf_bucket_t *bucket)
{
    simple_context_t *ctx = bucket->data;

    if (ctx->freefunc)
        (*ctx->freefunc)(ctx->baton, ctx->original);

    serf_default_destroy_and_data(bucket);
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_simple = {
    "SIMPLE",
    serf_simple_read,
    serf_simple_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_default_read_bucket,
    serf_simple_peek,
    serf_default_get_metadata,
    serf_default_set_metadata,
    serf_simple_destroy,
};
