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

#include "serf.h"
#include "serf_bucket_util.h"


/* Should be an APR_RING? */
typedef struct bucket_list {
    serf_bucket_t *bucket;
    struct bucket_list *next;
} bucket_list_t;

typedef struct {
    bucket_list_t *list;
} aggregate_context_t;


SERF_DECLARE(serf_bucket_t *) serf_bucket_aggregate_create(
    serf_bucket_alloc_t *allocator)
{
    aggregate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));
    ctx->list = NULL;

    return serf_bucket_create(&serf_bucket_type_aggregate, allocator, ctx);
}

SERF_DECLARE(void) serf_bucket_aggregate_become(serf_bucket_t *bucket)
{
    aggregate_context_t *ctx;

    ctx = serf_bucket_mem_alloc(bucket->allocator, sizeof(*ctx));
    ctx->list = NULL;

    bucket->type = &serf_bucket_type_aggregate;
    bucket->data = ctx;

    /* ### leave the metadata? */
    /* bucket->metadata = NULL; */

    /* The allocator remains the same. */
}


SERF_DECLARE(void) serf_bucket_aggregate_prepend(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *prepend_bucket)
{
    aggregate_context_t *ctx = aggregate_bucket->data;
    bucket_list_t *new_list;

    new_list = serf_bucket_mem_alloc(aggregate_bucket->allocator,
                                     sizeof(*new_list));
    new_list->bucket = prepend_bucket;
    new_list->next = ctx->list;

    ctx->list = new_list;
}

SERF_DECLARE(void) serf_bucket_aggregate_append(
    serf_bucket_t *aggregate_bucket,
    serf_bucket_t *prepend_bucket)
{
    aggregate_context_t *ctx = aggregate_bucket->data;
    bucket_list_t *new_list;

    new_list = serf_bucket_mem_alloc(aggregate_bucket->allocator,
                                     sizeof(*new_list));

    /* If we use APR_RING, this is trivial.  So, wait. 
    new_list->bucket = prepend_bucket;
    new_list->next = ctx->list;
    ctx->list = new_list;
    */
}

static apr_status_t serf_aggregate_read(serf_bucket_t *bucket,
                                        apr_size_t requested,
                                        const char **data, apr_size_t *len)
{
    apr_status_t status;
    aggregate_context_t *ctx = bucket->data;
    serf_bucket_t *head;

    if (!ctx->list) {
        *len = 0;
        /* ### can we leave *data unassigned given *len == 0? */
        return APR_EOF;
    }

    head = ctx->list->bucket;
    status = serf_bucket_read(head, requested, data, len);

    /* Somehow, we need to know whether we're exhausted! */
    if (APR_STATUS_IS_EOF(status)) {
        ctx->list = ctx->list->next;
        serf_bucket_destroy(head);

        /* Avoid recursive call here.  Too lazy now.  */
        return serf_aggregate_read(bucket, requested, data, len);
    }

    return status;
}

static apr_status_t serf_aggregate_readline(serf_bucket_t *bucket,
                                            int acceptable, int *found,
                                            const char **data, apr_size_t *len)
{
    /* Follow pattern from serf_aggregate_read. */
    return APR_ENOTIMPL;
}

static apr_status_t serf_aggregate_peek(serf_bucket_t *bucket,
                                        const char **data,
                                        apr_size_t *len)
{
    /* Follow pattern from serf_aggregate_read. */
    return APR_ENOTIMPL;
}

static serf_bucket_t * serf_aggregate_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    aggregate_context_t *ctx = bucket->data;
    serf_bucket_t *found_bucket;

    if (!ctx->list) {
        return NULL;
    }

    if (ctx->list->bucket->type == type) {
        /* Got the bucket. Consume it from our list. */
        found_bucket = ctx->list->bucket;
        ctx->list = ctx->list->next;
        return found_bucket;
    }

    /* Call read_bucket on first one in our list. */
    return serf_bucket_read_bucket(ctx->list->bucket, type);
}

SERF_DECLARE_DATA const serf_bucket_type_t serf_bucket_type_aggregate = {
    "AGGREGATE",
    serf_aggregate_read,
    serf_aggregate_readline,
    serf_default_read_iovec,
    serf_default_read_for_sendfile,
    serf_aggregate_read_bucket,
    serf_aggregate_peek,
    serf_default_get_metadata,
    serf_default_set_metadata,
    serf_default_destroy_and_data,
};
