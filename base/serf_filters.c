/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 The Apache Software Foundation.  All rights
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

#include <apr_ring.h>
#include <apr_hash.h>

static apr_hash_t *registered_filters = NULL;

static apr_status_t filter_type_cleanup(void *ctx)
{
    registered_filters = NULL; 
    return APR_SUCCESS;
}

SERF_DECLARE(serf_filter_list_t*) serf_create_filter_list(apr_pool_t *pool)
{
    serf_filter_list_t *filters;

    filters = apr_palloc(pool, sizeof(serf_filter_list_t));

    APR_RING_INIT(&filters->list, serf_filter_t, link);

    return filters;
}

SERF_DECLARE(apr_status_t) serf_execute_filters(serf_filter_list_t *filters,
                                                apr_bucket_brigade *brigade,
                                                apr_pool_t *pool)
{
    apr_status_t status;
    serf_filter_t *filter;

    APR_RING_FOREACH(filter, &filters->list, serf_filter_t, link) {
        status = filter->type->func(brigade, filter, pool);
        if (status) {
            return status;
        }
    }

    return APR_SUCCESS;
}

SERF_DECLARE(serf_filter_type_t*) serf_register_filter(const char *name,
                                                       serf_filter_func_t func,
                                                       apr_pool_t *pool)
{
    serf_filter_type_t *new_type;

    if (registered_filters == NULL) {
        registered_filters = apr_hash_make(pool);
        apr_pool_cleanup_register(pool, NULL, filter_type_cleanup,
                                  apr_pool_cleanup_null);
    }

    new_type = apr_palloc(pool, sizeof(serf_filter_type_t));

    new_type->name = name;
    new_type->func = func;

    apr_hash_set(registered_filters, name, APR_HASH_KEY_STRING, new_type);

    return new_type;
}

SERF_DECLARE(serf_filter_type_t*) serf_lookup_filter(const char *name)
{
    if (registered_filters == NULL) {
        return NULL;
    }

    return apr_hash_get(registered_filters, name, APR_HASH_KEY_STRING);
}

SERF_DECLARE(serf_filter_t*) serf_add_filter(serf_filter_list_t *filters,
                                             const char *name, apr_pool_t *pool)
{
    serf_filter_type_t *filter_type;
    serf_filter_t *new_filter;

    filter_type = serf_lookup_filter(name);

    if (!filter_type) {
        /* Not found! */
        return NULL;
    }

    new_filter = apr_pcalloc(pool, sizeof(serf_filter_t));
    new_filter->type = filter_type;

    APR_RING_ELEM_INIT(new_filter, link);

    APR_RING_INSERT_TAIL(&filters->list, new_filter, serf_filter_t, link);

    return new_filter;
}
