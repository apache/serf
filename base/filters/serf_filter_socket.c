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

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include "serf_filters.h"
#include "serf_buckets.h"
#include "serf.h"

SERF_DECLARE(apr_status_t) serf_socket_write(apr_bucket_brigade *brigade,
                                             serf_filter_t *filter,
                                             apr_pool_t *pool)
{
    serf_connection_t *conn = filter->ctx;

    while (!APR_BRIGADE_EMPTY(brigade)) {
        apr_bucket *bucket;
        const char *buf;
        apr_size_t length;
        apr_status_t status;

        bucket = APR_BRIGADE_FIRST(brigade);

        status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

        if (status) {
            return status;
        }

        do {
            apr_size_t written = length;

            status = apr_send(conn->socket, buf, &written);
            if (status) {
                return status;
            }
            length -= written;
            buf += written;
        }
        while (length);

        apr_bucket_delete(bucket);
    }

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_socket_read(apr_bucket_brigade *brigade,
                                            serf_filter_t *filter,
                                            apr_pool_t *pool)
{
    serf_connection_t *conn = filter->ctx;
    apr_bucket *bucket;

    bucket = apr_bucket_socket_create(conn->socket,
                                      brigade->bucket_alloc);

    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}
