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

#ifndef SERF_FILTERS_H
#define SERF_FILTERS_H

#include <apr_pools.h>
#include <apr_buckets.h>

#include "serf_declare.h"
#include "serf.h"

/**
 * @file serf_filters.h
 * @brief Common serf provided filters.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Filter which reads the HTTP status. */
SERF_DECLARE(apr_status_t) serf_http_status_read(apr_bucket_brigade *brigade,
                                                 serf_filter_t *filter,
                                                 apr_pool_t *pool);

/* Filter which reads the HTTP headers. */
SERF_DECLARE(apr_status_t) serf_http_header_read(apr_bucket_brigade *brigade,
                                                 serf_filter_t *filter,
                                                 apr_pool_t *pool);

/* Filter which reads HTTP chunks. */
SERF_DECLARE(apr_status_t) serf_http_dechunk(apr_bucket_brigade *brigade,
                                             serf_filter_t *filter,
                                             apr_pool_t *pool);

/* Filter that adds the appropriate headers to request compressed content. */
SERF_DECLARE(apr_status_t) serf_deflate_send_header(apr_bucket_brigade *brigade,
                                                    serf_filter_t *filter,
                                                    apr_pool_t *pool);

/* Filter that inflates compressed content. */
SERF_DECLARE(apr_status_t) serf_deflate_read(apr_bucket_brigade *brigade,
                                             serf_filter_t *filter,
                                             apr_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif	/* !SERF_FILTERS_H */
