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

#ifndef SERF_H
#define SERF_H

/**
 * @file serf.h
 * @brief Main serf header file
 */

#include <apr.h>
#include <apr_errno.h>
#include <apr_pools.h>

#include "serf_declare.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare some structures */
typedef struct serf_context_t serf_context_t;

typedef struct serf_bucket_t serf_bucket_t;
typedef struct serf_bucket_type_t serf_bucket_type_t;
typedef struct serf_bucket_alloc_t serf_bucket_alloc_t;
typedef struct serf_metadata_t serf_metadata_t;

typedef struct serf_connection_t serf_connection_t;


/**
 * @defgroup serf high-level constructs
 * @ingroup serf
 * @{
 */

/**
 * Create a new context for serf operations.
 *
 * A serf context defines a control loop which processes multiple
 * connections simultaneously.
 *
 * The context will be allocated within @a pool.
 */
SERF_DECLARE(serf_context_t *) serf_context_create(apr_pool_t *pool);


/** @see serf_context_run should not block at all. */
#define SERF_DURATION_NOBLOCK 0
/** @see serf_context_run should run for (nearly) "forever". */
#define SERF_DURATION_FOREVER 2000000000        /* approx 1^31 */

/**
 * Run the main networking control loop.
 *
 * The set of connections defined by the serf context @a ctx are processed.
 * Any outbound data is delivered, and incoming data is made available to
 * the associated response handlers and their buckets. This function will
 * block on the network for no longer than @a duration microseconds.
 *
 * If any data is processed (incoming or outgoing), then this function will
 * return with APR_SUCCESS. Typically, the caller will just want to call it
 * again to continue processing data.
 *
 * All temporary allocations will be made in @a pool.
 */
SERF_DECLARE(apr_status_t) serf_context_run(serf_context_t *ctx,
                                            apr_short_interval_time_t duration,
                                            apr_pool_t *pool);


/** @} */

/**
 * @defgroup serf connections
 * @ingroup serf
 * @{
 */

/**
 * Notification callback for when a connection closes.
 *
 * This callback is used to inform an application that the @a conn
 * connection has been (abnormally) closed. The @a closed_baton is the
 * baton provided when the connection was first opened. The reason for
 * closure is given in @a why, and will be APR_SUCCESS if the application
 * requested closure (by clearing the pool used to allocate this
 * connection).
 *
 * All temporary allocations should be made in @a pool.
 */
typedef void (*serf_connection_closed_t)(serf_connection_t *conn,
                                         void *closed_baton,
                                         apr_status_t why,
                                         apr_pool_t *pool);

/**
 * Response data has arrived and should be processed.
 *
 * Whenever a response arrives (initially, or continued data arrival), this
 * handler is invoked. The response data is available in the @a response
 * bucket. The @a handler_baton is passed along from the baton provided to
 * the creation of this response's associated request.
 *
 * The handler should process data from the @a response bucket until the
 * bucket's read function states it would block (see APR_STATUS_IS_EAGAIN).
 *
 * Note: if the connection closed (at the request of the application, or
 * because of an (abnormal) termination) while a request is being delivered,
 * or before a response arrives, then @a response will be NULL. This is the
 * signal that the request was not delivered properly, and no further
 * response should be expected (this callback will not be invoked again).
 * If a request is injected into the connection (during this callback, or
 * otherwise), then the connection will be reopened.
 *
 * All temporary allocations should be made in @a pool.
 */
typedef apr_status_t (*serf_response_handler_t)(serf_bucket_t *response,
                                                void *handler_baton,
                                                apr_pool_t *pool);

/**
 * Create a new connection associated with the @a ctx serf context.
 *
 * A connection will be created to (eventually) connect to the address
 * specified by @a address.
 *
 * The connection object will be allocated within @a pool. Clearing or
 * destroying this pool will close the connection, and terminate any
 * outstanding requests or responses.
 *
 * When the connection is closed (upon request or because of an error),
 * then the @a closed callback is invoked, and @a closed_baton is passed.
 *
 * Note: the connection is not made immediately. It will be opened on
 * the next call to @see serf_context_run.
 */
SERF_DECLARE(serf_connection_t *) serf_connection_create(
    serf_context_t *ctx,
    apr_sockaddr_t *address,
    serf_connection_closed_t closed,
    void *closed_baton,
    apr_pool_t *pool);

/**
 * Create a new request for the specified @a connection.
 *
 * The request is specified by the @a request bucket. When a response
 * arrives, @a handler will be invoked with the response bucket (allocated
 * using the @a allocator bucket allocator). The @a handler_baton will be
 * passed to the handler.
 *
 * All temporary allocations will be made in @a pool.
 */
/* ### is the status return value needed? I don't think this can fail(?) */
SERF_DECLARE(apr_status_t) serf_connection_request_create(
    serf_connection_t *conn,
    serf_bucket_t *request,
    serf_response_handler_t handler,
    void *handler_baton,
    serf_bucket_alloc_t *allocator,
    apr_pool_t *pool);

/**
 * Cancel the request specified by the @a request bucket, which should be
 * found in @a connection.
 *
 * The request's response handler will be run, passing NULL for the response
 * bucket.
 *
 * If the request has already been (partially or fully) delivered, then
 * APR_EBUSY is returned and the request is *NOT* canceled. To properly
 * cancel the request, the connection must be closed (by clearing or
 * destroying its associated pool).
 *
 * Note: APR_NOTFOUND will be returned if the request could not be found.
 */
SERF_DECLARE(apr_status_t) serf_connection_request_cancel(
    serf_connection_t *conn,
    serf_bucket_t *request);


/* ### maybe some connection control functions for flood? */

/** @} */


/**
 * @defgroup serf buckets
 * @ingroup serf
 * @{
 */

struct serf_bucket_type_t {

    /** name of this bucket type */
    const char *name;

    /** read/consume some data out of the bucket */
    apr_status_t (*read)(serf_bucket_t *bucket,
                         const char **data, apr_size_t *len);

    /** peek (don't consume) at the data in the bucket */
    apr_status_t (*peek)(serf_bucket_t *bucket,
                         const char **data, apr_size_t *len);

    /** if the given bucket type is available, then read/consume it and
     * return it to the caller
     */
    serf_bucket_t * (*read_bucket)(serf_bucket_t *bucket,
                                   serf_bucket_type_t *type);

    /** return a piece of metadata from the bucket */
    apr_status_t (*get_metadata)(serf_bucket_t *bucket, const char *md_type,
                                 const char *md_name, const void **md_value);

    /** set some metadata for the bucket */
    apr_status_t (*set_metadata)(serf_bucket_t *bucket, const char *md_type,
                                 const char *md_name, const void *md_value);

    /** destroy the bucket, along with any associated resources */
    void (*destroy)(serf_bucket_t *bucket);

    /* ### apr buckets have 'copy', 'split', and 'setaside' functions.
       ### not sure whether those will be needed in this bucket model.
    */
};

#define serf_bucket_read(b,d,l) ((b)->type->read(b,d,l))
#define serf_bucket_peek(b,d,l) ((b)->type->peek(b,d,l))
#define serf_bucket_read_bucket(b,t) ((b)->type->read_bucket(b,t))
#define serf_bucket_get_metadata(b,t,n,v) ((b)->type->get_metadata(b,t,n,v))
#define serf_bucket_set_metadata(b,t,n,v) ((b)->type->set_metadata(b,t,n,v))
#define serf_bucket_destroy(b) ((b)->type->destroy(b))


struct serf_bucket_t {

    /** the type of this bucket */
    const serf_bucket_type_t *type;

    /** bucket-private data */
    void *data;

    /** this bucket's metadata: (CLASS, NAME) -> VALUE */
    serf_metadata_t *metadata;

    /** the allocator used for this bucket (needed at destroy time) */
    serf_bucket_alloc_t *allocator;
};


/**
 * Generic macro to construct "is TYPE" macros.
 */
#define SERF_BUCKET_CHECK(b, btype) ((b)->type == &serf_bucket_type_ ## btype)


/**
 * Default implementation to set metadata within a bucket.
 *
 * Stores @a md_value into @a bucket under the metadata type @a md_type
 * and name @a md_name.
 */
SERF_DECLARE(apr_status_t) serf_default_set_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void *md_value);

/**
 * Default implementation to get metadata from a bucket.
 */
SERF_DECLARE(apr_status_t) serf_default_get_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void **md_value);

/** @} */


#ifdef __cplusplus
}
#endif


/*
 * Every user of serf will want to deal with our various bucket types.
 * Go ahead and include that header right now.
 *
 * Note: make sure this occurs outside of the C++ namespace block
 */
#include "serf_bucket_types.h"


#endif	/* !SERF_H */
