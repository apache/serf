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

#ifndef SERF_H
#define SERF_H

/**
 * @file serf.h
 * @brief Main serf header file
 */

#include <apr.h>
#include <apr_errno.h>
#include <apr_allocator.h>
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_time.h>

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

typedef struct serf_request_t serf_request_t;


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
 * If no activity occurs within the specified timeout duration, then
 * APR_TIMEUP is returned.
 *
 * All temporary allocations will be made in @a pool.
 */
SERF_DECLARE(apr_status_t) serf_context_run(serf_context_t *ctx,
                                            apr_short_interval_time_t duration,
                                            apr_pool_t *pool);


/** @} */

/**
 * @defgroup serf connections and requests
 * @ingroup serf
 * @{
 */

/**
 * Accept an incoming response for @a request, and its @a socket. A bucket
 * for the response will be constructed and returned. This is the control
 * point for assembling the appropriate wrapper buckets around the socket to
 * enable processing of the incoming response.
 *
 * The @a acceptor_baton is the baton provided when the connection was
 * first opened.
 *
 * The request's pool and bucket allocator should be used for any allocations
 * that need to live for the duration of the response. Care should be taken
 * to bound the amount of memory stored in this pool -- to ensure that
 * allocations are not proportional to the amount of data in the response.
 *
 * Responsibility for the bucket is passed to the serf library. It will be
 * destroyed when the response has been fully read (the bucket returns an
 * APR_EOF status from its read functions).
 *
 * All temporary allocations should be made in @a pool.
 */
/* ### do we need to return an error? */
typedef serf_bucket_t * (*serf_response_acceptor_t)(serf_request_t *request,
                                                    apr_socket_t *skt,
                                                    void *acceptor_baton,
                                                    apr_pool_t *pool);

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
 * The handler MUST process data from the @a response bucket until the
 * bucket's read function states it would block (see APR_STATUS_IS_EAGAIN).
 * The handler is invoked only when new data arrives. If no further data
 * arrives, and the handler does not process all available data, then the
 * system can result in a deadlock around the unprocessed, but read, data.
 *
 * The handler should return APR_EOF when the response has been fully read.
 * APR_EAGAIN should not be returned; simply return APR_SUCCESS.
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
 * specified by @a address. The address must live at least as long as
 * @a pool (thus, as long as the connection object).
 *
 * The connection object will be allocated within @a pool. Clearing or
 * destroying this pool will close the connection, and terminate any
 * outstanding requests or responses.
 *
 * When the connection is closed (upon request or because of an error),
 * then the @a closed callback is invoked, and @a closed_baton is passed.
 *
 * NULL may be passed for @a acceptor and @a closed; default implementations
 * will be used.
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
 * Construct a request object for the @a conn connection.
 *
 * A subpool for the request and its associated response will be built,
 * and the request will be allocated within that subpool. An associated
 * bucket allocator will be built. These items may be fetched from the
 * request object through @see serf_request_get_pool or
 * @see serf_request_get_alloc.
 *
 * The returned request can be finalized with @see ....
 *
 * If the request has not (yet) been delivered, then it may be canceled
 * with @see serf_connection_request_cancel.
 */
SERF_DECLARE(serf_request_t *) serf_connection_request_create(
    serf_connection_t *conn);

/**
 * Schedule the @a request for delivery on the connection.
 *
 * The content of the request is specified by the @a req_bkt bucket. When
 * a response arrives, the @a acceptor callback will be invoked (along with
 * the @a acceptor_baton) to produce a response bucket. That bucket will then
 * be passed to @a handler, along with the @a handler_baton.
 *
 * The responsibility for the request bucket is passed to the request
 * object. When the request is done with the bucket, it will be destroyed.
 */
SERF_DECLARE(void) serf_request_deliver(
    serf_request_t *request,
    serf_bucket_t *req_bkt,
    serf_response_acceptor_t acceptor,
    void *acceptor_baton,
    serf_response_handler_t handler,
    void *handler_baton);

/**
 * Cancel the request specified by the @a request object.
 *
 * If the request has been scheduled for delivery, then its response
 * handler will be run, passing NULL for the response bucket.
 *
 * If the request has already been (partially or fully) delivered, then
 * APR_EBUSY is returned and the request is *NOT* canceled. To properly
 * cancel the request, the connection must be closed (by clearing or
 * destroying its associated pool).
 */
SERF_DECLARE(apr_status_t) serf_request_cancel(serf_request_t *request);

/**
 * Return the pool associated with @a request.
 *
 * WARNING: be very careful about the kinds of things placed into this
 * pool. In particular, all allocation should be bounded in size, rather
 * than proportional to any data stream.
 */
SERF_DECLARE(apr_pool_t *) serf_request_get_pool(
    const serf_request_t *request);

/**
 * Return the bucket allocator associated with @a request.
 */
SERF_DECLARE(serf_bucket_alloc_t *) serf_request_get_alloc(
    const serf_request_t *request);


/* ### maybe some connection control functions for flood? */

/** @} */


/**
 * @defgroup serf buckets
 * @ingroup serf
 * @{
 */

/** Pass as REQUESTED to the read function of a bucket to read, consume,
 * and return all available data.
 */
#define SERF_READ_ALL_AVAIL ((apr_size_t)-1)

/** Acceptable newline types for bucket->readline(). */
#define SERF_NEWLINE_CR    0x0001
#define SERF_NEWLINE_CRLF  0x0002
#define SERF_NEWLINE_LF    0x0004
#define SERF_NEWLINE_ANY   0x0007

/** Used to indicate that a newline is not present in the data buffer. */
/* ### should we make this zero? */
#define SERF_NEWLINE_NONE  0x0008

/** Used to indicate that a CR was found at the end of a buffer, and CRLF
 * was acceptable. It may be that the LF is present, but it needs to be
 * read first.
 *
 * Note: an alternative to using this symbol would be for callers to see
 * the SERF_NEWLINE_CR return value, and know that some "end of buffer" was
 * reached. While this works well for @see serf_util_readline, it does not
 * necessary work as well for buckets (there is no obvious "end of buffer",
 * although there is an "end of bucket"). The other problem with that
 * alternative is that developers might miss the condition. This symbol
 * calls out the possibility and ensures that callers will watch for it.
 */
#define SERF_NEWLINE_CRLF_SPLIT 0x0010


struct serf_bucket_type_t {

    /** name of this bucket type */
    const char *name;

    /**
     * Read (and consume) up to @a requested bytes from @a bucket.
     *
     * A pointer to the data will be returned in @a data, and its length
     * is specified by @a len.
     *
     * The data will exist until one of two conditions occur:
     *
     * 1) this bucket is destroyed
     * 2) another call to any read function or to peek()
     *
     * If an application needs the data to exist for a longer duration,
     * then it must make a copy.
     */
    apr_status_t (*read)(serf_bucket_t *bucket, apr_size_t requested,
                         const char **data, apr_size_t *len);

    /**
     * Read (and consume) a line of data from @a bucket.
     *
     * The acceptable forms of a newline are given by @a acceptable, and
     * the type found is returned in @a found. If a newline is not present
     * in the returned data, then SERF_NEWLINE_NONE is stored into @a found.
     *
     * A pointer to the data is returned in @a data, and its length is
     * specified by @a len. The data will include the newline, if present.
     *
     * Note that there is no way to limit the amount of data returned
     * by this function.
     *
     * The lifetime of the data is the same as that of the @see read
     * function above.
     */
    apr_status_t (*readline)(serf_bucket_t *bucket, int acceptable,
                             int *found,
                             const char **data, apr_size_t *len);

    /**
     * Read a set of pointer/length pairs from the bucket.
     *
     * The size of the @a vecs array is specified by @a vecs_size. The
     * bucket should fill in elements of the array, and return the number
     * used in @a vecs_used.
     *
     * Each element of @a vecs should specify a pointer to a block of
     * data and a length of that data.
     *
     * The total length of all data elements should not exceed the
     * amount specified in @a requested.
     *
     * The lifetime of the data is the same as that of the @see read
     * function above.
     */
    apr_status_t (*read_iovec)(serf_bucket_t *bucket, apr_size_t requested,
                               int vecs_size, struct iovec *vecs,
                               int *vecs_used);

    /**
     * Read data from the bucket in a form suitable for apr_socket_sendfile()
     *
     * On input, hdtr->numheaders and hdtr->numtrailers specify the size
     * of the hdtr->headers and hdtr->trailers arrays, respectively. The
     * bucket should fill in the headers and trailers, up to the specified
     * limits, and set numheaders and numtrailers to the number of iovecs
     * filled in for each item.
     *
     * @a file should be filled in with a file that can be read. If a file
     * is not available or appropriate, then NULL should be stored. The
     * file offset for the data should be stored in @a offset, and the
     * length of that data should be stored in @a len. If a file is not
     * returned, then @a offset and @a len should be ignored.
     *
     * The file position is not required to correspond to @a offset, and
     * the caller may manipulate it at will.
     *
     * The total length of all data elements, and the portion of the
     * file should not exceed the amount specified in @a requested.
     *
     * The lifetime of the data is the same as that of the @see read
     * function above.
     */
    apr_status_t (*read_for_sendfile)(serf_bucket_t *bucket,
                                      apr_size_t requested, apr_hdtr_t *hdtr,
                                      apr_file_t **file, apr_off_t *offset,
                                      apr_size_t *len);

    /**
     * Look within @a bucket for a bucket of the given @a type. The bucket
     * must be the "initial" data because it will be consumed by this
     * function. If the given bucket type is available, then read and consume
     * it, and return it to the caller.
     *
     * This function is usually used by readers that have custom handling
     * for specific bucket types (e.g. looking for a file bucket to pass
     * to apr_socket_sendfile).
     *
     * If a bucket of the given type is not found, then NULL is returned.
     *
     * The returned bucket becomes the responsibility of the caller. When
     * the caller is done with the bucket, it should be destroyed.
     */
    serf_bucket_t * (*read_bucket)(serf_bucket_t *bucket,
                                   const serf_bucket_type_t *type);

    /**
     * Peek, but don't consume, the data in @a bucket.
     *
     * Since this function is non-destructive, the implicit read size is
     * SERF_READ_ALL_AVAIL. The caller can then use whatever amount is
     * appropriate.
     *
     * The @a data parameter will point to the data, and @a len will
     * specify how much data is available. The lifetime of the data follows
     * the same rules as the @see read function above.
     *
     * Note: if the peek does not return enough data for your particular
     * use, then you must read/consume some first, then peek again.
     *
     * If the returned data represents all available data, then APR_EOF
     * will be returned. Since this function does not consume data, it
     * can return the same data repeatedly rather than blocking; thus,
     * APR_EAGAIN will never be returned.
     */
    apr_status_t (*peek)(serf_bucket_t *bucket,
                         const char **data, apr_size_t *len);

    /**
     * Look up and return a piece of metadata from @a bucket.
     *
     * The metadata is specified by the metadata type @a md_type and the
     * metadata name @a md_name. The value is returned in @a md_value, or
     * NULL if the specified metadata does not exist in this bucket.
     *
     * Note that this function may return APR_EAGAIN if the metadata is
     * not (yet) available. Other (networking) errors may be returned, too.
     */
    apr_status_t (*get_metadata)(serf_bucket_t *bucket, const char *md_type,
                                 const char *md_name, const void **md_value);

    /**
     * Set some metadata for @a bucket.
     *
     * The metadata is specified by the metadata type @a md_type and the
     * metadata name @a md_name. The value is given by @a md_value, or
     * NULL if the specified metadata should be deleted.
     *
     * Note that this function may return errors if the metadata cannot
     * be set for some reason.
     */
    apr_status_t (*set_metadata)(serf_bucket_t *bucket, const char *md_type,
                                 const char *md_name, const void *md_value);

    /**
     * Destroy @a bucket, along with any associated resources.
     */
    void (*destroy)(serf_bucket_t *bucket);

    /* ### apr buckets have 'copy', 'split', and 'setaside' functions.
       ### not sure whether those will be needed in this bucket model.
    */
};

#define serf_bucket_read(b,r,d,l) ((b)->type->read(b,r,d,l))
#define serf_bucket_readline(b,a,f,d,l) ((b)->type->readline(b,a,f,d,l))
#define serf_bucket_read_iovec(b,r,s,v,u) ((b)->type->read_iovec(b,r,s,v,u))
#define serf_bucket_read_for_sendfile(b,r,h,f,o,l) \
    ((b)->type->read_for_sendfile(b,r,h,f,o,l))
#define serf_bucket_read_bucket(b,t) ((b)->type->read_bucket(b,t))
#define serf_bucket_peek(b,d,l) ((b)->type->peek(b,d,l))
#define serf_bucket_get_metadata(b,t,n,v) ((b)->type->get_metadata(b,t,n,v))
#define serf_bucket_set_metadata(b,t,n,v) ((b)->type->set_metadata(b,t,n,v))
#define serf_bucket_destroy(b) ((b)->type->destroy(b))


struct serf_bucket_t {

    /** the type of this bucket */
    const serf_bucket_type_t *type;

    /** bucket-private data */
    void *data;

    /** this bucket's metadata: (TYPE, NAME) -> VALUE */
    serf_metadata_t *metadata;

    /** the allocator used for this bucket (needed at destroy time) */
    serf_bucket_alloc_t *allocator;
};


/**
 * Generic macro to construct "is TYPE" macros.
 */
#define SERF_BUCKET_CHECK(b, btype) ((b)->type == &serf_bucket_type_ ## btype)


/**
 * Notification callback for a block that was not returned to the bucket
 * allocator when its pool was destroyed.
 *
 * The block of memory is given by @a block. The baton provided when the
 * allocator was constructed is passed as @a unfreed_baton.
 */
typedef void (*serf_unfreed_func_t)(void *unfreed_baton, void *block);

/**
 * Create a new allocator for buckets.
 *
 * All buckets are associated with a serf bucket allocator. This allocator
 * will be created within @a pool and will be destroyed when that pool is
 * cleared or destroyed.
 *
 * When the allocator is destroyed, if any allocations were not explicitly
 * returned (by calling serf_bucket_mem_free), then the @a unfreed callback
 * will be invoked for each block. @a unfreed_baton will be passed to the
 * callback.
 *
 * If @a unfreed is NULL, then the library will invoke the abort() stdlib
 * call. Any failure to return memory is a bug in the application, and an
 * abort can assist with determining what kinds of memory were not freed.
 */
SERF_DECLARE(serf_bucket_alloc_t *) serf_bucket_allocator_create(
    apr_pool_t *pool,
    serf_unfreed_func_t unfreed,
    void *unfreed_baton);

/**
 * Return the pool that was used for this @a allcoator.
 *
 * WARNING: the use of this pool for allocations requires a very
 *   detailed understanding of pool behaviors, the bucket system,
 *   and knowledge of the bucket's use within the overall pattern
 *   of request/response behavior.
 *
 * See design-guide.txt for more information about pool usage.
 */
SERF_DECLARE(apr_pool_t *) serf_bucket_allocator_get_pool(
    const serf_bucket_alloc_t *allocator);

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
