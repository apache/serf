/* ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

#include <apr.h>
#include <apr_errno.h>
#include <apr_network_io.h>
#include <apr_pools.h>
#include <apr_thread_mutex.h>
#include <apr_thread_pool.h>

#include "serf.h"
#include "serf_private.h"


#define HAVE_ASYNC_RESOLVER (SERF_USE_ASYNC_RESOLVER || APR_HAS_THREADS)

/*
 * FIXME: EXPERIMENTAL
 * TODO:
 *  - Add cleanup function for in-flight resolve tasks if their owning
 *    context is destroyed. This function should be called from the
 *    context's pool cleanup handler.
 *  - Figure out what to do if the lock/unlock calls return an error.
 *    This should not be possible unless we messed up the implementation,
 *    but there should be a way for clients to back out of this situation.
 *    Failed lock/unlock could potentially leave the context in an
 *    inconsistent state.
 */


#if HAVE_ASYNC_RESOLVER

/* Pushes the result of a successful or failed address resolution
   onto the context's result queue. */
static void push_resolve_result(serf_context_t *ctx,
                                apr_sockaddr_t *host_address,
                                apr_status_t status,
                                serf_address_resolved_t resolved,
                                void *resolved_baton,
                                apr_pool_t *resolve_pool);

/* This is the core of the asynchronous resolver implementation. */
static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool);

/* Public API */
apr_status_t serf_address_resolve_async(serf_context_t *ctx,
                                        apr_uri_t host_info,
                                        serf_address_resolved_t resolved,
                                        void *resolved_baton,
                                        apr_pool_t *pool)
{
    apr_pool_t *resolve_pool;

    apr_pool_create(&resolve_pool, ctx->pool);

    /* See serf_connection_create3(): if there's a proxy configured in the
       context, don't resolve the host address, just register the result. */
    if (ctx->proxy_address)
    {
        push_resolve_result(ctx, NULL, APR_SUCCESS,
                            resolved, resolved_baton, resolve_pool);
        return APR_SUCCESS;
    }

    return resolve_address_async(ctx, host_info, resolved, resolved_baton,
                                 resolve_pool, pool);
}

#else    /* !HAVE_ASYNC_RESOLVER */

/* Public API */
apr_status_t serf_address_resolve_async(serf_context_t *ctx,
                                        apr_uri_t host_info,
                                        serf_address_resolved_t resolved,
                                        void *resolved_baton,
                                        apr_pool_t *pool)
{
    /* We have no external asynchronous resolver library, nor threads,
       therefore no async resolver at all. */
    return APR_ENOTIMPL;
}

#endif  /* !HAVE_ASYNC_RESOLVER */


#if SERF_USE_ASYNC_RESOLVER

/* TODO: Add implementation for one or more async resolver libraries. */
#if 0
static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool)
{
    ...
}

/* Some asynchronous resolved libraries use event loop to harvest results.
   This function will be called from serf__process_async_resolve_results()
   so, in effect, from serf_context_prerun(). */
static void run_async_resolver_loop(void)
{
    ...
}
#endif

#else    /* !SERF_USE_ASYNC_RESOLVER */
#if APR_HAS_THREADS

/* This could be made configurable, but given that this is a fallback
   implementation, it really shouldn't be necessary. */
#define MAX_WORK_QUEUE_THREADS 50
static apr_pool_t *work_pool = NULL;
static apr_thread_pool_t *work_queue = NULL;
static apr_status_t init_work_queue(void *baton)
{
    serf_context_t *ctx = baton;
    apr_status_t status;

    apr_pool_create(&work_pool, NULL);
    status = apr_thread_pool_create(&work_queue,
                                    1, MAX_WORK_QUEUE_THREADS,
                                    work_pool);

    serf__log((status ? LOGLVL_ERROR : LOGLVL_DEBUG),
              LOGCOMP_CONN, __FILE__, ctx->config,
              "Init async resolve work queue, status %d\n", status);
    return status;
}


/* Task data for the thred pool resolver. */
typedef struct resolve_task_t resolve_task_t;
struct resolve_task_t
{
    serf_context_t *ctx;
    apr_uri_t host_info;
    serf_address_resolved_t resolved;
    void *resolved_baton;
    apr_pool_t *resolve_pool;
};


static void *APR_THREAD_FUNC resolve(apr_thread_t *thread, void *baton)
{
    resolve_task_t *task = baton;
    apr_sockaddr_t *host_address;
    apr_status_t status;

    status = apr_sockaddr_info_get(&host_address,
                                   task->host_info.hostname,
                                   APR_UNSPEC,
                                   task->host_info.port,
                                   0, task->resolve_pool);
    push_resolve_result(task->ctx, host_address, status,
                        task->resolved, task->resolved_baton,
                        task->resolve_pool);
    return NULL;
}

static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool)
{
    resolve_task_t *task;
    apr_status_t status;
    SERF__DECLARE_STATIC_INIT_ONCE_CONTEXT(init_ctx);

    status = serf__init_once(&init_ctx, init_work_queue, ctx);
    if (status)
        return status;

    task = apr_palloc(resolve_pool, sizeof(*task));
    task->ctx = ctx;
    task->host_info = host_info;
    task->resolved = resolved;
    task->resolved_baton = resolved_baton;
    task->resolve_pool = resolve_pool;
    return apr_thread_pool_push(work_queue, resolve, task,
                                APR_THREAD_TASK_PRIORITY_NORMAL,
                                (void*)ctx);
}

/* This is a no-op since we're using a thread pool that
   does its own task queue management. */
static void run_async_resolver_loop(void) {}

#endif  /* !APR_HAS_THREADS */
#endif  /* !SERF_USE_ASYNC_RESOLVER */


/*******************************************************************/
/* The result queue implementation. */
#if HAVE_ASYNC_RESOLVER

static apr_status_t lock_results(serf_context_t *ctx)
{
#if APR_HAS_THREADS
    apr_status_t status = apr_thread_mutex_lock(ctx->resolve_guard);
    if (status) {
        /* TODO: ctx->error_callback... */
        char buffer[256];
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "Lock async resolve results: %s\n",
                  apr_strerror(status, buffer, sizeof(buffer)));
    }
    return status;
#else
    return APR_SUCCESS;
#endif
}

static apr_status_t unlock_results(serf_context_t *ctx)
{
#if APR_HAS_THREADS
    apr_status_t status = apr_thread_mutex_unlock(ctx->resolve_guard);
    if (status) {
        /* TODO: ctx->error_callback... */
        char buffer[256];
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "Unlock async resolve results: %s\n",
                  apr_strerror(status, buffer, sizeof(buffer)));
    }
    return status;
#else
    return APR_SUCCESS;
#endif
}


static void push_resolve_result(serf_context_t *ctx,
                                apr_sockaddr_t *host_address,
                                apr_status_t status,
                                serf_address_resolved_t resolved,
                                void *resolved_baton,
                                apr_pool_t *resolve_pool)
{
    serf__resolve_result_t *result;
    apr_status_t lock_status;

    result = apr_palloc(resolve_pool, sizeof(*result));
    result->host_address = host_address;
    result->status = status;
    result->resolved = resolved;
    result->resolved_baton = resolved_baton;
    result->result_pool = resolve_pool;

    lock_status = lock_results(ctx);
    if (!lock_status)
    {
        result->next = ctx->resolve_head;
        ctx->resolve_head = result;
        lock_status = unlock_results(ctx);
    }

    /* TODO: if (lock_status) ... then what? */
}


/* Internal API */
apr_status_t serf__process_async_resolve_results(serf_context_t *ctx)
{
    serf__resolve_result_t *result = NULL;
    apr_status_t lock_status;

    run_async_resolver_loop();

    lock_status = lock_results(ctx);
    if (lock_status)
        return lock_status;

    result = ctx->resolve_head;
    ctx->resolve_head = NULL;
    lock_status = unlock_results(ctx);

    /* TODO: if (lock_status) ... then what? Shouldn't be possible. */
    /* if (lock_status) */
    /*     return lock_status; */

    while (result)
    {
        serf__resolve_result_t *const next = result->next;
        result->resolved(ctx, result->resolved_baton,
                         result->host_address, result->status,
                         result->result_pool);
        apr_pool_destroy(result->result_pool);
        result = next;
    }
    return APR_SUCCESS;
}

#else   /* !HAVE_ASYNC_RESOLVER */

/* Internal API */
apr_status_t serf__process_async_resolve_results(serf_context_t *ctx)
{
    /* The fallback is a no-op, the context should just continue to
       work without an asynchronous resolver. */
    return APR_SUCCESS;
}

#endif  /* !HAVE_ASYNC_RESOLVER */
