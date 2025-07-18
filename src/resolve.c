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
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_thread_mutex.h>
#include <apr_thread_pool.h>

/* This will include <netinet/in.h> and/or <arpa/inet.h>, which we'll
   use for logging the resolver results. On Windows, we'll always get
   <Winsock2.h> from <apr.h>. */
#define APR_WANT_BYTEFUNC
#include <apr_want.h>

#include "serf.h"
#include "serf_private.h"


#define HAVE_ASYNC_RESOLVER (SERF_HAVE_ASYNC_RESOLVER || APR_HAS_THREADS)

#if SERF_HAVE_ASYNC_RESOLVER
#if SERF_HAVE_UNBOUND
#include <unbound.h>
#else
/* Really shouldn't happen, but just in case it does, fall back
   to the apr_thread_pool-based resolver. */
#undef SERF_HAVE_ASYNC_RESOLVER
#endif  /* SERF_HAVE_UNBOUND */
#endif

/*
 * FIXME: EXPERIMENTAL
 * TODO:
 *  - Wake the poll/select in serf_context_run() when new resolve
 *    results are available.
 *
 *  - Add a way to cancel a resolve task?
 *
 *  - Figure out what to do if the lock/unlock calls return an error.
 *    This should not be possible unless we messed up the implementation,
 *    but there should be a way for clients to back out of this situation.
 *    Failed lock/unlock could potentially leave the context in an
 *    inconsistent state.
 *
 * TODO for Unbound:
 *  - Convert unbound results to apr_sockaddr_t.
 *
 *  - Resolve both IPv4 and IPv6 addresses. This will require creating two
 *    asynchronous resolve tasks and combining the results so that our
 *    callback gets invoked only once both tasks are completed.
 *
 *  - Figure out how to use libunbound's event-based API, because it uses
 *    true asynchronous I/O instead of background threads.
 */


#if HAVE_ASYNC_RESOLVER

/* Pushes the result of a successful or failed address resolution
   onto the context's result queue. */
static void push_resolve_result(serf_context_t *ctx,
                                apr_sockaddr_t *host_address,
                                apr_status_t resolve_status,
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

#if APR_HAS_THREADS
    if (ctx->resolve_init_status != APR_SUCCESS) {
        return ctx->resolve_init_status;
    }
#endif

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


#if SERF_HAVE_ASYNC_RESOLVER

/* TODO: Add implementation for one or more async resolver libraries. */
#if 0
/* Called during context creation. Must initialize ctx->resolver_context. */
static apr_status_t create_resolve_context(serf_context_t *ctx)
{
    ...
}

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
static apr_status_t run_async_resolver_loop(serf_context_t *ctx)
{
    ...
}
#endif  /* 0 */

#if SERF_HAVE_UNBOUND

static apr_status_t err_to_status(enum ub_ctx_err err)
{
    switch (err)
    {
    case UB_NOERROR:
        /* no error */
        return APR_SUCCESS;

    case UB_SOCKET:
        /* socket operation. Set to -1, so that if an error from _fd() is
           passed (-1) it gives a socket error. */
        if (errno)
            return APR_FROM_OS_ERROR(errno);
        return APR_ENOTSOCK;

    case UB_NOMEM:
        /* alloc failure */
        return APR_ENOMEM;

    case UB_SYNTAX:
        /* syntax error */
        return APR_EINIT;

    case UB_SERVFAIL:
        /* DNS service failed */
        return APR_EAGAIN;

    case UB_FORKFAIL:
        /* fork() failed */
        return APR_ENOMEM;

    case UB_AFTERFINAL:
        /* cfg change after finalize() */
        return APR_EINIT;

    case UB_INITFAIL:
        /* initialization failed (bad settings) */
        return APR_EINIT;

    case UB_PIPE:
        /* error in pipe communication with async bg worker */
        return APR_EPIPE;

    case UB_READFILE:
        /* error reading from file (resolv.conf) */
        if (errno)
            return APR_FROM_OS_ERROR(errno);
        return APR_ENOENT;

    case UB_NOID:
        /* error async_id does not exist or result already been delivered */
        return APR_EINVAL;

    default:
        return APR_EGENERAL;
    }
}


static apr_status_t cleanup_resolve_context(void *baton)
{
    struct ub_ctx *const resolve_context = baton;
    ub_ctx_delete(resolve_context);
    return APR_SUCCESS;
}

static apr_status_t create_resolve_context(serf_context_t *ctx)
{
    int err;
    struct ub_ctx *const resolve_context = ub_ctx_create();
    if (!resolve_context)
        return APR_ENOMEM;

    err = ub_ctx_resolvconf(resolve_context, NULL);
    if (!err)
        err = ub_ctx_hosts(resolve_context, NULL);
    if (!err)
        err = ub_ctx_async(resolve_context, true);

    if (err) {
        const apr_status_t status = err_to_status(err);
        /* TODO: Error callback */
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "unbound ctx init: %s\n", ub_strerror(err));
        return status;
    }

    ctx->resolve_context = resolve_context;
    /* pre-cleanup because the live resolve tasks contain subpools of the
       context pool and must be canceled before their pools go away. */
    apr_pool_pre_cleanup_register(ctx->pool, resolve_context,
                                  cleanup_resolve_context);
    return APR_SUCCESS;
}


/* Task data for the Unbound resolver. */
typedef struct unbound_resolve_task resolve_task_t;
struct unbound_resolve_task
{
    serf_context_t *ctx;
    apr_port_t host_port;
    serf_address_resolved_t resolved;
    void *resolved_baton;
    apr_pool_t *resolve_pool;
};

static void resolve_callback(void* baton, int err,
                             struct ub_result* result)
{
    resolve_task_t *const task = baton;
    apr_status_t status = err_to_status(err);

    if (err) {
        /* TODO: Error callback */
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                  "unbound resolve: error %s\n", ub_strerror(err));
    }
    if (!result->havedata) {
        if (result->nxdomain) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: NXDOMAIN [%d]\n", result->rcode);
            if (status == APR_SUCCESS)
                status = APR_ENOENT;
        }
        if (result->bogus) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: BOGUS [%d]%s%s\n", result->rcode,
                      result->why_bogus ? " " : "",
                      result->why_bogus ? result->why_bogus : "");
            if (status == APR_SUCCESS)
                status = APR_EINVAL;
        }
        if (result->was_ratelimited) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: SERVFAIL [%d]\n", result->rcode);
            if (status == APR_SUCCESS)
                status = APR_EAGAIN;
        }

        /* This shouldn't happen, one of the previous checks should
           have caught an error. */
        if (status == APR_SUCCESS) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: no data [%d]\n", result->rcode);
            status = APR_ENOENT;
        }
    }

    if (status)
    {
        push_resolve_result(task->ctx, NULL, status,
                            task->resolved, task->resolved_baton,
                            task->resolve_pool);
    }
    else
    {
        if (serf__log_enabled(LOGLVL_DEBUG, LOGCOMP_CONN,task->ctx->config))
        {
            int i;

            for (i = 0; result->data && result->data[i]; ++i) {
                char buf[INET6_ADDRSTRLEN];
                const socklen_t len = sizeof(buf);
                const char *address = "(AF-unknown)";

                if (result->len[i] == sizeof(struct in_addr))
                    address = inet_ntop(AF_INET, result->data[i], buf, len);
                else if (result->len[i] == sizeof(struct in6_addr))
                    address = inet_ntop(AF_INET6, result->data[i], buf, len);
                serf__log(LOGLVL_DEBUG, LOGCOMP_CONN,
                          __FILE__, task->ctx->config,
                          "unbound resolve: %s: %s\n", result->qname, address);
            }
        }

        /* TODO: Convert ub_result to apr_sockaddr_t */
        push_resolve_result(task->ctx, NULL, APR_EAFNOSUPPORT,
                            task->resolved, task->resolved_baton,
                            task->resolve_pool);
    }

    ub_resolve_free(result);
}

static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool)
{
    struct ub_ctx *const resolve_context = ctx->resolve_context;
    resolve_task_t *const task = apr_palloc(resolve_pool, sizeof(*task));
    apr_status_t status = APR_SUCCESS;
    int err;

    task->ctx = ctx;
    task->host_port = host_info.port;
    task->resolved = resolved;
    task->resolved_baton = resolved_baton;
    task->resolve_pool = resolve_pool;

    /* FIXME: We should resolve both RRType 1 (A) and RRType 28 (AAAA). */
    if ((err = ub_resolve_async(resolve_context, host_info.hostname,
                                1,   /* rrtype: IPv4 host address (A) */
                                1,   /* rrclass: IN(ternet) */
                                task, resolve_callback, NULL)))
    {
        /* TODO: Error callback */
        status = err_to_status(err);
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "unbound resolve start: %s\n", ub_strerror(err));
    }

    return status;
}

static apr_status_t run_async_resolver_loop(serf_context_t *ctx)
{
    struct ub_ctx *const resolve_context = ctx->resolve_context;

    if (ub_poll(resolve_context)) {
        const int err = ub_process(resolve_context);
        if (err) {
            const apr_status_t status = err_to_status(err);
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                      "unbound process: %s\n", ub_strerror(err));
            return status;
        }
    }

    return APR_SUCCESS;
}

#endif  /* SERF_HAVE_UNBOUND */

#else   /* !SERF_HAVE_ASYNC_RESOLVER */
#if APR_HAS_THREADS

/* This could be made configurable, but given that this is a fallback
   implementation, it really shouldn't be necessary. */
#define MAX_WORK_QUEUE_THREADS 50
static apr_pool_t *work_pool = NULL;
static apr_thread_pool_t *work_queue = NULL;

static apr_status_t do_init_work_queue(void *baton)
{
    serf_context_t *const ctx = baton;
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

static apr_status_t init_work_queue(serf_context_t *ctx)
{
    SERF__DECLARE_STATIC_INIT_ONCE_CONTEXT(init_ctx);
    return serf__init_once(&init_ctx, do_init_work_queue, ctx);
}


static apr_status_t cleanup_resolve_tasks(void *baton)
{
    /* baton is serf_context_t */
    return apr_thread_pool_tasks_cancel(work_queue, baton);
}

static apr_status_t create_resolve_context(serf_context_t *ctx)
{
    apr_status_t status;

    ctx->resolve_context = NULL;
    status = init_work_queue(ctx);
    if (status == APR_SUCCESS)
        apr_pool_pre_cleanup_register(ctx->pool, ctx, cleanup_resolve_tasks);

    return status;
}


/* Task data for the thred pool resolver. */
typedef struct threadpool_resolve_task resolve_task_t;
struct threadpool_resolve_task
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

    if (status) {
        host_address = NULL;
    }
    else if (serf__log_enabled(LOGLVL_DEBUG, LOGCOMP_CONN, task->ctx->config))
    {
        apr_sockaddr_t *addr = host_address;
        while (addr)
        {
            char buf[INET6_ADDRSTRLEN];
            const socklen_t len = sizeof(buf);
            const char *address = "(AF-unknown)";

            if (addr->family == APR_INET || addr->family == APR_INET6)
                address = inet_ntop(addr->family, addr->ipaddr_ptr, buf, len);
            serf__log(LOGLVL_DEBUG, LOGCOMP_CONN,
                      __FILE__, task->ctx->config,
                      "apr async resolve: %s: %s\n", addr->hostname, address);
            addr = addr->next;
        }
    }

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
    apr_status_t status = init_work_queue(ctx);
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
static apr_status_t run_async_resolver_loop(serf_context_t *ctx)
{
    return APR_SUCCESS;
}

#endif  /* !APR_HAS_THREADS */
#endif  /* !SERF_HAVE_ASYNC_RESOLVER */


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
                                apr_status_t resolve_status,
                                serf_address_resolved_t resolved,
                                void *resolved_baton,
                                apr_pool_t *resolve_pool)
{
    serf__resolve_result_t *result;
    apr_status_t status;

    result = apr_palloc(resolve_pool, sizeof(*result));
    result->host_address = host_address;
    result->status = resolve_status;
    result->resolved = resolved;
    result->resolved_baton = resolved_baton;
    result->result_pool = resolve_pool;

    status = lock_results(ctx);
    if (!status)
    {
        result->next = ctx->resolve_head;
        ctx->resolve_head = result;
        status = unlock_results(ctx);
    }

    /* TODO: if (status) ... then what? */
}


/* Internal API */
apr_status_t serf__create_resolve_context(serf_context_t *ctx)
{
    return create_resolve_context(ctx);
}


/* Internal API */
apr_status_t serf__process_async_resolve_results(serf_context_t *ctx)
{
    serf__resolve_result_t *result = NULL;
    apr_status_t status;

    status = run_async_resolver_loop(ctx);
    if (status)
        return status;

    status = lock_results(ctx);
    if (status)
        return status;

    result = ctx->resolve_head;
    ctx->resolve_head = NULL;
    status = unlock_results(ctx);

    /* TODO: if (status) ... then what? Shouldn't be possible. */
    /* if (status) */
    /*     return status; */

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
