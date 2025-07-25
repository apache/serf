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

/* Include the headers needed for inet_ntop and related structs.
   On Windows, we'll always get <Winsock2.h> from <apr.h>. */
#if APR_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <apr_errno.h>
#include <apr_pools.h>
#include <apr_atomic.h>
#include <apr_network_io.h>
#include <apr_thread_mutex.h>
#include <apr_thread_pool.h>

/* Third-party resolver headers. */
#if SERF_HAVE_ASYNC_RESOLVER
#if SERF_HAVE_UNBOUND
#include <unbound.h>
#else
/* Really shouldn't happen, but just in case it does, fall back
   to the apr_thread_pool-based resolver. */
#undef SERF_HAVE_ASYNC_RESOLVER
#endif  /* SERF_HAVE_UNBOUND */
#endif

#include "serf.h"
#include "serf_private.h"


#define HAVE_ASYNC_RESOLVER (SERF_HAVE_ASYNC_RESOLVER || APR_HAS_THREADS)

/*
 * FIXME: EXPERIMENTAL
 * TODO:
 *  - Wake the poll/select in serf_context_run() when new resolve
 *    results are available.
 *
 *  - Figure out what to do if the lock/unlock calls return an error.
 *    This should not be possible unless we messed up the implementation,
 *    but there should be a way for clients to back out of this situation.
 *    Failed lock/unlock could potentially leave the context in an
 *    inconsistent state.
 *
 * TODO for Unbound:
 *  - Convert unbound results to apr_sockaddr_t.
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

    if (ctx->resolve_init_status != APR_SUCCESS) {
        return ctx->resolve_init_status;
    }

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

/* DNS classes and record types.
   https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml */
#define RR_CLASS_IN    1        /* Internet */
#define RR_TYPE_A      1        /* IPv4 address */
#define RR_TYPE_AAAA  28        /* IPv6 address */


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


struct resolve_context
{
    struct ub_ctx *ub_ctx;
    volatile apr_uint32_t tasks;
};

static apr_status_t cleanup_resolve_context(void *baton)
{
    struct resolve_context *const rctx = baton;
    ub_ctx_delete(rctx->ub_ctx);
    return APR_SUCCESS;
}

static apr_status_t create_resolve_context(serf_context_t *ctx)
{
    struct resolve_context *const rctx = apr_palloc(ctx->pool, sizeof(*rctx));
    int err;

    rctx->ub_ctx = ub_ctx_create();
    rctx->tasks = 0;
    if (!rctx->ub_ctx)
        return APR_ENOMEM;

    err = ub_ctx_resolvconf(rctx->ub_ctx, NULL);
    if (!err)
        err = ub_ctx_hosts(rctx->ub_ctx, NULL);
    if (!err)
        err = ub_ctx_async(rctx->ub_ctx, true);

    if (err) {
        const apr_status_t status = err_to_status(err);
        /* TODO: Error callback */
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "unbound ctx init: %s\n", ub_strerror(err));
        cleanup_resolve_context(rctx);
        return status;
    }

    ctx->resolve_context = rctx;
    /* pre-cleanup because the live resolve tasks contain subpools of the
       context pool and must be canceled before their pools go away. */
    apr_pool_pre_cleanup_register(ctx->pool, rctx, cleanup_resolve_context);
    return APR_SUCCESS;
}


/* Task data for the Unbound resolver. */
typedef struct unbound_resolve_task resolve_task_t;

struct resolve_result
{
    int err;
    apr_status_t status;
    struct ub_result* ub_result;
    resolve_task_t *task;
    const char *qtype;
};

struct unbound_resolve_task
{
    serf_context_t *ctx;
    apr_port_t host_port;

    /* There can be one or two pending results, depending on whether
       we resolve for IPv6 as well as IPv4. */
    volatile apr_uint32_t pending_results;
    struct resolve_result results[2];

    serf_address_resolved_t resolved;
    void *resolved_baton;
    apr_pool_t *resolve_pool;
};

static void resolve_finalize(resolve_task_t *task)
{
    /* TODO: Convert ub_result to apr_sockaddr_t */
    if (task->results[0].ub_result)
        ub_resolve_free(task->results[0].ub_result);
    if (task->results[1].ub_result)
        ub_resolve_free(task->results[1].ub_result);

    push_resolve_result(task->ctx, NULL, APR_EAFNOSUPPORT,
                        task->resolved, task->resolved_baton,
                        task->resolve_pool);
}

static void resolve_callback(void* baton, int err,
                             struct ub_result* ub_result)
{
    struct resolve_result *const resolve_result = baton;
    resolve_task_t *const task = resolve_result->task;
    apr_status_t status = err_to_status(err);

    struct resolve_context *const rctx = task->ctx->resolve_context;
    apr_atomic_dec32(&rctx->tasks);

    if (err)
    {
        /* TODO: Error callback */
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                  "unbound resolve: [%s] error %s\n",
                  resolve_result->qtype, ub_strerror(err));
    }
    else if (!ub_result->havedata)
    {
        if (ub_result->nxdomain) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: [%s] NXDOMAIN [%d]\n",
                      resolve_result->qtype, ub_result->rcode);
            if (status == APR_SUCCESS)
                status = APR_ENOENT;
        }
        if (ub_result->bogus) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: [%s] BOGUS [%d]%s%s\n",
                      resolve_result->qtype, ub_result->rcode,
                      ub_result->why_bogus ? " " : "",
                      ub_result->why_bogus ? ub_result->why_bogus : "");
            if (status == APR_SUCCESS)
                status = APR_EINVAL;
        }
        if (ub_result->was_ratelimited) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: [%s] SERVFAIL [%d]\n",
                      resolve_result->qtype, ub_result->rcode);
            if (status == APR_SUCCESS)
                status = APR_EAGAIN;
        }

        /* This shouldn't happen, one of the previous checks should
           have caught an error. */
        if (status == APR_SUCCESS) {
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, task->ctx->config,
                      "unbound resolve: [%s] no data [%d]\n",
                      resolve_result->qtype, ub_result->rcode);
            status = APR_ENOENT;
        }
    }

    resolve_result->err = err;
    resolve_result->status = status;
    resolve_result->ub_result = ub_result;

    if (status == APR_SUCCESS
        && serf__log_enabled(LOGLVL_DEBUG, LOGCOMP_CONN, task->ctx->config))
    {
        char buf[INET6_ADDRSTRLEN];
        const socklen_t len = sizeof(buf);
        int i;

        for (i = 0; ub_result->data && ub_result->data[i]; ++i) {
            const char *address = "(AF-unknown)";

            if (ub_result->len[i] == sizeof(struct in_addr))
                address = inet_ntop(AF_INET, ub_result->data[i], buf, len);
            else if (ub_result->len[i] == sizeof(struct in6_addr))
                address = inet_ntop(AF_INET6, ub_result->data[i], buf, len);
            serf__log(LOGLVL_DEBUG, LOGCOMP_CONN,
                      __FILE__, task->ctx->config,
                      "unbound resolve: [%s] %s: %s\n",
                      resolve_result->qtype, ub_result->qname, address);
        }
    }

    /* The last pending task combines and publishes the results. */
    if (apr_atomic_dec32(&task->pending_results) == 1)
        resolve_finalize(task);
}

static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool)
{
    struct resolve_context *const rctx = ctx->resolve_context;
    resolve_task_t *const task = apr_palloc(resolve_pool, sizeof(*task));
    apr_status_t status = APR_SUCCESS;
    int err4 = 0, err6 = 0;

    task->ctx = ctx;
    task->host_port = host_info.port;

#if APR_HAVE_IPV6
    task->pending_results = 2;
#else
    task->pending_results = 1;
#endif
    task->results[0].err = task->results[1].err = 0;
    task->results[0].status = task->results[1].status = APR_SUCCESS;
    task->results[0].ub_result = task->results[1].ub_result = NULL;
    task->results[0].task = task->results[1].task = task;
    task->results[0].qtype = task->results[1].qtype = "??";

    task->resolved = resolved;
    task->resolved_baton = resolved_baton;
    task->resolve_pool = resolve_pool;

    task->results[0].qtype = "v4";
    err4 = ub_resolve_async(rctx->ub_ctx, host_info.hostname,
                            RR_TYPE_A, RR_CLASS_IN,
                            &task->results[0], resolve_callback, NULL);
    if (!err4) {
        apr_atomic_inc32(&rctx->tasks);
    }

#if APR_HAVE_IPV6
    task->results[1].qtype = "v6";
    err6 = ub_resolve_async(rctx->ub_ctx, host_info.hostname,
                            RR_TYPE_AAAA, RR_CLASS_IN,
                            &task->results[1], resolve_callback, NULL);
    if (!err6) {
        apr_atomic_inc32(&rctx->tasks);
    }
#endif  /* APR_HAVE_IPV6 */

    if (err4 || err6)
    {
        apr_uint32_t pending_results = -1;

        if (err4) {
            pending_results = apr_atomic_dec32(&task->pending_results);
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                      "unbound resolve start: [v4] %s\n", ub_strerror(err4));
            status = err_to_status(err4);
        }

#if APR_HAVE_IPV6
        if (err6) {
            pending_results = apr_atomic_dec32(&task->pending_results);
            /* TODO: Error callback */
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                      "unbound resolve start: [v6] %s\n", ub_strerror(err6));
            /* We have only one status to report. */
            if (!err4)
                status = err_to_status(err6);
        }
#endif  /* APR_HAVE_IPV6 */

        /* If one of the tasks failed and the other has already completed,
           we have to do the result processing here. Note that the Unbound
           callbacks can be called synchronously from ub_resolve_async(). */
        if (pending_results == 1)
            resolve_finalize(task);
    }

    return status;
}

static apr_status_t run_async_resolver_loop(serf_context_t *ctx)
{
    struct resolve_context *const rctx = ctx->resolve_context;

    /* No need to poll if there are no in-flight tasks. */
    if (apr_atomic_read32(&rctx->tasks))
    {
        if (ub_poll(rctx->ub_ctx)) {
            const int err = ub_process(rctx->ub_ctx);
            if (err) {
                const apr_status_t status = err_to_status(err);
                /* TODO: Error callback */
                serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                          "unbound process: %s\n", ub_strerror(err));
                return status;
            }
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
