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

#if defined(_DEBUG)
#include <assert.h>
#define SERF__RESOLV_assert(x) assert(x)
#else
#define SERF__RESOLV_assert(x) ((void)0)
#endif

#include <apr.h>
#include <apr_version.h>

#define APR_WANT_BYTEFUNC
#define APR_WANT_MEMFUNC
#include <apr_want.h>

#include <apr_errno.h>
#include <apr_pools.h>
#include <apr_atomic.h>
#include <apr_strings.h>
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

/* Sufficient buffer size for an IPv4 and IPv6 binary address. */
#define MAX_ADDRLEN 16

/* Stringified address lengths. */
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN  sizeof("255.255.255.255")
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#endif

#define HAVE_ASYNC_RESOLVER (SERF_HAVE_ASYNC_RESOLVER || APR_HAS_THREADS)


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

/*******************************************************************/
/* Async resolver that uses libunbound. */

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
        const char *message = apr_psprintf(ctx->pool, "unbound ctx init: %s",
                                           ub_strerror(err));
        serf__context_error(ctx, status, message);
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                  ctx->config, "%s\n", message);
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
    apr_status_t status;
    struct ub_result* ub_result;
    resolve_task_t *task;
    const char *qtype;
};

struct unbound_resolve_task
{
    serf_context_t *ctx;
    char *host_port_str;
    apr_port_t host_port;

    /* There can be one or two pending results, depending on whether
       we resolve for IPv6 as well as IPv4. */
    volatile apr_uint32_t pending_results;
    struct resolve_result results[2];

    serf_address_resolved_t resolved;
    void *resolved_baton;
    apr_pool_t *resolve_pool;
};

static apr_status_t resolve_convert(apr_sockaddr_t **host_address,
                                    apr_int32_t family, bool free_result,
                                    const struct resolve_result *result)
{
    const struct unbound_resolve_task *const task = result->task;
    const struct ub_result *const ub_result = result->ub_result;
    apr_pool_t *const resolve_pool = task->resolve_pool;
    apr_status_t status = result->status;

    if (status == APR_SUCCESS)
    {
        char *hostname = apr_pstrdup(resolve_pool, (ub_result->canonname
                                                    ? ub_result->canonname
                                                    : ub_result->qname));
        apr_socklen_t salen;
        int ipaddr_len;
        int addr_str_len;
        int i;

        if (family == APR_INET) {
            salen = sizeof(struct sockaddr_in);
            ipaddr_len = sizeof(struct in_addr);
            addr_str_len = INET_ADDRSTRLEN;
        }
#if APR_HAVE_IPV6
        else {
            salen = sizeof(struct sockaddr_in6);
            ipaddr_len = sizeof(struct in6_addr);
            addr_str_len = INET6_ADDRSTRLEN;
        }
#endif

        /* Check that all result sizes are correct. */
        for (i = 0; ub_result->data[i]; ++i)
        {
            if (ub_result->len[i] != ipaddr_len) {
                const char *message = apr_psprintf(
                    resolve_pool,
                    "unbound resolve: [%s] invalid address: "
                    " length %d, expected %d",
                    result->qtype, ub_result->len[i], ipaddr_len);
                status = APR_EINVAL;
                serf__context_error(task->ctx, status, message);
                serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                          task->ctx->config, "%s\n", message);
                goto cleanup;
            }
        }

        for (i = 0; ub_result->data[i]; ++i)
        {
            apr_sockaddr_t *addr = apr_palloc(resolve_pool, sizeof(*addr));
            addr->pool = resolve_pool;
            addr->hostname = hostname;
            addr->servname = task->host_port_str;
            addr->port = task->host_port;
            addr->family = family;
            addr->salen = salen;
            addr->ipaddr_len = ipaddr_len;
            addr->addr_str_len = addr_str_len;
            addr->next = *host_address;

            memset(&addr->sa, 0, sizeof(addr->sa));
            if (family == APR_INET) {
                addr->ipaddr_ptr = &addr->sa.sin.sin_addr.s_addr;
                addr->sa.sin.sin_family = APR_INET;
                addr->sa.sin.sin_port = htons(addr->port);
            }
#if APR_HAVE_IPV6
            else {
                addr->ipaddr_ptr = &addr->sa.sin6.sin6_addr.s6_addr;
                addr->sa.sin6.sin6_family = APR_INET6;
                addr->sa.sin6.sin6_port = htons(addr->port);
            }
#endif
            memcpy(addr->ipaddr_ptr, ub_result->data[i], ipaddr_len);
            *host_address = addr;

            if (serf__log_enabled(LOGLVL_DEBUG, LOGCOMP_CONN,
                                  task->ctx->config)) {
                char buf[INET6_ADDRSTRLEN];
                if (!apr_sockaddr_ip_getbuf(buf, sizeof(buf), addr)) {
                    serf__log(LOGLVL_DEBUG, LOGCOMP_CONN,
                              __FILE__, task->ctx->config,
                              "unbound resolve: [%s] %s: %s\n",
                              result->qtype, addr->hostname, buf);
                }
            }
        }
    }

  cleanup:
    if (free_result && result->ub_result)
        ub_resolve_free(result->ub_result);

    return status;
}

static void resolve_finalize(resolve_task_t *task)
{
    apr_sockaddr_t *host_address = NULL;
    apr_status_t status, status6;

    status = resolve_convert(&host_address, APR_INET, true, &task->results[0]);
#if APR_HAVE_IPV6
    status6 = resolve_convert(&host_address, APR_INET6, true, &task->results[1]);
#else
    status6 = APR_SUCCESS;
#endif

    if (!host_address) {
        if (status == APR_SUCCESS)
            status = status6;
        if (status == APR_SUCCESS)
            status = APR_ENOENT;
    }
    else {
        /* If we got a result, ee don't care if one of the resolves failed. */
        status = APR_SUCCESS;
    }

    push_resolve_result(task->ctx, host_address, status,
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
        const char *message = apr_psprintf(
            task->resolve_pool,
            "unbound resolve: [%s] error %s",
            resolve_result->qtype, ub_strerror(err));
        serf__context_error(task->ctx, status, message);
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                  task->ctx->config, "%s\n", message);
    }
    else if (!ub_result->havedata)
    {
        const char *message;
        if (ub_result->nxdomain) {
            if (status == APR_SUCCESS)
                status = APR_ENOENT;
            message = apr_psprintf(
                task->resolve_pool,
                "unbound resolve: [%s] NXDOMAIN [%d]",
                resolve_result->qtype, ub_result->rcode);
            serf__context_error(task->ctx, status, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      task->ctx->config, "%s\n", message);
        }
        if (ub_result->bogus) {
            if (status == APR_SUCCESS)
                status = APR_EINVAL;
            message = apr_psprintf(
                task->resolve_pool,
                "unbound resolve: [%s] BOGUS [%d]%s%s",
                resolve_result->qtype, ub_result->rcode,
                ub_result->why_bogus ? " " : "",
                ub_result->why_bogus ? ub_result->why_bogus : "");
            serf__context_error(task->ctx, status, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      task->ctx->config, "%s\n", message);
        }
        if (ub_result->was_ratelimited) {
            if (status == APR_SUCCESS)
                status = APR_EAGAIN;
            message = apr_psprintf(
                task->resolve_pool,
                "unbound resolve: [%s] SERVFAIL [%d]",
                resolve_result->qtype, ub_result->rcode);
            serf__context_error(task->ctx, status, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      task->ctx->config, "%s\n", message);
        }

        /* This shouldn't happen, one of the previous checks should
           have caught an error. */
        if (status == APR_SUCCESS) {
            status = APR_ENOENT;
            message = apr_psprintf(
                task->resolve_pool,
                "unbound resolve: [%s] no data [%d]\n",
                resolve_result->qtype, ub_result->rcode);
            serf__context_error(task->ctx, status, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      task->ctx->config, "%s\n", message);
        }
    }

    resolve_result->status = status;
    resolve_result->ub_result = ub_result;

    /* The last pending task combines and publishes the results. */
    if (apr_atomic_dec32(&task->pending_results) == 0)
        resolve_finalize(task);
}

static apr_status_t resolve_address_async(serf_context_t *ctx,
                                          apr_uri_t host_info,
                                          serf_address_resolved_t resolved,
                                          void *resolved_baton,
                                          apr_pool_t *resolve_pool,
                                          apr_pool_t *scratch_pool)
{
    unsigned char addr[MAX_ADDRLEN];
    struct resolve_context *const rctx = ctx->resolve_context;
    resolve_task_t *task;
    apr_status_t status = APR_SUCCESS;
    int err4 = 0, err6 = 0;
    apr_int32_t family;
    int pton, ipaddr_len, rr_type;

    /* If the hostname is an IP address, "resolve" it immediately. */
    pton = serf__inet_pton4(host_info.hostname, addr);
    if (pton > 0) {
        family = APR_INET;
        rr_type = RR_TYPE_A;
        ipaddr_len = sizeof(struct in_addr);
        SERF__RESOLV_assert(ipaddr_len <= MAX_ADDRLEN);
    }
    else {
        pton = serf__inet_pton6(host_info.hostname, addr);
        if (pton > 0) {
#if APR_HAVE_IPV6
            family = APR_INET6;
            rr_type = RR_TYPE_AAAA;
            ipaddr_len = sizeof(struct in6_addr);
            SERF__RESOLV_assert(ipaddr_len <= MAX_ADDRLEN);
#else
            return APR_EAFNOSUPPORT;
#endif
        }
    }

    if (pton > 0)
    {
        static const struct ub_result ub_template = {
            NULL,               /* .qname */
            0,                  /* .qtype */
            RR_CLASS_IN,        /* .qclass */
            NULL,               /* .data */
            NULL,               /* .len */
            NULL,               /* .canonname */
            0,                  /* .rcode */
            NULL,               /* .answer_packet */
            0,                  /* .answer_len */
            1,                  /* .havedata */
            0,                  /* .nxdomain */
            0,                  /* .secure */
            0,                  /* .bogus */
            NULL,               /* .why_bogus */
            0,                  /* .was_ratelimited */
            INT_MAX             /* .ttl */
        };

        struct ub_result ub_result = ub_template;
        apr_sockaddr_t *host_address = NULL;
        char *data[2] = { NULL, NULL };
        int len[2] = { 0, 0 };
        struct resolve_result *result;
        resolve_task_t local_task;

        memset(&local_task, 0, sizeof(local_task));
        data[0] = (char*) addr;
        len[0] = ipaddr_len;
        ub_result.qname = host_info.hostname;
        ub_result.qtype = rr_type;
        ub_result.data = data;
        ub_result.len = len;

        task = &local_task;
        task->ctx = ctx;
        task->host_port_str = host_info.port_str;
        task->host_port = host_info.port;
        task->resolve_pool = resolve_pool;
        result = &task->results[0];
        result->status = APR_SUCCESS;
        result->ub_result = &ub_result;
        result->task = task;
        result->qtype = family == APR_INET ? "v4" : "v6";

        status = resolve_convert(&host_address, family, false, result);
        if (status == APR_SUCCESS) {
            push_resolve_result(ctx, host_address, status,
                                resolved, resolved_baton,
                                resolve_pool);
        }
        return status;
    }

    /* Create the async resolve tasks. */
    task = apr_palloc(resolve_pool, sizeof(*task));
    task->ctx = ctx;
    task->host_port_str = apr_pstrdup(resolve_pool, host_info.port_str);
    task->host_port = host_info.port;

#if APR_HAVE_IPV6
    task->pending_results = 2;
#else
    task->pending_results = 1;
#endif
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
        const char *message;

        if (err4) {
            pending_results = apr_atomic_dec32(&task->pending_results);
            message = apr_psprintf(resolve_pool,
                                   "unbound resolve start: [v4] %s",
                                   ub_strerror(err4));
            status = err_to_status(err4);
            serf__context_error(ctx, status, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      ctx->config, "%s\n", message);
        }

#if APR_HAVE_IPV6
        if (err6) {
            const apr_status_t status6 = err_to_status(err6);
            pending_results = apr_atomic_dec32(&task->pending_results);
            message = apr_psprintf(resolve_pool,
                                   "unbound resolve start: [v6] %s",
                                   ub_strerror(err6));
            serf__context_error(ctx, status6, message);
            serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                      ctx->config, "%s\n", message);
            /* We have only one status to report. */
            if (!err4)
                status = status6;
        }
#endif  /* APR_HAVE_IPV6 */

        /* If one of the tasks failed and the other has already completed,
           we have to do the result processing here. Note that the Unbound
           callbacks can be called synchronously from ub_resolve_async(). */
        if (pending_results == 0)
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
                apr_pool_t *error_pool;
                const char *message;
                apr_pool_create(&error_pool, ctx->pool);
                message = apr_psprintf(error_pool, "unbound process: %s",
                                       ub_strerror(err));
                serf__context_error(ctx, status, message);
                serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__,
                          ctx->config, "%s\n", message);
                apr_pool_destroy(error_pool);
                return status;
            }
        }
    }

    return APR_SUCCESS;
}

#endif  /* SERF_HAVE_UNBOUND */

#else   /* !SERF_HAVE_ASYNC_RESOLVER */
#if APR_HAS_THREADS

/*******************************************************************/
/* Default async resolver that uses APR thread pools. */

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
            if (!apr_sockaddr_ip_getbuf(buf, sizeof(buf), addr)) {
                serf__log(LOGLVL_DEBUG, LOGCOMP_CONN,
                          __FILE__, task->ctx->config,
                          "thread pool resolve: %s: %s\n", addr->hostname, buf);
            }
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

#if APR_MAJOR_VERSION < 2
/* NOTE: The atomic pointer prototypes in apr-1.x are just horribly
         wrong. They're fixed in version 2.x and these macros deal
         with the difference. */
#define apr_atomic_casptr(mem, with, cmp) \
    (apr_atomic_casptr)((volatile void**)(mem), (with), (cmp))
#define apr_atomic_xchgptr(mem, with) \
    (apr_atomic_xchgptr)((volatile void**)(mem), (with))
#endif  /* APR_MAJOR_VERSION < 2 */


typedef struct resolve_result_t resolve_result_t;
struct resolve_result_t
{
    apr_sockaddr_t *host_address;
    apr_status_t status;
    serf_address_resolved_t resolved;
    void *resolved_baton;
    apr_pool_t *result_pool;
    resolve_result_t *next;
};


static void push_resolve_result(serf_context_t *ctx,
                                apr_sockaddr_t *host_address,
                                apr_status_t resolve_status,
                                serf_address_resolved_t resolved,
                                void *resolved_baton,
                                apr_pool_t *resolve_pool)
{
    resolve_result_t *result;
    void *head;

    result = apr_palloc(resolve_pool, sizeof(*result));
    result->host_address = host_address;
    result->status = resolve_status;
    result->resolved = resolved;
    result->resolved_baton = resolved_baton;
    result->result_pool = resolve_pool;

    /* Atomic push this result to the result stack. This might look like
       a potential priority inversion, however, it's not likely that we'll
       resolve several tens of thousands of results per second in hundreds
       of separate threads. */
    head = apr_atomic_casptr(&ctx->resolve_head, NULL, NULL);
    do {
        result->next = head;
        head = apr_atomic_casptr(&ctx->resolve_head, result, head);
    } while(head != result->next);

    serf__context_wakeup(ctx);
}


/* Internal API */
apr_status_t serf__create_resolve_context(serf_context_t *ctx)
{
    return create_resolve_context(ctx);
}


/* Internal API */
apr_status_t serf__process_async_resolve_results(serf_context_t *ctx)
{
    resolve_result_t *result;
    apr_status_t status;
    unsigned counter;

    if (ctx->resolve_init_status != APR_SUCCESS) {
        /* The async resolver initialization failed, so just return. */
        serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, ctx->config,
                  "context 0x%p async resolver is not initialized\n", ctx);
        return APR_SUCCESS;
    }

    status = run_async_resolver_loop(ctx);
    if (status) {
        serf__log(LOGLVL_ERROR, LOGCOMP_CONN, __FILE__, ctx->config,
                  "context 0x%p async resolve: <%d>\n", ctx, status);
        return status;
    }

    /* Grab the whole stack, leaving it empty, and process the contents. */
    counter = 0;
    result = apr_atomic_xchgptr(&ctx->resolve_head, NULL);
    while (result)
    {
        resolve_result_t *const next = result->next;
        result->resolved(ctx, result->resolved_baton,
                         result->host_address, result->status,
                         result->result_pool);
        apr_pool_destroy(result->result_pool);
        result = next;
        ++counter;
    }

    if (counter > 0) {
        serf__log(LOGLVL_DEBUG, LOGCOMP_CONN, __FILE__, ctx->config,
                  "context 0x%p async resolve: %d event%s\n",
                  ctx, counter, counter == 1 ? "" : "s");
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
