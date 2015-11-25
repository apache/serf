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

#include <apr_pools.h>
#include <apr_poll.h>
#include <apr_version.h>
#include <apr_portable.h>
#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"

#include "serf_private.h"

static apr_status_t clean_resp(void *data)
{
    serf_request_t *request = data;
    apr_pool_t *respool = request->respool;

    request->respool = NULL;

    /* The request's RESPOOL is being cleared.  */
    if (respool && request->writing >= SERF_WRITING_STARTED
                && request->writing < SERF_WRITING_FINISHED) {

        /* HOUSTON, WE HAVE A PROBLEM.

           We created buckets inside the pool that is now cleaned and
           stored them in an aggregate that still lives on.

           This happens when the application decides that it doesn't
           need the connection any more and clears the pool of the
           connection, of which the request pool is a subpool.

           Let's ask the connection to take care of things */
        serf__connection_pre_cleanup(request->conn);
    }

#ifdef SERF_DEBUG_BUCKET_USE
    if (respool && request->allocator) {
        serf_debug__closed_conn(request->allocator);
    }
#endif

    /* If the response has allocated some buckets, then destroy them (since
       the bucket may hold resources other than memory in RESPOOL). Also
       make sure to set their fields to NULL so connection closure does
       not attempt to free them again.  */
    if (request->resp_bkt) {
        serf_bucket_destroy(request->resp_bkt);
        request->resp_bkt = NULL;
    }
    if (request->req_bkt) {
        if (request->writing == SERF_WRITING_NONE)
            serf_bucket_destroy(request->req_bkt);
        request->req_bkt = NULL;
    }

#ifdef SERF_DEBUG_BUCKET_USE
    if (respool && request->allocator) {
        serf_debug__bucket_alloc_check(request->allocator);
    }
#endif

    request->allocator = NULL;

    return APR_SUCCESS;
}

void serf__link_requests(serf_request_t **list, serf_request_t **tail,
                         serf_request_t *request)
{
    if (*list == NULL) {
        *list = request;
        *tail = request;
    }
    else {
        (*tail)->next = request;
        *tail = request;
    }
}

apr_status_t serf__destroy_request(serf_request_t *request)
{
    serf_connection_t *conn = request->conn;

    if (request->depends_first && request->depends_on) {
        apr_uint64_t total = 0;
        serf_request_t *r, **pr;
        apr_uint64_t rqd = request->dep_priority;

        /* Calculate total priority of descendants */
        for (r = request->depends_first; r; r = r->depends_next) {
            total += r->dep_priority;
        }

        /* Apply now, as if they depend on the parent */
        for (r = request->depends_first; r; r = r->depends_next) {
            if (total) {

                r->dep_priority = (apr_uint16_t)(rqd * r->dep_priority
                                                 / total);
            }
            else
                r->dep_priority = 0;

            r->depends_on = request->depends_on;
        }

        /* Remove us from parent */
        pr = &request->depends_on->depends_first;
        while (*pr) {
            if (*pr == request) {
                *pr = request->depends_next;
                continue;
            }

            pr = &(*pr)->depends_next;
        }

        /* And append all our descendants */
        *pr = request->depends_first;

        request->depends_on = NULL;
        request->depends_first = NULL;
        request->depends_next = NULL;
    }
    else if (request->depends_first) {
        /* Dependencies will lose their parent */
        serf_request_t *r, *next;

        for (r = request->depends_first; r; r = next) {
            next = r->next;

            r->depends_on = NULL;
            r->depends_next = NULL;
        }
        request->depends_first = NULL;
    }
    else if (request->depends_on) {
        serf_request_t **pr;

        /* Remove us from parent */
        pr = &request->depends_on->depends_first;
        while (*pr) {
            if (*pr == request) {
                *pr = request->depends_next;
                break;
            }

            pr = &(*pr)->depends_next;
        }
        request->depends_on = NULL;
    }

    if (request->writing >= SERF_WRITING_STARTED
        && request->writing < SERF_WRITING_FINISHED) {

        /* Schedule for destroy when it is safe again.

           Destroying now will destroy memory of buckets that we
           may still need.
        */
        serf__link_requests(&conn->done_reqs, &conn->done_reqs_tail,
                            request);
    }
    else {

        if (request->respool) {
          apr_pool_t *pool = request->respool;

          apr_pool_cleanup_run(pool, request, clean_resp);
          apr_pool_destroy(pool);
        }

        serf_bucket_mem_free(conn->allocator, request);
    }

    return APR_SUCCESS;
}

apr_status_t serf__cancel_request(serf_request_t *request,
                                  serf_request_t **list,
                                  int notify_request)
{
    /* If we haven't run setup, then we won't have a handler to call. */
    if (request->handler && notify_request) {
        /* We actually don't care what the handler returns.
         * We have bigger matters at hand.
         */
        (void)request->handler(request, NULL, request->handler_baton,
                               request->respool);

        request->handler = NULL;
    }

    if (request->conn && request->conn->perform_cancel_request) {
        request->conn->perform_cancel_request(request,
                                              SERF_ERROR_HTTP2_CANCEL);
    }

    if (*list == request) {
        *list = request->next;
    }
    else {
        serf_request_t *scan = *list;

        while (scan->next && scan->next != request)
            scan = scan->next;

        if (scan->next) {
            scan->next = scan->next->next;
        }
    }

    return serf__destroy_request(request);
}

/* Calculate the length of a linked list of requests. */
unsigned int serf__req_list_length(serf_request_t *req)
{
    unsigned int length = 0;

    while (req) {
        length++;
        req = req->next;
    }

    return length;
}

apr_status_t serf__setup_request(serf_request_t *request)
{
    serf_connection_t *conn = request->conn;
    apr_status_t status;

    /* Now that we are about to serve the request, allocate a pool. */
    apr_pool_create(&request->respool, conn->pool);
    request->allocator = serf_bucket_allocator_create(request->respool,
                                                      NULL, NULL);
    apr_pool_cleanup_register(request->respool, request,
                              clean_resp, apr_pool_cleanup_null);

    /* Fill in the rest of the values for the request. */
    status = request->setup(request, request->setup_baton,
                            &request->req_bkt,
                            &request->acceptor,
                            &request->acceptor_baton,
                            &request->handler,
                            &request->handler_baton,
                            request->respool);
    return status;
}

/* A response message was received from the server, so call
   the handler as specified on the original request. */
apr_status_t serf__handle_response(serf_request_t *request,
                                   apr_pool_t *pool)
{
    int consumed_response = 0;

    /* Only enable the new authentication framework if the program has
     * registered an authentication credential callback.
     *
     * This permits older Serf apps to still handle authentication
     * themselves by not registering credential callbacks.
     */
    if (request->conn->ctx->cred_cb) {
        apr_status_t status;

        status = serf__handle_auth_response(&consumed_response,
                                            request,
                                            request->resp_bkt,
                                            pool);

        if (SERF_BUCKET_READ_ERROR(status)) {

            /* There was an error while checking the authentication headers of
               the response. We need to inform the application - which
               hasn't seen this response yet - of the error.

               These are the possible causes of the error:

               1. A communication error while reading the response status line,
                  headers or while discarding the response body: pass the
                  response unchanged to the application, it will see the same
                  error as serf did.

               2. A 401/407 response status for a supported authn scheme that
                  resulted in authn failure:
                  Pass the response as received to the application, the response
                  body can contain an error description. Terminate the response
                  body with the AUTHN error instead of APR_EOF.

               3. A 401/407 response status for a supported authn scheme that
                  resulted in an unknown error returned by the application in
                  the credentials callback (Basic/Digest):
                  Handle the same as 2.

               4. A 2xx response status for a supported authn scheme that
                  resulted in authn failure:
                  Pass the response headers to the application. The response
                  body is untrusted, so we should drop it and return the AUTHN
                  error instead of APR_EOF.

                  serf__handle_auth_response will already discard the response
                  body, so we can handle this case the same as 2.

               In summary, all these cases can be handled in the same way: call
               the application's response handler with the response bucket, but
               make sure that the application sees error code STATUS instead of
               APR_EOF after reading the response body.
            */

            serf__bucket_response_set_error_on_eof(request->resp_bkt, status);

            /* Ignore the application's status code here, use the error status
               from serf__handle_auth_response. */
            (void)(*request->handler)(request,
                                      request->resp_bkt,
                                      request->handler_baton,
                                      pool);
        }

        if (status)
            return status;
    }

    if (!consumed_response) {
        return (*request->handler)(request,
                                   request->resp_bkt,
                                   request->handler_baton,
                                   pool);
    }

    return APR_SUCCESS;
}

apr_status_t
serf__provide_credentials(serf_context_t *ctx,
                          char **username,
                          char **password,
                          serf_request_t *request,
                          int code, const char *authn_type,
                          const char *realm,
                          apr_pool_t *pool)
{
    serf_connection_t *conn = request->conn;
    serf_request_t *authn_req = request;
    apr_status_t status;

    if (request->ssltunnel == 1 &&
        conn->state == SERF_CONN_SETUP_SSLTUNNEL) {
        /* This is a CONNECT request to set up an SSL tunnel over a proxy.
           This request is created by serf, so if the proxy requires
           authentication, we can't ask the application for credentials with
           this request.

           Solution: setup the first request created by the application on
           this connection, and use that request and its handler_baton to
           call back to the application. */

        /* request->next will be NULL if this was the last request written */
        authn_req = request->next;
        if (!authn_req)
            authn_req = conn->unwritten_reqs;

        /* assert: app_request != NULL */
        if (!authn_req)
            return APR_EGENERAL;

        if (!authn_req->req_bkt) {
            status = serf__setup_request(authn_req);
            /* If we can't setup a request, don't bother setting up the
               ssl tunnel. */
            if (status)
                return status;
        }
    }

    /* Ask the application. */
    status = (*ctx->cred_cb)(username, password,
                             authn_req, authn_req->handler_baton,
                             code, authn_type, realm, pool);
    if (status)
        return status;

    return APR_SUCCESS;
}

static serf_request_t *
create_request(serf_connection_t *conn,
               serf_request_setup_t setup,
               void *setup_baton,
               int priority,
               int ssltunnel)
{
    serf_request_t *request;

    request = serf_bucket_mem_alloc(conn->allocator, sizeof(*request));
    request->conn = conn;
    request->setup = setup;
    request->setup_baton = setup_baton;
    request->handler = NULL;
    request->acceptor = NULL;
    request->respool = NULL;
    request->req_bkt = NULL;
    request->resp_bkt = NULL;
    request->priority = priority;
    request->writing = SERF_WRITING_NONE;
    request->ssltunnel = ssltunnel;
    request->next = NULL;
    request->auth_baton = NULL;
    request->protocol_baton = NULL;
    request->depends_on = NULL;
    request->depends_next = NULL;
    request->depends_first = NULL;
    request->dep_priority = SERF_REQUEST_PRIORITY_DEFAULT;

    return request;
}

serf_request_t *serf_connection_request_create(
    serf_connection_t *conn,
    serf_request_setup_t setup,
    void *setup_baton)
{
    serf_request_t *request;

    request = create_request(conn, setup, setup_baton,
                             0, /* priority */
                             0  /* ssl tunnel */);

    /* Link the request to the end of the request chain. */
    serf__link_requests(&conn->unwritten_reqs, &conn->unwritten_reqs_tail, request);
    conn->nr_of_unwritten_reqs++;

    /* Ensure our pollset becomes writable in context run */
    serf_io__set_pollset_dirty(&conn->io);

    return request;
}

static serf_request_t *
priority_request_create(serf_connection_t *conn,
                        int ssltunnelreq,
                        serf_request_setup_t setup,
                        void *setup_baton)
{
    serf_request_t *request;
    serf_request_t *iter, *prev;

    request = create_request(conn, setup, setup_baton,
                             1, /* priority */
                             ssltunnelreq);

    /* Link the new request after the last written request. */
    iter = conn->unwritten_reqs;
    prev = NULL;

    /* TODO: what if a request is partially written? */
    /* Find a request that has data which needs to be delivered. */
    while (iter != NULL && iter->req_bkt == NULL
           && (iter->writing >= SERF_WRITING_STARTED)) {
        prev = iter;
        iter = iter->next;
    }

    /* A CONNECT request to setup an ssltunnel has absolute priority over all
       other requests on the connection, so:
       a. add it first to the queue
       b. ensure that other priority requests are added after the CONNECT
          request */
    if (!request->ssltunnel) {
        /* Advance to next non priority request */
        while (iter != NULL && iter->priority) {
            prev = iter;
            iter = iter->next;
        }
    }

    if (prev) {
        request->next = iter;
        prev->next = request;
    } else {
        request->next = iter;
        conn->unwritten_reqs = request;
    }
    conn->nr_of_unwritten_reqs++;

    /* Ensure our pollset becomes writable in context run */
    serf_io__set_pollset_dirty(&conn->io);

    return request;
}

serf_request_t *serf_connection_priority_request_create(
    serf_connection_t *conn,
    serf_request_setup_t setup,
    void *setup_baton)
{
    return priority_request_create(conn,
                                   0, /* not a ssltunnel CONNECT request */
                                   setup, setup_baton);
}

serf_request_t *serf__ssltunnel_request_create(serf_connection_t *conn,
                                               serf_request_setup_t setup,
                                               void *setup_baton)
{
    return priority_request_create(conn,
                                   1, /* This is a ssltunnel CONNECT request */
                                   setup, setup_baton);
}


serf_request_t *serf__request_requeue(const serf_request_t *request)
{
    /* ### in the future, maybe we could reset REQUEST and try again?  */
    return priority_request_create(request->conn,
                                   request->ssltunnel,
                                   request->setup,
                                   request->setup_baton);
}


apr_status_t serf_request_cancel(serf_request_t *request)
{
    serf_connection_t *conn = request->conn;
    serf_request_t *tmp = conn->unwritten_reqs;

    /* Find out which queue holds the request */
    while (tmp != NULL && tmp != request)
        tmp = tmp->next;

    if (tmp)
        return serf__cancel_request(request, &conn->unwritten_reqs, 0);
    else
        return serf__cancel_request(request, &conn->written_reqs, 0);

}

void serf_connection_request_prioritize(serf_request_t *request,
                                        serf_request_t *depends_on,
                                        apr_uint16_t priority,
                                        int exclusive)
{
    if (request->depends_on != depends_on) {
        serf_request_t *r;

        if (depends_on->conn != request->conn || depends_on == request)
            abort();

        /* If we are indirectly made dependent on ourself, we first
           reprioritize the descendant on our current parent. See
           https://tools.ietf.org/html/rfc7540#section-5.3.3

           If a stream is made dependent on one of its own dependencies, the
           formerly dependent stream is first moved to be dependent on the
           reprioritized stream's previous parent.  The moved dependency
           retains its weight. */

        r = depends_on;

        while (r && r != request && r->depends_on)
            r = r->depends_on;

        if (r == request)
        {
            serf_connection_request_prioritize(depends_on,
                                               request->depends_on,
                                               depends_on->dep_priority,
                                               false /* exclusive */);
        }

        if (request->depends_on) {
        /* Ok, we can now update our dependency */

            serf_request_t **pr = &request->depends_on->depends_first;

            while (*pr) {
                if (*pr == request) {
                    *pr = request->depends_next;
                    break;
                }
                pr = &(*pr)->depends_next;
            }
        }

        request->depends_on = depends_on;

        if (depends_on) {
            if (exclusive) {
                r = depends_on->depends_first;

                while (r) {
                    r->depends_on = request;

                    if (r->depends_next)
                        r = r->depends_next;
                    else
                        break;
                }

                if (r) {
                    r->depends_next = request->depends_first;
                    r->depends_first = depends_on->depends_first;
                }
                request->depends_next = NULL;
            }
            else {
                request->depends_next = depends_on->depends_first;
            }
            depends_on->depends_first = request;
        }
        else
            request->depends_next = NULL;
    }

    if (priority)
        request->dep_priority = priority;

    /* And now tell the protocol about this */
    if (request->conn->perform_prioritize_request)
        request->conn->perform_prioritize_request(request, exclusive != 0);
}


apr_status_t serf_request_is_written(serf_request_t *request)
{
    if (request->writing >= SERF_WRITING_FINISHED)
        return APR_SUCCESS;

    return APR_EBUSY;
}

apr_pool_t *serf_request_get_pool(const serf_request_t *request)
{
    return request->respool;
}


serf_bucket_alloc_t *serf_request_get_alloc(
    const serf_request_t *request)
{
    return request->allocator;
}


serf_connection_t *serf_request_get_conn(
    const serf_request_t *request)
{
    return request->conn;
}


void serf_request_set_handler(
    serf_request_t *request,
    const serf_response_handler_t handler,
    const void **handler_baton)
{
    request->handler = handler;
    request->handler_baton = handler_baton;
}


serf_bucket_t *serf_request_bucket_request_create(
    serf_request_t *request,
    const char *method,
    const char *uri,
    serf_bucket_t *body,
    serf_bucket_alloc_t *allocator)
{
    serf_bucket_t *req_bkt;
    serf_bucket_t *hdrs_bkt;
    serf_connection_t *conn = request->conn;
    serf_context_t *ctx = conn->ctx;
    int tunneled;

    tunneled = ctx->proxy_address
               && (strcmp(conn->host_info.scheme, "https") == 0);

    req_bkt = serf_bucket_request_create(method, uri, body, allocator);
    hdrs_bkt = serf_bucket_request_get_headers(req_bkt);

    /* Use absolute uri's in requests to a proxy. USe relative uri's in
       requests directly to a server or sent through an SSL tunnel. */
    if (ctx->proxy_address && conn->host_url && !tunneled)
    {
        serf_bucket_request_set_root(req_bkt, conn->host_url);
    }

    if (conn->host_info.hostinfo)
    {
        serf_bucket_headers_setn(hdrs_bkt, "Host",  conn->host_info.hostinfo);
    }

    /* Setup server authentication headers.  */
    serf__auth_setup_request(HOST, request, method, uri, hdrs_bkt);

    /* Setup proxy authentication headers, unless we're tunneling.  */
    if (!tunneled)
        serf__auth_setup_request(PROXY, request, method, uri, hdrs_bkt);

    return req_bkt;
}
