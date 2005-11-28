/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <apr.h>
#include <apr_uri.h>
#include <apr_strings.h>
#include <apr_atomic.h>
#include <apr_base64.h>
#include <apr_getopt.h>
#include <apr_xml.h>
#include <apr_thread_proc.h>
#include <apr_thread_mutex.h>
#include <apr_thread_cond.h>

#include "serf.h"

#define SERF_VERSION_STRING "0.01"
/* #define SERF_VERBOSE */

#if !APR_HAS_THREADS
#error serf spider needs threads.
#endif

typedef struct {
    apr_xml_doc *doc;
    apr_uri_t url;
} doc_uri_pair_t;

typedef struct {
    const char *authn;
    int using_ssl;
    serf_ssl_context_t *ssl_ctx;
    serf_bucket_alloc_t *bkt_alloc;
} app_baton_t;

static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    if (why) {
        abort();
    }
}

static serf_bucket_t* conn_setup(apr_socket_t *skt,
                                void *setup_baton,
                                apr_pool_t *pool)
{
    serf_bucket_t *c;
    app_baton_t *ctx = setup_baton;

    c = serf_bucket_socket_create(skt, ctx->bkt_alloc);
    if (ctx->using_ssl) {
        c = serf_bucket_ssl_decrypt_create(c, ctx->ssl_ctx, ctx->bkt_alloc);
    }

    return c;
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      serf_bucket_t *stream,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    serf_bucket_t *c;
    serf_bucket_alloc_t *bkt_alloc;

    /* get the per-request bucket allocator */
    bkt_alloc = serf_request_get_alloc(request);

    /* Create a barrier so the response doesn't eat us! */
    c = serf_bucket_barrier_create(stream, bkt_alloc);

    return serf_bucket_response_create(c, bkt_alloc);
}

typedef struct {
    serf_bucket_alloc_t *allocator;
    apr_uint32_t *requests_outstanding;
    serf_bucket_alloc_t *doc_queue_alloc;
    apr_array_header_t *doc_queue;
    apr_thread_cond_t *doc_queue_condvar;
    apr_uri_t url;
    apr_xml_parser *parser;
    int hdr_read;
    int is_html;
} handler_baton_t;

static apr_status_t handle_response(serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    const char *data;
    apr_size_t len;
    serf_status_line sl;
    apr_status_t status;
    handler_baton_t *ctx = handler_baton;

    status = serf_bucket_response_status(response, &sl);
    if (status) {
        if (APR_STATUS_IS_EAGAIN(status)) {
            return APR_SUCCESS;
        }
        abort();
    }

    if (!ctx->hdr_read) {
        printf("Processing %s\n", ctx->url.path);
    }

    while (1) {
        status = serf_bucket_read(response, 2048, &data, &len);

        if (SERF_BUCKET_READ_ERROR(status))
            return status;

        /*fwrite(data, 1, len, stdout);*/

        if (!ctx->hdr_read) {
            serf_bucket_t *hdrs;
            const char *val;
            hdrs = serf_bucket_response_get_headers(response);
            val = serf_bucket_headers_get(hdrs, "Content-Type");
#ifdef strcasestr
            if (val && strcasestr(val, "text/html")) {
#else
            if (val && strcasecmp(val, "text/html")) {
#endif
                ctx->is_html = 1;
            }
            else {
                ctx->is_html = 0;
            }
            ctx->hdr_read = 1;
        }
        if (ctx->is_html) {
            apr_status_t xs;

            xs = apr_xml_parser_feed(ctx->parser, data, len);
            /* Uh-oh. */
            if (xs) {
#ifdef SERF_VERBOSE
                printf("XML parser error (feed): %d\n", xs);
#endif
                ctx->is_html = 0;
            }
        }

        /* are we done yet? */
        if (APR_STATUS_IS_EOF(status)) {

            if (ctx->is_html) {
                apr_xml_doc *xmld;
                apr_status_t xs;
                doc_uri_pair_t *dup;

                xs = apr_xml_parser_done(ctx->parser, &xmld);
                if (xs) {
#ifdef SERF_VERBOSE
                    printf("XML parser error (done): %d\n", xs);
#endif
                    return xs;
                }
                dup = (doc_uri_pair_t*)
                    serf_bucket_mem_alloc(ctx->doc_queue_alloc,
                                          sizeof(doc_uri_pair_t));
                dup->doc = xmld;
                dup->url = ctx->url;
                *(doc_uri_pair_t **)apr_array_push(ctx->doc_queue) = dup;
                apr_thread_cond_signal(ctx->doc_queue_condvar);
            }

            apr_atomic_dec32(ctx->requests_outstanding);
            serf_bucket_mem_free(ctx->allocator, ctx);
            return APR_EOF;
        }

        /* have we drained the response so far? */
        if (APR_STATUS_IS_EAGAIN(status))
            return APR_SUCCESS;

        /* loop to read some more. */
    }
    /* NOTREACHED */
}

typedef struct {
    apr_uint32_t *requests_outstanding;
    serf_connection_t *connection;
    apr_array_header_t *doc_queue;
    serf_bucket_alloc_t *doc_queue_alloc;

    apr_thread_cond_t *condvar;
    apr_thread_mutex_t *mutex;

    app_baton_t *app_ctx;
} parser_baton_t;

static apr_status_t create_request(apr_uri_t url,
                                   parser_baton_t *ctx,
                                   apr_pool_t *tmppool)
{
    serf_request_t *request;
    serf_bucket_t *req_bkt, *hdrs_bkt;
    handler_baton_t *new_ctx;
    apr_pool_t *pool;
    char *req_path;

    request = serf_connection_request_create(ctx->connection);

    pool = serf_request_get_pool(request);

    /* we need to copy it so it falls under the request's scope. */
    req_path = apr_pstrdup(pool, url.path);

    req_bkt = serf_bucket_request_create("GET", req_path, NULL,
                                         serf_request_get_alloc(request));

    hdrs_bkt = serf_bucket_request_get_headers(req_bkt);

    /* FIXME: Shouldn't we be able to figure out the host ourselves? */
    serf_bucket_headers_setn(hdrs_bkt, "Host", url.hostinfo);
    serf_bucket_headers_setn(hdrs_bkt, "User-Agent",
                             "Serf/" SERF_VERSION_STRING);

    /* Shouldn't serf do this for us? */
    serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");

    if (ctx->app_ctx->authn != NULL) {
        serf_bucket_headers_setn(hdrs_bkt, "Authorization",
                                 ctx->app_ctx->authn);
    }

    if (ctx->app_ctx->using_ssl) {
        serf_bucket_alloc_t *req_alloc;

        req_alloc = serf_request_get_alloc(request);

        if (ctx->app_ctx->ssl_ctx == NULL) {
            req_bkt = serf_bucket_ssl_encrypt_create(req_bkt, NULL,
                                                     ctx->app_ctx->bkt_alloc);
            ctx->app_ctx->ssl_ctx =
                serf_bucket_ssl_encrypt_context_get(req_bkt);
        }
        else {
            req_bkt =
                serf_bucket_ssl_encrypt_create(req_bkt, ctx->app_ctx->ssl_ctx,
                                               ctx->app_ctx->bkt_alloc);
        }
    }

    new_ctx = (handler_baton_t*)serf_bucket_mem_alloc(ctx->app_ctx->bkt_alloc,
                                    sizeof(handler_baton_t));
    new_ctx->allocator = ctx->app_ctx->bkt_alloc;
    new_ctx->requests_outstanding = ctx->requests_outstanding;
    new_ctx->url = url;
    new_ctx->url.path = req_path;
    new_ctx->parser = apr_xml_parser_create(pool);
    new_ctx->hdr_read = 0;

    new_ctx->doc_queue_condvar = ctx->condvar;
    new_ctx->doc_queue = ctx->doc_queue;
    new_ctx->doc_queue_alloc = ctx->doc_queue_alloc;

    apr_atomic_inc32(ctx->requests_outstanding);

#ifdef SERF_VERBOSE
    printf("Url requesting: %s\n", url.path);
#endif
    serf_request_deliver(request, req_bkt, accept_response, &ctx->app_ctx,
                         handle_response, new_ctx);

    return APR_SUCCESS;
}

static apr_status_t put_req(const char *c, apr_uri_t *orig_url,
                            parser_baton_t *ctx, apr_pool_t *pool)
{
    apr_status_t status;
    apr_uri_t url;

    /* Build url */
#ifdef SERF_VERBOSE
    printf("Url discovered: %s\n", c);
#endif

    status = apr_uri_parse(pool, c, &url);

    /* We got something that was minimally useful. */
    if (status == 0 && url.path) {
        if (!url.hostinfo) {
            /* This is likely a relative URL. So, merge and hope for the
             * best.
             */
            apr_uri_t new_url;

            new_url = *orig_url;

            if (url.path[0] == '/') {
                new_url.path = url.path;
            }
            else {
                struct iovec vec[2];
                char *c;
                apr_size_t nbytes;

                c = strrchr(orig_url->path, '/');

                /* assert c */
                if (!c) {
                    return APR_EGENERAL;
                }

                vec[0].iov_base = orig_url->path;
                vec[0].iov_len = c - orig_url->path + 1;
                vec[1].iov_base = url.path;
                vec[1].iov_len = strlen(url.path);

                new_url.path = apr_pstrcatv(pool, vec, 2, &nbytes);
            }

            new_url.query = url.query;
            new_url.fragment = url.fragment;

            url = new_url;
        }
    }

    return create_request(url, ctx, pool);
}

static apr_status_t find_href(apr_xml_elem *e, apr_uri_t *url,
                              parser_baton_t *ctx, apr_pool_t *pool)
{
    apr_status_t status;

    do {
        /* print */
        if (e->name[0] == 'a' && e->name[1] == '\0') {
            apr_xml_attr *a;

            a = e->attr;
            while (a) {
                if (strcasecmp(a->name, "href") == 0) {
                    break;
                }
                a = a->next;
            }
            if (a) {
                status = put_req(a->value, url, ctx, pool);
                if (status) {
                    return status;
                }
            }
        }

        if (e->first_child) {
            status = find_href(e->first_child, url, ctx, pool);
            if (status) {
                return status;
            }
        }

        e = e->next;
    }
    while (e);

    return APR_SUCCESS;
}

static apr_status_t find_href_doc(apr_xml_doc *doc, apr_uri_t *url,
                                  parser_baton_t *ctx,
                                  apr_pool_t *pool)
{
    return find_href(doc->root, url, ctx, pool);
}

static void * APR_THREAD_FUNC parser_thread(apr_thread_t *thread, void *data)
{
    apr_status_t status;
    apr_pool_t *pool, *subpool;
    parser_baton_t *ctx;

    ctx = (parser_baton_t*)data;
    pool = apr_thread_pool_get(thread);

    apr_pool_create(&subpool, pool);

    while (1) {
        apr_pool_clear(subpool);

        doc_uri_pair_t *dup;

        /* Grab it. */
        apr_thread_mutex_lock(ctx->mutex);
        /* Sleep. */
        apr_thread_cond_wait(ctx->condvar, ctx->mutex);

        /* Fetch the doc off the list. */
        if (ctx->doc_queue->nelts) {
            dup = *(doc_uri_pair_t**)(apr_array_pop(ctx->doc_queue));
            /* dup = (ctx->doc_queue->conns->elts)[0]; */
        }
        else {
            dup = NULL;
        }

        /* Don't need the mutex now. */
        apr_thread_mutex_unlock(ctx->mutex);

        /* Parse the doc/url pair. */
        if (dup) {
            status = find_href_doc(dup->doc, &dup->url, ctx, subpool);
            if (status) {
                printf("Error finding hrefs: %d %s\n", status, dup->url);
            }
            /* Free the doc pair. */
            serf_bucket_mem_free(ctx->doc_queue_alloc, dup);
        }

        /* Hey are we done? */
        if (!apr_atomic_read32(ctx->requests_outstanding)) {
            break;
        }
    }
    return NULL;
}

void print_usage(apr_pool_t *pool)
{
    puts("serf_get [options] URL");
    puts("-h\tDisplay this help");
    puts("-v\tDisplay version");
    puts("-H\tPrint response headers");
    puts("-n <count> Fetch URL <count> times");
    puts("-a <user:password> Present Basic authentication credentials");
    puts("-m <method> Use the <method> HTTP Method");
    puts("-f <file> Use the <file> as the request body");
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *pool;
    apr_sockaddr_t *address;
    serf_context_t *context;
    serf_connection_t *connection;
    serf_request_t *request;
    serf_bucket_t *req_bkt;
    serf_bucket_t *hdrs_bkt;
    app_baton_t app_ctx;
    handler_baton_t *handler_ctx;
    apr_uri_t url;
    const char *raw_url, *method, *req_body_path = NULL;
    int count;
    int i;
    apr_getopt_t *opt;
    char opt_c;
    char *authn = NULL;
    const char *opt_arg;

    /* For the parser threads */
    apr_thread_t *thread[3];
    apr_threadattr_t *tattr;
    apr_status_t parser_status;
    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *condvar;
    parser_baton_t *parser_ctx;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    apr_atomic_init(pool);
    /* serf_initialize(); */

    /* Default to one round of fetching. */
    count = 1;
    /* Default to GET. */
    method = "GET";

    apr_getopt_init(&opt, pool, argc, argv);

    while ((status = apr_getopt(opt, "a:f:hm:n:v", &opt_c, &opt_arg)) ==
           APR_SUCCESS) {
        int srclen, enclen;

        switch (opt_c) {
        case 'a':
            srclen = strlen(opt_arg);
            enclen = apr_base64_encode_len(srclen);
            authn = apr_palloc(pool, enclen + 6);
            strcpy(authn, "Basic ");
            (void) apr_base64_encode(&authn[6], opt_arg, srclen);
            break;
        case 'f':
            req_body_path = opt_arg;
            break;
        case 'h':
            print_usage(pool);
            exit(0);
            break;
        case 'm':
            method = opt_arg;
            break;
        case 'n':
            errno = 0;
            count = apr_strtoi64(opt_arg, NULL, 10);
            if (errno) {
                printf("Problem converting number of times to fetch URL (%d)\n",
                       errno);
                return errno;
            }
            break;
        case 'v':
            puts("Serf version: " SERF_VERSION_STRING);
            exit(0);
        default:
            break;
        }
    }

    if (opt->ind != opt->argc - 1) {
        print_usage(pool);
        exit(-1);
    }

    raw_url = argv[opt->ind];

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_port_of_scheme(url.scheme);
    }
    if (!url.path) {
        url.path = "/";
    }

    if (strcasecmp(url.scheme, "https") == 0) {
        app_ctx.using_ssl = 1;
    }
    else {
        app_ctx.using_ssl = 0;
    }

    status = apr_sockaddr_info_get(&address,
                                   url.hostname, APR_UNSPEC, url.port, 0,
                                   pool);
    if (status) {
        printf("Error creating address: %d\n", status);
        exit(1);
    }

    context = serf_context_create(pool);

    /* ### Connection or Context should have an allocator? */
    app_ctx.bkt_alloc = serf_bucket_allocator_create(pool, NULL, NULL);
    app_ctx.ssl_ctx = NULL;
    app_ctx.authn = authn;

    connection = serf_connection_create(context, address,
                                        conn_setup, &app_ctx,
                                        closed_connection, &app_ctx,
                                        pool);

    handler_ctx = (handler_baton_t*)serf_bucket_mem_alloc(app_ctx.bkt_alloc,
                                                      sizeof(handler_baton_t));
    handler_ctx->allocator = app_ctx.bkt_alloc;
    handler_ctx->doc_queue = apr_array_make(pool, 1, sizeof(doc_uri_pair_t*));
    handler_ctx->doc_queue_alloc = app_ctx.bkt_alloc;

    handler_ctx->requests_outstanding =
        (apr_uint32_t*)serf_bucket_mem_alloc(app_ctx.bkt_alloc,
                                             sizeof(apr_uint32_t));
    handler_ctx->url = url;
    handler_ctx->parser = apr_xml_parser_create(pool);
    handler_ctx->hdr_read = 0;

    parser_ctx = (void*)serf_bucket_mem_alloc(app_ctx.bkt_alloc,
                                       sizeof(parser_baton_t));

    parser_ctx->requests_outstanding = handler_ctx->requests_outstanding;
    parser_ctx->connection = connection;
    parser_ctx->app_ctx = &app_ctx;
    parser_ctx->doc_queue = handler_ctx->doc_queue;
    parser_ctx->doc_queue_alloc = handler_ctx->doc_queue_alloc;

    status = apr_thread_mutex_create(&parser_ctx->mutex,
                                     APR_THREAD_MUTEX_DEFAULT, pool);
    if (status) {
        printf("Couldn't create mutex %d\n", status);
        return status;
    }

    status = apr_thread_cond_create(&parser_ctx->condvar, pool);
    if (status) {
        printf("Couldn't create condvar: %d\n", status);
        return status;
    }

    /* Let the handler now which condvar to use. */
    handler_ctx->doc_queue_condvar = parser_ctx->condvar;

    apr_threadattr_create(&tattr, pool);

    /* Start the parser thread. */
    apr_thread_create(&thread[0], tattr, parser_thread, parser_ctx, pool);

    /* Deliver the request. */
    for (i = 0; i < count; i++) {
        serf_bucket_t *body_bkt;

        request = serf_connection_request_create(connection);

        if (req_body_path) {
            apr_file_t *file;

            status = apr_file_open(&file, req_body_path, APR_READ,
                                   APR_OS_DEFAULT, pool);

            if (status) {
                printf("Error opening file (%s): %d\n", req_body_path,
                       status);
                exit(2);
            }
            body_bkt = serf_bucket_file_create(file,
                                               serf_request_get_alloc(request));
        }
        else {
            body_bkt = NULL;
        }

        req_bkt = serf_bucket_request_create(method, url.path, body_bkt,
                                             serf_request_get_alloc(request));

        hdrs_bkt = serf_bucket_request_get_headers(req_bkt);

        /* FIXME: Shouldn't we be able to figure out the host ourselves? */
        serf_bucket_headers_setn(hdrs_bkt, "Host", url.hostinfo);
        serf_bucket_headers_setn(hdrs_bkt, "User-Agent",
                                 "Serf/" SERF_VERSION_STRING);
        /* Shouldn't serf do this for us? */
        serf_bucket_headers_setn(hdrs_bkt, "Accept-Encoding", "gzip");

        if (authn != NULL) {
            serf_bucket_headers_setn(hdrs_bkt, "Authorization", authn);
        }

        apr_atomic_inc32(handler_ctx->requests_outstanding);

        if (app_ctx.using_ssl) {
            serf_bucket_alloc_t *req_alloc;

            req_alloc = serf_request_get_alloc(request);

            if (app_ctx.ssl_ctx == NULL) {
                req_bkt =
                    serf_bucket_ssl_encrypt_create(req_bkt, NULL,
                                                   app_ctx.bkt_alloc);
                app_ctx.ssl_ctx =
                    serf_bucket_ssl_encrypt_context_get(req_bkt);
            }
            else {
                req_bkt =
                    serf_bucket_ssl_encrypt_create(req_bkt, app_ctx.ssl_ctx,
                                                   app_ctx.bkt_alloc);
            }
        }

        serf_request_deliver(request, req_bkt,
                             accept_response, &app_ctx,
                             handle_response, handler_ctx);
    }

    /* Go run our normal thread. */
    while (1) {
        int tries = 0;

        status = serf_context_run(context, SERF_DURATION_FOREVER, pool);
        if (APR_STATUS_IS_TIMEUP(status))
            continue;
        if (status) {
            char buf[200];

            printf("Error running context: (%d) %s\n", status,
                   apr_strerror(status, buf, sizeof(buf)));
            exit(1);
        }
        for (tries = 0; tries < 3; tries++) {
            if (!apr_atomic_read32(handler_ctx->requests_outstanding)) {
#ifdef SERF_VERBOSE
                printf("Waiting...");
#endif
                apr_sleep(100000);
#ifdef SERF_VERBOSE
                printf("Done\n");
#endif
            }
            else {
                break;
            }
        }
        if (tries >= 3) {
            break;
        }
        /* Debugging purposes only! */
        serf_debug__closed_conn(app_ctx.bkt_alloc);
    }

    printf("Quitting...\n");
    serf_connection_close(connection);

    /* wake up the parser via condvar signal */
    apr_thread_cond_signal(parser_ctx->condvar);

    status = apr_thread_join(&parser_status, thread[0]);
    if (status) {
        printf("Error joining thread: %d\n", status);
        return status;
    }

    serf_bucket_mem_free(app_ctx.bkt_alloc, handler_ctx->requests_outstanding);
    serf_bucket_mem_free(app_ctx.bkt_alloc, parser_ctx);

    apr_pool_destroy(pool);
    return 0;
}
