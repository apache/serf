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
#include <apr.h>
#include <apr_queue.h>
#include <apr_strmatch.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_hash.h>

#include "serf.h"
#include "serf_filters.h"
#include "serf_version.h"

#include <assert.h>

#if !APR_HAS_THREADS
#error This spider program requires an APR built with threads!
#endif

#define CRLF "\r\n"

/* Yes, it'd be nice if these were command-line options... */
/* Define this to 1 to print out header information. */
#define SERF_SPIDER_DEBUG 0

/* httpd-2.0 is cute WRT chunking and will only do it on a keep-alive.
 * Define this to 1 to test serf's ability to handle chunking.
 */
#define SERF_SPIDER_USE_CHUNKING 0

/* If you request a .gz file, we could incorrectly get back a deflated
 * file.
 */
#define SERF_SPIDER_USE_DEFLATE 0

/* The maximal size of our queue */
#define SERF_SPIDER_QUEUE_SIZE 10000000

/* The number of concurrent threads we will have running. */
#define SERF_SPIDER_THREADS 20

/* Maximum number of hits we will run per thread. */
/*#define SERF_SPIDER_LIMIT 1000*/

/* Define if the spider should not leave the root space given to it. */
#define SERF_SPIDER_DO_NOT_LEAVE_ROOT 1

/* How long threads should be staggered on startup. */
#define SERF_SPIDER_RAMP_DELAY 1

/* Define to 0 if the spider shouldn't print anything to stdout. */
#define SERF_SPIDER_PRINT 0

static apr_pool_t *spider_pool;
static apr_queue_t *spider_queue;
static apr_hash_t *spider_hash;
static apr_thread_mutex_t *spider_mutex;
static const apr_strmatch_pattern *link_start_pattern;
static const apr_strmatch_pattern *link_stop_pattern;
static const apr_strmatch_pattern *link_href_start_pattern;
static const apr_strmatch_pattern *link_href_stop_pattern;
static const apr_strmatch_pattern *img_start_pattern;
static const apr_strmatch_pattern *img_stop_pattern;
static const apr_strmatch_pattern *img_src_start_pattern;
static const apr_strmatch_pattern *img_src_stop_pattern;
static const apr_strmatch_pattern *head_start_pattern;
static const apr_strmatch_pattern *head_stop_pattern;
static const apr_strmatch_pattern *base_start_pattern;
static const apr_strmatch_pattern *base_stop_pattern;
static const char *original_root_uri;
static apr_uri_t *parsed_root_uri;

static apr_status_t add_uri(apr_uri_t *uri, apr_pool_t *uri_pool,
                            apr_hash_t *hash, apr_pool_t *hash_pool,
                            apr_queue_t *queue, const char *root_uri,
                            apr_thread_mutex_t *mutex)
{
    char *new_uri;
    apr_size_t new_uri_len;

    new_uri = apr_uri_unparse(uri_pool, uri, 0);
    new_uri_len = strlen(new_uri);
    /* Our hash routines aren't thread-safe!  Ick!  */
    apr_thread_mutex_lock(mutex);
    if (!apr_hash_get(hash, new_uri, new_uri_len) &&
        (!SERF_SPIDER_DO_NOT_LEAVE_ROOT ||
         strstr(new_uri, root_uri) == new_uri)) {
        apr_status_t status;
        char *new_uri_copy;
        int tries = 0;

        new_uri_copy = apr_pstrmemdup(hash_pool, new_uri, new_uri_len);
        apr_hash_set(hash, new_uri_copy, new_uri_len, new_uri_copy);

        do {
            status = apr_queue_trypush(queue, new_uri_copy);

            if (status) {
                if (tries++ > 5 || !APR_STATUS_IS_EAGAIN(status)) {
                    apr_thread_mutex_unlock(mutex);
                    return status;
                }
                fprintf(stderr, "Queue full: %s %ld (try #%d)\n", new_uri_copy,
                        pthread_self(), tries);
                apr_sleep(apr_time_from_sec(SERF_SPIDER_RAMP_DELAY));
            }
        } while (APR_STATUS_IS_EAGAIN(status));
    }
    apr_thread_mutex_unlock(mutex);

    return APR_SUCCESS;
}

static apr_status_t search_base(apr_bucket *bucket,
                                apr_uri_t *base_uri,
                                apr_pool_t *pool)
{
    const char *buf, *match, *new_match;
    apr_size_t length, match_length, written;
    apr_status_t status;
        
    status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

    if (status) {
        fprintf(stderr, "Error %d\n", status);
        return status;
    }

    match = buf;
    match_length = length;
    /* We must look for the <head> tag */
    new_match = apr_strmatch(head_start_pattern, match, match_length);

    if (new_match) {
        const char *end_match, *base_match;
        match = new_match + head_start_pattern->length;
        match_length = length - (match - buf);
 
        end_match = apr_strmatch(head_stop_pattern, match, match_length);
        /* We don't have the end of the </head> portion, try to deal. */
        if (!end_match) {
            end_match = buf + length;
        }

        base_match = apr_strmatch(base_start_pattern, match,
                                  end_match - match);
        if (base_match) {
            const char *base_end;
            base_match += base_start_pattern->length;

            base_end = apr_strmatch(base_stop_pattern, base_match,
                                    end_match - base_match);
            if (base_end) {
                const char *base_uri_full;

                base_uri_full = apr_pstrmemdup(pool, base_match,
                                               base_end - base_match);

                apr_uri_parse(pool, base_uri_full, base_uri);
            }

            return APR_SUCCESS;
        }

        new_match = apr_strmatch(head_start_pattern, match, match_length);
    }
    return APR_SUCCESS;
}

static apr_status_t harvest_link(const char *raw_uri, apr_uri_t *base_uri,
                                 apr_pool_t *pool)
{
    apr_uri_t *uri;

    uri = apr_palloc(pool, sizeof(apr_uri_t));
    apr_uri_parse(pool, raw_uri, uri);
    /* We'll only restrict our spidering to the scheme we
     * originally started with.
     *
     * Special case mailto: since our uri parser doesn't
     * handle it correctly.
     */
    if ((!uri->scheme ||
         strcasecmp(uri->scheme, base_uri->scheme) == 0) &&
        (uri->scheme || (!uri->path ||
         strncasecmp(uri->path, "mailto:",
                     sizeof("mailto:") - 1) != 0))) {
        if (!uri->path) {
            uri->path = base_uri->path;
        }
        else if (*uri->path != '/') {
            uri->path = apr_pstrcat(pool,
                                    base_uri->path,
                                    uri->path, NULL);
        }
        if (!uri->hostinfo) {
            char *p, *q, *f;
            p = uri->path;
            q = uri->query;
            f = uri->fragment;
            uri = apr_pmemdup(pool, base_uri, sizeof(apr_uri_t));
            uri->path = p;
            uri->query = q;
            uri->fragment = f;
        }
        /* Eliminate fragments. */
        if (uri->fragment) {
            uri->fragment = 0;
        }
        add_uri(uri, pool, spider_hash, spider_pool, spider_queue,
                original_root_uri, spider_mutex);
    }

    return APR_SUCCESS;
}

static apr_status_t search_bucket(apr_bucket *bucket,
                                  serf_request_t *request,
                                  apr_uri_t *base_uri,
                                  apr_pool_t *pool)
{
    const char *buf, *match, *new_match;
    apr_size_t length, match_length, written;
    apr_status_t status;
        
    status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

    if (status) {
        fprintf(stderr, "Error %d\n", status);
        return status;
    }

    match = buf;
    match_length = length;
    new_match = apr_strmatch(link_start_pattern, match, match_length);
    while (new_match) {
        const char *end_match;
        match = new_match + link_start_pattern->length;
        match_length = length - (match - buf);
 
        end_match = apr_strmatch(link_stop_pattern, match, match_length);
        if (end_match) {
            const char *href_begin;

            href_begin = apr_strmatch(link_href_start_pattern, match,
                                      end_match - match);
            if (href_begin) {
                const char *href_end;

                href_begin += link_href_start_pattern->length;

                href_end = apr_strmatch(link_href_stop_pattern, href_begin,
                                        end_match - href_begin);

                if (href_end) {
                    char *our_match;
                    our_match = apr_pstrmemdup(pool, href_begin,
                                               href_end - href_begin);

                    harvest_link(our_match, base_uri, pool);
                }
            }
            match = end_match;
            match_length = length - (match - buf);
        } 
        new_match = apr_strmatch(link_start_pattern, match, match_length);
    }

    match = buf;
    match_length = length;
    new_match = apr_strmatch(img_start_pattern, match, match_length);
    while (new_match) {
        const char *end_match;
        match = new_match + img_start_pattern->length;
        match_length = length - (match - buf);
 
        end_match = apr_strmatch(img_stop_pattern, match, match_length);
        if (end_match) {
            const char *href_begin;

            href_begin = apr_strmatch(img_src_start_pattern, match,
                                      end_match - match);
            if (href_begin) {
                const char *href_end;

                href_begin += img_src_start_pattern->length;

                href_end = apr_strmatch(img_src_stop_pattern, href_begin,
                                        end_match - href_begin);

                if (href_end) {
                    char *our_match;
                    our_match = apr_pstrmemdup(pool, href_begin,
                                               href_end - href_begin);

                    harvest_link(our_match, base_uri, pool);
                }
            }
            match = end_match;
            match_length = length - (match - buf);
        } 
        new_match = apr_strmatch(img_start_pattern, match, match_length);
    }
    return APR_SUCCESS;
}

static apr_status_t print_bucket(apr_bucket *bucket, apr_file_t *file)
{
    const char *buf;
    apr_size_t length, written;
    apr_status_t status;
        
    status = apr_bucket_read(bucket, &buf, &length, APR_BLOCK_READ);

    if (status) {
        return status;
    }

    return apr_file_write_full(file, buf, length, &written);
}

static apr_status_t http_source(apr_bucket_brigade *brigade,
                                serf_request_t *request,
                                apr_pool_t *pool)
{
    apr_bucket *bucket;

    bucket = serf_bucket_request_line_create(request->method,
                                             request->uri->path,
                                             "HTTP/1.1", pool,
                                             brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_HEAD(brigade, bucket);

#if !SERF_SPIDER_USE_CHUNKING
    bucket = serf_bucket_header_create("Connection",
                                       "Close",
                                       pool, brigade->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);
#endif

    return APR_SUCCESS;
}

static apr_status_t host_header_filter(apr_bucket_brigade *brigade,
                                       serf_filter_t *filter,
                                       apr_pool_t *pool)
{
    apr_bucket *bucket;
    serf_request_t *request = filter->ctx;

    bucket = serf_bucket_header_create("Host",
                                       request->uri->hostname,
                                       pool, brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t user_agent_filter(apr_bucket_brigade *brigade,
                                      serf_filter_t *filter,
                                      apr_pool_t *pool)
{
    apr_bucket *bucket;

    bucket = serf_bucket_header_create("User-Agent",
                                       "Serf " SERF_VERSION_STRING,
                                       pool, brigade->bucket_alloc);
 
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t http_headers_filter(apr_bucket_brigade *brigade,
                                        serf_filter_t *filter,
                                        apr_pool_t *pool)
{
    apr_bucket *bucket;

    /* All we do here is stick CRLFs in the right places. */
    bucket = APR_BRIGADE_FIRST(brigade);
    while (bucket != APR_BRIGADE_SENTINEL(brigade)) {
        if (SERF_BUCKET_IS_REQUEST_LINE(bucket) ||
            SERF_BUCKET_IS_HEADER(bucket)) {
            apr_bucket *eol;

            eol = apr_bucket_immortal_create(CRLF, sizeof(CRLF)-1,
                                             brigade->bucket_alloc);

            APR_BUCKET_INSERT_AFTER(bucket, eol);
       }

        bucket = APR_BUCKET_NEXT(bucket);
    }

    /* FIXME: We need a way to indicate we are EOH. */
    bucket = apr_bucket_immortal_create(CRLF, sizeof(CRLF)-1,
                                        brigade->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    return APR_SUCCESS;
}

static apr_status_t debug_request(apr_bucket_brigade *brigade,
                                  serf_filter_t *filter,
                                  apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {

        status = print_bucket(bucket, out_file);
        if (status) {
            return status;
        }
    }

    return APR_SUCCESS;
}

static apr_status_t debug_response(apr_bucket_brigade *brigade,
                                   serf_filter_t *filter,
                                   apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    /* Print the STATUS bucket first. */ 
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (SERF_BUCKET_IS_STATUS(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
            status = apr_file_putc('\n', out_file);
            if (status) {
                return status;
            }
        } 
    }

    /* Now, print all headers.  */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (SERF_BUCKET_IS_HEADER(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
            status = apr_file_putc('\n', out_file);
            if (status) {
                return status;
            }
        } 
    }

    /* Print a separator line. */
    status = apr_file_putc('\n', out_file);
    if (status) {
        return status;
    }

    return APR_SUCCESS;
}

static apr_status_t harvest_response(apr_bucket_brigade *brigade,
                                     serf_filter_t *filter,
                                     apr_pool_t *pool)
{
    apr_status_t status;
    apr_bucket *bucket;
    serf_request_t *request = (serf_request_t*)filter->ctx;
    apr_uri_t *base_uri;
    int do_harvest = 0;

    base_uri = apr_palloc(pool, sizeof(apr_uri_t));
    base_uri->is_initialized = 0;

    /* We can only harvest from text/html content-types. */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
        bucket = APR_BUCKET_NEXT(bucket)) {
        if (SERF_BUCKET_IS_HEADER(bucket)) {
            serf_bucket_header *hdr = bucket->data;

            if (strcasecmp(hdr->key, "Content-Type") == 0) {
                /* FIXME: Add token support! */
                if (strncasecmp(hdr->value, "text/html",
                                sizeof("text/html") - 1) == 0) {
                    do_harvest = 1;
                    break;
                }
            }
        }
    }

    if (!do_harvest) {
        return APR_SUCCESS;
    }

    /* Search for a BASE tag to establish relationship. */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (!APR_BUCKET_IS_METADATA(bucket)) {
            status = search_base(bucket, base_uri, pool);
            if (status) {
                return status;
            }
            if (base_uri->is_initialized == 1) {
                break;
            }
        }
    }

    if (!base_uri->is_initialized) {
        base_uri = request->uri;
    }

    /* Now, search all the content.  */
    for (bucket = APR_BRIGADE_FIRST(brigade);
         bucket != APR_BRIGADE_SENTINEL(brigade);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (!APR_BUCKET_IS_METADATA(bucket)) {
            status = search_bucket(bucket, request, base_uri, pool);
            if (status) {
                return status;
            }
        } 
    }

    return APR_SUCCESS;
}

/* This function prints out the output in a manner that swishe likes. */
static apr_status_t swishe_handler(serf_response_t *response, apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;
    apr_off_t length;

    apr_brigade_length(response->entity, 1, &length);

#if SERF_SPIDER_PRINT
    /* When we print, we must hold the lock! */
    apr_thread_mutex_lock(spider_mutex);

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    apr_file_printf(out_file, "Path-Name: %s\n",
                    apr_uri_unparse(pool, response->request->uri, 0));
    apr_file_printf(out_file, "Content-Length: %ld\n\n", length);

    /* Print anything that isn't metadata. */
    for (bucket = APR_BRIGADE_FIRST(response->entity);
         bucket != APR_BRIGADE_SENTINEL(response->entity);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (!APR_BUCKET_IS_METADATA(bucket)) {
            /* Print out the data so it can be indexed. */
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
        }
    }

    /* We can now unlock. */
    apr_thread_mutex_unlock(spider_mutex);
#endif

    apr_brigade_cleanup(response->entity);

    return APR_SUCCESS;
}

void* spider_worker(apr_thread_t *my_thread, void *data)
{
    apr_pool_t *pool;
    apr_pool_t *request_pool;
    int count = 0;

    pool = (apr_pool_t*)data;
    apr_pool_create(&request_pool, pool);

    while (1) {
        serf_connection_t *connection;
        serf_request_t *request;
        serf_response_t *response;
        serf_filter_t *filter;
        apr_uri_t *url;
        apr_status_t status;
        void *queue_val;
        char *current_url;
        int using_ssl = 0;

#ifdef SERF_SPIDER_LIMIT
        if (count++ > SERF_SPIDER_LIMIT) {
            break;
        }   
#endif

        status = apr_queue_trypop(spider_queue, &queue_val);

        if (APR_STATUS_IS_EAGAIN(status)) {
            break;
        }

        if (status) {
            printf("Error: %d\n", status);
            apr_thread_exit(my_thread, status);
        }

        current_url = *(char**)queue_val;
        fprintf(stderr, "%s %ld\n", current_url, pthread_self());

        url = apr_palloc(request_pool, sizeof(apr_uri_t));
        apr_uri_parse(request_pool, current_url, url);
        if (!url->port) {
            url->port = apr_uri_default_port_for_scheme(url->scheme);
        }
#if SERF_HAS_OPENSSL
        if (strcasecmp(url->scheme, "https") == 0) {
            using_ssl = 1;
        }
#endif
        status = serf_open_uri(url, &connection, &request, request_pool);

        if (status) {
            printf("Error: %d\n", status);
            apr_thread_exit(my_thread, status);
        }

        request->source = http_source;
        request->handler = swishe_handler;

        request->method = "GET";
        request->uri = url;

        /* FIXME: Install an endpoint which has access to the conn. */
        if (using_ssl) {
            filter = serf_add_filter(connection->request_filters, 
                                     "SSL_WRITE", request_pool);
            filter->ctx = connection;

            filter = serf_add_filter(connection->response_filters, 
                                     "SSL_READ", request_pool);
            filter->ctx = connection;
        }
        else {
            filter = serf_add_filter(connection->request_filters, 
                                     "SOCKET_WRITE",
                                     request_pool);
            filter->ctx = connection;

            filter = serf_add_filter(connection->response_filters, 
                                     "SOCKET_READ", request_pool);
            filter->ctx = connection;
        }
#if SERF_SPIDER_DEBUG
        filter = serf_add_filter(connection->request_filters, "DEBUG_REQUEST",
                                 request_pool);
#endif

        filter = serf_add_filter(request->request_filters, "USER_AGENT",
                                 request_pool);
        filter = serf_add_filter(request->request_filters, "HOST_HEADER",
                                 request_pool);
        filter->ctx = request;

#if SERF_SPIDER_DEFLATE
        filter = serf_add_filter(request->request_filters,
                                 "DEFLATE_SEND_HEADER", request_pool);
#endif
        filter = serf_add_filter(request->request_filters, "HTTP_HEADERS_OUT",
                                 request_pool);

        /* Now add the response filters. */
        filter = serf_add_filter(request->response_filters, "HTTP_STATUS_IN",
                                 request_pool);
        filter = serf_add_filter(request->response_filters, "HTTP_HEADERS_IN",
                                 request_pool);
        filter = serf_add_filter(request->response_filters, "HTTP_DECHUNK",
                                 request_pool);
#if SERF_SPIDER_DEFLATE
        filter = serf_add_filter(request->response_filters, "DEFLATE_READ",
                                 request_pool);
#endif
#if SERF_GET_DEBUG
        filter = serf_add_filter(request->response_filters, "DEBUG_RESPONSE",
                                 request_pool);
#endif
        filter = serf_add_filter(request->response_filters, "HARVEST_RESPONSE",
                                 request_pool);
        filter->ctx = request;

        status = serf_open_connection(connection);
        if (status) {
            printf("Error: %d\n", status);
            apr_thread_exit(my_thread, status);
        }

        status = serf_write_request(request, connection);

        if (status) {
            printf("Error: %d\n", status);
            apr_thread_exit(my_thread, status);
        }

        status = serf_read_response(&response, connection, request_pool);

        if (status) {
            printf("Error: %d\n", status);
            apr_thread_exit(my_thread, status);
        }

        apr_pool_clear(request_pool);
    }

    apr_thread_exit(my_thread, APR_SUCCESS);
}

int main(int argc, const char **argv)
{
    apr_status_t status;
    apr_pool_t *pool;
    apr_thread_t **threads;
    int i;
   
    if (argc != 2) {
        puts("Gimme a URL, stupid!");
        exit(-1);
    }
    original_root_uri = argv[1];

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    /* serf_initialize(); */

    serf_register_filter("SOCKET_WRITE", serf_socket_write, pool);
    serf_register_filter("SOCKET_READ", serf_socket_read, pool);

#if SERF_HAS_OPENSSL
    serf_register_filter("SSL_WRITE", serf_ssl_write, pool);
    serf_register_filter("SSL_READ", serf_ssl_read, pool);
#endif

    serf_register_filter("USER_AGENT", user_agent_filter, pool);
    serf_register_filter("HOST_HEADER", host_header_filter, pool);
    serf_register_filter("HTTP_HEADERS_OUT", http_headers_filter, pool);

    serf_register_filter("HTTP_STATUS_IN", serf_http_status_read, pool);
    serf_register_filter("HTTP_HEADERS_IN", serf_http_header_read, pool);
    serf_register_filter("HTTP_DECHUNK", serf_http_dechunk, pool);

    serf_register_filter("DEFLATE_SEND_HEADER", serf_deflate_send_header, pool);
    serf_register_filter("DEFLATE_READ", serf_deflate_read, pool);

    serf_register_filter("DEBUG_REQUEST", debug_request, pool);
    serf_register_filter("DEBUG_RESPONSE", debug_response, pool);

    serf_register_filter("HARVEST_RESPONSE", harvest_response, pool);

    /*
    serf_register_filter("DEFLATE_READ", serf_deflate_read, pool);
    */

    parsed_root_uri = apr_palloc(pool, sizeof(apr_uri_t));
    apr_uri_parse(pool, original_root_uri, parsed_root_uri);

    apr_pool_create(&spider_pool, pool);

    apr_queue_create(&spider_queue, SERF_SPIDER_QUEUE_SIZE, spider_pool);
    apr_queue_push(spider_queue, (void*)original_root_uri);

    /* This hash table could very large - one entry per doc. */
    spider_hash = apr_hash_make(spider_pool);
    apr_hash_set(spider_hash, original_root_uri, APR_HASH_KEY_STRING,
                 original_root_uri);

    head_start_pattern = apr_strmatch_precompile(pool, "<head>", 0);
    head_stop_pattern = apr_strmatch_precompile(pool, "</head>", 0);
    link_start_pattern = apr_strmatch_precompile(pool, "<a ", 0);
    link_stop_pattern = apr_strmatch_precompile(pool, ">", 0);
    link_href_start_pattern = apr_strmatch_precompile(pool, "href=\"", 0);
    link_href_stop_pattern = apr_strmatch_precompile(pool, "\"", 0);
    img_start_pattern = apr_strmatch_precompile(pool, "<img ", 0);
    img_stop_pattern = link_stop_pattern;
    img_src_start_pattern = apr_strmatch_precompile(pool, "src=\"", 0);
    img_src_stop_pattern = link_href_stop_pattern;
    base_start_pattern = apr_strmatch_precompile(pool, "<base href=\"", 0);
    base_stop_pattern = link_href_stop_pattern;

    apr_thread_mutex_create(&spider_mutex, APR_THREAD_MUTEX_DEFAULT, pool);

    threads = apr_palloc(pool, sizeof(apr_thread_t*));

    for (i = 0; i < SERF_SPIDER_THREADS; i++) {
        apr_pool_t *thread_pool;

        apr_pool_create(&thread_pool, pool);

        status = apr_thread_create(&threads[i], NULL, spider_worker,
                                   thread_pool, thread_pool);
        if (status) {
            printf("Error: %d\n", status);
            exit(status);
        }

        /* Slowly ramp up so that there should be requests for the subsequent
         * threads to work off of.
         */
        apr_sleep(apr_time_from_sec(SERF_SPIDER_RAMP_DELAY));
    }

    for (i = 0; i < SERF_SPIDER_THREADS; i++) {
        apr_thread_join(&status, threads[i]);
        if (status) {
            printf("Error: %d\n", status);
        }
    }

    apr_thread_mutex_destroy(spider_mutex);

    return 0;
}
