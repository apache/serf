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

#include <stdlib.h>

#include <apr.h>
#include <apr_uri.h>

#include "serf.h"

#if 0

#include "serf_filters.h"
#include "serf_version.h"

#define CRLF "\r\n"

/* Yes, it'd be nice if these were command-line options... */
/* Define this to 1 to print out header information. */
#define SERF_GET_DEBUG 0
/* httpd-2.0 is cute WRT chunking and will only do it on a keep-alive.
 * Define this to 1 to test serf's ability to handle chunking.
 */
#define SERF_GET_TEST_CHUNKING 0 

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

#if !SERF_GET_TEST_CHUNKING
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

static apr_status_t http_handler(serf_response_t *response, apr_pool_t *pool)
{
    apr_status_t status;
    apr_file_t *out_file;
    apr_bucket *bucket;

    status = apr_file_open_stdout(&out_file, pool);
    if (status) {
        return status;
    }

    /* Print anything that isn't metadata. */
    for (bucket = APR_BRIGADE_FIRST(response->entity);
         bucket != APR_BRIGADE_SENTINEL(response->entity);
         bucket = APR_BUCKET_NEXT(bucket)) {
        if (!APR_BUCKET_IS_METADATA(bucket)) {
            status = print_bucket(bucket, out_file);
            if (status) {
                return status;
            }
        }
    }

    apr_brigade_cleanup(response->entity);

    return APR_SUCCESS;
}

#endif /* 0 */


static void closed_connection(serf_connection_t *conn,
                              void *closed_baton,
                              apr_status_t why,
                              apr_pool_t *pool)
{
    abort();
}

static serf_bucket_t* accept_response(serf_request_t *request,
                                      apr_socket_t *socket,
                                      void *acceptor_baton,
                                      apr_pool_t *pool)
{
    abort();
    return NULL;
}

static apr_status_t handle_response(serf_bucket_t *response,
                                    void *handler_baton,
                                    apr_pool_t *pool)
{
    abort();
    return APR_SUCCESS;
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
#if 0
    serf_filter_t *filter;
#endif /* 0 */
    apr_uri_t url;
    const char *raw_url;
#if 0
    int using_ssl = 0;
#endif /* 0 */

    if (argc != 2) {
        puts("Gimme a URL, stupid!");
        exit(-1);
    }
    raw_url = argv[1];

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    /* serf_initialize(); */

#if 0
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

    /*
    serf_register_filter("DEFLATE_READ", serf_deflate_read, pool);
    */
#endif /* 0 */

    apr_uri_parse(pool, raw_url, &url);
    if (!url.port) {
        url.port = apr_uri_default_port_for_scheme(url.scheme);
    }
#if SERF_HAS_OPENSSL
    if (strcasecmp(url.scheme, "https") == 0) {
        using_ssl = 1;
    }
#endif

    status = apr_sockaddr_info_get(&address,
                                   url.hostname, APR_UNSPEC, url.port, 0,
                                   pool);
    if (status) {
        printf("Error creating address: %d\n", status);
        exit(1);
    }

    context = serf_context_create(pool);

    connection = serf_connection_create(context, address,
                                        closed_connection, NULL, pool);
    request = serf_connection_request_create(connection);

    req_bkt = serf_bucket_request_create("GET", url.path, NULL,
                                         serf_request_get_alloc(request));

#if 0
    serf_bucket_set_metadata(request, SERF_REQUEST_HEADERS, "User-Agent",
                             "Serf" SERF_VERSION_STRING);
#endif /* 0 */

    serf_request_deliver(request, req_bkt,
                         accept_response, NULL,
                         handle_response, NULL);

    while (1) {
        status = serf_context_run(context, SERF_DURATION_FOREVER, pool);
        if (APR_STATUS_IS_TIMEUP(status))
            continue;
        if (status) {
            printf("Error running context: %d\n", status);
            exit(1);
        }
    }

#if 0
    status = serf_open_uri(url, &connection, &request, pool);

    if (status) {
        printf("Error opening uri: %d\n", status);
        exit(1);
    }

    request->source = http_source;
    request->handler = http_handler;

    request->method = "GET";
    request->uri = url;

    /* FIXME: Get serf to install an endpoint which has access to the conn. */
    if (using_ssl) {
        filter = serf_add_filter(connection->request_filters, 
                                 "SSL_WRITE", pool);
        filter->ctx = connection;

        filter = serf_add_filter(connection->response_filters, 
                                 "SSL_READ", pool);
        filter->ctx = connection;
    }
    else {
        filter = serf_add_filter(connection->request_filters, 
                                 "SOCKET_WRITE",
                                 pool);
        filter->ctx = connection;

        filter = serf_add_filter(connection->response_filters, 
                                 "SOCKET_READ", pool);
        filter->ctx = connection;
    }
#if SERF_GET_DEBUG
    filter = serf_add_filter(connection->request_filters, "DEBUG_REQUEST", pool);
#endif

    filter = serf_add_filter(request->request_filters, "USER_AGENT", pool);
    filter = serf_add_filter(request->request_filters, "HOST_HEADER", pool);
    filter->ctx = request;
    filter = serf_add_filter(request->request_filters, "DEFLATE_SEND_HEADER",
                             pool);
    filter = serf_add_filter(request->request_filters, "HTTP_HEADERS_OUT",
                             pool);

    /* Now add the response filters. */
    filter = serf_add_filter(request->response_filters, "HTTP_STATUS_IN",
                             pool);
    filter = serf_add_filter(request->response_filters, "HTTP_HEADERS_IN",
                             pool);
    filter = serf_add_filter(request->response_filters, "HTTP_DECHUNK",
                             pool);
    filter = serf_add_filter(request->response_filters, "DEFLATE_READ",
                             pool);
#if SERF_GET_DEBUG
    filter = serf_add_filter(request->response_filters, "DEBUG_RESPONSE",
                             pool);
#endif

    status = serf_open_connection(connection);
    if (status) {
        printf("Error opening connection: %d\n", status);
        exit(1);
    }

    status = serf_write_request(request, connection);

    if (status) {
        printf("Error writing request: %d\n", status);
        exit(1);
    }

    status = serf_read_response(&response, connection, pool);

    if (status) {
        printf("Error reading response: %d\n", status);
        exit(1);
    }
#endif /* 0 */

    return 0;
}
