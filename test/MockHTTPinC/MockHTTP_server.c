 /* Copyright 2014 Lieven Govaerts
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

/* This file includes code originally submitted to the Serf project, covered by
 * the Apache License, Version 2.0, copyright Justin Erenkrantz & Greg Stein.
 */
#include <apr_thread_proc.h>
#include <apr_strings.h>
#include <apr_uri.h>

#include <stdlib.h>

#include "MockHTTP.h"
#include "MockHTTP_private.h"

/* Copied from serf.  */
#if defined(APR_VERSION_AT_LEAST) && defined(WIN32)
#if APR_VERSION_AT_LEAST(1,4,0)
#define BROKEN_WSAPOLL
#endif
#endif

static apr_status_t initSSLCtx(_mhClientCtx_t *cctx);
static apr_status_t sslHandshake(_mhClientCtx_t *cctx);
static apr_status_t sslSocketWrite(_mhClientCtx_t *cctx, const char *data,
                                   apr_size_t *len);
static apr_status_t sslSocketRead(_mhClientCtx_t *cctx, char *data,
                                  apr_size_t *len);
static apr_status_t renegotiateSSLSession(_mhClientCtx_t *cctx);

static const int DefaultSrvPort =   30080;
static const int DefaultProxyPort = 38080;

typedef apr_status_t (*handshake_func_t)(_mhClientCtx_t *cctx);
typedef apr_status_t (*reset_conn_func_t)(_mhClientCtx_t *cctx);
typedef apr_status_t (*send_func_t)(_mhClientCtx_t *cctx, const char *data,
                                    apr_size_t *len);
typedef apr_status_t (*receive_func_t)(_mhClientCtx_t *cctx, char *data,
                                       apr_size_t *len);

typedef struct sslCtx_t sslCtx_t;

#define BUFSIZE 32768
struct _mhClientCtx_t {
    apr_pool_t *pool;
    apr_socket_t *skt;
    char buf[BUFSIZE];  /* buffer for data received from the client @ server */
    apr_size_t buflen;
    apr_size_t bufrem;
    char obuf[BUFSIZE]; /* buffer for data to be sent from server to client */
    apr_size_t obuflen;
    apr_size_t obufrem;
    const char *respBody;
    apr_size_t respRem;
    apr_array_header_t *respQueue;  /*  test will queue a response */
    mhResponse_t *currResp; /* response in progress */
    mhRequest_t *req;
    apr_int16_t reqevents;
    bool closeConn;
    sslCtx_t *ssl_ctx;
    int protocols;                  /* SSL protocol versions */

    send_func_t send;
    receive_func_t read;
    /* SSL-only callback functions, should be NULL when not implemented */
    handshake_func_t handshake;
    reset_conn_func_t reset;
    const char *keyFile;
    apr_array_header_t *certFiles;
    mhClientCertVerification_t clientCert;
};

static apr_status_t setupTCPServer(mhServCtx_t *ctx, bool blocking);

static void * APR_THREAD_FUNC start_thread(apr_thread_t *tid, void *baton)
{
    mhServCtx_t *ctx = baton;

    setupTCPServer(ctx, YES);

    while (1) {
        _mhRunServerLoop(ctx);
    }

    return NULL;
}

static apr_status_t cleanupServer(void *baton)
{
    mhServCtx_t *ctx = baton;
    apr_status_t status;

    /*    apr_thread_exit(tid, APR_SUCCESS);*/
    if (ctx->pollset)
        apr_pollset_destroy(ctx->pollset);
    if (ctx->skt)
        STATUSERR(apr_socket_close(ctx->skt));

    ctx->skt = NULL;
    ctx->pollset = NULL;

    return APR_SUCCESS;
}

static apr_status_t socketWrite(_mhClientCtx_t *cctx, const char *data,
                                apr_size_t *len)
{
    return apr_socket_send(cctx->skt, data, len);
}

static apr_status_t socketRead(_mhClientCtx_t *cctx, char *data,
                               apr_size_t *len)
{
    return apr_socket_recv(cctx->skt, data, len);
}

static apr_status_t setupTCPServer(mhServCtx_t *ctx, bool blocking)
{
    apr_sockaddr_t *serv_addr;
    apr_pool_t *pool = ctx->pool;
    apr_status_t status;

    while (1) {
        STATUSERR(apr_sockaddr_info_get(&serv_addr, ctx->hostname,
                                        APR_UNSPEC, ctx->port, 0,
                                        pool));

        /* Create server socket */
        /* Note: this call requires APR v1.0.0 or higher */
        STATUSERR(apr_socket_create(&ctx->skt, serv_addr->family,
                                    SOCK_STREAM, 0, pool));

        STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_NONBLOCK, 1));
        STATUSERR(apr_socket_timeout_set(ctx->skt, 0));
        STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_REUSEADDR, 1));

        /* TODO: try the next port until bind succeeds */
        status = apr_socket_bind(ctx->skt, serv_addr);
        if (status == EADDRINUSE) {
            ctx->port++;
            continue;
        }
        /* Listen for clients */
        STATUSERR(apr_socket_listen(ctx->skt, SOMAXCONN));
        break;
    };

    /* Create a new pollset, avoid broken WSAPoll implemenation on Windows. */
#ifdef BROKEN_WSAPOLL
    STATUSERR(apr_pollset_create_ex(&ctx->pollset, 32, pool, 0,
                                    APR_POLLSET_SELECT));
#else
    STATUSERR(apr_pollset_create(&ctx->pollset, 32, pool, 0));
#endif

    {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = ctx->skt;
        pfd.reqevents = APR_POLLIN;

        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }

    return APR_SUCCESS;
}

/* connect to the server (url in form localhost:30080) */
static apr_status_t connectToServer(mhServCtx_t *ctx, const char *url)
{
    apr_sockaddr_t *address;
    char *host, *scopeid;
    apr_port_t port;
    apr_status_t status;

    STATUSERR(apr_parse_addr_port(&host, &scopeid, &port, url, ctx->pool));
    STATUSERR(apr_sockaddr_info_get(&address, host, APR_UNSPEC,
                                    port, 0, ctx->pool));

    /* Create server socket */
    /* Note: this call requires APR v1.0.0 or higher */
    STATUSERR(apr_socket_create(&ctx->proxyskt, address->family,
                                SOCK_STREAM, 0, ctx->pool));
    STATUSERR(apr_socket_opt_set(ctx->proxyskt, APR_SO_NONBLOCK, 1));
    STATUSERR(apr_socket_timeout_set(ctx->proxyskt, 0));
    STATUSERR(apr_socket_opt_set(ctx->proxyskt, APR_SO_REUSEADDR, 1));

    status = apr_socket_connect(ctx->proxyskt, address);
    if (status == APR_SUCCESS || APR_STATUS_IS_EINPROGRESS(status)) {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = ctx->proxyskt;
        pfd.reqevents = APR_POLLIN | APR_POLLOUT;

        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }

    return status;
}

static const int MaxReqRespQueueSize = 50;
static mhServCtx_t *
initServCtx(const MockHTTP *mh, const char *hostname, apr_port_t port)
{
    apr_pool_t *pool = mh->pool;

    mhServCtx_t *ctx = apr_pcalloc(pool, sizeof(mhServCtx_t));
    ctx->pool = pool;
    ctx->mh = mh;
    ctx->hostname = apr_pstrdup(pool, hostname);
    ctx->port = port;
    ctx->reqsReceived = apr_array_make(pool, 5, sizeof(mhRequest_t *));
    ctx->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));
    ctx->incompleteReqMatchers = apr_array_make(pool, 5,
                                               sizeof(ReqMatcherRespPair_t *));
    ctx->mode = ModeServer;
    ctx->clientCert = mhCCVerifyNone;
    ctx->protocols = mhProtoUnspecified;

    apr_pool_cleanup_register(pool, ctx,
                              cleanupServer,
                              apr_pool_cleanup_null);

    return ctx;
}

static mhError_t startServer(mhServCtx_t *ctx)
{
    apr_thread_t *thread;

    /* TODO: second thread doesn't work. */
    if (0) { /* second thread */
        /* Setup a non-blocking TCP server in a separate thread */
        apr_thread_create(&thread, NULL, start_thread, ctx, ctx->pool);
    } else {
        apr_status_t status;
        /* Setup a non-blocking TCP server */
        status = setupTCPServer(ctx, NO);
        if (status)
            return MOCKHTTP_SETUP_FAILED;
    }

    return MOCKHTTP_NO_ERROR;
}

/******************************************************************************/
/* Parse a request structure from incoming data                               */
/******************************************************************************/

mhRequest_t *_mhInitRequest(apr_pool_t *pool)
{
    mhRequest_t *req = apr_pcalloc(pool, sizeof(mhRequest_t));
    req->pool = pool;
    req->hdrs = apr_table_make(pool, 5);
    req->body = apr_array_make(pool, 5, sizeof(struct iovec));
    req->chunks = apr_array_make(pool, 5, sizeof(struct iovec));

    return req;
}

/* *len will be non-0 if a line ending with CRLF was found. buf will be copied
   in mem allocatod from cctx->pool, cctx->buf ptrs will be moved. */
static void readLine(_mhClientCtx_t *cctx, const char **buf, apr_size_t *len)
{
    const char *ptr = cctx->buf;

    *len = 0;
    while (*ptr && ptr - cctx->buf < cctx->buflen) {
        if (*ptr == '\r' && *(ptr+1) == '\n') {
            *len = ptr - cctx->buf + 2;
            *buf = apr_pstrndup(cctx->pool, cctx->buf, *len);

            cctx->buflen -= *len; /* eat line */
            cctx->bufrem += *len;
            memmove(cctx->buf, cctx->buf + *len, cctx->buflen);

            break;
        }
        ptr++;
    }
}

#define FAIL_ON_EOL(ptr)\
    if (*ptr == '\0') return APR_EGENERAL; /* TODO: error code */

/* APR_EAGAIN if no line ready, APR_SUCCESS + done = YES if request line parsed */
static apr_status_t readReqLine(_mhClientCtx_t *cctx, mhRequest_t *req, bool *done)
{
    const char *start, *ptr, *version;
    const char *buf;
    apr_size_t len;

    *done = FALSE;

    readLine(cctx, &buf, &len);
    if (!len) return APR_EAGAIN;

    /* TODO: add checks for incomplete request line */
    start = ptr = buf;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    FAIL_ON_EOL(ptr);
    req->method = apr_pstrndup(cctx->pool, start, ptr-start);

    ptr++; start = ptr;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    FAIL_ON_EOL(ptr);
    req->url = apr_pstrndup(cctx->pool, start, ptr-start);

    ptr++; start = ptr;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    if (ptr - start != strlen("HTTP/x.y")) {
        return APR_EGENERAL;
    }
    version = apr_pstrndup(cctx->pool, start, ptr-start);
    req->version = (version[5] - '0') * 10 +
    version[7] - '0';

    *done = TRUE;

    return APR_SUCCESS;
}

/* APR_EAGAIN if no line ready, APR_SUCCESS + done = YES when LAST header was
   parsed */
static apr_status_t readHeader(_mhClientCtx_t *cctx, mhRequest_t *req, bool *done)
{
    const char *buf;
    apr_size_t len;

    *done = NO;

    readLine(cctx, &buf, &len);
    if (!len) return APR_EAGAIN;

    if (len == 2 && *buf == '\r' && *(buf+1) == '\n') {
        *done = YES;
        return APR_SUCCESS;
    } else {
        const char *start = buf, *ptr = buf;
        const char *hdr, *val;
        while (*ptr != ':' && *ptr != '\r') ptr++;
        hdr = apr_pstrndup(cctx->pool, start, ptr-start);

        ptr++; while (*ptr == ' ') ptr++; start = ptr;
        while (*ptr != '\r') ptr++;
        val = apr_pstrndup(cctx->pool, start, ptr-start);

        setHeader(req->hdrs, hdr, val);
    }
    return APR_SUCCESS;
}

static void
storeRawDataBlock(mhRequest_t *req, const char *buf, apr_size_t len)
{
    struct iovec vec;
    vec.iov_base = apr_pstrndup(req->pool, buf, len);
    vec.iov_len = len;
    *((struct iovec *)apr_array_push(req->body)) = vec;
    req->bodyLen += len;
}

/* APR_EAGAIN if not all data is ready, APR_SUCCESS + done = YES if body
   completely received. */
static apr_status_t readBody(_mhClientCtx_t *cctx, mhRequest_t *req, bool *done)
{
    const char *clstr;
    char *body;
    long cl;
    apr_size_t len;

    req->chunked = NO;

    clstr = getHeader(cctx->pool, req->hdrs, "Content-Length");
    cl = atol(clstr);

    len = cl - req->bodyLen; /* remaining # of bytes */
    len = cctx->buflen <= len ? cctx->buflen : len; /* this packet */

    if (req->body == NULL) {
        req->body = apr_palloc(cctx->pool, sizeof(struct iovec) * 256);
    }
    body = apr_palloc(cctx->pool, len + 1);

    memcpy(body, cctx->buf, len);
    *(body + len) = '\0';
    storeRawDataBlock(req, body, len);

    cctx->buflen -= len; /* eat body */
    cctx->bufrem += len;
    memmove(cctx->buf, cctx->buf + len, cctx->buflen);
    if (req->bodyLen < cl)
        return APR_EAGAIN;

    *done = YES;
    return APR_SUCCESS;
}

static apr_status_t readChunk(_mhClientCtx_t *cctx, mhRequest_t *req, bool *done)
{
    const char *buf;
    apr_size_t len, chlen;

    *done = NO;

    switch (req->readState) {
        case ReadStateBody:
        case ReadStateChunked:
            req->readState = ReadStateChunkedHeader;
            /* fall through */
        case ReadStateChunkedHeader:
        {
            struct iovec vec;
            apr_size_t chlen;
            readLine(cctx, &buf, &len);
            if (!len)
                return APR_EAGAIN;
            storeRawDataBlock(req, buf, len);

            chlen = apr_strtoi64(buf, NULL, 16); /* read hex chunked length */
            vec.iov_len = chlen;
            *((struct iovec *)apr_array_push(req->chunks)) = vec;
            if (chlen == 0) {
                req->readState = ReadStateChunkedTrailer;
                return APR_SUCCESS;
            }

            req->readState = ReadStateChunkedChunk;
            /* fall through */
        }
        case ReadStateChunkedChunk:
        {
            struct iovec *vec;
            apr_size_t chlen, curchunklen, len;

            vec = &APR_ARRAY_IDX(req->chunks, req->chunks->nelts - 1, struct iovec);
            chlen = vec->iov_len;
            if (req->incomplete_chunk) {
                const char *tmp;
                curchunklen = strlen(vec->iov_base); /* already read some data */
                /* partial or full chunk? */
                len = (cctx->buflen + curchunklen) >= chlen ? chlen - curchunklen :
                                                              cctx->buflen;
                tmp = apr_pstrndup(req->pool, cctx->buf, len);
                storeRawDataBlock(req, cctx->buf, len);
                vec->iov_base = apr_pstrcat(req->pool, vec->iov_base, tmp, NULL);
                curchunklen += len;
            } else {
                /* partial or full chunk? */
                len = cctx->buflen >= chlen ? chlen : cctx->buflen;
                vec->iov_base = apr_pstrndup(req->pool, cctx->buf, len);
                storeRawDataBlock(req, cctx->buf, len);
                curchunklen = len;
            }
            cctx->buflen -= len; /* eat (part of the) chunk */
            cctx->bufrem += len;
            memmove(cctx->buf, cctx->buf + len, cctx->buflen);

            if (curchunklen < chlen) { /* More data is needed to read one chunk */
                req->incomplete_chunk = YES;
                return APR_EAGAIN;
            }
            req->incomplete_chunk = NO;
            req->readState = ReadStateChunkedTrailer;
            /* fall through */
        }
        case ReadStateChunkedTrailer:
        {
            struct iovec vec;
            vec = APR_ARRAY_IDX(req->chunks, req->chunks->nelts - 1, struct iovec);
            chlen = vec.iov_len;

            readLine(cctx, &buf, &len);
            if (len < 2)
                return APR_EAGAIN;
            storeRawDataBlock(req, buf, len);
            if (len == 2 && *buf == '\r' && *(buf+1) == '\n') {
                if (chlen == 0) { /* body ends with chunk of length 0 */
                    *done = YES;
                    req->readState = ReadStateDone;
                    apr_array_pop(req->chunks); /* remove the 0-chunk */
                } else {
                    req->readState = ReadStateChunked;
                }
            } else {
                return APR_EGENERAL; /* TODO: error code */
            }
            break;
        }
        default:
            break;
    }

    return APR_SUCCESS;
}

static apr_status_t readChunked(_mhClientCtx_t *cctx, mhRequest_t *req, bool *done)
{
    apr_status_t status;

    *done = NO;
    req->chunked = YES;

    while (*done == NO)
        STATUSERR(readChunk(cctx, req, done));

    return status;
}

static apr_status_t readData(_mhClientCtx_t *cctx)
{
    apr_status_t status;
    apr_size_t len = cctx->bufrem;
    STATUSREADERR(cctx->read(cctx, cctx->buf + cctx->buflen, &len));
    if (len) {
        _mhLog(MH_VERBOSE, cctx->skt,
               "recvd with status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, cctx->buf + cctx->buflen,
               (unsigned int)len);
        cctx->buflen += len;
        cctx->bufrem -= len;
    }
    return status;
}

/* New request data was made available, read status line/hdrs/body (chunks).
   APR_EAGAIN: wait for more data
   APR_EOF: request received, or no more data available. */
static apr_status_t readRequest(_mhClientCtx_t *cctx, mhRequest_t **preq)
{
    mhRequest_t *req = *preq;
    apr_status_t status = APR_SUCCESS;

    if (req == NULL) {
        req = *preq = _mhInitRequest(cctx->pool);
    }

    while (!status) { /* read all available data */
        bool done = NO;

        STATUSREADERR(readData(cctx));

        switch(cctx->req->readState) {
            case ReadStateStatusLine: /* status line */
                STATUSREADERR(readReqLine(cctx, req, &done));
                if (done) req->readState = ReadStateHeaders;
                break;
            case ReadStateHeaders: /* headers */
                STATUSREADERR(readHeader(cctx, req, &done));
                if (done) req->readState = ReadStateBody;
                break;
            case ReadStateBody: /* body */
            case ReadStateChunked:
            case ReadStateChunkedHeader:
            case ReadStateChunkedChunk:
            case ReadStateChunkedTrailer:
            {
                const char *clstr, *chstr;
                chstr = getHeader(cctx->pool, req->hdrs,
                                  "Transfer-Encoding");
                /* TODO: chunked can be one of more encodings */
                /* Read Transfer-Encoding first, ignore C-L when T-E is set */
                if (chstr && apr_strnatcasecmp(chstr, "chunked") == 0) {
                    STATUSREADERR(readChunked(cctx, req, &done));
                } else {
                    clstr = getHeader(cctx->pool, req->hdrs, "Content-Length");
                    if (clstr) {
                        STATUSREADERR(readBody(cctx, req, &done));
                    } else {
                        done = YES; /* no body to read */
                    }
                }
                if (done) {
                    _mhLog(MH_VERBOSE, cctx->skt, "Server received request: %s %s\n",
                           req->method, req->url);
                    return APR_EOF;
                }
            }
            case ReadStateDone:
                break;
        }
    }

    if (!cctx->buflen) {
        if (APR_STATUS_IS_EOF(status))
            return MH_STATUS_INCOMPLETE_REQUEST;

        return status;
    }

    return status;
}

static const char *codeToString(unsigned int code)
{
    switch(code) {
        case 100: return "Continue"; break;
        case 101: return "Switching Protocols"; break;
        case 200: return "OK"; break;
        case 201: return "Created"; break;
        case 202: return "Accepted"; break;
        case 203: return "Non-Authoritative Information"; break;
        case 204: return "No Content"; break;
        case 205: return "Reset Content"; break;
        case 206: return "Partial Content"; break;
        case 300: return "Multiple Choices"; break;
        case 301: return "Moved Permanently"; break;
        case 302: return "Found"; break;
        case 303: return "See Other"; break;
        case 304: return "Not Modified"; break;
        case 305: return "Use Proxy"; break;
        case 307: return "Temporary Redirect"; break;
        case 400: return "Bad Request"; break;
        case 401: return "Unauthorized"; break;
        case 402: return "Payment Required"; break;
        case 403: return "Forbidden"; break;
        case 404: return "Not Found"; break;
        case 405: return "Method Not Allowed"; break;
        case 406: return "Not Acceptable"; break;
        case 407: return "Proxy Authentication Required"; break;
        case 408: return "Request Timeout"; break;
        case 409: return "Conflict"; break;
        case 410: return "Gone"; break;
        case 411: return "Length Required"; break;
        case 412: return "Precondition Failed"; break;
        case 413: return "Request Entity Too Large"; break;
        case 414: return "Request-URI Too Long"; break;
        case 415: return "Unsupported Media Type"; break;
        case 416: return "Requested Range Not Satisfiable"; break;
        case 417: return "Expectation Failed"; break;
        case 500: return "Internal Server Error"; break;
        case 501: return "Not Implemented"; break;
        case 502: return "Bad Gateway"; break;
        case 503: return "Service Unavailable"; break;
        case 504: return "Gateway Timeout"; break;
        case 505: return "HTTP Version Not Supported"; break;
        default: return "<not defined>";
    }
}

/******************************************************************************/
/* Send a response                                                            */
/******************************************************************************/

static char *respToString(apr_pool_t *pool, mhResponse_t *resp)
{
    char *str;
    const apr_table_entry_t *elts;
    const apr_array_header_t *arr;
    int i;

    /* status line */
    str = apr_psprintf(pool, "HTTP/1.1 %d %s\r\n", resp->code,
                       codeToString(resp->code));

    arr = apr_table_elts(resp->hdrs);
    elts = (const apr_table_entry_t *)arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        str = apr_psprintf(pool, "%s%s: %s\r\n", str, elts[i].key, elts[i].val);
    }
    str = apr_psprintf(pool, "%s\r\n", str);

    /* body */
    if (resp->chunked == NO) {
        int i;
        for (i = 0 ; i < resp->body->nelts; i++) {
            struct iovec vec;

            vec = APR_ARRAY_IDX(resp->body, i, struct iovec);
            str = apr_psprintf(pool, "%s%.*s", str, (unsigned int)vec.iov_len,
                               (const char *)vec.iov_base);
        }
    } else {
        int i;
        bool emptyChunk = NO; /* empty response should atleast have 0-chunk */
        for (i = 0 ; i < resp->chunks->nelts; i++) {
            struct iovec vec;

            vec = APR_ARRAY_IDX(resp->chunks, i, struct iovec);
            str = apr_psprintf(pool, "%s%" APR_UINT64_T_HEX_FMT "\r\n%.*s\r\n",
                               str, (apr_uint64_t)vec.iov_len,
                               (unsigned int)vec.iov_len, (char *)vec.iov_base);
            emptyChunk = vec.iov_len == 0 ? YES : NO;
        }
        if (!emptyChunk) /* Add 0 chunk only if last chunk wasn't empty already */
            str = apr_psprintf(pool, "%s0\r\n\r\n", str);
    }
    return str;
}

static apr_status_t writeResponse(_mhClientCtx_t *cctx, mhResponse_t *resp)
{
    apr_pool_t *pool = cctx->pool;
    apr_size_t len;
    apr_status_t status;

    if (!cctx->respRem) {
        _mhBuildResponse(resp);
        if (resp->raw_data) {
            cctx->respBody = resp->raw_data;
        } else {
            cctx->respBody = respToString(pool, resp);
        }
        cctx->respRem = strlen(cctx->respBody);
    }

    len = cctx->respRem;
    STATUSREADERR(cctx->send(cctx, cctx->respBody, &len));
    _mhLog(MH_VERBOSE, cctx->skt, "sent with status %d:\n%.*s\n---- %d ----\n",
           status, (unsigned int)len, cctx->respBody, (unsigned int)len);

    if (len < cctx->respRem) {
        cctx->respBody += len;
        cctx->respRem -= len;
        cctx->currResp = resp;
    } else {
        cctx->respBody = NULL;
        cctx->respRem = 0;
        cctx->currResp = 0;
        return APR_EOF;
    }
    return status;
}

void mhPushRequest(mhServCtx_t *ctx, mhRequestMatcher_t *rm)
{
    ReqMatcherRespPair_t *pair;
    int i;

    pair = apr_palloc(ctx->pool, sizeof(ReqMatcherRespPair_t));
    pair->rm = rm;
    pair->resp = NULL;
    pair->action = mhActionInitiateNone;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhMatchingPattern_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhMatchingPattern_t *);
        if (mp->match_incomplete == YES) {
            rm->incomplete = YES;
            break;
        }
    }
    if (rm->incomplete)
        *((ReqMatcherRespPair_t **)
          apr_array_push(ctx->incompleteReqMatchers)) = pair;
    else
        *((ReqMatcherRespPair_t **)apr_array_push(ctx->reqMatchers)) = pair;
}

static bool
matchRequest(const _mhClientCtx_t *cctx, mhRequest_t *req, mhResponse_t **resp,
             mhAction_t *action, apr_array_header_t *matchers)
{
    int i;

    for (i = 0 ; i < matchers->nelts; i++) {
        const ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
            *resp = pair->resp;
            *action = pair->action;
            return YES;
        }
    }
    _mhLog(MH_VERBOSE, cctx->skt, "Couldn't match request!\n");

    *resp = NULL;
    return NO;
}

static bool
_mhMatchRequest(const mhServCtx_t *ctx, const _mhClientCtx_t *cctx,
                mhRequest_t *req, mhResponse_t **resp, mhAction_t *action)
{
    return matchRequest(cctx, req, resp, action, ctx->reqMatchers);
}

static bool
_mhMatchIncompleteRequest(const mhServCtx_t *ctx, const _mhClientCtx_t *cctx,
                          mhRequest_t *req, mhResponse_t **resp,
                          mhAction_t *action)
{
    return matchRequest(cctx, req, resp, action, ctx->incompleteReqMatchers);
}

static mhResponse_t *cloneResponse(apr_pool_t *pool, mhResponse_t *resp)
{
    mhResponse_t *clone;
    clone = apr_pmemdup(pool, resp, sizeof(mhResponse_t));
    clone->hdrs = apr_table_copy(pool, resp->hdrs);
    if (resp->chunks)
        clone->chunks = apr_array_copy(pool, resp->chunks);
    if (resp->body)
        clone->body = apr_array_copy(pool, resp->body);
    return clone;
}

/* Process events on connection proxy <-> server */
static apr_status_t processProxy(mhServCtx_t *ctx, const apr_pollfd_t *desc)
{
    apr_status_t status = APR_SUCCESS;
    _mhClientCtx_t *cctx = ctx->cctx;

    if ((desc->rtnevents & APR_POLLOUT) && (cctx->buflen > 0)) {
        apr_size_t len = cctx->buflen;
        STATUSREADERR(apr_socket_send(ctx->proxyskt, cctx->buf, &len));
        _mhLog(MH_VERBOSE, ctx->proxyskt,
               "Proxy sent to server, status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, cctx->buf, (unsigned int)len);
        cctx->bufrem += len;
        cctx->buflen -= len;
    }
    if (desc->rtnevents & APR_POLLIN) {
        char *buf = cctx->buf + cctx->obuflen;
        apr_size_t len = cctx->obufrem;
        STATUSREADERR(apr_socket_recv(ctx->proxyskt, cctx->obuf, &len));
        _mhLog(MH_VERBOSE, ctx->proxyskt,
               "Proxy received from server, status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, buf, (unsigned int)len);
        cctx->obuflen += len;
        cctx->obufrem -= len;
    }

    if (status == APR_EOF && cctx->obuflen == 0) {
        apr_socket_close(ctx->proxyskt);
        ctx->proxyskt = NULL;
        apr_socket_close(cctx->skt);
        cctx->skt = NULL;
        ctx->mode = ModeServer;
    }

    return status;
}

/* Process events on connection client <-> proxy or client <-> server */
static apr_status_t processServer(mhServCtx_t *ctx, _mhClientCtx_t *cctx,
                                  const apr_pollfd_t *desc)
{
    apr_status_t status = APR_EAGAIN;

    /* First sent any pending responses before reading the next request. */
    if (desc->rtnevents & APR_POLLOUT &&
        (cctx->currResp || cctx->respQueue->nelts || cctx->obuflen)) {
        mhResponse_t *resp;

        if (cctx->obuflen) {
            apr_size_t len = cctx->obuflen;
            STATUSREADERR(apr_socket_send(cctx->skt, cctx->obuf, &len));
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Proxy/Server sent to client, status %d:\n%.*s\n---- %d ----\n",
                   status, (unsigned int)len, cctx->obuf, (unsigned int)len);
            cctx->obufrem += len;
            cctx->obuflen -= len;
            return status; /* can't send more data */
        }

        /* TODO: response in progress */
        resp = cctx->currResp ? cctx->currResp :
                                *(mhResponse_t **)apr_array_pop(cctx->respQueue);
        if (resp) {
            _mhLog(MH_VERBOSE, cctx->skt, "Sending response to client.\n");

            status = writeResponse(cctx, resp);
            if (status == APR_EOF) {
                cctx->currResp = NULL;
                ctx->mh->verifyStats->requestsResponded++;
                if (resp->closeConn) {
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "Actively closing connection.\n");
                    apr_socket_close(cctx->skt);
                    ctx->cctx = NULL;
                    return APR_EOF;
                }
                status = APR_SUCCESS;
            } else {
                cctx->currResp = resp;
                status = APR_EAGAIN;
            }
        } else {
            return APR_EGENERAL;
        }
    }
    if (desc->rtnevents & APR_POLLIN || cctx->buflen) {
        mhAction_t action;

        switch (ctx->mode) {
          case ModeServer:
          case ModeProxy:             /* Read partial or full requests */
            STATUSREADERR(readRequest(cctx, &cctx->req));

            if (!cctx->req)
                return status;

            if (status == APR_EOF) {  /* complete request received */
                mhResponse_t *resp;
                mhAction_t action;

                ctx->mh->verifyStats->requestsReceived++;
                *((mhRequest_t **)apr_array_push(ctx->reqsReceived)) = cctx->req;
                if (_mhMatchRequest(ctx, cctx, cctx->req,
                                    &resp, &action) == YES) {
                    ctx->mh->verifyStats->requestsMatched++;
                    if (resp) {
                        _mhLog(MH_VERBOSE, cctx->skt,
                               "Request matched, queueing response.\n");
                    } else {
                        _mhLog(MH_VERBOSE, cctx->skt,
                               "Request matched, queueing default response.\n");
                        resp = cloneResponse(ctx->pool, ctx->mh->defResponse);
                    }

                    if (action == mhActionInitiateSSLTunnel) {
                        _mhLog(MH_VERBOSE, cctx->skt, "Initiating SSL tunnel.\n");
                        ctx->mode = ModeTunnel;
                        ctx->proxyhost = apr_pstrdup(ctx->pool, cctx->req->url);
                        connectToServer(ctx, ctx->proxyhost);
                    } else if (action == mhActionSSLRenegotiate) {
                        _mhLog(MH_VERBOSE, cctx->skt, "Renegotiating SSL "
                               "session.\n");
                        renegotiateSSLSession(cctx);
                    } else if (action == mhActionCloseConnection) {
                        resp->closeConn = YES; /* close conn after response */
                    }
                } else {
                    ctx->mh->verifyStats->requestsNotMatched++;
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "Request found no match, queueing error response.\n");
                    resp = cloneResponse(ctx->pool, ctx->mh->defErrorResponse);
                }

                resp->req = cctx->req;
                *((mhResponse_t **)apr_array_push(cctx->respQueue)) = resp;
                cctx->req = NULL;
                return APR_SUCCESS;
            }

            if (ctx->incompleteReqMatchers->nelts > 0) {
                mhResponse_t *resp = NULL;
                /* (currently) incomplete request received? */
                if (_mhMatchIncompleteRequest(ctx, cctx, cctx->req,
                                              &resp, &action) == YES) {
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "Incomplete request matched, queueing response.\n");
                    ctx->mh->verifyStats->requestsMatched++;
                    if (!resp)
                        resp = cloneResponse(ctx->pool, ctx->mh->defResponse);
                    resp->req = cctx->req;
                    *((mhResponse_t **)apr_array_push(cctx->respQueue)) = resp;
                    cctx->req = NULL;
                    return APR_SUCCESS;
                }
            }
            break;
          case ModeTunnel:            /* Forward raw data */
            STATUSREADERR(readData(cctx));
            break;
          default:
            break;
        }
    }

    return status;
}

_mhClientCtx_t *_mhGetClientCtx(mhServCtx_t *serv_ctx)
{
    return serv_ctx->cctx;
}

static _mhClientCtx_t *initClientCtx(apr_pool_t *pool, mhServCtx_t *serv_ctx,
                                     apr_socket_t *cskt, mhServerType_t type)
{
    _mhClientCtx_t *cctx;
    cctx = apr_pcalloc(pool, sizeof(_mhClientCtx_t));
    cctx->pool = pool;
    cctx->skt = cskt;
    cctx->buflen = 0;
    cctx->bufrem = BUFSIZE;
    cctx->obuflen = 0;
    cctx->obufrem = BUFSIZE;
    cctx->closeConn = NO;
    cctx->respQueue = apr_array_make(pool, 5, sizeof(mhResponse_t *));
    cctx->currResp = NULL;
    if (type == mhHTTPServer || type == mhHTTPProxy) {
        cctx->read = socketRead;
        cctx->send = socketWrite;
    }
#ifdef MOCKHTTP_OPENSSL
    if (type == mhHTTPSServer) {
        cctx->handshake = sslHandshake;
        cctx->read = sslSocketRead;
        cctx->send = sslSocketWrite;
        cctx->keyFile = serv_ctx->keyFile;
        cctx->certFiles = serv_ctx->certFiles;
        cctx->clientCert = serv_ctx->clientCert;
        cctx->protocols = serv_ctx->protocols;
        initSSLCtx(cctx);
    }
#endif
    return cctx;
}

/******************************************************************************/
/* Process socket events                                                      */
/******************************************************************************/
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx)
{
    apr_int32_t num;
    const apr_pollfd_t *desc;
    _mhClientCtx_t *cctx;
    apr_pollfd_t pfd = { 0 };
    apr_status_t status;

    cctx = ctx->cctx;
#if 0
    /* something to write */
    if (cctx && cctx->skt) {
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = cctx->skt;
        pfd.reqevents = cctx->reqevents;
        pfd.client_data = cctx;
        apr_pollset_remove(ctx->pollset, &pfd);

        cctx->reqevents = APR_POLLIN;
        if (cctx->currResp || cctx->respQueue->nelts > 0 || cctx->obuflen > 0)
            cctx->reqevents |= APR_POLLOUT;
        pfd.reqevents = ctx->cctx->reqevents;
        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }
#endif
    STATUSERR(apr_pollset_poll(ctx->pollset, APR_USEC_PER_SEC / 100,
                               &num, &desc));

    /* The same socket can be returned multiple times by apr_pollset_poll() */
    while (num--) {
        if (desc->desc.s == ctx->skt) {
            apr_socket_t *cskt;
            apr_pollfd_t pfd = { 0 };

            _mhLog(MH_VERBOSE, ctx->skt, "Accepting client connection.\n");

            STATUSERR(apr_socket_accept(&cskt, ctx->skt, ctx->pool));

            STATUSERR(apr_socket_opt_set(cskt, APR_SO_NONBLOCK, 1));
            STATUSERR(apr_socket_timeout_set(cskt, 0));

            cctx = initClientCtx(ctx->pool, ctx, cskt, ctx->type);
            pfd.desc_type = APR_POLL_SOCKET;
            pfd.desc.s = cskt;
            pfd.reqevents = APR_POLLIN | APR_POLLOUT;
            pfd.client_data = cctx;

            STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
            cctx->reqevents = pfd.reqevents;
            ctx->cctx = cctx;
        } else if (desc->desc.s == ctx->proxyskt) {
            STATUSREADERR(processProxy(ctx, desc));
        } else {
            /* one of the client sockets */
            _mhClientCtx_t *cctx = desc->client_data;

            if (!cctx->skt) /* socket already closed? */
                continue;

            if (cctx->handshake) {
                status = cctx->handshake(cctx);
                if (status)     /* APR_SUCCESS -> handshake finished */
                    continue;
            }
            STATUSREADERR(processServer(ctx, cctx, desc));
        }
        desc++;
    }

    return status;
}

/******************************************************************************/
/* Init HTTP server                                                           */
/******************************************************************************/

mhServCtx_t *mhNewServer(MockHTTP *mh)
{
    mh->servCtx = initServCtx(mh, "localhost", DefaultSrvPort);
    mh->servCtx->type = mhGenericServer;
    return mh->servCtx;
}

void mhConfigAndStartServer(mhServCtx_t *serv_ctx, ...)
{
    apr_status_t status;
    mhError_t err;

    if (serv_ctx->protocols == mhProtoUnspecified) {
        serv_ctx->protocols = mhProtoAllSecure;
    }
    /* No more config to do here, has been done during parameter evaluation */
    status = startServer(serv_ctx);
    if (status == MH_STATUS_WAITING)
        err = MOCKHTTP_WAITING;

    err = MOCKHTTP_SETUP_FAILED;

    /* TODO: store error message */
}

unsigned int mhServerPortNr(const MockHTTP *mh)
{
    return mh->servCtx->port;
}

unsigned int mhProxyPortNr(const MockHTTP *mh)
{
    return mh->proxyCtx->port;
}

int mhSetServerPort(mhServCtx_t *ctx, unsigned int port)
{
    ctx->port = port;
    return YES;
}

int mhSetServerType(mhServCtx_t *ctx, mhServerType_t type)
{
    switch (ctx->type) {
        case mhGenericServer:
            if (type == mhHTTP)
                ctx->type = mhHTTPServer;
            else
                ctx->type = mhHTTPSServer;
            break;
        case mhGenericProxy:
            if (type == mhHTTP)
                ctx->type = mhHTTPProxy;
            else
                ctx->type = mhHTTPSProxy;
            break;
        default:
            /* TODO: error in test configuration. */
            break;
    }
    return YES;
}

int mhSetServerCertKeyFile(mhServCtx_t *ctx, const char *keyFile)
{
    ctx->keyFile = keyFile;
    return YES;
}

int mhAddServerCertFiles(mhServCtx_t *ctx, ...)
{
    va_list argp;

    if (!ctx->certFiles)
        ctx->certFiles = apr_array_make(ctx->pool, 5, sizeof(const char *));
    va_start(argp, ctx);
    while (1) {
        const char *certFile = va_arg(argp, const char *);
        if (certFile == NULL)
            break;
        *((const char **)apr_array_push(ctx->certFiles)) = certFile;
    }
    va_end(argp);
    return YES;
}

int mhAddServerCertFileArray(mhServCtx_t *ctx, const char **certFiles)
{
    const char *certFile;
    int i = 0;

    do {
        certFile = certFiles[i++];
        mhAddServerCertFiles(ctx, certFile, NULL);
    } while (certFiles[i] != NULL);
    return YES;
}

int mhSetServerRequestClientCert(mhServCtx_t *ctx, mhClientCertVerification_t v)
{
    ctx->clientCert = v;
    return YES;
}

int mhAddSSLProtocol(mhServCtx_t *ctx, mhSSLProtocol_t proto)
{
    ctx->protocols |= proto;
    return YES;
}

mhServCtx_t *mhNewProxy(MockHTTP *mh)
{
    mh->proxyCtx = initServCtx(mh, "localhost", DefaultSrvPort);
    mh->proxyCtx->type = mhGenericProxy;
    return mh->proxyCtx;
}

mhServCtx_t *mhGetServerCtx(MockHTTP *mh)
{
    return mh->servCtx;
}

mhServCtx_t *mhGetProxyCtx(MockHTTP *mh)
{
    return mh->proxyCtx;
}


#ifdef MOCKHTTP_OPENSSL
/******************************************************************************/
/* Init HTTPS server                                                          */
/******************************************************************************/
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct sslCtx_t {
    bool handshake_done;
    bool renegotiate;
    apr_status_t bio_read_status;

    SSL_CTX* ctx;
    SSL* ssl;
    BIO *bio;

};

static int init_done = 0;

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    strncpy(buf, "serftest", size); /* TODO */
    buf[size - 1] = '\0';
    return strlen(buf);
}


static int bio_apr_socket_create(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

    return 1;
}

static int bio_apr_socket_destroy(BIO *bio)
{
    /* Did we already free this? */
    if (bio == NULL) {
        return 0;
    }

    return 1;
}

static long bio_apr_socket_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
        default:
            /* abort(); */
            break;
        case BIO_CTRL_FLUSH:
            /* At this point we can't force a flush. */
            break;
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            ret = 0;
            break;
    }
    return ret;
}

/* Returns the amount read. */
static int bio_apr_socket_read(BIO *bio, char *in, int inlen)
{
    apr_size_t len = inlen;
    _mhClientCtx_t *cctx = bio->ptr;
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    apr_status_t status;

    BIO_clear_retry_flags(bio);

    status = apr_socket_recv(cctx->skt, in, &len);
    ssl_ctx->bio_read_status = status;

    if (len || status != APR_EAGAIN)
        _mhLog(MH_VERBOSE, cctx->skt, "Read %d bytes from ssl socket with "
               "status %d.\n", len, status);

    if (status == APR_EAGAIN) {
        BIO_set_retry_read(bio);
        if (len == 0)
            return -1;
    }

    if (READ_ERROR(status))
        return -1;

    return len;
}

/* Returns the amount written. */
static int bio_apr_socket_write(BIO *bio, const char *in, int inlen)
{
    apr_size_t len = inlen;
    _mhClientCtx_t *cctx = bio->ptr;

    apr_status_t status = apr_socket_send(cctx->skt, in, &len);

    if (len || status != APR_EAGAIN)
        _mhLog(MH_VERBOSE, cctx->skt, "Wrote %d of %d bytes to ssl socket with "
               "status %d.\n", len, inlen, status);

    if (READ_ERROR(status))
        return -1;

    return len;
}


static BIO_METHOD bio_apr_socket_method = {
    BIO_TYPE_SOCKET,
    "APR sockets",
    bio_apr_socket_write,
    bio_apr_socket_read,
    NULL,                        /* Is this called? */
    NULL,                        /* Is this called? */
    bio_apr_socket_ctrl,
    bio_apr_socket_create,
    bio_apr_socket_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

static apr_status_t renegotiateSSLSession(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    if (!SSL_renegotiate(ssl_ctx->ssl))
        return APR_EGENERAL;     /* TODO: log error */
    if (!SSL_do_handshake(ssl_ctx->ssl))
        return APR_EGENERAL;

    ssl_ctx->renegotiate = YES;

    return APR_SUCCESS;
}

static apr_status_t cleanupSSL(void *baton)
{
    _mhClientCtx_t *cctx = baton;
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    if (ssl_ctx) {
        if (ssl_ctx->ssl)
            SSL_clear(ssl_ctx->ssl);
        SSL_CTX_free(ssl_ctx->ctx);
    }

    return APR_SUCCESS;
}

static int validateClientCertificate(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
    _mhClientCtx_t *cctx = SSL_get_app_data(ssl);

    _mhLog(MH_VERBOSE, cctx->skt, "validate_client_certificate called, "
                                 "preverify: %d.\n", preverify_ok);
    /* Client cert is valid for now, can be validated later. */
    return 1;
}

static apr_status_t initSSL(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    SSL_set_cipher_list(ssl_ctx->ssl, "ALL");
    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);
    SSL_set_app_data(ssl_ctx->ssl, cctx);

    return APR_SUCCESS;
}

static apr_status_t initSSLCtx(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = apr_pcalloc(cctx->pool, sizeof(*ssl_ctx));
    cctx->ssl_ctx = ssl_ctx;
    ssl_ctx->bio_read_status = APR_SUCCESS;

    /* Init OpenSSL globally */
    if (!init_done)
    {
        CRYPTO_malloc_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        init_done = 1;
    }

    if (!ssl_ctx->ctx) {
        X509_STORE *store;
        const char *certfile;
        int i;

        /* Configure supported protocol versions */
        ssl_ctx->ctx = SSL_CTX_new(SSLv23_server_method());
        if (! (cctx->protocols & mhProtoSSLv2))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv2);
        if (! (cctx->protocols & mhProtoSSLv3))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv3);
        if (! (cctx->protocols & mhProtoTLSv1))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1);
#ifdef SSL_OP_NO_TLSv1_1
        if (! (cctx->protocols & mhProtoTLSv11))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1_1);
#endif
#ifdef SSL_OP_NO_TLSv1_2
        if (! (cctx->protocols & mhProtoTLSv12))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1_2);
#endif

        if (cctx->protocols == mhProtoSSLv2) {
            /* In recent versions of OpenSSL, SSLv2 has been disabled by removing
               all SSLv2 ciphers from the cipher string. 
               If SSLv2 is the only protocol this test wants to be enabled,
               re-add the SSLv2 ciphers. */
            int result = SSL_CTX_set_cipher_list(ssl_ctx->ctx, "SSLv2");
            /* ignore result */
        }

        SSL_CTX_set_default_passwd_cb(ssl_ctx->ctx, pem_passwd_cb);
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx->ctx, cctx->keyFile,
                                        SSL_FILETYPE_PEM) != 1) {
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Cannot load private key from file '%s'\n", cctx->keyFile);
            return APR_EGENERAL;
        }

        /* Set server certificate, add ca certificates if provided. */
        certfile = APR_ARRAY_IDX(cctx->certFiles, 0, const char *);
        if (SSL_CTX_use_certificate_file(ssl_ctx->ctx, certfile,
                                         SSL_FILETYPE_PEM) != 1) {
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Cannot load certificatefrom file '%s'\n", certfile);
            return APR_EGENERAL;
        }

        store = SSL_CTX_get_cert_store(ssl_ctx->ctx);
        for (i = 1; i < cctx->certFiles->nelts; i++) {
            FILE *fp;
            certfile = APR_ARRAY_IDX(cctx->certFiles, i, const char *);
            fp = fopen(certfile, "r");
            if (fp) {
                X509 *ssl_cert = PEM_read_X509(fp, NULL, NULL, NULL);
                fclose(fp);

                SSL_CTX_add_extra_chain_cert(ssl_ctx->ctx, ssl_cert);
                X509_STORE_add_cert(store, ssl_cert);
            }
        }

        /* Check if the server needs to ask the client to send a certificate
           during handshake. */
        switch (cctx->clientCert) {
            case mhCCVerifyNone:
                break;
            case mhCCVerifyPeer:
                SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER,
                                   validateClientCertificate);
                break;
            case mhCCVerifyFailIfNoPeerSet:
                SSL_CTX_set_verify(ssl_ctx->ctx,
                                   SSL_VERIFY_PEER |
                                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                                   validateClientCertificate);
                break;
            default:
                break;
        }

        SSL_CTX_set_mode(ssl_ctx->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

        ssl_ctx->bio = BIO_new(&bio_apr_socket_method);
        ssl_ctx->bio->ptr = cctx;
        initSSL(cctx);

        apr_pool_cleanup_register(cctx->pool, cctx,
                                  cleanupSSL, apr_pool_cleanup_null);
    }
    return APR_SUCCESS;
}

static apr_status_t
sslSocketWrite(_mhClientCtx_t *cctx, const char *data, apr_size_t *len)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    int result = SSL_write(ssl_ctx->ssl, data, *len);
    if (result > 0) {
        *len = result;
        return APR_SUCCESS;
    }

    if (result == 0)
        return APR_EAGAIN;

    _mhLog(MH_VERBOSE, cctx->skt, "ssl_socket_write: ssl error?\n");

    return APR_EGENERAL;
}

static apr_status_t
sslSocketRead(_mhClientCtx_t *cctx, char *data, apr_size_t *len)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    int result = SSL_read(ssl_ctx->ssl, data, *len);
    if (result > 0) {
        *len = result;
        return APR_SUCCESS;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_SYSCALL:
                /* error in bio_bucket_read, probably APR_EAGAIN or APR_EOF */
                *len = 0;
                return ssl_ctx->bio_read_status;
            case SSL_ERROR_WANT_READ:
                *len = 0;
                return APR_EAGAIN;
            case SSL_ERROR_SSL:
            default:
                *len = 0;
                _mhLog(MH_VERBOSE, cctx->skt,
                          "ssl_socket_read SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                return APR_EGENERAL;
        }
    }

    /* not reachable */
    return APR_EGENERAL;
}

static void appendSSLErrMessage(const MockHTTP *mh, long result)
{
    apr_size_t startpos = strlen(mh->errmsg);
    ERR_error_string(result, mh->errmsg + startpos);
    /* TODO: debug */
    ERR_print_errors_fp(stderr);
}

bool _mhClientcert_valid_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                                 const _mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    X509 *peer;

    /* Check client certificate */
    peer = SSL_get_peer_certificate(ssl_ctx->ssl);
    if (peer) {
        long result = SSL_get_verify_result(ssl_ctx->ssl);
        if (result == X509_V_OK) {
            /* The client sent a certificate which verified OK */
            return YES;
        } else {
//            appendSSLErrMessage(mh, result);
        }
        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "No client certificate was received.\n");
    }
    return NO;
}

bool _mhClientcertcn_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                             const _mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    X509 *peer;
    const char *clientCN = mp->baton;

    /* Check client certificate */
    peer = SSL_get_peer_certificate(ssl_ctx->ssl);
    if (peer) {
        char buf[1024];
        int ret;
        X509_NAME *subject = X509_get_subject_name(peer);

        ret = X509_NAME_get_text_by_NID(subject,
                                        NID_commonName,
                                        buf, 1024);
        if (ret != -1 && strcmp(clientCN, buf) == 0) {
            return YES;
        }

        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "Client certificate common name "
               "\"%s\" doesn't match expected \"%s\".\n", buf, clientCN);
        return NO;
    } else {
        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "No client certificate was received.\n");
        return NO;
    }
}


static apr_status_t sslHandshake(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    int result;


    if (ssl_ctx->renegotiate) {
        if (!SSL_do_handshake(ssl_ctx->ssl))
            return APR_EGENERAL;
    }

    if (ssl_ctx->handshake_done)
        return APR_SUCCESS;

    /* Initial SSL handshake */
    result = SSL_accept(ssl_ctx->ssl);
    if (result == 1) {
        _mhLog(MH_VERBOSE, cctx->skt, "Handshake successful.\n");
        ssl_ctx->handshake_done = YES;

        return APR_SUCCESS;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return APR_EAGAIN;
            case SSL_ERROR_SYSCALL:
                return ssl_ctx->bio_read_status; /* Usually APR_EAGAIN */
            default:
                _mhLog(MH_VERBOSE, cctx->skt, "SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                return APR_EGENERAL;
        }
    }

    /* not reachable */
    return APR_EGENERAL;
}

#else /* OpenSSL not available => empty implementations */

#endif

