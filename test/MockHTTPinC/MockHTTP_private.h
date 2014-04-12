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

#ifndef MockHTTP_private_H
#define MockHTTP_private_H

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_poll.h>
#include <apr_time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MH_VERBOSE 0

/* Simple macro to return from function when status != 0
   expects 'apr_status_t status;' declaration. */
#define STATUSERR(x) if ((status = (x))) return status;

#define READ_ERROR(status) ((status) \
                                && !APR_STATUS_IS_EOF(status) \
                                && !APR_STATUS_IS_EAGAIN(status))

#define STATUSREADERR(x) if (((status = (x)) && READ_ERROR(status)))\
                            return status;

#define MH_STATUS_START (APR_OS_START_USERERR + 1500)

/* This code indicates that the server is waiting for a timed event */
#define MH_STATUS_WAITING (MH_STATUS_START + 1)

#define MH_STATUS_INCOMPLETE_REQUEST (MH_STATUS_START + 1)

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

typedef struct _mhClientCtx_t _mhClientCtx_t;

typedef bool (*reqmatchfunc_t)(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                               const mhRequest_t *req);
typedef bool (*connmatchfunc_t)(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                                const _mhClientCtx_t *cctx);

typedef enum expectation_t {
    RequestsReceivedOnce    = 0x00000001,
    RequestsReceivedInOrder = 0x00000002,
} expectation_t;

struct MockHTTP {
    apr_pool_t *pool;
    mhServCtx_t *servCtx;
    char *errmsg;
    unsigned long expectations;
    mhStats_t *verifyStats;             /* Statistics gathered by the server */
    mhResponse_t *defResponse;          /* Default req matched response */
    mhResponse_t *defErrorResponse;     /* Default req not matched response */
    mhConnectionMatcher_t *connMatcher; /* Connection-level matching */
    mhServCtx_t *proxyCtx;
};

typedef struct ReqMatcherRespPair_t {
    mhRequestMatcher_t *rm;
    mhResponse_t *resp;
    mhAction_t action;
} ReqMatcherRespPair_t;

typedef enum servMode_t {
    ModeServer,
    ModeProxy,
    ModeTunnel,
} servMode_t;

struct mhServCtx_t {
    apr_pool_t *pool;
    const MockHTTP *mh;        /* keep const to avoid thread race problems */
    const char *hostname;
    const char *serverID;      /* unique id for this server */
    apr_port_t port;
    apr_pollset_t *pollset;
    apr_socket_t *skt;         /* Server listening socket */
    apr_socket_t *proxyskt;    /* Socket for conn proxy <-> server */
    const char *proxyhost;     /* Proxy host:port */
    mhServerType_t type;
    int partialRequest;        /* 1 if a request is in progress, 0 if no req
                                  received yet or read completely. */
    unsigned int maxRequests;  /* Max. nr of reqs per connection. */

    /* TODO: allow more connections */
    _mhClientCtx_t *cctx;

    servMode_t mode;      /* default = server, but can switch to proxy/tunnel */

    /* HTTPS specific */
    const char *certFilesPrefix;
    const char *keyFile;
    apr_array_header_t *certFiles;
    mhClientCertVerification_t clientCert;
    int protocols;              /* SSL protocol versions */

    apr_array_header_t *reqsReceived;   /* array of mhRequest_t *'s */
    apr_array_header_t *reqMatchers;    /* array of ReqMatcherRespPair_t *'s */
    apr_array_header_t *incompleteReqMatchers;       /*       .... same type */
};
    

typedef enum reqReadState_t {
    ReadStateStatusLine = 0,
    ReadStateHeaders,
    ReadStateBody,
    ReadStateChunked,
    ReadStateChunkedHeader,
    ReadStateChunkedChunk,
    ReadStateChunkedTrailer,
    ReadStateDone
} reqReadState_t;

struct mhRequest_t {
    apr_pool_t *pool;
    const char *method;
    const char *url;
    apr_table_t *hdrs;
    int version;
    apr_array_header_t *body; /* array of iovec strings that form the raw body */
    apr_size_t bodyLen;
    bool chunked;
    /* array of iovec strings that form the dechunked body */
    apr_array_header_t *chunks;
    reqReadState_t readState;
    bool incomplete_chunk; /* chunk reading in progress */
};

struct mhResponse_t {
    apr_pool_t *pool;
    bool built;
    unsigned int code;
    apr_table_t *hdrs;
    apr_array_header_t *body; /* array of iovec strings that form the raw body */
    apr_size_t bodyLen;
    bool chunked;
    /* array of iovec strings that form the dechunked body */
    apr_array_header_t *chunks;
    const char *raw_data;
    apr_array_header_t *builders;
    bool closeConn;
    mhRequest_t *req;  /* mhResponse_t instance is reply to req */
};

struct mhRequestMatcher_t {
    apr_pool_t *pool;

    const char *method;
    apr_array_header_t *matchers; /* array of mhMatchingPattern_t *'s. */
    bool incomplete;
};

struct mhMatchingPattern_t {
    const void *baton; /* use this for an expected string */
    const void *baton2;
    reqmatchfunc_t matcher;
    connmatchfunc_t connmatcher;
    const char *describe_key;
    const char *describe_value;
    bool match_incomplete; /* Don't wait for full valid requests */
};

const char *getHeader(apr_pool_t *pool, apr_table_t *hdrs, const char *hdr);
void setHeader(apr_table_t *hdrs, const char *hdr, const char *val);

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhInitRequest(apr_pool_t *pool);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm,
                            const mhRequest_t *req);
bool _mhClientcertcn_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                             const _mhClientCtx_t *cctx);
bool _mhClientcert_valid_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                                 const _mhClientCtx_t *cctx);
_mhClientCtx_t *_mhGetClientCtx(mhServCtx_t *serv_ctx);

/* Build a response */
void _mhBuildResponse(mhResponse_t *resp);

/* Test servers */
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx);

void _mhLog(int verbose_flag, apr_socket_t *skt, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
