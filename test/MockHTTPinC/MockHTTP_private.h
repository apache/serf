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
#include <apr_queue.h>
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


typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

static const int MaxReqRespQueueSize = 50;

typedef bool (*matchfunc_t)(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                            const mhRequest_t *req);

typedef enum expectation_t {
    RequestsReceivedOnce    = 0x00000001,
    RequestsReceivedInOrder = 0x00000002,
} expectation_t;

struct MockHTTP {
    apr_pool_t *pool;
    apr_array_header_t *reqMatchers;
    apr_array_header_t *reqsReceived;
    mhServCtx_t *servCtx;
    apr_queue_t *reqQueue; /* Thread safe FIFO queue. */
    char *errmsg;
    unsigned long expectations;
    mhStats_t *verifyStats;
    mhResponse_t *defResponse;
    mhResponse_t *defErrorResponse;
};

typedef struct _mhClientCtx_t _mhClientCtx_t;

struct mhServCtx_t {
    apr_pool_t *pool;
    const MockHTTP *mh; /* keep const to avoid thread race problems */
    const char *hostname;
    apr_port_t port;
    apr_pollset_t *pollset;
    apr_socket_t *skt;
    apr_queue_t *reqQueue;   /* thread safe, pass received reqs back to test, */
    /* TODO: allow more connections */
    _mhClientCtx_t *cctx;
};

struct mhRequest_t {
    const char *method;
    const char *url;
    apr_hash_t *hdrs;
    int version;
    char *body;
    apr_size_t bodyLen;
    bool chunked;
    apr_array_header_t *chunks;
    int readState;
};

struct mhResponse_t {
    apr_pool_t *pool;
    bool built;
    unsigned int code;
    const char *body;
    bool chunked;
    apr_array_header_t *chunks;
    apr_hash_t *hdrs;
    apr_array_header_t *builders;
    bool closeConn;
    mhRequest_t *req;  /* mhResponse_t instance is reply to req */
};

struct mhRequestMatcher_t {
    apr_pool_t *pool;

    const char *method;
    apr_array_header_t *matchers;
};

struct mhMatchingPattern_t {
    const void *baton; /* use this for an expected string */
    const void *baton2;
    matchfunc_t matcher;
};

typedef void (* respbuilderfunc_t)(mhResponse_t *resp, const void *baton);

struct mhRespBuilder_t {
    void *baton;
    respbuilderfunc_t builder;
};

const char *getHeader(apr_pool_t *pool, apr_hash_t *hdrs, const char *hdr);
void setHeader(apr_pool_t *pool, apr_hash_t *hdrs,
               const char *hdr, const char *val);

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhRequestInit(MockHTTP *mh);
bool _mhMatchRequest(const MockHTTP *mh, mhRequest_t *req, mhResponse_t **resp);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm,
                            const mhRequest_t *req);
/* Build a response */
void _mhResponseBuild(mhResponse_t *resp);

/* Test servers */
mhServCtx_t *_mhInitTestServer(const MockHTTP *mh, const char *host,
apr_port_t port);
mhError_t _mhStartServer(mhServCtx_t *ctx);
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx);

void _mhLog(int verbose_flag, const char *filename, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
