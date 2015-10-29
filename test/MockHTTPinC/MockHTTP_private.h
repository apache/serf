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
#include <apr_thread_proc.h>

#if !defined(HAVE_STDBOOL_H) && defined(_MSC_VER) && (_MSC_VER >= 1800)
/* VS 2015 errors out when redefining bool */
#define HAVE_STDBOOL_H 1
#endif

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#include "MockHTTP.h"

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

#ifndef HAVE_STDBOOL_H
typedef short int bool;
#endif

static const bool YES = 1;
static const bool NO = 0;

typedef struct _mhClientCtx_t _mhClientCtx_t;

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
    mhServCtx_t *proxyCtx;
    mhServCtx_t *ocspRespCtx;
    apr_array_header_t *connMatchers;   /* array of mhConnMatcherBldr_t *'s */
    apr_array_header_t *reqMatchers;    /* array of ReqMatcherRespPair_t *'s */
    apr_array_header_t *ocspReqMatchers;    /* array of ReqMatcherRespPair_t *'s */
    apr_array_header_t *incompleteReqMatchers;       /*       .... same type */
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


typedef enum loopRequestState_t {
    NoReqsReceived = 0,
    PartialReqReceived = 1,
    FullReqReceived = 2,
} loopRequestState_t;

struct mhServCtx_t {
    apr_pool_t *pool;
    const MockHTTP *mh;        /* keep const to avoid thread race problems */
    const char *hostname;
    const char *serverID;      /* unique id for this server */
    apr_port_t port;
    apr_port_t default_port;
    const char *alpn;
    apr_pollset_t *pollset;
    apr_socket_t *skt;         /* Server listening socket */
    mhServerType_t type;
    mhThreading_t threading;
#if APR_HAS_THREADS
    bool cancelThread;         /* Variable used to signal that the thread should
                                  be cancelled. */
    apr_thread_t * threadid;
#endif
    loopRequestState_t reqState;  /* 1 if a request is in progress, 0 if
                                  no req received yet or read completely. */
    unsigned int maxRequests;  /* Max. nr of reqs per connection. */

    apr_array_header_t *clients;        /* array of _mhClientCtx_t *'s */

    /* HTTPS specific */
    const char *certFilesPrefix;
    const char *keyFile;
    const char *passphrase;
    apr_array_header_t *certFiles;
    mhClientCertVerification_t clientCert;
    int protocols;              /* SSL protocol versions */
    bool ocspEnabled;

    apr_array_header_t *reqsReceived;   /* array of mhRequest_t *'s */
    apr_array_header_t *connMatchers;   /* array of mhConnMatcherBldr_t *'s */
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


typedef enum method_t {
    MethodOther = 0,
    MethodACL,
    MethodBASELINE_CONTROL,
    MethodCHECKIN,
    MethodCHECKOUT,
    MethodCONNECT,
    MethodCOPY,
    MethodDELETE,
    MethodGET,
    MethodHEAD,
    MethodLABEL,
    MethodLOCK,
    MethodMERGE,
    MethodMKACTIVITY,
    MethodMKCOL,
    MethodMKWORKSPACE,
    MethodMOVE,
    MethodOPTIONS,
    MethodORDERPATCH,
    MethodPATCH,
    MethodPOST,
    MethodPROPFIND,
    MethodPROPPATCH,
    MethodPUT,
    MethodREPORT,
    MethodSEARCH,
    MethodTRACE,
    MethodUNCHECKOUT,
    MethodUNLOCK,
    MethodUPDATE,
    MethodVERSION_CONTROL
} method_t;

typedef enum requestType_t {
    RequestTypeHTTP,
    RequestTypeOCSP,
} requestType_t;

struct mhRequest_t {
    apr_pool_t *pool;
    requestType_t type;
    const char *method;
    method_t methodCode;
    const char *url;
    apr_table_t *hdrs;
    apr_array_header_t *hdrHashes;
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
    const MockHTTP *mh;
    bool built;
    unsigned int code;
    apr_table_t *hdrs;
    apr_array_header_t *body; /* array of iovec strings that form the raw body */
    apr_size_t bodyLen;
    bool chunked;
    /* array of iovec strings that form the dechunked body */
    const apr_array_header_t *chunks;
    const char *raw_data;
    size_t raw_data_length;
    apr_array_header_t *builders;
    bool closeConn;
    mhRequest_t *req;  /* mhResponse_t instance is reply to req */

    /* This is a OCSP response */
    bool ocspResponse;
    mhOCSPRespnseStatus_t ocsp_response_status;
};


/* Builder structures for server setup, request matching and response creation */
enum { MagicKey = 0x4D484244 }; /* MHBD */

typedef enum builderType_t {
    BuilderTypeReqMatcher,
    BuilderTypeConnMatcher,
    BuilderTypeServerSetup,
    BuilderTypeResponse,
    BuilderTypeNone,           /* A noop builder */
} builderType_t;


typedef struct builder_t {
    unsigned int magic;
    builderType_t type;
} builder_t;

typedef bool (*reqmatchfunc_t)(const mhReqMatcherBldr_t *mp,
                               const mhRequest_t *req);

struct mhRequestMatcher_t {
    apr_pool_t *pool;
    requestType_t type;
    apr_array_header_t *matchers; /* array of mhReqMatcherBldr_t *'s. */
    bool incomplete;
};

struct mhReqMatcherBldr_t {
    builder_t builder;
    const void *baton; /* use this for an expected string */
    unsigned long ibaton;
    const void *baton2;
    reqmatchfunc_t matcher;
    const char *describe_key;
    const char *describe_value;
    bool match_incomplete; /* Don't wait for full valid requests */
};

typedef bool (*connmatchfunc_t)(const mhConnMatcherBldr_t *cmb,
                                const _mhClientCtx_t *cctx);

struct mhConnMatcherBldr_t {
    builder_t builder;
    const void *baton;
    connmatchfunc_t connmatcher;
    const char *describe_key;
    const char *describe_value;
};

typedef bool (*serversetupfunc_t)(const mhServerSetupBldr_t *ssb,
                                  mhServCtx_t *ctx);

struct mhServerSetupBldr_t {
    builder_t builder;
    const void *baton;
    unsigned int ibaton;
    serversetupfunc_t serversetup;
};


typedef bool (* respbuilderfunc_t)(const mhResponseBldr_t *rb,
                                   mhResponse_t *resp);

struct mhResponseBldr_t {
    builder_t builder;
    const void *baton;
    unsigned int ibaton;
    respbuilderfunc_t respbuilder;
};

method_t methodToCode(const char *code);
unsigned long calculateHeaderHash(const char *hdr, const char *val);

const char *getHeader(apr_table_t *hdrs, const char *hdr);
void setHeader(apr_table_t *hdrs, const char *hdr, const char *val);

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhInitRequest(apr_pool_t *pool, requestType_t type);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm,
                            const mhRequest_t *req);
bool _mhClientcertcn_matcher(const mhConnMatcherBldr_t *mp,
                             const _mhClientCtx_t *cctx);
bool _mhClientcert_valid_matcher(const mhConnMatcherBldr_t *mp,
                                 const _mhClientCtx_t *cctx);

/* Build a response */
void _mhBuildResponse(mhResponse_t *resp);

void _mhErrorUnexpectedBuilder(const MockHTTP *mh, void *actual,
                               builderType_t expected);

/* Test servers */
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx);

void _mhLog(int verbose_flag, apr_socket_t *skt, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
