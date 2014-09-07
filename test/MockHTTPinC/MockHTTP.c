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

#include "MockHTTP_private.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <apr_strings.h>
#include <apr_lib.h>

static char *serializeArrayOfIovecs(apr_pool_t *pool,
                                    apr_array_header_t *blocks);
static mhResponse_t *initResponse(MockHTTP *mh);


/* private functions */

/* Header should be stored with their original case to use them in responses.
   Search on header name is case-insensitive per RFC2616. */
const char *getHeader(apr_table_t *hdrs, const char *hdr)
{
    return apr_table_get(hdrs, hdr);
}

void setHeader(apr_table_t *hdrs, const char *hdr, const char *val)
{
    apr_table_add(hdrs, hdr, val);
}

/* To enable calls like Assert(expected, Verify...(), ErrorMessage()), with the
   evaluation order of the arguments not specified in C, we need the pointer to 
   where an error message will be stored before the call to Verify...().
   So we allocate up to ERRMSG_MAXSIZE bytes for the error message memory up 
   front and use it when needed */
#define ERRMSG_MAXSIZE 65000

static void appendErrMessage(const MockHTTP *mh, const char *fmt, ...)
{
    apr_pool_t *scratchpool;
    apr_size_t startpos = strlen(mh->errmsg);
    apr_size_t len;
    const char *msg;
    va_list argp;

    apr_pool_create(&scratchpool, mh->pool);
    msg = apr_pvsprintf(scratchpool, fmt, argp);

    len = strlen(msg) + 1; /* include trailing \0 */
    len = startpos + len > ERRMSG_MAXSIZE ? ERRMSG_MAXSIZE - startpos - 1: len;
    memcpy(mh->errmsg + startpos, msg, len);

    apr_pool_destroy(scratchpool);
}

/* Define a MockHTTP context */
MockHTTP *mhInit()
{
    apr_pool_t *pool;
    MockHTTP *__mh, *mh;
    mhResponse_t *__resp;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    __mh = mh = apr_pcalloc(pool, sizeof(struct MockHTTP));
    mh->pool = pool;
    mh->errmsg = apr_palloc(pool, ERRMSG_MAXSIZE);
    *mh->errmsg = '\0';
    mh->expectations = 0;
    mh->verifyStats = apr_pcalloc(pool, sizeof(mhStats_t));

    __resp = mhNewDefaultResponse(__mh);
    mhConfigResponse(__resp, WithCode(200), WithBody("Default Response"), NULL);

    __resp = mh->defErrorResponse = initResponse(__mh);
    mhConfigResponse(__resp, WithCode(500),
                     WithBody("Mock server error."), NULL);
    mh->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));
    mh->incompleteReqMatchers = apr_array_make(pool, 5,
                                               sizeof(ReqMatcherRespPair_t *));
    mh->ocspReqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));

    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    if (mh->servCtx) {
        mhStopServer(mh->servCtx);
    }

    if (mh->proxyCtx) {
        mhStopServer(mh->proxyCtx);
    }


    /* The MockHTTP * is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    apr_pool_destroy(mh->pool);

    /* mh ptr is now invalid */
}

/**
 * Runs both the proxy and the server loops. This function will block as long
 * as there's data to read or write.
 *
 * reqState: NoReqsReceived if no requests were received
 *           PartialReqReceived if either proxy or server blocks on a partly 
 *                              read request.
 *           FullReqReceived if all requests have been read completely.
 */
static apr_status_t runServerLoop(MockHTTP *mh, loopRequestState_t *reqState)
{
    apr_status_t status = APR_EGENERAL;

    *reqState = NoReqsReceived;
    do {
        if (mh->proxyCtx && mh->proxyCtx->threading != mhThreadSeparate) {
            status = _mhRunServerLoop(mh->proxyCtx);
            *reqState = mh->proxyCtx->reqState;
        }
        /* TODO: status? */
        if (mh->servCtx && mh->servCtx->threading != mhThreadSeparate) {
            status = _mhRunServerLoop(mh->servCtx);
            *reqState |= mh->servCtx->reqState;
        }
    } while (status == APR_SUCCESS);

    return status;
}

mhError_t mhRunServerLoop(MockHTTP *mh)
{
    loopRequestState_t dummy;
    apr_status_t status = runServerLoop(mh, &dummy);

    if (status == MH_STATUS_WAITING)
        return MOCKHTTP_WAITING;

    if (READ_ERROR(status) && !APR_STATUS_IS_TIMEUP(status))
        return MOCKHTTP_TEST_FAILED;

    return MOCKHTTP_NO_ERROR;
}

mhError_t mhRunServerLoopCompleteRequests(MockHTTP *mh)
{
    loopRequestState_t reqState = NoReqsReceived;
    apr_status_t status = APR_EGENERAL;
    apr_time_t finish_time = apr_time_now() + apr_time_from_sec(15);

    while (1) {
        status = runServerLoop(mh, &reqState);

        if (status != APR_EAGAIN)
            break;
        if (apr_time_now() > finish_time)
            break;
        if (reqState == FullReqReceived)
            break;
    };

    if (status == APR_EAGAIN)
        return MOCKHTTP_TIMEOUT;

    return status;
}

static const builder_t NoopBuilder = { MagicKey, BuilderTypeNone };

const void *mhSetOnConditionThat(int condition, void *builder)
{
    if (condition)
        return builder;

    return &NoopBuilder;
}

/******************************************************************************/
/* Requests matchers: define criteria to match different aspects of a HTTP    */
/* request received by the MockHTTP server.                                   */
/******************************************************************************/

static mhReqMatcherBldr_t *createReqMatcherBldr(apr_pool_t *pool)
{
    mhReqMatcherBldr_t *mp = apr_pcalloc(pool, sizeof(mhReqMatcherBldr_t));
    mp->builder.magic = MagicKey;
    mp->builder.type = BuilderTypeReqMatcher;
    return mp;
}

/**
 * Builder callback, checks that the response body chunks match what's expected.
 */
static bool
chunks_matcher(const mhReqMatcherBldr_t *mp, apr_array_header_t *chunks)
{
    const char *ptr, *expected = mp->baton;
    int i;

    ptr = expected;
    for (i = 0 ; i < chunks->nelts; i++) {
        struct iovec vec;
        apr_size_t len;

        vec = APR_ARRAY_IDX(chunks, i, struct iovec);
        /* iov_base can be incomplete, so shorter than iov_len */
        len = strlen(vec.iov_base);
        if (strncmp(ptr, vec.iov_base, len) != 0)
            return NO;
        ptr += len;
    }

    /* Up until now the body matches, but maybe the body is expected to be
       longer. */
    if (*ptr != '\0')
        return NO;

    return YES;
}

/**
 * Builder callback, checks that a string matches what's expected.
 */
static bool str_matcher(const mhReqMatcherBldr_t *mp, const char *actual)
{
    const char *expected = mp->baton;

    if (expected == actual)
        return YES; /* case where both are NULL, e.g. test for header not set */

    if ((!expected && *actual == '\0') ||
        (!actual && *expected == '\0'))
        return YES; /* "" and NULL are equal */

    if (expected && actual && strcmp(expected, actual) == 0)
        return YES;

    return NO;
}

/**
 * Builder callback, checks if the request url matches.
 */
static bool url_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return str_matcher(mp, req->url);
}

mhReqMatcherBldr_t *
mhMatchURLEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_matcher;
    mp->describe_key = "URL equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the request url doesn't match.
 */
static bool
url_not_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return !str_matcher(mp, req->url);
}

mhReqMatcherBldr_t *
mhMatchURLNotEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_not_matcher;
    mp->describe_key = "URL not equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the body (chunked or not chunked) matches what's
 * expected.
 */
static bool
body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    /* ignore chunked or not chunked */
    if (req->chunked == YES)
        return chunks_matcher(mp, req->chunks);
    else {
        return chunks_matcher(mp, req->body);
    }
}

mhReqMatcherBldr_t *
mhMatchBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->describe_key = "Body equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the raw body matches what's expected.
 */
static bool
raw_body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return chunks_matcher(mp, req->body);
}

mhReqMatcherBldr_t *
mhMatchRawBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = raw_body_matcher;
    mp->describe_key = "Raw body equal to";
    mp->describe_value = expected;
    return mp;
}

mhReqMatcherBldr_t *
mhMatchIncompleteBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->match_incomplete = TRUE;
    mp->describe_key = "Incomplete body equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the body is not chunked and it matches the
 * expected body.
 */
static bool
body_notchunked_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    if (req->chunked == YES)
        return NO;
    return chunks_matcher(mp, req->body);
}

mhReqMatcherBldr_t *
mhMatchBodyNotChunkedEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_notchunked_matcher;
    mp->describe_key = "Body not chunked equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the body is chunked and matches what's
 * expected.
 */
static bool
chunked_body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    if (req->chunked == NO)
        return NO;

    return chunks_matcher(mp, req->chunks);
}

mhReqMatcherBldr_t *
mhMatchChunkedBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = chunked_body_matcher;
    mp->describe_key = "Chunked body equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the body is chunk and each chunk matches exactly
 * the expected chunks.
 */
static bool chunked_body_chunks_matcher(const mhReqMatcherBldr_t *mp,
                                        const mhRequest_t *req)
{
    const apr_array_header_t *chunks;
    int i;

    if (req->chunked == NO)
        return NO;

    chunks = mp->baton;
    if (chunks->nelts != req->chunks->nelts)
        return NO;

    for (i = 0 ; i < chunks->nelts; i++) {
        struct iovec actual, expected;

        actual = APR_ARRAY_IDX(req->chunks, i, struct iovec);
        expected = APR_ARRAY_IDX(chunks, i, struct iovec);

        if (actual.iov_len != expected.iov_len)
            return NO;

        if (strncmp(expected.iov_base, actual.iov_base, actual.iov_len) != 0)
            return NO;
    }

    return YES;
}

mhReqMatcherBldr_t *
mhMatchBodyChunksEqualTo(const MockHTTP *mh, ...)
{
    apr_pool_t *pool = mh->pool;
    apr_array_header_t *chunks;
    mhReqMatcherBldr_t *mp;
    va_list argp;

    chunks = apr_array_make(pool, 5, sizeof(struct iovec));
    va_start(argp, mh);
    while (1) {
        struct iovec vec;
        vec.iov_base = (void *)va_arg(argp, const char *);
        if (vec.iov_base == NULL)
            break;
        vec.iov_len = strlen(vec.iov_base);
        *((struct iovec *)apr_array_push(chunks)) = vec;
    }
    va_end(argp);

    mp = createReqMatcherBldr(pool);
    mp->baton = chunks;
    mp->matcher = chunked_body_chunks_matcher;
    mp->describe_key = "Chunked body with chunks";
    mp->describe_value = serializeArrayOfIovecs(pool, chunks);
    return mp;
}


/**
 * Builder callback, checks if a header's value matches the expected value.
 * When a header isn't set its value will be NULL, so a NULL check can be used
 * to check that the header doesn't exist.
 */
static bool
header_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *actual;
    int i, found = 0;
    unsigned long exphash = mp->ibaton;

    /* exphash == 0 means testing that header is NOT set */
    if (exphash) {
        for (i = 0; i < req->hdrHashes->nelts; i++) {
            unsigned long acthash = APR_ARRAY_IDX(req->hdrHashes, i, unsigned long);
            if (exphash == acthash) {
                found = 1;
                break;
            }
        }
        if (found == 0)
            return NO;
    }

    actual = getHeader(req->hdrs, mp->baton2);
    return str_matcher(mp, actual);
}

mhReqMatcherBldr_t *
mhMatchHeaderEqualTo(const MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->ibaton = calculateHeaderHash(hdr, value);
    mp->matcher = header_matcher;
    mp->describe_key = "Header equal to";
    mp->describe_value = apr_psprintf(pool, "%s: %s", hdr, value);
    return mp;
}

/**
 * Builder callback, checks if a header's value is not equal to the expected 
 * value.
 * When a header isn't set its value will be NULL, so a non-NULL check can be 
 * used to check if the header exists.
 */
static bool
header_not_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *actual = getHeader(req->hdrs, mp->baton2);
    return !str_matcher(mp, actual);
}

mhReqMatcherBldr_t *
mhMatchHeaderNotEqualTo(const MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->matcher = header_not_matcher;
    mp->describe_key = "Header not equal to";
    mp->describe_value = apr_psprintf(pool, "%s: %s", hdr, value);
    return mp;
}

method_t methodToCode(const char *code)
{
    char ch1, ch2;
    ch1 = toupper(*code);

    if (ch1 == 'G' && strcasecmp(code, "GET") == 0)
        return MethodGET;
    if (ch1 == 'H' && strcasecmp(code, "HEAD") == 0)
        return MethodHEAD;

    ch2 = toupper(*(code+1));
    if (ch1 == 'P') {
        if (ch2 == 'O' && strcasecmp(code, "POST") == 0)
            return MethodPOST;
        if (ch2 == 'A' && strcasecmp(code, "PATCH") == 0)
            return MethodPATCH;
        if (ch2 == 'A' && strcasecmp(code, "PUT") == 0)
            return MethodPUT;
        if (ch2 == 'R') {
            if (strcasecmp(code, "PROPFIND") == 0)
                return MethodPROPFIND;
            if (strcasecmp(code, "PROPPATCH") == 0)
                return MethodPROPPATCH;
        }
        return MethodOther;
    }
    if (ch1 == 'O') {
        if (ch2 == 'P' && strcasecmp(code, "OPTIONS") == 0)
            return MethodOPTIONS;
        if (ch2 == 'R' && strcasecmp(code, "ORDERPATCH") == 0)
            return MethodORDERPATCH;
        return MethodOther;
    }

    if (ch1 == 'A' && strcasecmp(code, "ACL") == 0)
        return MethodACL;
    if (ch1 == 'B' && strcasecmp(code, "BASELINE-CONTROL") == 0)
        return MethodBASELINE_CONTROL;
    if (ch1 == 'L' && strcasecmp(code, "LABEL") == 0)
        return MethodLABEL;
    if (ch1 == 'D' && strcasecmp(code, "DELETE") == 0)
        return MethodDELETE;
    return MethodOther;
}

/**
 * Builder callback, checks if the request method matches the expected method.
 * (case insensitive).
 * TODO: not used at this time!!
 */
static bool method_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *method = mp->baton;
    method_t methodCode = mp->ibaton;

    if (methodCode != req->methodCode) {
        return NO;
    } else {
        if (methodCode != MethodOther)
            return YES;
        if (strcasecmp(method, req->method) == 0) {
            return YES;
        }
        return NO;
    }
}

mhReqMatcherBldr_t *
mhMatchMethodEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->ibaton = methodToCode(expected);
    mp->matcher = method_matcher;
    mp->describe_key = "Method equal to";
    mp->describe_value = expected;
    return mp;
}

static bool any_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return YES;
}

mhConnMatcherBldr_t *mhMatchAny(const MockHTTP *mh)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->matcher = any_matcher;
    mp->describe_key = "Matches all";
    mp->describe_value = "";
    return mp;
}

/**
 * Takes a list of builders of type mhReqMatcherBldr_t *'s and stores them in
 * a new request matcher. The builders will be evaluated later when a request
 * arrives in the server.
 */
static mhRequestMatcher_t *
constructRequestMatcher(const MockHTTP *mh, requestType_t type, va_list argp)
{
    apr_pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = apr_pcalloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->type = type;
    rm->matchers = apr_array_make(pool, 5, sizeof(mhReqMatcherBldr_t *));

    while (1) {
        mhReqMatcherBldr_t *rmb;
        rmb = va_arg(argp, mhReqMatcherBldr_t *);
        if (rmb == NULL)
            break;
        if (rmb->builder.type == BuilderTypeNone)
            continue;
        if (rmb->builder.type != BuilderTypeReqMatcher) {
            _mhErrorUnexpectedBuilder(mh, rmb, BuilderTypeReqMatcher);
            break;
        }
        *((mhReqMatcherBldr_t **)apr_array_push(rm->matchers)) = rmb;
    }
    return rm;
}

mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, mh);
    rm = constructRequestMatcher(mh, RequestTypeHTTP, argp);
    va_end(argp);

    return rm;
}

mhRequestMatcher_t *mhGivenOCSPRequest(MockHTTP *mh, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, mh);
    rm = constructRequestMatcher(mh, RequestTypeOCSP, argp);
    va_end(argp);

    return rm;
}

bool
_mhRequestMatcherMatch(const mhRequestMatcher_t *rm, const mhRequest_t *req)
{
    int i;

    if (rm->type != req->type)
        return NO;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhReqMatcherBldr_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhReqMatcherBldr_t *);
        if (mp->matcher(mp, req) == NO)
            return NO;
    }

    return YES;
}

/******************************************************************************/
/* Connection-level matchers: define criteria to match different aspects of a */
/* HTTP or HTTPS connection.                                                  */
/******************************************************************************/

static mhConnMatcherBldr_t *createConnMatcherBldr(apr_pool_t *pool)
{
    mhConnMatcherBldr_t *mp = apr_pcalloc(pool, sizeof(mhConnMatcherBldr_t));
    mp->builder.magic = MagicKey;
    mp->builder.type = BuilderTypeConnMatcher;
    return mp;
}

/* Stores a mhConnMatcherBldr_t * in the MockHTTP context */
void mhGivenConnSetup(MockHTTP *mh, ...)
{
    va_list argp;
    mhConnMatcherBldr_t *cmb;

    mh->connMatchers = apr_array_make(mh->pool, 5,
                                      sizeof(mhConnMatcherBldr_t *));

    va_start(argp, mh);
    while (1) {
        cmb = va_arg(argp, mhConnMatcherBldr_t *);
        if (cmb == NULL)
            break;
        if (cmb->builder.type == BuilderTypeNone)
            continue;
        if (cmb->builder.type != BuilderTypeConnMatcher) {
            _mhErrorUnexpectedBuilder(mh, cmb, BuilderTypeConnMatcher);
            break;
        }
        *((mhConnMatcherBldr_t **)apr_array_push(mh->connMatchers)) = cmb;
    }
    va_end(argp);
}

mhConnMatcherBldr_t *
mhMatchClientCertCNEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhConnMatcherBldr_t *mp = createConnMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->connmatcher = _mhClientcertcn_matcher;
    mp->describe_key = "Client Certificate CN equal to";
    mp->describe_value = expected;
    return mp;
}

mhConnMatcherBldr_t *mhMatchClientCertValid(const MockHTTP *mh)
{
    apr_pool_t *pool = mh->pool;

    mhConnMatcherBldr_t *mp = createConnMatcherBldr(pool);
    mp->connmatcher = _mhClientcert_valid_matcher;
    mp->describe_key = "Client Certificate";
    mp->describe_value = "valid";
    return mp;
}

/******************************************************************************/
/* Response                                                                   */
/******************************************************************************/
static mhResponse_t *initResponse(MockHTTP *mh)
{
    apr_pool_t *pool;
    mhResponse_t *resp;

    apr_pool_create(&pool, mh->pool);

    resp = apr_pcalloc(pool, sizeof(mhResponse_t));
    resp->pool = pool;
    resp->mh = mh;
    resp->code = 200;
    resp->body = apr_array_make(pool, 5, sizeof(struct iovec));
    resp->hdrs = apr_table_make(pool, 5);
    resp->builders = apr_array_make(pool, 5, sizeof(mhResponseBldr_t *));
    return resp;
}

mhResponse_t *mhNewResponseForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                                      mhRequestMatcher_t *rm)
{
    apr_array_header_t *matchers = NULL;
    int i;

    mhResponse_t *resp = initResponse(mh);

    switch (rm->type) {
        case RequestTypeHTTP:
            if (ctx)
                matchers = rm->incomplete ? ctx->incompleteReqMatchers :
                                            ctx->reqMatchers;
            else
                matchers = rm->incomplete ? mh->incompleteReqMatchers :
                                            mh->reqMatchers;
            break;
        case RequestTypeOCSP:
            matchers = mh->ocspReqMatchers;
            break;
    }

    /* TODO: how can this not be the last element?? */
    for (i = matchers->nelts - 1 ; i >= 0; i--) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);
        if (rm == pair->rm) {
            pair->resp = resp;
            break;
        }
    }

    return resp;
}

void mhNewActionForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                           mhRequestMatcher_t *rm, mhAction_t action)
{
    apr_array_header_t *matchers;
    int i;

    if (ctx)
        matchers = rm->incomplete ? ctx->incompleteReqMatchers : ctx->reqMatchers;
    else
        matchers = rm->incomplete ? mh->incompleteReqMatchers : mh->reqMatchers;
    for (i = matchers->nelts - 1 ; i >= 0; i--) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);
        if (rm == pair->rm) {
            pair->action = action;
            break;
        }
    }
}

mhResponse_t *mhNewDefaultResponse(MockHTTP *mh)
{
    mh->defResponse = initResponse(mh);
    return mh->defResponse;
}

void mhConfigResponse(mhResponse_t *resp, ...)
{
    va_list argp;
    /* This is only needed for values that are only known when the request
       is received, e.g. WithRequestBody. */
    va_start(argp, resp);
    while (1) {
        mhResponseBldr_t *rb;
        rb = va_arg(argp, mhResponseBldr_t *);
        if (rb == NULL)
            break;
        if (rb->builder.type == BuilderTypeNone)
            continue;
        if (rb->builder.type != BuilderTypeResponse) {
            _mhErrorUnexpectedBuilder(resp->mh, rb, BuilderTypeResponse);
            break;
        }

        *((mhResponseBldr_t **)apr_array_push(resp->builders)) = rb;
    }
    va_end(argp);
}

static mhResponseBldr_t *createResponseBldr(apr_pool_t *pool)
{
    mhResponseBldr_t *rb = apr_pcalloc(pool, sizeof(mhResponseBldr_t));
    rb->builder.magic = MagicKey;
    rb->builder.type = BuilderTypeResponse;
    return rb;
}

static bool resp_set_code(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->code = rb->ibaton;
    return YES;
}

mhResponseBldr_t *mhRespSetCode(mhResponse_t *resp, unsigned int code)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_code;
    rb->ibaton = code;
    return rb;
}

static bool resp_set_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    struct iovec vec;
    const char *body = rb->baton;

    vec.iov_base = (void *)body;
    vec.iov_len = strlen(body);
    *((struct iovec *)apr_array_push(resp->body)) = vec;
    resp->bodyLen = vec.iov_len;
    resp->chunked = NO;
    setHeader(resp->hdrs, "Content-Length",
              apr_itoa(resp->pool, resp->bodyLen));
    return YES;
}

mhResponseBldr_t *mhRespSetBody(mhResponse_t *resp, const char *body)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_body;
    rb->baton = apr_pstrdup(pool, body);
    return rb;
}


static bool
resp_set_chunked_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->chunks = rb->baton;
    setHeader(resp->hdrs, "Transfer-Encoding", "chunked");
    resp->chunked = YES;
    return YES;
}

mhResponseBldr_t *mhRespSetChunkedBody(mhResponse_t *resp, ...)
{
    apr_array_header_t *chunks;
    va_list argp;

    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);

    chunks = apr_array_make(resp->pool, 5, sizeof(struct iovec));
    va_start(argp, resp);
    while (1) {
        struct iovec vec;
        vec.iov_base = (void *)va_arg(argp, const char *);
        if (vec.iov_base == NULL)
            break;
        vec.iov_len = strlen(vec.iov_base);
        *((struct iovec *)apr_array_push(chunks)) = vec;
    }
    va_end(argp);

    rb->baton = chunks;
    rb->respbuilder = resp_set_chunked_body;
    return rb;
}

static bool
resp_add_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    apr_hash_index_t *hi;
    apr_hash_t *hdrs;
    apr_pool_t *tmppool;

    apr_pool_create(&tmppool, resp->pool);
    /* get rid of const for call to apr_hash_first */
    hdrs = apr_hash_copy(tmppool, rb->baton);
    for (hi = apr_hash_first(tmppool, hdrs); hi; hi = apr_hash_next(hi)) {
        void *val;
        const void *key;
        apr_ssize_t klen;
        apr_hash_this(hi, &key, &klen, &val);

        setHeader(resp->hdrs, (const char *)key, (const char *)val);
    }
    apr_pool_destroy(tmppool);

    return YES;
}

mhResponseBldr_t *mhRespAddHeader(mhResponse_t *resp, const char *header,
                                  const char *value)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    apr_hash_t *hdrs = apr_hash_make(resp->pool);
    apr_hash_set(hdrs, header, APR_HASH_KEY_STRING, value);
    rb->baton = hdrs;
    rb->respbuilder = resp_add_header;
    return rb;
}

static bool
resp_set_close_conn_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    setHeader(resp->hdrs, "Connection", "close");
    resp->closeConn = YES;
    return YES;
}

mhResponseBldr_t *mhRespSetConnCloseHdr(mhResponse_t *resp)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_close_conn_header;
    return rb;
}


static bool
resp_use_request_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    mhRequest_t *req = resp->req;
    const char *value = getHeader(req->hdrs, rb->baton);
    if (value)
        setHeader(resp->hdrs, rb->baton, value);
    return YES;
}

mhResponseBldr_t *
mhRespSetUseRequestHeader(mhResponse_t *resp, const char *header)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_use_request_header;
    rb->baton = header;
    return rb;
}

static bool
resp_use_request_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    mhRequest_t *req = resp->req;
    if (req->chunked) {
        resp->chunks = req->chunks;
        resp->chunked = YES;
        setHeader(resp->hdrs, "Transfer-Encoding", "chunked");
    } else {
        resp->body  = req->body;
        resp->bodyLen = req->bodyLen;
        resp->chunked = NO;
        setHeader(resp->hdrs, "Content-Length",
                  apr_itoa(resp->pool, resp->bodyLen));
    }
    return YES;
}

mhResponseBldr_t *mhRespSetUseRequestBody(mhResponse_t *resp)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_use_request_body;
    return rb;
}

static bool resp_set_raw_data(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->raw_data = rb->baton;
    resp->raw_data_length = rb->ibaton;
    return YES;
}

mhResponseBldr_t *
mhRespSetRawData(mhResponse_t *resp, const char *raw_data, size_t length)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_raw_data;
    rb->baton = apr_pstrdup(pool, raw_data);
    rb->ibaton = length;
    return rb;
}

static bool
resp_set_repeat_pattern(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    unsigned int i, n = rb->ibaton;
    const char *pattern = rb->baton;
    apr_size_t len = strlen(pattern);
    apr_pool_t *tmppool;
    struct iovec *vecs;

    /* TODO: the whole reponse body should be converted to buckets so that
       we can generate the body on the fly. */
    apr_pool_create(&tmppool, resp->pool);
    vecs = apr_pcalloc(tmppool, sizeof(struct iovec) * n);

    for (i = 0; i < n; i++) {
        vecs[i].iov_base = (void *)pattern;
        vecs[i].iov_len = len;
    }
    resp->raw_data = apr_pstrcatv(resp->pool, vecs, n, &resp->raw_data_length);

    return YES;
}

mhResponseBldr_t *mhRespSetBodyPattern(mhResponse_t *resp, const char *pattern,
                                       unsigned int n)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_repeat_pattern;
    rb->baton = apr_pstrdup(pool, pattern);
    rb->ibaton = n;
    return rb;
}

static bool
resp_set_ocsp_response_status(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    unsigned int status = rb->ibaton;
    resp->ocsp_response_status = status;
    return YES;
}

mhResponseBldr_t *
mhRespOCSPResponseStatus(mhResponse_t *resp, mhOCSPRespnseStatus_t status)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_ocsp_response_status;
    rb->ibaton = status;
    return rb;

}

void _mhBuildResponse(mhResponse_t *resp)
{
    int i;
    if (resp->built == YES)
        return;
    resp->built = YES;
    for (i = 0 ; i < resp->builders->nelts; i++) {
        mhResponseBldr_t *rb;

        rb = APR_ARRAY_IDX(resp->builders, i, mhResponseBldr_t *);
        rb->respbuilder(rb, resp);
    }
}

/******************************************************************************/
/* Expectations                                                               */
/******************************************************************************/
void mhExpectAllRequestsReceivedOnce(MockHTTP *mh)
{
    mh->expectations |= RequestsReceivedOnce;
}

void mhExpectAllRequestsReceivedInOrder(MockHTTP *mh)
{
    mh->expectations |= RequestsReceivedInOrder;
}

/******************************************************************************/
/* Verify results                                                             */
/******************************************************************************/
static const char *serializeHeaders(apr_pool_t *pool, const mhRequest_t *req,
                                    const char *indent)
{
    const apr_table_entry_t *elts;
    const apr_array_header_t *arr;
    const char *hdrs = "";
    bool first = YES;
    int i;

    arr = apr_table_elts(req->hdrs);
    elts = (const apr_table_entry_t *)arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        hdrs = apr_psprintf(pool, "%s%s%s: %s\n", hdrs, first ? "" : indent,
                            elts[i].key, elts[i].val);
        first = NO;
    }
    return hdrs;
}

static char *serializeArrayOfIovecs(apr_pool_t *pool,
                                    apr_array_header_t *blocks)
{
    int i;
    char *str = "";
    for (i = 0 ; i < blocks->nelts; i++) {
        struct iovec vec = APR_ARRAY_IDX(blocks, i, struct iovec);
        str = apr_pstrcat(pool, str, vec.iov_base, NULL);
    }
    return str;
}

static const char *formatBody(apr_pool_t *outpool, int indent, const char *body)
{
    const char *newbody = "";
    char *nextkv, *line, *tmpbody;
    apr_pool_t *tmppool;

    /* Need a copy cuz we're going to write NUL characters into the string.  */
    apr_pool_create(&tmppool, outpool);
    tmpbody = apr_pstrdup(tmppool, body);

    for ( ; (line = apr_strtok(tmpbody, "\n", &nextkv)) != NULL; tmpbody = NULL)
    {
        newbody = apr_psprintf(outpool, "%s%s\n%*s", newbody, line,
                               indent, *nextkv != '\0' ? "|" : "");
    }
    apr_pool_destroy(tmppool);

    return newbody;
}

static const char *
serializeRawBody(apr_pool_t *pool, int indent, const mhRequest_t *req)
{
    char *body = serializeArrayOfIovecs(pool, req->body);
    return formatBody(pool, indent, body);
}

static const char *serializeRequest(apr_pool_t *pool, const mhRequest_t *req)
{
    const char *str;
    str = apr_psprintf(pool, "         Method: %s\n"
                             "            URL: %s\n"
                             "        Version: HTTP/%d.%d\n"
                             "        Headers: %s"
                             "  Raw body size: %ld\n"
                             "   %s:|%s\n",
                       req->method, req->url,
                       req->version / 10, req->version % 10,
                       serializeHeaders(pool, req, "                 "),
                       req->bodyLen,
                       req->chunked ? "Chunked Body" : "        Body",
                       serializeRawBody(pool, 17, req));
    return str;
}

static const char *
serializeRequestMatcher(apr_pool_t *pool, const mhRequestMatcher_t *rm,
                        const mhRequest_t *req)
{
    const char *str = "";
    int i;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhReqMatcherBldr_t *mp;
        bool matches;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhReqMatcherBldr_t *);
        matches = mp->matcher(mp, req);

        if (strstr(mp->describe_key, "body") != NULL) {
            /* format the expected request body */
            str = apr_psprintf(pool, "%s%25s:|%s%s\n", str,
                               mp->describe_key,
                               formatBody(pool, 27, mp->describe_value),
                               matches ? "" : "   <--- rule failed!");

        } else {
            str = apr_psprintf(pool, "%s%25s: %s%s\n", str,
                               mp->describe_key, mp->describe_value,
                               matches ? "" : "   <--- rule failed!");
        }
    }
    return str;
}

static int verifyAllRequestsReceivedInOrder(const MockHTTP *mh,
                                            const mhServCtx_t *ctx)
{
    int i;

    /* TODO: improve error message */
    if (ctx->reqsReceived->nelts > ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (ctx->reqsReceived->nelts < ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    for (i = 0; i < ctx->reqsReceived->nelts; i++)
    {
        const ReqMatcherRespPair_t *pair;
        const mhRequest_t *req;

        pair = APR_ARRAY_IDX(ctx->reqMatchers, i, ReqMatcherRespPair_t *);
        req  = APR_ARRAY_IDX(ctx->reqsReceived, i, mhRequest_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == NO) {
            apr_pool_t *tmppool;
            apr_pool_create(&tmppool, mh->pool);
            appendErrMessage(mh, "ERROR: Request wasn't expected!\n");
            appendErrMessage(mh, "=================================\n");
            appendErrMessage(mh, "Expected request with:\n");
            appendErrMessage(mh, serializeRequestMatcher(tmppool, pair->rm, req));
            appendErrMessage(mh, "---------------------------------\n");
            appendErrMessage(mh, "Actual request:\n");
            appendErrMessage(mh, serializeRequest(tmppool, req));
            appendErrMessage(mh, "=================================\n");
            apr_pool_destroy(tmppool);
            return NO;
        }
    }
    return YES;
}

int mhVerifyAllRequestsReceivedInOrder(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceivedInOrder(mh, mh->servCtx);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceivedInOrder(mh, mh->proxyCtx);
    return result;
}

static bool
isArrayElement(apr_array_header_t *ary, const ReqMatcherRespPair_t *element)
{
    int i;
    for (i = 0; i < ary->nelts; i++) {
        const ReqMatcherRespPair_t *pair;
        pair = APR_ARRAY_IDX(ary, i, ReqMatcherRespPair_t *);
        if (pair == element)
            return YES;
    }
    return NO;
}

static int verifyAllRequestsReceived(const MockHTTP *mh, const mhServCtx_t *ctx,
                                     bool breakOnNotOnce)
{
    int i;
    apr_array_header_t *used;
    apr_pool_t *pool;
    bool result = YES;

    /* TODO: improve error message */
    if (breakOnNotOnce && ctx->reqsReceived->nelts > ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (ctx->reqsReceived->nelts < ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    apr_pool_create(&pool, mh->pool);
    used = apr_array_make(mh->pool, ctx->reqsReceived->nelts,
                          sizeof(ReqMatcherRespPair_t *));;

    for (i = 0; i < ctx->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(ctx->reqsReceived, i, mhRequest_t *);
        int j;
        bool matched = NO;

        for (j = 0 ; j < ctx->reqMatchers->nelts; j++) {
            const ReqMatcherRespPair_t *pair;

            pair = APR_ARRAY_IDX(ctx->reqMatchers, j, ReqMatcherRespPair_t *);

            if (breakOnNotOnce && isArrayElement(used, pair))
                continue; /* skip this match if request matched before */

            if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
                *((const ReqMatcherRespPair_t **)apr_array_push(used)) = pair;
                matched = YES;
                break;
            }
        }

        if (matched == NO) {
            apr_pool_t *tmppool;
            apr_pool_create(&tmppool, mh->pool);
            appendErrMessage(mh, "ERROR: No rule matched this request!\n");
            appendErrMessage(mh, "====================================\n");
            /* log all rules (yes this can be a long list) */
            for (j = 0 ; j < ctx->reqMatchers->nelts; j++) {
                const ReqMatcherRespPair_t *pair;

                pair = APR_ARRAY_IDX(ctx->reqMatchers, j, ReqMatcherRespPair_t *);

                if (breakOnNotOnce && isArrayElement(used, pair))
                    continue; /* skip this match if request matched before */
                appendErrMessage(mh, "Expected request(s) with:\n");
                appendErrMessage(mh, serializeRequestMatcher(tmppool, pair->rm, req));
                if (j + 1 < ctx->reqMatchers->nelts)
                    appendErrMessage(mh, "        ------------------------\n");
            }
            appendErrMessage(mh, "---------------------------------\n");
            appendErrMessage(mh, "Actual request:\n");
            appendErrMessage(mh, serializeRequest(tmppool, req));
            appendErrMessage(mh, "=================================\n");
            apr_pool_destroy(tmppool);

            result = NO;
            break;
        }
    }

    apr_pool_destroy(pool);

    return result;
}

int mhVerifyAllRequestsReceived(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceived(mh, mh->servCtx, NO);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceived(mh, mh->proxyCtx, NO);
    return result;
}

int mhVerifyAllRequestsReceivedOnce(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceived(mh, mh->servCtx, YES);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceived(mh, mh->proxyCtx, YES);
    return result;
}

const char *mhGetLastErrorString(const MockHTTP *mh)
{
    return mh->errmsg;
}

mhStats_t *mhVerifyStatistics(const MockHTTP *mh)
{
    return mh->verifyStats;
}



int mhVerifyAllExpectationsOk(const MockHTTP *mh)
{
    if (mh->expectations & RequestsReceivedInOrder)
        return mhVerifyAllRequestsReceivedInOrder(mh);
    if (mh->expectations & RequestsReceivedOnce)
        return mhVerifyAllRequestsReceivedOnce(mh);

    /* No expectations set. Consider this an error to avoid false positives */
    return NO;
}


int mhVerifyConnectionSetupOk(const MockHTTP *mh)
{
    int i;
    bool result = NO;
    apr_pool_t *match_pool;
    apr_array_header_t *clients = mh->servCtx->clients;

    apr_pool_create(&match_pool, mh->pool);
    for (i = 0; i < clients->nelts; i++) {
        _mhClientCtx_t *cctx = APR_ARRAY_IDX(clients, i, _mhClientCtx_t *);

        for (i = 0 ; i < mh->connMatchers->nelts; i++) {
            const mhConnMatcherBldr_t *cmb;

            cmb = APR_ARRAY_IDX(mh->connMatchers, i, mhConnMatcherBldr_t *);
            if (cmb->connmatcher(cmb, cctx) == NO) {
                result = NO;
                goto cleanup;
            }
        }
    }
    result = YES;

cleanup:
    apr_pool_destroy(match_pool);

    return result;
}

static const char *buildertype_to_string(builderType_t type)
{
    switch (type) {
        case BuilderTypeReqMatcher:
            return "Request Matcher";
        case BuilderTypeConnMatcher:
            return "Connection Matcher";
        case BuilderTypeResponse:
            return "Response Builder";
        case BuilderTypeServerSetup:
            return "Server Setup";
        default:
            break;
    }
    return "<unknown type>";
}

void _mhErrorUnexpectedBuilder(const MockHTTP *mh, void *actual,
                               builderType_t expected)
{
    builder_t *builder = actual;
    appendErrMessage(mh, "A builder of type %s was provided, where a builder of "
                         " type %s was expected!",
                     buildertype_to_string(builder->type),
                     buildertype_to_string(expected));
}

static void log_time(void)
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void _mhLog(int verbose_flag, apr_socket_t *skt, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (skt) {
            apr_sockaddr_t *sa;
            apr_port_t lp = 0, rp = 0;

            /* Log client (remote) and server (local) port */
            if (apr_socket_addr_get(&sa, APR_LOCAL, skt) == APR_SUCCESS)
                lp = sa->port;
            if (apr_socket_addr_get(&sa, APR_REMOTE, skt) == APR_SUCCESS)
                rp = sa->port;
            fprintf(stderr, "[cp:%u sp:%u] ", rp, lp);
        }

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}
