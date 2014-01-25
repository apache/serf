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

#include "MockHTTP.h"
#include "MockHTTP_private.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <apr_strings.h>
#include <apr_lib.h>

static char *serializeArrayOfIovecs(apr_pool_t *pool,
                                    apr_array_header_t *blocks);
mhResponse_t *initResponse(MockHTTP *mh);

typedef struct ReqMatcherRespPair_t {
    mhRequestMatcher_t *rm;
    mhResponse_t *resp;
} ReqMatcherRespPair_t;

/* private functions */
static const char *toLower(apr_pool_t *pool, const char *str)
{
    char *lstr, *l;
    const char *u;

    lstr = apr_palloc(pool, strlen(str) + 1);
    for (u = str, l = lstr; *u != 0; u++, l++)
        *l = (char)apr_tolower(*u);
    *l = '\0';

    return lstr;
}

/* header should be stored with their original case to use them in responses.
   Search on header name is case-insensitive per RFC2616. */
const char *
getHeader(apr_pool_t *pool, apr_hash_t *hdrs, const char *hdr)
{
    const char *lhdr = toLower(pool, hdr);
    apr_hash_index_t *hi;
    void *val;
    const void *key;
    apr_ssize_t klen;

    for (hi = apr_hash_first(pool, hdrs); hi; hi = apr_hash_next(hi)) {
        const char *tmp;

        apr_hash_this(hi, &key, &klen, &val);

        tmp = toLower(pool, key);
        if (strcmp(tmp, lhdr) == 0)
            return val;
    }

    return NULL;
}

void setHeader(apr_pool_t *pool, apr_hash_t *hdrs,
               const char *hdr, const char *val)
{
    apr_hash_set(hdrs, hdr, APR_HASH_KEY_STRING, val);
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
    mh->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));;
    mh->incompleteReqMatchers = apr_array_make(pool, 5,
                                               sizeof(ReqMatcherRespPair_t *));;
    apr_queue_create(&mh->reqQueue, MaxReqRespQueueSize, pool);
    mh->reqsReceived = apr_array_make(pool, 5, sizeof(mhRequest_t *));
    mh->errmsg = apr_palloc(pool, ERRMSG_MAXSIZE);
    *mh->errmsg = '\0';
    mh->expectations = 0;
    mh->verifyStats = apr_pcalloc(pool, sizeof(mhStats_t));

    __resp = mhNewDefaultResponse(__mh);
    mhConfigResponse(__resp, WithCode(200), WithBody("Default Response"), NULL);

    __resp = mh->defErrorResponse = initResponse(__mh);
    mhConfigResponse(__resp, WithCode(500),
                     WithBody("Mock server error."), NULL);
    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    /* The MockHTTP * is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    apr_pool_destroy(mh->pool);

    /* mh ptr is now invalid */
}

mhError_t mhRunServerLoop(MockHTTP *mh)
{
    apr_status_t status = APR_EGENERAL;

    do {
        void *data;

        if (mh->servCtx) {
            status = _mhRunServerLoop(mh->servCtx);

            while (apr_queue_trypop(mh->reqQueue, &data) == APR_SUCCESS) {
                mhRequest_t *req;

                req = data;
                *((mhRequest_t **)apr_array_push(mh->reqsReceived)) = req;

                _mhLog(MH_VERBOSE, __FILE__,
                       "Request added to incoming queue: %s %s\n", req->method,
                       req->url);
            }
        }
    } while (status == APR_SUCCESS);

    if (status == MH_STATUS_WAITING)
        return MOCKHTTP_WAITING;

    return MOCKHTTP_NO_ERROR;
}

static bool
matchRequest(const MockHTTP *mh, mhRequest_t *req, mhResponse_t **resp,
             apr_array_header_t *matchers)
{
    int i;

    for (i = 0 ; i < matchers->nelts; i++) {
        const ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
            *resp = pair->resp;
            return YES;
        }
    }
    _mhLog(MH_VERBOSE, __FILE__, "Couldn't match request!\n");

    *resp = NULL;
    return NO;
}

bool _mhMatchRequest(const MockHTTP *mh, mhRequest_t *req, mhResponse_t **resp)
{
    return matchRequest(mh, req, resp, mh->reqMatchers);
}

bool _mhMatchIncompleteRequest(const MockHTTP *mh, mhRequest_t *req,
                               mhResponse_t **resp)
{
    return matchRequest(mh, req, resp, mh->incompleteReqMatchers);
}

/* Define expectations*/

void mhPushRequest(MockHTTP *mh, mhRequestMatcher_t *rm)
{
    ReqMatcherRespPair_t *pair;
    int i;

    pair = apr_palloc(mh->pool, sizeof(ReqMatcherRespPair_t));
    pair->rm = rm;
    pair->resp = NULL;

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
                apr_array_push(mh->incompleteReqMatchers)) = pair;
    else
        *((ReqMatcherRespPair_t **)apr_array_push(mh->reqMatchers)) = pair;
}

/******************************************************************************/
/* Requests matchers: define criteria to match different aspects of a HTTP    */
/* request received by the MockHTTP server.                                   */
/******************************************************************************/
static bool
chunks_matcher(const mhMatchingPattern_t *mp, apr_array_header_t *chunks)
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

static bool str_matcher(const mhMatchingPattern_t *mp, const char *actual)
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

static bool url_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                        const mhRequest_t *req)
{
    return str_matcher(mp, req->url);
}

mhMatchingPattern_t *
mhMatchURLEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_matcher;
    mp->describe_key = "URL equal to";
    mp->describe_value = expected;
    return mp;
}

static bool body_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                         const mhRequest_t *req)
{
    /* ignore chunked or not chunked */
    if (req->chunked == YES)
        return chunks_matcher(mp, req->chunks);
    else {
        return chunks_matcher(mp, req->body);
    }
}

mhMatchingPattern_t *
mhMatchBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->describe_key = "Body equal to";
    mp->describe_value = expected;
    return mp;
}

static bool raw_body_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                             const mhRequest_t *req)
{
    return chunks_matcher(mp, req->body);
}

mhMatchingPattern_t *
mhMatchRawBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = raw_body_matcher;
    mp->describe_key = "Raw body equal to";
    mp->describe_value = expected;
    return mp;
}

mhMatchingPattern_t *
mhMatchIncompleteBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->match_incomplete = TRUE;
    mp->describe_key = "Incomplete body equal to";
    mp->describe_value = expected;
    return mp;
}

static bool
body_notchunked_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                        const mhRequest_t *req)
{
    if (req->chunked == YES)
        return NO;
    return chunks_matcher(mp, req->body);
}

mhMatchingPattern_t *
mhMatchBodyNotChunkedEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_notchunked_matcher;
    mp->describe_key = "Body not chunked equal to";
    mp->describe_value = expected;
    return mp;
}

static bool
chunked_body_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                     const mhRequest_t *req)
{
    if (req->chunked == NO)
        return NO;

    return chunks_matcher(mp, req->chunks);
}

mhMatchingPattern_t *
mhMatchChunkedBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = chunked_body_matcher;
    mp->describe_key = "Chunked body equal to";
    mp->describe_value = expected;
    return mp;
}

static bool chunked_body_chunks_matcher(apr_pool_t *pool,
                                        const mhMatchingPattern_t *mp,
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

mhMatchingPattern_t *
mhMatchChunkedBodyChunksEqualTo(const MockHTTP *mh, ...)
{
    apr_pool_t *pool = mh->pool;
    apr_array_header_t *chunks;
    mhMatchingPattern_t *mp;
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

    mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = chunks;
    mp->matcher = chunked_body_chunks_matcher;
    mp->describe_key = "Chunked body with chunks";
    mp->describe_value = serializeArrayOfIovecs(pool, chunks);
    return mp;
}

static bool
header_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
               const mhRequest_t *req)
{
    const char *actual = getHeader(pool, req->hdrs, mp->baton2);
    return str_matcher(mp, actual);
}

mhMatchingPattern_t *
mhMatchHeaderEqualTo(const MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->matcher = header_matcher;
    mp->describe_key = "Header equal to";
    mp->describe_value = apr_psprintf(pool, "%s: %s", hdr, value);
    return mp;
}

static bool method_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                           const mhRequest_t *req)
{
    const char *expected = mp->baton;

    if (apr_strnatcasecmp(expected, req->method) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *
mhMatchMethodEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_pcalloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = method_matcher;
    mp->describe_key = "Method equal to";
    mp->describe_value = expected;
    return mp;
}

static mhRequestMatcher_t *
constructRequestMatcher(const MockHTTP *mh, const char *method, va_list argp)
{
    apr_pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = apr_pcalloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->method = apr_pstrdup(pool, method);
    rm->matchers = apr_array_make(pool, 5, sizeof(mhMatchingPattern_t *));

    while (1) {
        mhMatchingPattern_t *mp;
        mp = va_arg(argp, mhMatchingPattern_t *);
        if (mp == NULL) break;
        *((mhMatchingPattern_t **)apr_array_push(rm->matchers)) = mp;
    }
    return rm;
}

mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, const char *method, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, method);
    rm = constructRequestMatcher(mh, method, argp);
    va_end(argp);

    return rm;
}

bool
_mhRequestMatcherMatch(const mhRequestMatcher_t *rm, const mhRequest_t *req)
{
    int i;
    apr_pool_t *match_pool;

    if (apr_strnatcasecmp(rm->method, req->method) != 0) {
        return NO;
    }

    apr_pool_create(&match_pool, rm->pool);

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhMatchingPattern_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhMatchingPattern_t *);
        if (mp->matcher(match_pool, mp, req) == NO)
            return NO;
    }
    apr_pool_destroy(match_pool);

    return YES;
}

/******************************************************************************/
/* Response                                                                   */
/******************************************************************************/
mhResponse_t *initResponse(MockHTTP *mh)
{
    apr_pool_t *pool = mh->pool;

    mhResponse_t *resp = apr_pcalloc(pool, sizeof(mhResponse_t));
    resp->pool = pool;
    resp->code = 200;
    resp->body = apr_array_make(pool, 5, sizeof(struct iovec));
    resp->hdrs = apr_hash_make(pool);
    resp->builders = apr_array_make(pool, 5, sizeof(mhRespBuilder_t *));
    return resp;
}

mhResponse_t *mhNewResponseForRequest(MockHTTP *mh, mhRequestMatcher_t *rm)
{
    apr_array_header_t *matchers;
    int i;

    mhResponse_t *resp = initResponse(mh);

    matchers = rm->incomplete ? mh->incompleteReqMatchers : mh->reqMatchers;
    for (i = 0 ; i < matchers->nelts; i++) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);
        if (rm == pair->rm) {
            pair->resp = resp;
            break;
        }
    }

    return resp;
}

mhResponse_t *mhNewDefaultResponse(MockHTTP *mh)
{
    mh->defResponse = initResponse(mh);
    return mh->defResponse;
}

static void noop(mhResponse_t *resp) { }

void mhConfigResponse(mhResponse_t *resp, ...)
{
    va_list argp;
    /* This is only needed for values that are only known when the request
       is received, e.g. WithRequestBody. */
    va_start(argp, resp);
    while (1) {
        respbuilder_t builder;
        builder = va_arg(argp, respbuilder_t);
        if (builder == NULL) break;
        *((respbuilder_t *)apr_array_push(resp->builders)) = builder;
    }
    va_end(argp);
}

respbuilder_t mhRespSetCode(mhResponse_t *resp, unsigned int code)
{
    resp->code = code;
    return noop;
}

respbuilder_t mhRespSetBody(mhResponse_t *resp, const char *body)
{
    struct iovec vec;
    vec.iov_base = (void *)body;
    vec.iov_len = strlen(body);
    *((struct iovec *)apr_array_push(resp->body)) = vec;
    resp->bodyLen = vec.iov_len;
    resp->chunked = NO;
    return noop;
}

respbuilder_t mhRespSetChunkedBody(mhResponse_t *resp, ...)
{
    apr_array_header_t *chunks;
    va_list argp;

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
    resp->chunks = chunks;
    resp->chunked = YES;
    return noop;
}

respbuilder_t mhRespAddHeader(mhResponse_t *resp, const char *header,
                              const char *value)
{
    setHeader(resp->pool, resp->hdrs, header, value);
    return noop;
}

respbuilder_t mhRespSetConnCloseHdr(mhResponse_t *resp)
{
    setHeader(resp->pool, resp->hdrs, "Connection", "close");
    resp->closeConn = YES;
    return noop;
}

static void respUseRequestBody(mhResponse_t *resp)
{
    mhRequest_t *req = resp->req;
    if (req->chunked) {
        resp->chunks = req->chunks;
        resp->chunked = YES;
    } else {
        resp->body  = req->body;
        resp->bodyLen = req->bodyLen;
        resp->chunked = NO;
    }
}

respbuilder_t mhRespSetUseRequestBody(mhResponse_t *resp)
{
    return respUseRequestBody;
}

respbuilder_t mhRespSetRawData(mhResponse_t *resp, const char *raw_data)
{
    resp->raw_data = raw_data;
    return noop;
}

void _mhBuildResponse(mhResponse_t *resp)
{
    int i;
    if (resp->built == YES)
        return;
    resp->built = YES;
    for (i = 0 ; i < resp->builders->nelts; i++) {
        respbuilder_t builder;

        builder = APR_ARRAY_IDX(resp->builders, i, respbuilder_t);
        builder(resp);
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
    apr_hash_index_t *hi;
    const char *hdrs = "";
    bool first = YES;
    for (hi = apr_hash_first(pool, req->hdrs); hi; hi = apr_hash_next(hi)) {
        const void *key;
        apr_ssize_t klen;
        void *val;

        apr_hash_this(hi, &key, &klen, &val);
        hdrs = apr_psprintf(pool, "%s%s%s: %s\n", hdrs, first ? "" : indent,
                            (const char *)key, (const char *)val);
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

static const char *serializeRawBody(apr_pool_t *pool, const mhRequest_t *req)
{
    char *body = serializeArrayOfIovecs(pool, req->body);
    const char *newbody = "";
    char *nextkv, *line;
    for ( ; (line = apr_strtok(body, "\n", &nextkv)) != NULL; body = NULL) {
        newbody = apr_psprintf(pool, "%s%s\n%s", newbody, line,
                               *nextkv != '\0' ? "                |" : "");
    }
    return newbody;
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
                       serializeRawBody(pool, req));
    return str;
}

static const char *
serializeRequestMatcher(apr_pool_t *pool, const mhRequestMatcher_t *rm,
                        const mhRequest_t *req)
{
    const char *str = "";
    int i;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhMatchingPattern_t *mp;
        bool matches;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhMatchingPattern_t *);
        matches = mp->matcher(pool, mp, req);
        str = apr_psprintf(pool, "%s%25s: %s%s\n", str,
                           mp->describe_key, mp->describe_value,
                           matches ? "" : "   <--- rule failed!");
    }
    return str;
}

int mhVerifyRequestReceived(const MockHTTP *mh, const mhRequestMatcher_t *rm)
{
    int i;

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);
        if (_mhRequestMatcherMatch(rm, req) == YES)
            return YES;
    }

    return NO;
}

int mhVerifyAllRequestsReceivedInOrder(const MockHTTP *mh)
{
    int i;

    /* TODO: improve error message */
    if (mh->reqsReceived->nelts > mh->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (mh->reqsReceived->nelts < mh->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        const ReqMatcherRespPair_t *pair;
        const mhRequest_t *req;

        pair = APR_ARRAY_IDX(mh->reqMatchers, i, ReqMatcherRespPair_t *);
        req  = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);

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

static int verifyAllRequestsReceived(const MockHTTP *mh, bool breakOnNotOnce)
{
    int i;
    apr_array_header_t *used;
    apr_pool_t *pool;
    bool result = YES;

    /* TODO: improve error message */
    if (breakOnNotOnce && mh->reqsReceived->nelts > mh->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (mh->reqsReceived->nelts < mh->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    apr_pool_create(&pool, mh->pool);
    used = apr_array_make(mh->pool, mh->reqsReceived->nelts,
                          sizeof(ReqMatcherRespPair_t *));;

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);
        int j;
        bool matched = NO;

        for (j = 0 ; j < mh->reqMatchers->nelts; j++) {
            const ReqMatcherRespPair_t *pair;

            pair = APR_ARRAY_IDX(mh->reqMatchers, j, ReqMatcherRespPair_t *);

            if (breakOnNotOnce && isArrayElement(used, pair))
                continue; /* skip this match if request matched before */

            if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
                *((const ReqMatcherRespPair_t **)apr_array_push(used)) = pair;
                matched = YES;
                break;
            }
        }

        if (matched == NO) {
            result = NO;
            break;
        }
    }

    apr_pool_destroy(pool);

    return result;
}

int mhVerifyAllRequestsReceived(const MockHTTP *mh)
{
    return verifyAllRequestsReceived(mh, NO);
}

int mhVerifyAllRequestsReceivedOnce(const MockHTTP *mh)
{
    return verifyAllRequestsReceived(mh, YES);
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

static void log_time()
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void _mhLog(int verbose_flag, const char *filename, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (filename)
            fprintf(stderr, "[%s]: ", filename);

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}
