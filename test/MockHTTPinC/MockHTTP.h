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

#ifndef MockHTTP_H
#define MockHTTP_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* TODO: define defaults, eg HTTP/1.1 in req/resp */
/* TODO: use requests only once, use them in order, use best matching first */
/* TODO: raw requests */
/* TODO: add delay time for accept skt, response */
/* TODO: define all macro's with mh prefix, + create shortcuts with flag to
      not define this (in case of conflicts with other code ) */
/* TODO: connection level checks:
   - ssl related: client certificate, handshake successful, 
   - authn: Negotiate, NTLM, Kerberos */

typedef enum mhServerType_t {
    mhGenericServer,  /* Abstract type */
    mhGenericProxy,   /* Abstract type */
    mhHTTPv1,         /* Abstract type */
    mhHTTPSv1,        /* Abstract type */
    mhHTTPv11,        /* Abstract type */
    mhHTTPSv11,       /* Abstract type */
    mhHTTPv1Server,
    mhHTTPv11Server,
    mhHTTPSv1Server,
    mhHTTPSv11Server,
    mhHTTPv1Proxy,
    mhHTTPv11Proxy,
    mhHTTPSv1Proxy,     /* Sets up SSL tunnel on CONNECT request. */
    mhHTTPSv11Proxy,    /* Sets up SSL tunnel on CONNECT request. */
    mhOCSPResponder,
} mhServerType_t;

typedef enum mhAction_t {
    mhActionInitiateNone,
    mhActionInitiateProxyConn,
    mhActionInitiateSSLTunnel,
    mhActionSSLRenegotiate,
    mhActionCloseConnection,
} mhAction_t;

typedef enum mhClientCertVerification_t {
    mhCCVerifyNone,
    mhCCVerifyPeer,
    mhCCVerifyFailIfNoPeerSet,
} mhClientCertVerification_t;

typedef enum mhSSLProtocol_t {
    mhProtoUnspecified = 0x00,
    mhProtoAllSecure   = 0x1E,
    mhProtoAll    = 0xFF,
    mhProtoSSLv2  = 0x01,
    mhProtoSSLv3  = 0x02,
    mhProtoTLSv1  = 0x04,
    mhProtoTLSv11 = 0x08,
    mhProtoTLSv12 = 0x10,
} mhSSLProtocol_t;

typedef enum mhThreading_t {
    mhThreadMain,
    mhThreadSeparate,
} mhThreading_t;

typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;
typedef struct mhServCtx_t mhServCtx_t;
typedef struct mhReqMatcherBldr_t mhReqMatcherBldr_t;
typedef struct mhConnMatcherBldr_t mhConnMatcherBldr_t;
typedef struct mhServerSetupBldr_t mhServerSetupBldr_t;
typedef struct mhResponseBldr_t mhResponseBldr_t;

#define DEFAULT_SERVER_ID "server"
#define DEFAULT_PROXY_ID  "proxy"

/******************************************************************************
 * MockHTTPinC API                                                            *
 * ---------------                                                            *
 * This is the main API of the MockHTTPinC library. Most if the API consists  *
 * of macro's providing a fluent-like API (as much as that's possible in C).  *
 ******************************************************************************/

/* Note: the variadic macro's used here require C99. */
/* TODO: we can provide xxx1(x), xxx2(x,y)... macro's for C89 compilers */

/**
 * Initialize the MockHTTP library. To be used like this:
 *
 *   MockHTTP *mh = mhInit();
 *   InitMockHTTP(mh)
 *     WithHTTPServer(WithPort(30080))
 *   EndInit
 */   /* TODO: rename */
#define InitMockServers(mh)\
            {\
                MockHTTP *__mh = mh;\
                mhServCtx_t *__servctx = NULL;

/* TODO: Variadic macro's require at least one argument, otherwise compilation
   will fail. We should be able to initiate a server with all default params. */

#define   SetupServer(...)\
                __servctx = mhNewServer(__mh);\
                mhConfigServer(__servctx, __VA_ARGS__, NULL);\
                mhStartServer(__servctx);

/* Setup a HTTP server */

/* WithHTTP defaults to HTTP v1.1 */
#define     WithHTTP\
                mhSetServerType(__servctx, mhHTTPv11)

#define     WithHTTPv1\
                mhSetServerType(__servctx, mhHTTPv1)

#define     WithHTTPv11\
                mhSetServerType(__servctx, mhHTTPv11)

/* Setup a HTTPS server */

/* WithHTTPS defaults to HTTPS v1.1 */
#define     WithHTTPS\
                mhSetServerType(__servctx, mhHTTPSv11)
#define     WithHTTPSv1\
                mhSetServerType(__servctx, mhHTTPSv1)
#define     WithHTTPSv11\
                mhSetServerType(__servctx, mhHTTPSv11)

/* Give the server a name, so it can be found (optional, only needed when
   using multiple servers and requiring post-init configuration) */
#define     WithID(serverID)\
                mhSetServerID(__servctx, serverID)

/*   Specify on which TCP port the server should listen. */
#define     WithPort(port)\
                mhSetServerPort(__servctx, port)

/* Set the maximum number of requests per connection. Default is unlimited */
#define     WithMaxKeepAliveRequests(maxRequests)\
                mhSetServerMaxRequestsPerConn(__servctx, maxRequests)

/* Runs the mock server and proxy in separate threads, use this when testing a
   blocking http client library */
/* EXPERIMENTAL: this feature doesn't work in all cases, can cause crashes! */
#define     InSeparateThread\
                mhSetServerThreading(__servctx, mhThreadSeparate)

/* Runs the mock server and proxy in the main thread, use this when testing a 
   non-blocking http client library.
   This is the default. */
#define     InMainThread\
                mhSetServerThreading(__servctx, mhThreadMain)

#define   SetupProxy(...)\
                __servctx = mhNewProxy(__mh);\
                mhConfigServer(__servctx, __VA_ARGS__, NULL);\
                mhStartServer(__servctx);

#define   SetupOCSPResponder(...)\
                __servctx = mhNewOCSPResponder(__mh);\
                mhConfigServer(__servctx, __VA_ARGS__, NULL);\
                mhStartServer(__servctx);

#define   ConfigServerWithID(serverID, ...)\
                __servctx = mhFindServerByID(__mh, serverID);\
                mhConfigServer(__servctx, __VA_ARGS__, NULL);
/**
 * HTTPS Server configuration options
 */
#define     WithCertificateFilesPrefix(prefix)\
                mhSetServerCertPrefix(__servctx, prefix)
#define     WithCertificateKeyFile(keyFile)\
                mhSetServerCertKeyFile(__servctx, keyFile)
#define     WithCertificateKeyPassPhrase(passphrase)\
                mhSetServerCertKeyPassPhrase(__servctx, passphrase)
#define     WithCertificateFiles(...)\
                mhAddServerCertFiles(__servctx, __VA_ARGS__, NULL)
#define     WithCertificateFileArray(files)\
                mhAddServerCertFileArray(__servctx, files)
#define     WithOptionalClientCertificate\
                mhSetServerRequestClientCert(__servctx, mhCCVerifyPeer)
#define     WithRequiredClientCertificate\
                mhSetServerRequestClientCert(__servctx,\
                                             mhCCVerifyFailIfNoPeerSet)
#define     WithSSLv2     mhAddSSLProtocol(__servctx, mhProtoSSLv2)
#define     WithSSLv3     mhAddSSLProtocol(__servctx, mhProtoSSLv3)
#define     WithTLSv1     mhAddSSLProtocol(__servctx, mhProtoTLSv1)
#define     WithTLSv11    mhAddSSLProtocol(__servctx, mhProtoTLSv11)
#define     WithTLSv12    mhAddSSLProtocol(__servctx, mhProtoTLSv12)

#define     WithOCSPEnabled mhSetServerEnableOCSP(__servctx)

/* Finalize MockHTTP library initialization */
#define EndInit\
            }
/**
 * Stub requests to the proxy or server, return canned responses. Define the
 * expected results before starting the test, so the server can exit early
 * when expectations can't be matched. These macro's should be used like this:
 *
 *   Given(mh)
 *     GETRequest(URLEqualTo("/index.html"))
 *       Respond(WithCode(200), WithBody("body"))
 *   Expect
 *     AllRequestsReceivedOnce
 *   EndGiven
 */
#define Given(mh)\
            {\
                MockHTTP *__mh = mh;\
                mhResponse_t *__resp;\
                mhRequestMatcher_t *__rm;\
                mhServCtx_t *__servctx = mhFindServerByID(__mh, DEFAULT_SERVER_ID);


#define RequestsReceivedByServer\
                __servctx = mhFindServerByID(__mh, DEFAULT_SERVER_ID);

#define RequestsReceivedByProxy\
                __servctx = mhFindServerByID(__mh, DEFAULT_PROXY_ID);

/* Stub a GET request */
#define   GETRequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("GET"),\
                       __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub a POST request */
#define   POSTRequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("POST"),\
                                      __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub a PUT request */
#define   PUTRequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("PUT"),\
                                      __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub a DELETE request */
#define   DELETERequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("DELETE"),\
                                      __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub a HEAD request */
#define   HEADRequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("HEAD"),\
                                            __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub an OPTIONS request */
#define   OPTIONSRequest(...)\
                __rm = mhGivenRequest(__mh, MethodEqualTo("OPTIONS"),\
                                            __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Stub a HTTP request, first parameter is HTTP method (e.g. PROPFIND) */
#define   HTTPRequest(...)\
                __rm = mhGivenRequest(__mh, __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

/* Match the request's METHOD equal to EXP */
#define     MethodEqualTo(exp)\
                mhMatchMethodEqualTo(__mh, (exp))

/* Match the request's URL equal to EXP */
#define     URLEqualTo(exp)\
                mhMatchURLEqualTo(__mh, (exp))

/* Match the request's URL not equal to EXP */
#define     URLNotEqualTo(exp)\
                mhMatchURLNotEqualTo(__mh, (exp))

/* Match the request's body, ignoring transfer encoding (e.g. chunked) */
#define     BodyEqualTo(x)\
                mhMatchBodyEqualTo(__mh, (x))

/* Match the request's body as raw data (e.g. including the chunk header). */
#define     RawBodyEqualTo(x)\
                mhMatchRawBodyEqualTo(__mh, (x))

/* Match a request header's value. */
#define     HeaderEqualTo(h, v)\
                mhMatchHeaderEqualTo(__mh, (h), (v))

/* Match a request with the specified header set */
#define     HeaderSet(h)\
                mhMatchHeaderNotEqualTo(__mh, (h), NULL)

/* Match a request header's value. */
#define     HeaderNotEqualTo(h, v)\
                mhMatchHeaderNotEqualTo(__mh, (h), (v))

/* Match a request with the specified header not set */
#define     HeaderNotSet(h)\
                mhMatchHeaderEqualTo(__mh, (h), NULL)

/* These are lower level tests, probably only interesting when testing the
   protocol layer. */
/* Match a request's non-chunked body. IOW, a chunked body won't match. */
#define     NotChunkedBodyEqualTo(x)\
                mhMatchNotChunkedBodyEqualTo(__mh, (x))

/* Match a request's body which should be chunked encoded, after decoding
    e.g. ChunkedBodyEqualTo("chunk1chunk2") */
#define     ChunkedBodyEqualTo(x)\
                mhMatchChunkedBodyEqualTo(__mh, (x))

/* Match a request's body which should be chunked encoded with a list of
   chunks.
   e.g. BodyChunksEqualTo("chunk1", "chunk2") */
#define     BodyChunksEqualTo(...)\
                mhMatchBodyChunksEqualTo(__mh, __VA_ARGS__, NULL)

#define     IncompleteBodyEqualTo(x)\
                mhMatchIncompleteBodyEqualTo(__mh, (x))

#define     ClientCertificateIsValid\
                mhMatchClientCertValid(__mh)

#define     ClientCertificateCNEqualTo(x)\
                mhMatchClientCertCNEqualTo(__mh, (x))

#define     MatchAny\
                mhMatchAny(__mh)


/* Connection-level aspect matching */
#define   ConnectionSetup(...)\
                mhGivenConnSetup(__mh, __VA_ARGS__, NULL);

/* TODO: http version, conditional, */
/* When a request matches, the server will respond with the response defined
   here. */
#define   DefaultResponse(...)\
                __resp = mhNewDefaultResponse(__mh);\
                mhConfigResponse(__resp, __VA_ARGS__, NULL);

#define   Respond(...)\
                __resp = mhNewResponseForRequest(__mh, __servctx, __rm);\
                mhConfigResponse(__resp, __VA_ARGS__, NULL);

#define   SetupSSLTunnel\
                mhNewActionForRequest(__mh, __servctx, __rm,\
                                      mhActionInitiateSSLTunnel);
#define   SSLRenegotiate\
                mhNewActionForRequest(__mh, __servctx, __rm,\
                                      mhActionSSLRenegotiate);
#define   CloseConnection\
                mhNewActionForRequest(__mh, __servctx, __rm,\
                                      mhActionCloseConnection);
/* Set the HTTP response code. Default: 200 OK */
#define     WithCode(x)\
                mhRespSetCode(__resp, (x))

/* Set a header/value pair */
#define     WithHeader(h,v)\
                mhRespAddHeader(__resp, (h), (v))

/* Set the body of the response. This will automatically add a Content-Length
   header */
#define     WithBody(x)\
                mhRespSetBody(__resp, (x))

/* Set the chunked body of a response. This will automatically add a 
   Transfer-Encoding: chunked header.
   e.g. WithChunkedBody("chunk1", "chunk2") */
#define     WithChunkedBody(...)\
                mhRespSetChunkedBody(__resp, __VA_ARGS__, NULL)

/* Use the body of the request as the body of the response. */
#define     WithRequestBody\
                mhRespSetUseRequestBody(__resp)

/* If HEADER is set on the request, set it with its value on the response */
#define     WithRequestHeader(header)\
                mhRespSetUseRequestHeader(__resp, header)

/* Adds a "Connection: close" header to the response, makes the mock server
   close the connection after sending the response. */
#define     WithConnectionCloseHeader\
                mhRespSetConnCloseHdr(__resp)

/* Use the provided string as raw response data. The response need not be
   valid HTTP.*/
#define     WithRawData(data, len)\
                mhRespSetRawData(__resp, (data), (len))

#define     WithBodyRepeatedPattern(pattern, repeat)\
                mhRespSetBodyPattern(__resp, (pattern), (repeat))

#define EndGiven\
                /* Assign local variables to NULL to avoid 'variable unused' 
                   warnings. */\
                (void)__resp; (void)__rm; (void)__mh;\
            }


#define     OnConditionThat(condition, builder)\
                mhSetOnConditionThat(condition, builder)


/* Set expectations for a series of requests */
#define   Expect

/* Specify that all stubbed requests should arrive at the server exactly once.
   The order how they are received is not important for this expectation. */
#define     AllRequestsReceivedOnce\
                mhExpectAllRequestsReceivedOnce(__mh);

/* Specify that all stubbed requests should arrive at the server exactly once
   and in the order in which they were defined. */
#define     AllRequestsReceivedInOrder\
                mhExpectAllRequestsReceivedInOrder(__mh);

/**
 * After the test was completed, check the results and match the expectations
 * defined upfront, and verify other aspects of the mock server(s).
 * To be used like this:
 *   Verify(mh)
 *     ASSERT(VerifyAllExpectationsOk);
 *     ASSERT(GETRequestReceivedFor(URLEqualTo("/index.html"));
 *   EndVerify
 *
 * Note: the ASSERT macro is not included in this library, but should be
 *       provided by an external unit testing library.
 */
#define Verify(mh)\
            {\
                MockHTTP *__mh = mh;

/* Verify that all stubbed requests where received at least once, order not
   important */
#define   VerifyAllRequestsReceived\
                mhVerifyAllRequestsReceived(__mh)

/* Verify that all stubbed requests where received once by the serer, in the 
   order in which they were defined. */
#define   VerifyAllRequestsReceivedInOrder\
                mhVerifyAllRequestsReceivedInOrder(__mh)

/* Verify that all expectations in the Except section where matched.
   This macro will fail (return NO) when no expectations were defined, as this
   is likely an oversight in creation of the test */
#define   VerifyAllExpectationsOk\
               mhVerifyAllExpectationsOk(__mh)

#define   VerifyConnectionSetupOk\
               mhVerifyConnectionSetupOk(__mh)

#define   VerifyStats\
              mhVerifyStatistics(__mh)

/* Return the last error message, if any.
   e.g. ASSERT_MSG(ErrorMessage, VerifyAllExpectationsOk); */
#define   ErrorMessage\
                mhGetLastErrorString(__mh)

/* End of test result verification section */
#define EndVerify\
            }

typedef enum mhOCSPRespnseStatus_t {
    mhOCSPRespnseStatusSuccessful,
    mhOCSPRespnseStatusMalformedRequest,
    mhOCSPRespnseStatusInternalError,
    mhOCSPRespnseStatusTryLater,
    mhOCSPRespnseStatusSigRequired,
    mhOCSPRespnseStatusUnauthorized,
} mhOCSPRespnseStatus_t;

/* Stub a OCSP request (certificate status request). */
#define   OCSPRequest(...)\
                __rm = mhGivenOCSPRequest(__mh, __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __servctx, __rm);

#define     WithOCSPResponseStatus(status)\
                mhRespOCSPResponseStatus(__resp, (status))


typedef struct mhStats_t {
    /* Number of requests received and read by the server. This does not include
       pipelined requests that were received after the server closed the socket.
     */
    unsigned int requestsReceived;

    /* Number of requests the server responded to. This includes default 
       responses or 500 Internal Server Error responses */
    unsigned int requestsResponded;

    /* Number of requests for which a match was found. */
    unsigned int requestsMatched;

    /* Number of requests for which no match was found. */
    unsigned int requestsNotMatched;
} mhStats_t;

typedef unsigned long mhError_t;

/* Everything ok */
#define MOCKHTTP_NO_ERROR 0
/* Responses pending in queueu but can't be sent now */
#define MOCKHTTP_WAITING  1
/* Maximum timeout exceeded when waiting for a complete request */
#define MOCKHTTP_TIMEOUT  2
/* There was a problem while setting up the test environment */
#define MOCKHTTP_SETUP_FAILED 100
/* There was a problem while running a test */
#define MOCKHTTP_TEST_FAILED 101

typedef struct MockHTTP MockHTTP;

/**
 * Initialize a MockHTTP context.
 * 
 * This context manages the server(s), stubs, expectations of a test. It also
 * manages one pool of memory which only gets freed when this context is
 * cleaned up, so a MockHTTP context should be short-lived.
 */
MockHTTP *mhInit(void);

/**
 * Cleans up a MockHTTP context and all of its associated resources.
 */
void mhCleanup(MockHTTP *mh);

/**
 * Runs the server loop as long as there are requests to receive or responses
 * to send.
 *
 * Returns:
 * MOCKHTTP_NO_ERROR if there's nothing more to be done at this time
 * MOCKHTTP_WAITING if there's nothing more to be done at this time, but there
 *                  are still pending responses with a certain delay
 */
mhError_t mhRunServerLoopCompleteRequests(MockHTTP *mh);

/**
 * Runs the server loop as long as there are requests to receive or responses
 * to send. This function will wait for requests to arrive completely, with
 * a maximum delay of 15 seconds.
 *
 * Returns:
 * MOCKHTTP_NO_ERROR if there's nothing more to be done at this time
 * MOCKHTTP_TIMEOUT  maximum timeout exceeded when waiting for a complete 
 *                   request
 */
mhError_t mhRunServerLoop(MockHTTP *mh);

/**
 * Get the actual port number on which the server is listening.
 */
unsigned int mhServerPortNr(const MockHTTP *mh);

/**
 * Get the actual port number on which the proxy is listening.
 */
unsigned int mhProxyPortNr(const MockHTTP *mh);

/**
 * Get the actual port number on which server with id serverID is listening.
 */
unsigned int mhServerByIDPortNr(const MockHTTP *mh, const char *serverID);


/******************************************************************************
 * Semi-public API                                                            *
 * ---------------                                                            *
 * These are the functions that are used by the public API macro's.           *
 * While they're tecnically part of the API (they have to be because we use   *
 * macro's), we've made no effort to make them easy to use.                   *
 ******************************************************************************/

/**
   The following functions should not be used directly, as they can be quite
   complex to use. Use the macro's instead.
 **/
mhServCtx_t *mhNewServer(MockHTTP *mh);
mhServCtx_t *mhNewProxy(MockHTTP *mh);
mhServCtx_t *mhNewOCSPResponder(MockHTTP *mh);
mhServCtx_t *mhFindServerByID(const MockHTTP *mh, const char *serverID);
void mhConfigServer(mhServCtx_t *ctx, ...);
void mhStartServer(mhServCtx_t *ctx);
void mhStopServer(mhServCtx_t *ctx);
mhServerSetupBldr_t *mhSetServerID(mhServCtx_t *ctx, const char *serverID);
mhServerSetupBldr_t *mhSetServerPort(mhServCtx_t *ctx, unsigned int port);
mhServerSetupBldr_t *mhSetServerType(mhServCtx_t *ctx, mhServerType_t type);
mhServerSetupBldr_t *mhSetServerThreading(mhServCtx_t *ctx,
                                          mhThreading_t threading);
mhServerSetupBldr_t *mhSetServerMaxRequestsPerConn(mhServCtx_t *ctx,
                                                   unsigned int maxRequests);
mhServerSetupBldr_t *mhSetServerCertPrefix(mhServCtx_t *ctx, const char *prefix);
mhServerSetupBldr_t *mhSetServerCertKeyFile(mhServCtx_t *ctx,
                                            const char *keyFile);
mhServerSetupBldr_t *mhSetServerCertKeyPassPhrase(mhServCtx_t *ctx,
                                                  const char *passphrase);
mhServerSetupBldr_t *mhAddServerCertFiles(mhServCtx_t *ctx, ...);
mhServerSetupBldr_t *mhAddServerCertFileArray(mhServCtx_t *ctx,
                                              const char **certFiles);
mhServerSetupBldr_t *mhSetServerRequestClientCert(mhServCtx_t *ctx,
                                                  mhClientCertVerification_t v);
mhServerSetupBldr_t *mhSetServerEnableOCSP(mhServCtx_t *ctx);

mhServerSetupBldr_t *mhAddSSLProtocol(mhServCtx_t *ctx, mhSSLProtocol_t proto);

/* Define request stubs */
mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, ...);
mhRequestMatcher_t *mhGivenOCSPRequest(MockHTTP *mh, ...);

/* Request matching functions */
mhReqMatcherBldr_t *mhMatchURLEqualTo(const MockHTTP *mh,
                                       const char *expected);
mhReqMatcherBldr_t *mhMatchURLNotEqualTo(const MockHTTP *mh,
                                          const char *expected);
mhReqMatcherBldr_t *mhMatchMethodEqualTo(const MockHTTP *mh,
                                          const char *expected);
mhReqMatcherBldr_t *mhMatchBodyEqualTo(const MockHTTP *mh,
                                        const char *expected);
mhReqMatcherBldr_t *mhMatchRawBodyEqualTo(const MockHTTP *mh,
                                           const char *expected);
mhReqMatcherBldr_t *mhMatchIncompleteBodyEqualTo(const MockHTTP *mh,
                                                  const char *expected);
/* Network level matching functions, for testing of http libraries */
mhReqMatcherBldr_t *mhMatchBodyNotChunkedEqualTo(const MockHTTP *mh,
                                                  const char *expected);
mhReqMatcherBldr_t *mhMatchChunkedBodyEqualTo(const MockHTTP *mh,
                                               const char *expected);
mhReqMatcherBldr_t *mhMatchBodyChunksEqualTo(const MockHTTP *mh, ...);
mhReqMatcherBldr_t *mhMatchHeaderEqualTo(const MockHTTP *mh,
                                          const char *hdr, const char *value);
mhReqMatcherBldr_t *mhMatchHeaderNotEqualTo(const MockHTTP *mh,
                                             const char *hdr, const char *value);
/* TODO: make this a generic matcher */
mhReqMatcherBldr_t *mhMatchAny(const MockHTTP *mh);

void mhGivenConnSetup(MockHTTP *mh, ...);
mhConnMatcherBldr_t *mhMatchClientCertCNEqualTo(const MockHTTP *mh,
                                                const char *expected);
mhConnMatcherBldr_t *mhMatchClientCertValid(const MockHTTP *mh);

mhResponse_t *mhNewResponseForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                                      mhRequestMatcher_t *rm);
void mhConfigResponse(mhResponse_t *resp, ...);
mhResponse_t *mhNewDefaultResponse(MockHTTP *mh);
void mhNewActionForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                           mhRequestMatcher_t *rm, mhAction_t action);

mhResponseBldr_t *mhRespSetCode(mhResponse_t *resp, unsigned int status);
mhResponseBldr_t *mhRespAddHeader(mhResponse_t *resp, const char *header,
                                  const char *value);
mhResponseBldr_t *mhRespSetConnCloseHdr(mhResponse_t *resp);
mhResponseBldr_t *mhRespSetUseRequestHeader(mhResponse_t *resp,
                                            const char *header);
mhResponseBldr_t *mhRespSetBody(mhResponse_t *resp, const char *body);
mhResponseBldr_t *mhRespSetChunkedBody(mhResponse_t *resp, ...);
mhResponseBldr_t *mhRespSetUseRequestBody(mhResponse_t *resp);
mhResponseBldr_t *mhRespSetRawData(mhResponse_t *resp, const char *raw_data,
                                   size_t length);
mhResponseBldr_t *mhRespSetBodyPattern(mhResponse_t *resp, const char *pattern,
                                       unsigned int n);
mhResponseBldr_t *
    mhRespOCSPResponseStatus(mhResponse_t *resp, mhOCSPRespnseStatus_t status);

const void *mhSetOnConditionThat(int condition, void *builder);

/* Define request/response pairs */
void mhPushRequest(MockHTTP *mh, mhServCtx_t *ctx, mhRequestMatcher_t *rm);

/* Define expectations */
void mhExpectAllRequestsReceivedOnce(MockHTTP *mh);
void mhExpectAllRequestsReceivedInOrder(MockHTTP *mh);

/* Verify */
int mhVerifyAllRequestsReceived(const MockHTTP *mh);
int mhVerifyAllRequestsReceivedInOrder(const MockHTTP *mh);
int mhVerifyAllRequestsReceivedOnce(const MockHTTP *mh);
int mhVerifyAllExpectationsOk(const MockHTTP *mh);
int mhVerifyConnectionSetupOk(const MockHTTP *mh);
mhStats_t *mhVerifyStatistics(const MockHTTP *mh);
const char *mhGetLastErrorString(const MockHTTP *mh);


mhError_t mhInitHTTPSserver(MockHTTP *mh, ...);

#define MOCKHTTP_VERSION 0.2.0

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
