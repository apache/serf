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
    mhHTTP,           /* Abstract type */
    mhHTTPS,          /* Abstract type */
    mhHTTPServer,
    mhHTTPSServer,
    mhHTTPProxy,
    mhHTTPSProxy,     /* Sets up SSL tunnel on CONNECT request. */
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
#define     WithHTTP\
                mhSetServerType(__servctx, mhHTTP)

/* Setup a HTTPS server */
#define     WithHTTPS\
                mhSetServerType(__servctx, mhHTTPS)

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

/* Finalize MockHTTP library initialization */
#define EndInit\
            }

#define   SetupProxy(...)\
                __servctx = mhNewProxy(__mh);\
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
                mhServCtx_t *__servctx = mhGetServerCtx(__mh);

#define RequestsReceivedByServer\
                __servctx = mhGetServerCtx(__mh);

#define RequestsReceivedByProxy\
                __servctx = mhGetProxyCtx(__mh);

/* Stub a GET request */
#define   GETRequest(...)\
                __rm = mhGivenRequest(__mh, "GET", __VA_ARGS__, NULL);\
                mhPushRequest(__servctx, __rm);

/* Stub a POST request */
#define   POSTRequest(...)\
                __rm = mhGivenRequest(__mh, "POST", __VA_ARGS__, NULL);\
                mhPushRequest(__servctx, __rm);

/* Stub a HEAD request */
#define   HEADRequest(...)\
                __rm = mhGivenRequest(__mh, "HEAD", __VA_ARGS__, NULL);\
                mhPushRequest(__servctx, __rm);

/* Stub a HTTP request, first parameter is HTTP method (e.g. PROPFIND) */
#define   HTTPRequest(method, ...)\
                __rm = mhGivenRequest(__mh, method, __VA_ARGS__, NULL);\
                mhPushRequest(__servctx, __rm);

/* Match the request's URL */
#define     URLEqualTo(x)\
                mhMatchURLEqualTo(__mh, (x))

/* Match the request's body, ignoring transfer encoding (e.g. chunked) */
#define     BodyEqualTo(x)\
                mhMatchBodyEqualTo(__mh, (x))

/* Match the request's body as raw data (e.g. including the chunk header). */
#define     RawBodyEqualTo(x)\
                mhMatchRawBodyEqualTo(__mh, (x))

/* Match a request header's value. */
#define     HeaderEqualTo(h, v)\
                mhMatchHeaderEqualTo(__mh, (h), (v))

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
   e.g. ChunkedBodyChunksEqualTo("chunk1", "chunk2") */
#define     ChunkedBodyChunksEqualTo(...)\
                mhMatchChunkedBodyChunksEqualTo(__mh, __VA_ARGS__, NULL)

#define     IncompleteBodyEqualTo(x)\
                mhMatchIncompleteBodyEqualTo(__mh, (x))

#define     ClientCertificateIsValid\
                mhMatchClientCertValid(__mh)

#define     ClientCertificateCNEqualTo(x)\
                mhMatchClientCertCNEqualTo(__mh, (x))

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
                mhNewActionForRequest(__servctx, __rm,\
                                      mhActionInitiateSSLTunnel);
#define   SSLRenegotiate\
                mhNewActionForRequest(__servctx, __rm,\
                                      mhActionSSLRenegotiate);
#define   CloseConnection\
                mhNewActionForRequest(__servctx, __rm,\
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

/* Adds a "Connection: close" header to the response, makes the mock server
   close the connection after sending the response. */
#define     WithConnectionCloseHeader\
                mhRespSetConnCloseHdr(__resp)

/* Use the provided string as raw response data. The response need not be
   valid HTTP.*/
#define     WithRawData(data)\
                mhRespSetRawData(__resp, (data))

#define EndGiven\
                /* Assign local variables to NULL to avoid 'variable unused' 
                   warnings. */\
                __resp = NULL; __rm = NULL; __mh = NULL;\
            }

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

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;
typedef struct mhRespBuilder_t mhRespBuilder_t;
typedef struct mhServCtx_t mhServCtx_t;
typedef struct mhServerBuilder_t mhServerBuilder_t;
typedef struct mhRequestMatcher_t mhConnectionMatcher_t; /* TODO */

typedef unsigned long mhError_t;

typedef struct mhStats_t {
    /* Number of requests received and read by the server. This does not include
       pipelined requests that were received after the server closed the socket.
     */
    unsigned int requestsReceived;
    /* Number of requests the server responded to. This includes default 
       responses or 500 Internal Server Error responses */
    unsigned int requestsResponded;
    /* Number of requests for which a match was found. */
    unsigned int requestsNotMatched;
    /* Number of requests for which no match was found. */
    unsigned int requestsMatched;
} mhStats_t;

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
mhError_t mhRunServerLoopOneRequest(MockHTTP *mh);

/**
 * Get the actual port number on which the server is listening.
 */
unsigned int mhServerPortNr(const MockHTTP *mh);

/**
 * Get the actual port number on which the proxy is listening.
 */
unsigned int mhProxyPortNr(const MockHTTP *mh);

/**
   The following functions should not be used directly, as they can be quite
   complex to use. Use the macro's instead.
 **/
mhServCtx_t *mhNewServer(MockHTTP *mh);
mhServCtx_t *mhNewProxy(MockHTTP *mh);
mhServCtx_t *mhFindServerByID(MockHTTP *mh, const char *serverID);
void mhConfigServer(mhServCtx_t *ctx, ...);
void mhStartServer(mhServCtx_t *ctx);
mhServCtx_t *mhGetServerCtx(MockHTTP *mh);
mhServCtx_t *mhGetProxyCtx(MockHTTP *mh);
int mhSetServerID(mhServCtx_t *ctx, const char *serverID);
int mhSetServerPort(mhServCtx_t *ctx, unsigned int port);
int mhSetServerType(mhServCtx_t *ctx, mhServerType_t type);
int mhSetServerMaxRequestsPerConn(mhServCtx_t *ctx, unsigned int maxRequests);
int mhSetServerCertPrefix(mhServCtx_t *ctx, const char *prefix);
int mhSetServerCertKeyFile(mhServCtx_t *ctx, const char *keyFile);
int mhAddServerCertFiles(mhServCtx_t *ctx, ...);
int mhAddServerCertFileArray(mhServCtx_t *ctx, const char **certFiles);
int mhSetServerRequestClientCert(mhServCtx_t *ctx, mhClientCertVerification_t v);
int mhAddSSLProtocol(mhServCtx_t *ctx, mhSSLProtocol_t proto);

/* Define request stubs */
mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, const char *method, ...);

/* Request matching functions */
mhMatchingPattern_t *mhMatchURLEqualTo(const MockHTTP *mh,
                                       const char *expected);
mhMatchingPattern_t *mhMatchMethodEqualTo(const MockHTTP *mh,
                                          const char *expected);
mhMatchingPattern_t *mhMatchBodyEqualTo(const MockHTTP *mh,
                                        const char *expected);
mhMatchingPattern_t *mhMatchRawBodyEqualTo(const MockHTTP *mh,
                                           const char *expected);
mhMatchingPattern_t *mhMatchIncompleteBodyEqualTo(const MockHTTP *mh,
                                                  const char *expected);
/* Network level matching functions, for testing of http libraries */
mhMatchingPattern_t *mhMatchBodyNotChunkedEqualTo(const MockHTTP *mh,
                                                  const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyEqualTo(const MockHTTP *mh,
                                               const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyChunksEqualTo(const MockHTTP *mh, ...);
mhMatchingPattern_t *mhMatchHeaderEqualTo(const MockHTTP *mh,
                                          const char *hdr, const char *value);
mhMatchingPattern_t *mhMatchHeaderNotEqualTo(const MockHTTP *mh,
                                             const char *hdr, const char *value);

void mhGivenConnSetup(MockHTTP *mh, ...);
mhMatchingPattern_t *mhMatchClientCertCNEqualTo(const MockHTTP *mh,
                                                const char *expected);
mhMatchingPattern_t *mhMatchClientCertValid(const MockHTTP *mh);

/* Response functions */
typedef void (* respbuilder_t)(mhResponse_t *resp);

mhResponse_t *mhNewResponseForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                                      mhRequestMatcher_t *rm);
void mhConfigResponse(mhResponse_t *resp, ...);
mhResponse_t *mhNewDefaultResponse(MockHTTP *mh);
void mhNewActionForRequest(mhServCtx_t *ctx, mhRequestMatcher_t *rm,
                           mhAction_t action);

respbuilder_t mhRespSetCode(mhResponse_t *resp, unsigned int status);
respbuilder_t mhRespSetBody(mhResponse_t *resp, const char *body);
respbuilder_t mhRespSetChunkedBody(mhResponse_t *resp, ...);
respbuilder_t mhRespAddHeader(mhResponse_t *resp, const char *header,
                                 const char *value);
respbuilder_t mhRespSetConnCloseHdr(mhResponse_t *resp);
respbuilder_t mhRespSetUseRequestBody(mhResponse_t *resp);
respbuilder_t mhRespSetRawData(mhResponse_t *resp, const char *raw_data);

/* Define request/response pairs */
void mhPushRequest(mhServCtx_t *ctx, mhRequestMatcher_t *rm);

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

#define MOCKHTTP_VERSION 0.1

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
