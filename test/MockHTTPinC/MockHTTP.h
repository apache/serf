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
/* TODO: any method, raw requests + responses */
/* TODO: add delay time for accept skt, response */
/* TODO: define all macro's with mh prefix, + create shortcuts with flag to
      not define this (in case of conflicts with other code ) */

/* Note: the variadic macro's used here require C99. */
/* TODO: we can provide xxx1(x), xxx2(x,y)... macro's for C89 compilers */

/**
 * Initialize the MockHTTP library. To be used like this:
 *
 *   MockHTTP *mh;
 *   InitMockHTTP(mh)
 *     WithHTTPServer(WithPort(30080))
 *   EndInit
 */
#define InitMockHTTP(mh)\
            {\
                MockHTTP *__mh = (mh) = mhInit();

/* TODO: Variadic macro's require at least one argument, otherwise compilation
   will fail. We should be able to initiate a server with all default params. */

/* Setup a HTTP server */
#define   WithHTTPserver(...)\
                mhInitHTTPserver(__mh, __VA_ARGS__, NULL);

/* Setup a HTTPS server (not yet implemented) */
#define   WithHTTPSserver(...)

/* Setup a HTTP/HTTPS proxy (not yet implemented) */
#define   WithHTTPproxy(...)

/*   Specify on which TCP port the server should listen. */
#define     WithPort(port)\
                mhConstructServerPortSetter(__mh, port)

/* Finalize MockHTTP library initialization */
#define EndInit\
            }

/**
 * Stub requests to the proxy or server, return canned responses. Define the 
 * expected results before starting the test, so the server can exit early
 * when expectations can't be matched. These macro's should be used like this:
 *
 *   Given(mh)
 *     GetRequest(URLEqualTo("/index.html"))
 *       Respond(WithCode(200), WithBody("body"))
 *   Expect
 *     AllRequestsReceivedOnce
 *   EndGiven
 */
#define Given(mh)\
            {\
                MockHTTP *__mh = mh;\
                mhResponse_t *__resp;\
                mhRequestMatcher_t *__rm;

/* Stub a GET request */
#define   GETRequest(...)\
                __rm = mhGivenRequest(__mh, "GET", __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __rm);

/* Stub a POST request */
#define   POSTRequest(...)\
                __rm = mhGivenRequest(__mh, "POST", __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __rm);

/* Stub a HEAD request */
#define   HEADRequest(...)\
                __rm = mhGivenRequest(__mh, "HEAD", __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __rm);

/* Match the request's URL */
#define     URLEqualTo(x)\
                mhMatchURLEqualTo(__mh, (x))

/* Match the request's body, ignoring transfer encoding (e.g. chunked) */
#define     BodyEqualTo(x)\
                mhMatchBodyEqualTo(__mh, (x))

/* Match a request header's value. */
#define     HeaderEqualTo(h, v)\
                mhMatchHeaderEqualTo(__mh, (h), (v))

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

/* TODO: http version, conditional, */
/* When a request matches, the server will respond with the response defined
   here. */
#define   Respond(...)\
                __resp = mhResponse(__mh, __VA_ARGS__, NULL);\
                mhSetRespForReq(__mh, __rm, __resp);

/* Set the HTTP response code. Default: 200 OK */
#define     WithCode(x)\
                mhRespSetCode(__mh, (x))

/* Set a header/value pair */
#define     WithHeader(h,v)\
                mhRespAddHeader(__mh, (h), (v))

/* Set the body of the response. This will automatically add a Content-Length
   header */
#define     WithBody(x)\
                mhRespSetBody(__mh, (x))

/* Set the chunked body of a response. This will automatically add a 
   Transfer-Encoding: chunked header.
   e.g. WithChunkedBody("chunk1", "chunk2") */
#define     WithChunkedBody(...)\
                mhRespSetChunkedBody(__mh, __VA_ARGS__, NULL)

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
 *     ASSERT(GetRequestReceivedFor(URLEqualTo("/index.html"));
 *   EndVerify
 *
 * Note: the ASSERT macro is not included in this library, but should be
 *       provided by an external unit testing library.
 */
#define Verify(mh)\
            {\
                MockHTTP *__mh = mh;

/* TODO: check that these can be used with multiple arguments */
/* Verify that a matching GET request was received by the server */
#define   GETRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhGivenRequest(__mh, "GET", (x), NULL))

/* Verify that a matching POST request was received by the server */
#define   POSTRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhGivenRequest(__mh, "POST", (x), NULL))

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

/* Return the last error message, if any.
   e.g. ASSERT_MSG(ErrorMessage, VerifyAllExpectationsOk); */
#define   ErrorMessage\
                mhGetLastErrorString(__mh)

/* End of test result verification section */
#define EndVerify\
            }

/* TODO: remove these when the test suite is updated */
#define GetRequest GETRequest
#define PostRequest POSTRequest
#define GetRequestReceivedFor GETRequestReceivedFor
#define PostRequestReceivedFor POSTRequestReceivedFor

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;
typedef struct mhRespBuilder_t mhRespBuilder_t;
typedef struct mhServCtx_t mhServCtx_t;
typedef struct mhServerBuilder_t mhServerBuilder_t;

typedef unsigned long mhError_t;

/* Everything ok */
#define MOCKHTTP_NO_ERROR 0
/* Responses pending in queueu but can't be sent now */
#define MOCKHTTP_WAITING 1
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
mhError_t mhRunServerLoop(MockHTTP *mh);

/* TODO: this is not going to work once we add the proxy, should take a 
   mhServCtx_t* instead! */
/**
 * Get the actual port number on which the server is listening.
 */
int mhServerPortNr(MockHTTP *mh);

/**
   The following functions should not be used directly, as they can be quite
   complex to use. Use the macro's instead.
 **/
mhError_t mhInitHTTPserver(MockHTTP *mh, ...);
mhServerBuilder_t *mhConstructServerPortSetter(MockHTTP *mh, unsigned int port);

/* Define request stubs */
mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, const char *method, ...);

/* Request matching functions */
mhMatchingPattern_t *mhMatchURLEqualTo(MockHTTP *mh, const char *expected);
mhMatchingPattern_t *mhMatchMethodEqualTo(MockHTTP *mh, const char *expected);
mhMatchingPattern_t *mhMatchBodyEqualTo(MockHTTP *mh, const char *expected);
/* Network level matching functions, for testing of http libraries */
mhMatchingPattern_t *mhMatchBodyNotChunkedEqualTo(MockHTTP *mh,
                                                  const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyEqualTo(MockHTTP *mh,
                                               const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyChunksEqualTo(MockHTTP *mh, ...);
mhMatchingPattern_t *mhMatchHeaderEqualTo(MockHTTP *mh,
                                          const char *hdr, const char *value);

/* Response functions */
mhResponse_t *mhResponse(MockHTTP *mh, ...);
mhRespBuilder_t *mhRespSetCode(MockHTTP *mh, unsigned int status);
mhRespBuilder_t *mhRespSetBody(MockHTTP *mh, const char *body);
mhRespBuilder_t *mhRespSetChunkedBody(MockHTTP *mh, ...);
mhRespBuilder_t *mhRespAddHeader(MockHTTP *mh, const char *header,
                                 const char *value);
void mhResponseBuild(mhResponse_t *resp);

/* Define request/response pairs */
void mhPushRequest(MockHTTP *mh, mhRequestMatcher_t *rm);
void mhSetRespForReq(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp);

/* Define expectations */
void mhExpectAllRequestsReceivedOnce(MockHTTP *mh);
void mhExpectAllRequestsReceivedInOrder(MockHTTP *mh);

/* Verify */
int mhVerifyRequestReceived(MockHTTP *mh, mhRequestMatcher_t *rm);
int mhVerifyAllRequestsReceived(MockHTTP *mh);
int mhVerifyAllRequestsReceivedInOrder(MockHTTP *mh);
int mhVerifyAllRequestsReceivedOnce(MockHTTP *mh);
int mhVerifyAllExpectationsOk(MockHTTP *mh);
const char *mhGetLastErrorString(MockHTTP *mh);

#define MOCKHTTP_VERSION 0.1

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
