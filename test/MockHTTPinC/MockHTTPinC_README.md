Originally obtained from "https://github.com/lgov/MockHTTPinC".

MockHTTPinC
===========

MockHTTPinC is a C library that helps testing HTTP client code.

The library provides:
- a HTTP server that can be instructed to handle requests in certain ways: returning a prebaked response, abort the connection etc.
- support for both HTTP/1.0 and HTTP/1.1 including pipelining and chunked encoding
- macro's to make writing expectations and verifying the results straigthforward
- strong HTTPS support: full SSL/TLS handshake, client certificates and session renegotiation
- SSL tunnel support

The library will provide (but does not at this time):
- a simple HTTP proxy
- SSL session resumption
- Basic and Digest authentication
- Deflate/GZip content encoding support

MockHTTPinC does not come with or mandate the use of a specific unit test framework. Instead it should integrate fine with the unit test framework your project is currently using.

Getting started
---------------

Include these 4 source files in your project:
- MockHTTP.c
- MockHTTP.h
- MockHTTP_private.h
- MockHTTP_server.c

MockHTTPinC depends on these libraries:
- Apache's apr and apr-util libraries. (http://apr.apache.org)
- OpenSSL (http://www.openssl.org)

At this time the code conforms to the C99 standard. The code has been written with C89 in mind, but we use variadic macros (a C99 feature) to facilitate test writing.

Write a first test
------------------

In these examples we will use the CuTest framework (https://github.com/asimjalis/cutest) as unit testing library, you'll recognize its functions by the *Cu* prefix.


**Step 1**: Include MockHTTPinC's main header file, create a test function and setup the mock HTTP server on the default port 30080.

    #include "MockHTTP.h"

    static void test_simple_request_response(CuTest *tc)
    {
      MockHTTP *mh;

      mh = mhInit();
      InitMockServers(mh)
        SetupServer(WithHTTP)
      EndInit

**Step 2**: Use the macro's to instruct the mock HTTP server to expect a GET request to url /index.html. Also, tell the server how to respond when that request arrives.

      Given(mh)
        GETRequest(URLEqualTo("/index.html"))
          Respond(
            WithCode(200), WithHeader("Connection", "Close"),
            WithBody("response body"))
      EndGiven

**Step 3**: Run the code that's expected to eventually send a GET request to the server.

      ctx = connectToTCPServer("http://localhost:30080");
      sendRequest(ctx, "GET", "/index.html", headers, "body of the request");
      response = readResponse(ctx);

      // ... test that the response was received correctly

**Step 4**: Use the macro's to verify that all requests were received in the correct order, at least the one request in this simple example.

      Verify(mh)
        CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
      EndVerify
    }
