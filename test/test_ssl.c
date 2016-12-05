/* ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_env.h>
#include <apr_md5.h>

#include "serf.h"
#include "serf_bucket_types.h"

#include "test_serf.h"

#if defined(WIN32) && defined(_DEBUG)
/* Include this file to allow running a Debug build of serf with a Release
   build of OpenSSL. */
#if defined(_MSC_VER) && _MSC_VER >= 1400
#pragma warning(push)
#pragma warning(disable: 4152)
#endif
#include <openssl/applink.c>
#if defined(_MSC_VER) && _MSC_VER >= 1400
#pragma warning(pop)
#endif
#endif

/* Test setting up the openssl library. */
static void test_ssl_init(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_bucket_t *decrypt_bkt;
    serf_bucket_t *encrypt_bkt;
    serf_bucket_t *in_stream;
    serf_bucket_t *out_stream;
    serf_ssl_context_t *ssl_context;
    apr_status_t status;

    serf_bucket_alloc_t *alloc = test__create_bucket_allocator(tc, tb->pool);

    in_stream = SERF_BUCKET_SIMPLE_STRING("", alloc);
    out_stream = SERF_BUCKET_SIMPLE_STRING("", alloc);

    decrypt_bkt = serf_bucket_ssl_decrypt_create(in_stream, NULL,
                                                 alloc);
    ssl_context = serf_bucket_ssl_decrypt_context_get(decrypt_bkt);

    encrypt_bkt = serf_bucket_ssl_encrypt_create(out_stream, ssl_context,
                                                 alloc);

    status = serf_ssl_use_default_certificates(ssl_context);

    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_bucket_destroy(decrypt_bkt);
    serf_bucket_destroy(encrypt_bkt);
}


/* Test that loading a custom CA certificate file works. */
static void test_ssl_load_cert_file(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_ssl_certificate_t *cert = NULL;

    apr_status_t status = serf_ssl_load_cert_file(
        &cert, get_srcdir_file(tb->pool, "test/serftestca.pem"), tb->pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);
}

/* Test that reading the subject from a custom CA certificate file works. */
static void test_ssl_cert_subject(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_hash_t *subject;
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status;


    status = serf_ssl_load_cert_file(&cert,
                                     get_srcdir_file(tb->pool,
                                                     "test/serftestca.pem"),
                                     tb->pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    subject = serf_ssl_cert_subject(cert, tb->pool);
    CuAssertPtrNotNull(tc, subject);

    CuAssertStrEquals(tc, "Serf",
                      apr_hash_get(subject, "CN", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Test Suite",
                      apr_hash_get(subject, "OU", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "In Serf we trust, Inc.",
                      apr_hash_get(subject, "O", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Mechelen",
                      apr_hash_get(subject, "L", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Antwerp",
                      apr_hash_get(subject, "ST", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "BE",
                      apr_hash_get(subject, "C", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "serf@example.com",
                      apr_hash_get(subject, "E", APR_HASH_KEY_STRING));
}

/* Test that reading the issuer from a custom CA certificate file works. */
static void test_ssl_cert_issuer(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_hash_t *issuer;
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status;


    status = serf_ssl_load_cert_file(&cert,
                                     get_srcdir_file(tb->pool,
                                                     "test/serftestca.pem"),
                                     tb->pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    issuer = serf_ssl_cert_issuer(cert, tb->pool);
    CuAssertPtrNotNull(tc, issuer);

    /* TODO: create a new test certificate with different issuer and subject. */
    CuAssertStrEquals(tc, "Serf",
                      apr_hash_get(issuer, "CN", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Test Suite",
                      apr_hash_get(issuer, "OU", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "In Serf we trust, Inc.",
                      apr_hash_get(issuer, "O", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Mechelen",
                      apr_hash_get(issuer, "L", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Antwerp",
                      apr_hash_get(issuer, "ST", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "BE",
                      apr_hash_get(issuer, "C", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "serf@example.com",
                      apr_hash_get(issuer, "E", APR_HASH_KEY_STRING));
}

/* Test that reading the notBefore,notAfter,sha1 fingerprint and subjectAltNames
   from a custom CA certificate file works. */
static void test_ssl_cert_certificate(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    apr_hash_t *kv;
    serf_ssl_certificate_t *cert = NULL;
    apr_array_header_t *san_arr;
    apr_status_t status;


    status = serf_ssl_load_cert_file(&cert,
                                     get_srcdir_file(tb->pool,
                                                     "test/serftestca.pem"),
                                     tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    kv = serf_ssl_cert_certificate(cert, tb->pool);
    CuAssertPtrNotNull(tc, kv);

    CuAssertStrEquals(tc, "8A:4C:19:D5:F2:52:4E:35:49:5E:7A:14:80:B2:02:BD:B4:4D:22:18",
                      apr_hash_get(kv, "sha1", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Mar 21 13:18:17 2008 GMT",
                      apr_hash_get(kv, "notBefore", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, "Mar 21 13:18:17 2011 GMT",
                      apr_hash_get(kv, "notAfter", APR_HASH_KEY_STRING));

    /* TODO: create a new test certificate with a/some sAN's. */
    san_arr = apr_hash_get(kv, "subjectAltName", APR_HASH_KEY_STRING);
    CuAssertTrue(tc, san_arr == NULL);
}

static const char *extract_cert_from_pem(const char *pemdata,
                                         apr_pool_t *pool)
{
    enum { INIT, CERT_BEGIN, CERT_FOUND } state;
    serf_bucket_t *pembkt;
    const char *begincert = "-----BEGIN CERTIFICATE-----";
    const char *endcert = "-----END CERTIFICATE-----";
    char *certdata = "";
    apr_size_t certlen = 0;
    apr_status_t status = APR_SUCCESS;

    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(pool,
                                                              NULL, NULL);

    /* Extract the certificate from the .pem file, also remove newlines. */
    pembkt = SERF_BUCKET_SIMPLE_STRING(pemdata, alloc);
    state = INIT;
    while (state != CERT_FOUND && status != APR_EOF) {
        const char *data;
        apr_size_t len;
        int found;

        status = serf_bucket_readline(pembkt, SERF_NEWLINE_ANY, &found,
                                      &data, &len);
        if (SERF_BUCKET_READ_ERROR(status))
            return NULL;

        if (state == INIT) {
            if (strncmp(begincert, data, strlen(begincert)) == 0)
                state = CERT_BEGIN;
        } else if (state == CERT_BEGIN) {
            if (strncmp(endcert, data, strlen(endcert)) == 0)
                state = CERT_FOUND;
            else {
                certdata = apr_pstrcat(pool, certdata, data, NULL);
                certlen += len;
                switch (found) {
                    case SERF_NEWLINE_CR:
                    case SERF_NEWLINE_LF:
                        certdata[certlen-1] = '\0';
                        certlen --;
                        break;
                    case SERF_NEWLINE_CRLF:
                        certdata[certlen-2] = '\0';
                        certlen-=2;
                        break;
                }
            }
        }
    }

    serf_bucket_destroy(pembkt);

    if (state == CERT_FOUND)
        return certdata;
    else
        return NULL;
}

static const char* load_cert_file_der(CuTest *tc,
                                      const char *path,
                                      apr_pool_t *pool)
{
    apr_file_t *fp;
    apr_finfo_t file_info;
    char *pembuf;
    apr_size_t pemlen;
    apr_status_t status;

    status = apr_file_open(&fp, path,
                           APR_FOPEN_READ | APR_FOPEN_BINARY,
                           APR_FPROT_OS_DEFAULT, pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    status = apr_file_info_get(&file_info, APR_FINFO_SIZE, fp);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    pembuf = apr_palloc(pool, file_info.size + 1);

    status = apr_file_read_full(fp, pembuf, file_info.size, &pemlen);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    pembuf[file_info.size] = '\0';

    return extract_cert_from_pem(pembuf, pool);
}

static void test_ssl_cert_export(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_ssl_certificate_t *cert = NULL;
    const char *extractedbuf;
    const char *base64derbuf;
    apr_status_t status;


    status = serf_ssl_load_cert_file(&cert,
                                     get_srcdir_file(tb->pool,
                                                     "test/serftestca.pem"),
                                     tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    /* A .pem file contains a Base64 encoded DER certificate, which is exactly
       what serf_ssl_cert_export is supposed to be returning. */
    extractedbuf = load_cert_file_der(tc,
                                      get_srcdir_file(tb->pool,
                                                      "test/serftestca.pem"),
                                      tb->pool);
    base64derbuf = serf_ssl_cert_export(cert, tb->pool);

    CuAssertStrEquals(tc, extractedbuf, base64derbuf);
}

static void test_ssl_cert_import(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    serf_ssl_certificate_t *cert = NULL;
    serf_ssl_certificate_t *imported_cert = NULL;
    const char *extractedbuf;
    const char *base64derbuf;
    apr_status_t status;

    status = serf_ssl_load_cert_file(&cert,
                                     get_srcdir_file(tb->pool,
                                                     "test/serftestca.pem"),
                                     tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    /* A .pem file contains a Base64 encoded DER certificate, which is exactly
       what serf_ssl_cert_import expects as input. */
    extractedbuf = load_cert_file_der(tc,
                                      get_srcdir_file(tb->pool,
                                                      "test/serftestca.pem"),
                                      tb->pool);

    imported_cert = serf_ssl_cert_import(extractedbuf, tb->pool);
    CuAssertPtrNotNull(tc, imported_cert);

    base64derbuf = serf_ssl_cert_export(imported_cert, tb->pool);
    CuAssertStrEquals(tc, extractedbuf, base64derbuf);
}

/*****************************************************************************
 * SSL handshake tests
 *****************************************************************************/
static const char *server_certs[] = {
    "serfservercert.pem",
    "serfcacert.pem",
    NULL };

static const char *all_server_certs[] = {
    "serfservercert.pem",
    "serfcacert.pem",
    "serfrootcacert.pem",
    NULL };

static const char *server_key = "private/serfserverkey.pem";

static apr_status_t validate_servercert(const serf_ssl_certificate_t *cert,
                                        apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("localhost",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Test Suite Server",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("serfserver@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();

    return APR_SUCCESS;
}

static apr_status_t validate_cacert(const serf_ssl_certificate_t *cert,
                                    apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("Serf CA",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Test Suite CA",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("serfca@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();

    return APR_SUCCESS;
}

static apr_status_t validate_rootcacert(const serf_ssl_certificate_t *cert,
                                        apr_pool_t *pool)
{
    apr_hash_t *subject;
    subject = serf_ssl_cert_subject(cert, pool);
    if (strcmp("Serf Root CA",
               apr_hash_get(subject, "CN", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Test Suite Root CA",
               apr_hash_get(subject, "OU", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("In Serf we trust, Inc.",
               apr_hash_get(subject, "O", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Mechelen",
               apr_hash_get(subject, "L", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Antwerp",
               apr_hash_get(subject, "ST", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("BE",
               apr_hash_get(subject, "C", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("serfrootca@example.com",
               apr_hash_get(subject, "E", APR_HASH_KEY_STRING)) != 0)
        return REPORT_TEST_SUITE_ERROR();

    return APR_SUCCESS;
}

static apr_status_t
ssl_server_cert_cb_expect_failures(void *baton, int failures,
                                   const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    int expected_failures = *(int *)tb->user_baton;

    tb->result_flags |= TEST_RESULT_SERVERCERTCB_CALLED;

    /* We expect an error from the certificate validation function. */
    if (failures & expected_failures)
        return APR_SUCCESS;
    else
        return REPORT_TEST_SUITE_ERROR();
}

static apr_status_t
ssl_server_cert_cb_expect_allok(void *baton, int failures,
                                const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    tb->result_flags |= TEST_RESULT_SERVERCERTCB_CALLED;

    /* No error expected, certificate is valid. */
    if (failures)
        return REPORT_TEST_SUITE_ERROR();
    else
        return APR_SUCCESS;
}

static apr_status_t
ssl_server_cert_cb_reject(void *baton, int failures,
                          const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    tb->result_flags |= TEST_RESULT_SERVERCERTCB_CALLED;

    return REPORT_TEST_SUITE_ERROR();
}

/* Validate that we can connect successfully to an https server. This
   certificate is not trusted, so a cert validation failure is expected. */
static void test_ssl_handshake(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;
    static const char *server_cert[] = { "serfservercert.pem",
        NULL };


    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_cert,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb, NULL,
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* This unknown failures is X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
       meaning the chain has only the server cert. A good candidate for its
       own failure code. */
    expected_failures = SERF_SSL_CERT_UNKNOWNCA;
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/* Validate that connecting to a SSLv2 only server fails. */
static void test_ssl_handshake_nosslv2(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;
    static const char *server_cert[] = { "serfservercert.pem",
        NULL };


    /* Set up a test context and a https server */
    tb->mh = mhInit();

    InitMockServers(tb->mh)
      SetupServer(WithHTTPS, WithPort(30080),
                  WithCertificateFilesPrefix(get_srcdir_file(tb->pool,
                                                             "test/certs")),
                  WithCertificateKeyFile(server_key),
                  WithCertificateKeyPassPhrase("serftest"),
                  WithCertificateFileArray(server_cert),
                  WithSSLv2)  /* SSLv2 only */
    EndInit

    tb->serv_port = mhServerPortNr(tb->mh);
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost", tb->serv_port);
    tb->serv_url = apr_psprintf(tb->pool, "https://%s", tb->serv_host);

    status = setup_test_client_https_context(tb, NULL,
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* This unknown failures is X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
       meaning the chain has only the server cert. A good candidate for its
       own failure code. */
    expected_failures = SERF_SSL_CERT_UNKNOWNCA;
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = run_client_and_mock_servers_loops(tb, num_requests,
                                               handler_ctx, tb->pool);
    CuAssert(tc, "Serf does not disable SSLv2, but it should!",
             status != APR_SUCCESS);
}

/* Set up the ssl context with the CA and root CA certificates needed for
   successful valiation of the server certificate. */
static apr_status_t
https_set_root_ca_conn_setup(apr_socket_t *skt,
                             serf_bucket_t **input_bkt,
                             serf_bucket_t **output_bkt,
                             void *setup_baton,
                             apr_pool_t *pool)
{
    serf_ssl_certificate_t *rootcacert;
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = default_https_conn_setup(skt, input_bkt, output_bkt,
                                      setup_baton, pool);
    if (status)
        return status;

    status = serf_ssl_load_cert_file(&rootcacert,
                                     get_srcdir_file(pool,
                                               "test/certs/serfrootcacert.pem"),
                                     pool);
    if (status)
        return status;
    status = serf_ssl_trust_cert(tb->ssl_context, rootcacert);
    if (status)
        return status;

    return status;
}

/* Validate that server certificate validation is ok when we
   explicitly trust our self-signed root ca. */
static void test_ssl_trust_rootca(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             ssl_server_cert_cb_expect_allok,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}

/* Validate that when the application rejects the cert, the context loop
   bails out with an error. */
static void test_ssl_application_rejects_cert(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;


    /* Set up a test context and a https server */
    /* The certificate is valid, but we tell serf to reject it. */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             ssl_server_cert_cb_reject,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
    /* We expect an error from the certificate validation function. */
    CuAssert(tc, "Application told serf the certificate should be rejected,"
                 " expected error!", status != APR_SUCCESS);
}

/* Test for ssl certificate chain callback. */
static apr_status_t
cert_chain_cb(void *baton,
              int failures,
              int error_depth,
              const serf_ssl_certificate_t * const * certs,
              apr_size_t certs_len)
{
    test_baton_t *tb = baton;
    apr_status_t status;

    tb->result_flags |= TEST_RESULT_SERVERCERTCHAINCB_CALLED;

    if (failures)
        return REPORT_TEST_SUITE_ERROR();

    if (certs_len != 3)
        return REPORT_TEST_SUITE_ERROR();

    status = validate_rootcacert(certs[2], tb->pool);
    if (status)
        return status;

    status = validate_cacert(certs[1], tb->pool);
    if (status)
        return status;

    status = validate_servercert(certs[0], tb->pool);
    if (status)
        return status;

    return APR_SUCCESS;
}

static apr_status_t
chain_rootca_callback_conn_setup(apr_socket_t *skt,
                                 serf_bucket_t **input_bkt,
                                 serf_bucket_t **output_bkt,
                                 void *setup_baton,
                                 apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = https_set_root_ca_conn_setup(skt, input_bkt, output_bkt,
                                          setup_baton, pool);
    if (status)
        return status;

    serf_ssl_server_cert_chain_callback_set(tb->ssl_context,
                                            ssl_server_cert_cb_expect_allok,
                                            cert_chain_cb,
                                            tb);

    return APR_SUCCESS;
}

/* Make the server return a partial certificate chain (server cert, CA cert),
   the root CA cert is trusted explicitly in the client. Test the chain
   callback. */
static void test_ssl_certificate_chain_with_anchor(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             chain_rootca_callback_conn_setup,
                                             ssl_server_cert_cb_expect_allok,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCHAINCB_CALLED);
}

static apr_status_t
cert_chain_all_certs_cb(void *baton,
                        int failures,
                        int error_depth,
                        const serf_ssl_certificate_t * const * certs,
                        apr_size_t certs_len)
{
    /* Root CA cert is selfsigned, ignore this 'failure'. */
    failures &= ~SERF_SSL_CERT_SELF_SIGNED;

    return cert_chain_cb(baton, failures, error_depth, certs, certs_len);
}

static apr_status_t
chain_callback_conn_setup(apr_socket_t *skt,
                          serf_bucket_t **input_bkt,
                          serf_bucket_t **output_bkt,
                          void *setup_baton,
                          apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = default_https_conn_setup(skt, input_bkt, output_bkt,
                                      setup_baton, pool);
    if (status)
        return status;

    serf_ssl_server_cert_chain_callback_set(tb->ssl_context,
                                            ssl_server_cert_cb_expect_allok,
                                            cert_chain_all_certs_cb,
                                            tb);

    return APR_SUCCESS;
}

/* Make the server return the complete certificate chain (server cert, CA cert
   and root CA cert). Test the chain callback. */
static void test_ssl_certificate_chain_all_from_server(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 all_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             chain_callback_conn_setup,
                                             ssl_server_cert_cb_expect_allok,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCHAINCB_CALLED);
}

/* Validate that the ssl handshake succeeds if no application callbacks
   are set, and the ssl server certificate chains is ok. */
static void test_ssl_no_servercert_callback_allok(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/* Validate that the ssl handshake fails if no application callbacks
 are set, and the ssl server certificate chains is NOT ok. */
static void test_ssl_no_servercert_callback_fail(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup,
                                                      no certs */
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    /* We expect an error from the certificate validation function. */
    CuAssertIntEquals(tc, SERF_ERROR_SSL_CERT_FAILED, status);
}

/* Similar to test_connection_large_response, validate reading a large
   chunked response over SSL. */
static void test_ssl_large_response(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;
    const char *response;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* create large chunked response message */
    response = create_large_response_message(tb->pool);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
        Respond(WithRawData(response, strlen(response)))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* TODO: check the actual response data (duh). */
    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

/* Similar to test_connection_large_request, validate sending a large
   chunked request over SSL. */
static void test_ssl_large_request(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    const char *request, *body;
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* create large chunked request message */
    body = create_large_request_message_body(tb->pool);
    request = create_large_request_message(tb->pool, body);
    Given(tb->mh)
      GETRequest(URLEqualTo("/"), RawBodyEqualTo(body))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    handler_ctx[0].request = request;

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

static apr_status_t client_cert_cb(void *data, const char **cert_path)
{
    test_baton_t *tb = data;

    tb->result_flags |= TEST_RESULT_CLIENT_CERTCB_CALLED;

    *cert_path = get_srcdir_file(tb->pool, "test/certs/serfclientcert.p12");

    return APR_SUCCESS;
}

static apr_status_t client_cert_pw_cb(void *data,
                                      const char *cert_path,
                                      const char **password)
{
    test_baton_t *tb = data;

    tb->result_flags |= TEST_RESULT_CLIENT_CERTPWCB_CALLED;

    if (strcmp(cert_path,
               get_srcdir_file(tb->pool, "test/certs/serfclientcert.p12")) == 0)
    {
        *password = "serftest";
        return APR_SUCCESS;
    }

    return REPORT_TEST_SUITE_ERROR();
}

static apr_status_t
client_cert_conn_setup(apr_socket_t *skt,
                       serf_bucket_t **input_bkt,
                       serf_bucket_t **output_bkt,
                       void *setup_baton,
                       apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = https_set_root_ca_conn_setup(skt, input_bkt, output_bkt,
                                          setup_baton, pool);
    if (status)
        return status;

    serf_ssl_client_cert_provider_set(tb->ssl_context,
                                      client_cert_cb,
                                      tb,
                                      pool);

    serf_ssl_client_cert_password_set(tb->ssl_context,
                                      client_cert_pw_cb,
                                      tb,
                                      pool);

    return APR_SUCCESS;
}

static void test_ssl_client_certificate(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;


    /* Set up a test context and a https server */
    /* The SSL server uses the complete certificate chain to validate the client
       certificate. */
    setup_test_mock_https_server(tb, server_key,
                                 all_server_certs,
                                 test_clientcert_optional);
    status = setup_test_client_https_context(tb,
                                             client_cert_conn_setup,
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      ConnectionSetup(ClientCertificateIsValid,
                      ClientCertificateCNEqualTo("Serf Client"))

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_CLIENT_CERTCB_CALLED);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_CLIENT_CERTPWCB_CALLED);
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyConnectionSetupOk);
    EndVerify
}

/* Validate that the expired certificate is reported as failure in the
   callback. */
static void test_ssl_expired_server_cert(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;

    static const char *expired_server_certs[] = {
        "serfserver_expired_cert.pem",
        "serfcacert.pem",
        "serfrootcacert.pem",
        NULL };

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 expired_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup */
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_SELF_SIGNED |
                        SERF_SSL_CERT_EXPIRED;
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);

}

/* Validate that the expired certificate is reported as failure in the
 callback. */
static void test_ssl_future_server_cert(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;

    static const char *future_server_certs[] = {
        "serfserver_future_cert.pem",
        "serfcacert.pem",
        "serfrootcacert.pem",
        NULL };

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 future_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup */
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_SELF_SIGNED |
                        SERF_SSL_CERT_NOTYETVALID;
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}


/* Set up the ssl context with the CA and root CA certificates needed for
 successful valiation of the server certificate. */
static apr_status_t
https_load_crl_conn_setup(apr_socket_t *skt,
                          serf_bucket_t **input_bkt,
                          serf_bucket_t **output_bkt,
                          void *setup_baton,
                          apr_pool_t *pool)
{
    test_baton_t *tb = setup_baton;
    apr_status_t status;

    status = https_set_root_ca_conn_setup(skt, input_bkt, output_bkt,
                                          setup_baton, pool);
    if (status)
        return status;

    /* Load the certificate revocation list */
    status = serf_ssl_add_crl_from_file(tb->ssl_context,
                                        get_srcdir_file(pool,
                                                "test/certs/serfservercrl.pem"),
                                        tb->pool);

    return status;
}

/* Logs failures for each depth in tb->user_baton, for later validation. */
/* TODO: use this in place of ssl_server_cert_cb_expect_failures */
static apr_status_t
ssl_server_cert_cb_log_failures(void *baton, int failures,
                                const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    apr_array_header_t *failure_list = (apr_array_header_t *)tb->user_baton;
    int depth = serf_ssl_cert_depth(cert);
    int *failures_for_depth;

    if (!tb->user_baton) {
        /* make the array big enough to not have to worry about resizing */
        tb->user_baton = apr_array_make(tb->pool, 10, sizeof(int));
    }
    failure_list = tb->user_baton;

    if (depth + 1 > failure_list->nalloc) {
        return REPORT_TEST_SUITE_ERROR();
    }

    failures_for_depth = &APR_ARRAY_IDX(failure_list, depth, int);
    *failures_for_depth |= failures;

    tb->result_flags |= TEST_RESULT_SERVERCERTCB_CALLED;

    return APR_SUCCESS;
}

/* Validate that a CRL file can be loaded and revocation actually works. */
static void test_ssl_revoked_server_cert(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int depth;
    apr_status_t status;

    static const char *future_server_certs[] = {
        "serfservercert.pem",
        "serfcacert.pem",
        "serfrootcacert.pem",
        NULL };

    static int expected_failures[] = {
        SERF_SSL_CERT_REVOKED,
        SERF_SSL_CERT_UNABLE_TO_GET_CRL,
        SERF_SSL_CERT_UNABLE_TO_GET_CRL
    };

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 future_server_certs,
                                 test_clientcert_none);

    /* OpenSSL first checks the revocation status before verifying the rest of
       certificate. OpenSSL may call the application multiple times per depth,
       e.g. once to tell that the cert is revoked, and a second time to tell
       that the certificate itself is valid.
       We'll have to combine the results of these multiple calls to the callback
       to get a complete view of the certificate. That's why we use
       ssl_server_cert_cb_log_failures here, and then later check expected
       failures for each depth. */
    status = setup_test_client_https_context(tb,
                                             https_load_crl_conn_setup,
                                             ssl_server_cert_cb_log_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
    for (depth = 0; depth < 3; depth++) {
        apr_array_header_t *ary = tb->user_baton;

        CuAssertIntEquals(tc, expected_failures[depth],
                          APR_ARRAY_IDX(ary, depth, int));

    }
}

/* Test if serf is sets up an SSL tunnel to the proxy and doesn't contact the
 https server directly. */
static void test_setup_ssltunnel(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    int i;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);

    /* Set up a test context with a server and a proxy. Serf should send a
       CONNECT request to the server. */
    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 all_server_certs,
                                 test_clientcert_none);
    CuAssertIntEquals(tc, APR_SUCCESS, setup_test_mock_proxy(tb));
    CuAssertIntEquals(tc, APR_SUCCESS,
            setup_serf_https_context_with_proxy(tb, chain_callback_conn_setup,
                                                ssl_server_cert_cb_expect_allok,
                                                tb->pool));

    Given(tb->mh)
      RequestsReceivedByServer
        GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                   HeaderEqualTo("Host", tb->serv_host))
          Respond(WithCode(200), WithChunkedBody(""))

      RequestsReceivedByProxy
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host))
          Respond(WithCode(200), WithChunkedBody(""))
          SetupSSLTunnel
    EndGiven
    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);

    /* Check that the response were received in the order we sent the requests */
    for (i = 0; i < tb->handled_requests->nelts; i++) {
        int req_nr = APR_ARRAY_IDX(tb->handled_requests, i, int);
        CuAssertIntEquals(tc, i + 1, req_nr);
    }
}

/* Test error if no creds callback */
static void test_ssltunnel_no_creds_cb(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context with a server and a proxy. Serf should send a
       CONNECT request to the server. */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    CuAssertIntEquals(tc, APR_SUCCESS, setup_test_mock_proxy(tb));
    CuAssertIntEquals(tc, APR_SUCCESS,
            setup_serf_https_context_with_proxy(tb, https_set_root_ca_conn_setup,
                                                NULL, /* No server cert cb */
                                                tb->pool));

    Given(tb->mh)
      RequestsReceivedByProxy
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host))
          Respond(WithCode(407), WithChunkedBody(""),
                  WithHeader("Proxy-Authentication",
                             "Basic realm=\"Test Suite Proxy\""))
          SetupSSLTunnel
    EndGiven
    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* No credentials callback configured. */
    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, SERF_ERROR_SSLTUNNEL_SETUP_FAILED, status);
}

static apr_status_t
ssltunnel_basic_authn_callback(char **username,
                               char **password,
                               serf_request_t *request, void *baton,
                               int code, const char *authn_type,
                               const char *realm,
                               apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;

    test__log(TEST_VERBOSE, __FILE__, "ssltunnel_basic_authn_callback\n");

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (strcmp("Basic", authn_type) != 0)
        return REPORT_TEST_SUITE_ERROR();

    if (code == 401) {
        if (strcmp(apr_psprintf(pool, "<%s> Test Suite", tb->serv_url),
                   realm) != 0)
            return REPORT_TEST_SUITE_ERROR();

        *username = "serf";
        *password = "serftest";
    }
    else if (code == 407) {
        if (strcmp(apr_psprintf(pool, "<http://localhost:%u> Test Suite Proxy",
                                tb->proxy_port), realm) != 0)
            return REPORT_TEST_SUITE_ERROR();

        *username = "serfproxy";
        *password = "serftest";
    } else
        return REPORT_TEST_SUITE_ERROR();

    test__log(TEST_VERBOSE, __FILE__, "ssltunnel_basic_authn_callback finished successfully.\n");

    return APR_SUCCESS;
}

/* Test if serf can successfully authenticate to a proxy used for an ssl
   tunnel. Retry the authentication a few times to test requeueing of the
   CONNECT request. */
static void ssltunnel_basic_auth(CuTest *tc, int serv_close_conn,
                                 int proxy407_close_conn,
                                 int proxy200_close_conn)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    int num_requests_sent, num_requests_recvd;
    apr_status_t status;

    /* Set up a test context with a server and a proxy. Serf should send a
       CONNECT request to the server. */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    CuAssertIntEquals(tc, APR_SUCCESS, setup_test_mock_proxy(tb));
    CuAssertIntEquals(tc, APR_SUCCESS,
            setup_serf_https_context_with_proxy(tb, https_set_root_ca_conn_setup,
                                                NULL, /* No server cert cb */
                                                tb->pool));

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC);
    serf_config_credentials_callback(tb->context, ssltunnel_basic_authn_callback);

    Given(tb->mh)
      RequestsReceivedByServer
        GETRequest(URLEqualTo("/"), HeaderNotSet("Authorization"))
          Respond(WithCode(401),WithChunkedBody("1"),
                  WithHeader("www-Authenticate", "bAsIc realm=\"Test Suite\""),
                  OnConditionThat(serv_close_conn, WithConnectionCloseHeader))
        GETRequest(URLEqualTo("/"),
                   HeaderEqualTo("Authorization", "Basic c2VyZjpzZXJmdGVzdA=="))
          Respond(WithCode(200),WithChunkedBody(""))
      RequestsReceivedByProxy
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderNotSet("Proxy-Authorization"))
          Respond(WithCode(407), WithChunkedBody(""),
                  WithHeader("Proxy-Authenticate",
                             "Basic realm=\"Test Suite Proxy\""),
                  OnConditionThat(proxy407_close_conn, WithConnectionCloseHeader))
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderEqualTo("Proxy-Authorization",
                                  "Basic c2VyZnByb3h5OnNlcmZ0ZXN0"))
          Respond(WithCode(200), WithChunkedBody(""),
                  /* Don't kill the connection here, just send the header */
                  OnConditionThat(proxy200_close_conn,
                                  WithHeader("Connection", "close")))
          SetupSSLTunnel
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;
    num_requests_recvd = 2;

    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify

    CuAssertIntEquals(tc, num_requests_recvd, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests_recvd, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

static void test_ssltunnel_basic_auth(CuTest *tc)
{
    /* KeepAlive On for both proxy and server */
    ssltunnel_basic_auth(tc, 0, 0, 0);
}

static void test_ssltunnel_basic_auth_server_has_keepalive_off(CuTest *tc)
{
    /* Add Connection:Close header to server response */
    ssltunnel_basic_auth(tc, 1, 0, 0);
}

static void test_ssltunnel_basic_auth_proxy_has_keepalive_off(CuTest *tc)
{
    /* Add Connection:Close header to proxy 407 response */
    ssltunnel_basic_auth(tc, 0, 1, 0);
}

static void test_ssltunnel_basic_auth_proxy_close_conn_on_200resp(CuTest *tc)
{
    /* Add Connection:Close header to proxy 200 Conn. Establ. response  */
    ssltunnel_basic_auth(tc, 0, 0, 1);
}

static apr_status_t
basic_authn_callback_2ndtry(char **username,
                            char **password,
                            serf_request_t *request, void *baton,
                            int code, const char *authn_type,
                            const char *realm,
                            apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;
    int secondtry = tb->result_flags & TEST_RESULT_AUTHNCB_CALLED;

    test__log(TEST_VERBOSE, __FILE__, "ssltunnel_basic_authn_callback\n");

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (strcmp("Basic", authn_type) != 0)
        return REPORT_TEST_SUITE_ERROR();

    if (code == 401) {
        if (strcmp(apr_psprintf(pool, "<%s> Test Suite", tb->serv_url),
                   realm) != 0)
            return REPORT_TEST_SUITE_ERROR();

        *username = "serf";
        *password = secondtry ? "serftest" : "wrongpwd";
    }
    else if (code == 407) {
        if (strcmp(apr_psprintf(pool, "<http://localhost:%u> Test Suite Proxy",
                                tb->proxy_port), realm) != 0)
            return REPORT_TEST_SUITE_ERROR();

        *username = "serfproxy";
        *password = secondtry ? "serftest" : "wrongpwd";
    } else
        return REPORT_TEST_SUITE_ERROR();

    test__log(TEST_VERBOSE, __FILE__, "ssltunnel_basic_authn_callback finished successfully.\n");

    return APR_SUCCESS;
}


/* This test used to make serf crash on Windows when the server aborting the
   connection resulted in APR_ECONNRESET on the client side.

   This can be simulated by applying this change to serf__handle_auth_response
   right after the discard_body call.

   if (request->conn->completed_responses > 0 && status == APR_EOF)
       status = APR_ECONNRESET;

   TODO: create a mock socket or socket bucket wrapper to simulate
         APR_ECONNRESET.
 */
static void test_ssltunnel_basic_auth_2ndtry(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    int num_requests_sent, num_requests_recvd;
    apr_status_t status;

    /* Set up a test context with a server and a proxy. Serf should send a
       CONNECT request to the server. */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    CuAssertIntEquals(tc, APR_SUCCESS, setup_test_mock_proxy(tb));
    CuAssertIntEquals(tc, APR_SUCCESS,
            setup_serf_https_context_with_proxy(tb, https_set_root_ca_conn_setup,
                                                NULL, /* No server cert cb */
                                                tb->pool));

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC);
    serf_config_credentials_callback(tb->context, basic_authn_callback_2ndtry);

    Given(tb->mh)
      RequestsReceivedByServer
        GETRequest(URLEqualTo("/"))
          Respond(WithCode(200),WithChunkedBody(""))

      RequestsReceivedByProxy
        /* Don't close connection when client didn't provide creds */
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderNotSet("Proxy-Authorization"))
            Respond(WithCode(407), WithChunkedBody(""),
                    WithHeader("Proxy-Authenticate",
                               "Basic realm=\"Test Suite Proxy\""))
        /* serfproxy:wrongpwd fails, close connection. */
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderNotEqualTo("Proxy-Authorization",
                                     "Basic c2VyZnByb3h5OnNlcmZ0ZXN0"))
            Respond(WithCode(407), WithChunkedBody(""),
                    WithHeader("Proxy-Authenticate",
                               "Basic realm=\"Test Suite Proxy\""))
            CloseConnection
        /* serfproxy:serftest succeeds */
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderEqualTo("Proxy-Authorization",
                                  "Basic c2VyZnByb3h5OnNlcmZ0ZXN0"))
          Respond(WithCode(200), WithChunkedBody(""))
          SetupSSLTunnel
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* Test that a request is retried and authentication headers are set
       correctly. */
    num_requests_sent = 1;
    num_requests_recvd = 1;

    status = run_client_and_mock_servers_loops(tb, num_requests_sent,
                                               handler_ctx, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify

    CuAssertIntEquals(tc, num_requests_recvd, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests_recvd, tb->accepted_requests->nelts);
    CuAssertIntEquals(tc, num_requests_sent, tb->handled_requests->nelts);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

static apr_status_t
proxy_digest_authn_callback(char **username,
                            char **password,
                            serf_request_t *request, void *baton,
                            int code, const char *authn_type,
                            const char *realm,
                            apr_pool_t *pool)
{
    handler_baton_t *handler_ctx = baton;
    test_baton_t *tb = handler_ctx->tb;

    tb->result_flags |= TEST_RESULT_AUTHNCB_CALLED;

    if (code != 407)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp("Digest", authn_type) != 0)
        return REPORT_TEST_SUITE_ERROR();
    if (strcmp(apr_psprintf(pool, "<http://localhost:%u> Test Suite Proxy",
                            tb->proxy_port), realm) != 0)
        return REPORT_TEST_SUITE_ERROR();

    *username = "serf";
    *password = "serftest";

    return APR_SUCCESS;
}

/* Calculate the md5 over INPUT and return as string allocated in POOL */
static const char *simple_md5(char *input,
                              apr_pool_t *pool)
{
  unsigned char digest[APR_MD5_DIGESTSIZE];
  const char *hexmap = "0123456789abcdef";
  int i;
  char *result = apr_palloc(pool, 2 * APR_MD5_DIGESTSIZE + 1);

  if (apr_md5(digest, input, strlen(input)))
      REPORT_TEST_SUITE_ERROR();

  for (i = 0; i < sizeof(digest); i++) {
      result[i * 2] = hexmap[digest[i] >> 4];
      result[i * 2 + 1] = hexmap[digest[i] & 0xF];
  }
  result[APR_MD5_DIGESTSIZE * 2] = 0;
  return result;
}

/* Test if serf can successfully authenticate to a proxy used for an ssl
   tunnel. */
static void test_ssltunnel_digest_auth(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    const char *digest;
    const char *response_md5;

    /* Set up a test context with a server and a proxy. Serf should send a
       CONNECT request to the server. */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    CuAssertIntEquals(tc, APR_SUCCESS, setup_test_mock_proxy(tb));
    CuAssertIntEquals(tc, APR_SUCCESS,
            setup_serf_https_context_with_proxy(tb, https_set_root_ca_conn_setup,
                                                NULL, /* No server cert cb */
                                                tb->pool));

    serf_config_authn_types(tb->context, SERF_AUTHN_BASIC | SERF_AUTHN_DIGEST);
    serf_config_credentials_callback(tb->context, proxy_digest_authn_callback);

    /* Calculate the proper response. We can't use a hardcoded string as
       that would make the test fail when the port is in use. */
    {
      const char *ha1 = simple_md5(apr_psprintf(tb->pool,
                                                "%s:Test Suite Proxy:%s",
                                                "serf", "serftest"),
                                   tb->pool);
      const char *ha2 = simple_md5(apr_psprintf(tb->pool,
                                                "CONNECT:%s", tb->serv_host),
                                   tb->pool);

      response_md5 = simple_md5(apr_psprintf(tb->pool, "%s:%s:%s",
                                             ha1,
                                             "ABCDEF1234567890",
                                             ha2),
                                tb->pool);
    }
    digest = apr_psprintf(tb->pool, "Digest realm=\"Test Suite Proxy\", "
        "username=\"serf\", nonce=\"ABCDEF1234567890\", uri=\"localhost:%u\", "
        "response=\"%s\", opaque=\"myopaque\", "
        "algorithm=\"MD5\"", tb->serv_port, response_md5);
    Given(tb->mh)
      RequestsReceivedByServer
        GETRequest(URLEqualTo("/test/index.html"), ChunkedBodyEqualTo("1"))
          Respond(WithCode(200),WithChunkedBody(""))

    /* Add a Basic header before Digest header, to test that serf uses the most
       secure authentication scheme first, instead of following the order of
       the headers. */
    /* Use non standard case for Proxy-Authenticate header to test case
       insensitivity for http headers. */
      RequestsReceivedByProxy
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderNotSet("Proxy-Authorization"))
          Respond(WithCode(407), WithChunkedBody("1"),
                  WithHeader("Proxy-Authenticate",
                             "Basic realm=\"Test Suite Proxy\""),
                  WithHeader("Proxy-Authenticate", "NonExistent blablablabla"),
                  WithHeader("proXy-Authenticate", "Digest "
                   "realm=\"Test Suite Proxy\",nonce=\"ABCDEF1234567890\","
                   "opaque=\"myopaque\",algorithm=\"MD5\""))
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderEqualTo("Proxy-Authorization", digest))
          Respond(WithCode(200), WithChunkedBody(""))
          SetupSSLTunnel
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/test/index.html", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                               handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_AUTHNCB_CALLED);
}

/* Minimum tests for Negotiate authentication. If serf is built on Windows or
   with GSSAPI support, and the user is logged in to a Kerberos realm, this test
   will initiate a context and send the initial token to the proxy/server. */
static void test_ssltunnel_spnego_authn(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context with a proxy */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_mock_proxy(tb);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    status = setup_test_client_context_with_proxy(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_NEGOTIATE |
                                         SERF_AUTHN_NTLM);
    serf_config_credentials_callback(tb->context, ssltunnel_basic_authn_callback);

    Given(tb->mh)
      RequestsReceivedByProxy
        HTTPRequest(MethodEqualTo("CONNECT"),
                    URLEqualTo(tb->serv_host),
                    HeaderEqualTo("Host", tb->serv_host))
          Respond(WithCode(407),
                  WithHeader("Proxy-Authenticate", "Negotiate"),
                  WithHeader("Proxy-Authenticate", "Kerberos"),
                  WithHeader("Proxy-Authenticate", "NTLM"),
                  WithHeader("Connection", "close"),
                  WithHeader("Proxy-Connection", "close"),
                  WithHeader("Content-Type", "text/html"),
                  WithBody("<html><body>Authn required</body></html>"))
    EndGiven
    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* Don't check the result, authn will fail. */
    run_client_and_mock_servers_loops(tb, num_requests, handler_ctx, tb->pool);
}

static void test_server_spnego_authn(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context with a server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_authn_types(tb->context, SERF_AUTHN_NEGOTIATE |
                                         SERF_AUTHN_NTLM);
    serf_config_credentials_callback(tb->context, ssltunnel_basic_authn_callback);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(401),
                WithHeader("WWW-Authenticate", "Negotiate"),
                WithHeader("Content-Type", "text/html"),
                WithBody("<html><body>Authn required</body></html>"))
    EndGiven
    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    /* Don't check the result, authn will fail. */
    run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                      tb->pool);
}


static void test_ssl_renegotiate(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[2];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             ssl_server_cert_cb_expect_allok,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/index1.html"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
        SSLRenegotiate
      GETRequest(URLEqualTo("/index2.html"), ChunkedBodyEqualTo("2"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/index1.html", 1);

/*    status = run_client_and_mock_servers_loops(tb, 1, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);*/

    create_new_request(tb, &handler_ctx[1], "GET", "/index2.html", 2);

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    /* Check that the requests were sent and reveived by the server */
    /* Note: the test server will have received the first request twice, so
       we can't check for VerifyAllRequestsReceivedInOrder here. */
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify
    CuAssertIntEquals(tc, num_requests, tb->handled_requests->nelts);
}

static void test_ssl_missing_client_certificate(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;


    /* Set up a test context and a https server */
    /* The SSL server uses the complete certificate chain to validate the client
       certificate. */
    setup_test_mock_https_server(tb, server_key,
                                 all_server_certs,
                                 test_clientcert_mandatory);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             NULL, /* No server cert callback */
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      ConnectionSetup(ClientCertificateIsValid,
                      ClientCertificateCNEqualTo("Serf Client"))

      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, SERF_ERROR_SSL_SETUP_FAILED, status);
}

static apr_status_t handle_response_set_flag(serf_request_t *request,
                                             serf_bucket_t *response,
                                             void *handler_baton,
                                             apr_pool_t *pool)
{
    handler_baton_t *ctx = handler_baton;
    test_baton_t *tb = ctx->tb;

#if 0
    /* TODO: this is the expected behahior: if there was an error reading
       the response while looking for authn headers, serf should pass the
       response to the application to let it read the error from the response.
       Not passing the response will make the application think the response
       get cancelled, and it will requeue it. */
    if (!response)
        return REPORT_TEST_SUITE_ERROR();
#endif

    tb->result_flags |= TEST_RESULT_HANDLE_RESPONSECB_CALLED;

    return handle_response(request, response, handler_baton, pool);
}

/* Test that serf doesn't crash when connecting to a non-HTTP server. */
static void test_connect_to_non_http_server(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context and a http server */
    setup_test_mock_server(tb);
    status = setup_test_client_context(tb, NULL, tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    serf_config_credentials_callback(tb->context, dummy_authn_callback);

#define RESPONSE "6EQUJ5 6EQUJ5 hello stranger!\r\n"
    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"))
        /* Assume that extraterrestrials also use CRLF as line ending symbol. */
        Respond(WithRawData(RESPONSE, strlen(RESPONSE)))
    EndGiven
#undef RESPONSE

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);
    handler_ctx[0].handler = handle_response_set_flag;

    status = run_client_and_mock_servers_loops(tb, num_requests, handler_ctx,
                                               tb->pool);
    CuAssertIntEquals(tc, SERF_ERROR_BAD_HTTP_RESPONSE, status);

    /* Check that the requests were sent and reveived by the server */
    Verify(tb->mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify
    CuAssertIntEquals(tc, num_requests, tb->sent_requests->nelts);
    CuAssertIntEquals(tc, num_requests, tb->accepted_requests->nelts);
    /* The response will not have been handled completely, but at least make
       sure that the handler got called. */
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_HANDLE_RESPONSECB_CALLED);
}

static apr_status_t
ocsp_response_cb_expect_failures(void *baton, int failures,
                                     const serf_ssl_certificate_t *cert)
{
    test_baton_t *tb = baton;
    int expected_failures = tb->user_baton_l;

    /* Root CA cert is selfsigned, ignore this 'failure'. */
    failures &= ~SERF_SSL_CERT_SELF_SIGNED;

    /* This callback gets called with both the server certificate and the ocsp
       response status */
    tb->result_flags |= TEST_RESULT_SERVERCERTCB_CALLED;

    /* We expect an error from the certificate validation function. */
    if (!failures)
        return APR_SUCCESS;
    if (failures & expected_failures) {
        tb->result_flags |= TEST_RESULT_OCSP_CHECK_SUCCESSFUL;
        return APR_SUCCESS;
    }

    return REPORT_TEST_SUITE_ERROR();
}

static void test_ssl_ocsp_response_error_and_override(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    /* Set up a test context, a https server, and a OCSP responder */
    setup_test_mock_https_server(tb, server_key,
                                 all_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             default_https_conn_setup,
                                             ocsp_response_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    tb->enable_ocsp_stapling = 1;

    InitMockServers(tb->mh)
      ConfigServerWithID("server", WithOCSPEnabled)
    EndInit

    Given(tb->mh)
      OCSPRequest(MatchAny)
        Respond(WithOCSPResponseStatus(mhOCSPRespnseStatusInternalError))
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven
    /* Expect this error */
    tb->user_baton_l = SERF_SSL_OCSP_RESPONDER_ERROR;

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);

    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_OCSP_CHECK_SUCCESSFUL);
}

/* Validate that the subject's CN containing a '\0' byte is reported as failure
   SERF_SSL_CERT_INVALID_HOST in the callback. */
static void test_ssl_server_cert_with_cn_nul_byte(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;

    static const char *nul_byte_server_certs[] = {
        "servercert_cn_nul.pem",
        "cacert_nul.pem",
        NULL };
    static const char *nul_byte_server_key = "servercert_cn_nul.key";

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, nul_byte_server_key,
                                 nul_byte_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup */
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_SELF_SIGNED |
                        SERF_SSL_CERT_INVALID_HOST; /* NUL byte error */
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}

/* Validate that the subject's SAN containing a '\0' byte is reported as failure
   SERF_SSL_CERT_INVALID_HOST in the callback. */
static void test_ssl_server_cert_with_san_nul_byte(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;

    static const char *nul_byte_server_certs[] = {
        "servercert_san_nul.pem",
        "cacert_nul.pem",
        NULL };
    static const char *nul_byte_server_key = "servercert_san_nul.key";

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, nul_byte_server_key,
                                 nul_byte_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup */
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_SELF_SIGNED |
                        SERF_SSL_CERT_INVALID_HOST; /* NUL byte error */
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}

/* Validate that the subject's CN and SAN containing a '\0' byte is reported
   as failure SERF_SSL_CERT_INVALID_HOST in the callback. */
static void test_ssl_server_cert_with_cnsan_nul_byte(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;

    static const char *nul_byte_server_certs[] = {
        "servercert_cnsan_nul.pem",
        "cacert_nul.pem",
        NULL };
    static const char *nul_byte_server_key = "servercert_cnsan_nul.key";

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, nul_byte_server_key,
                                 nul_byte_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             NULL, /* default conn setup */
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_SELF_SIGNED |
                        SERF_SSL_CERT_INVALID_HOST; /* NUL byte error */
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}

/* Validate a certificate with subjectAltName a DNS entry, but no CN. */
static void test_ssl_server_cert_with_san_and_empty_cb(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    apr_status_t status;

    static const char *san_server_certs[] = {
        "serfserver_san_nocn_cert.pem",
        "serfcacert.pem",
        NULL };

    /* Set up a test context and a https server */
    setup_test_mock_https_server(tb, server_key,
                                 san_server_certs,
                                 test_clientcert_none);
    status = setup_test_client_https_context(tb,
                                             https_set_root_ca_conn_setup,
                                             ssl_server_cert_cb_expect_allok,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
    CuAssertTrue(tc, tb->result_flags & TEST_RESULT_SERVERCERTCB_CALLED);
}

static apr_status_t http11_select_protocol(void *baton,
                                           const char *protocol)
{
  test_baton_t *tb = baton;

  if (! strcmp(protocol, "http/1.1"))
      serf_connection_set_framing_type(tb->connection,
                                       SERF_CONNECTION_FRAMING_TYPE_HTTP1);
  else
      return APR_EGENERAL; /* Failure */

  return APR_SUCCESS;
}

static apr_status_t http11_alpn_setup(apr_socket_t *skt,
                                      serf_bucket_t **input_bkt,
                                      serf_bucket_t **output_bkt,
                                      void *setup_baton,
                                      apr_pool_t *pool)
{
  test_baton_t *tb = setup_baton;
  apr_status_t status;

  status = default_https_conn_setup(skt, input_bkt, output_bkt,
                                    setup_baton, pool);
  if (status)
    return status;

  status = serf_ssl_negotiate_protocol(tb->ssl_context, "h2,http/1.1",
                                       http11_select_protocol, tb);

  if (!status) {
      /* Delay writing out the protocol type until we know how */
      serf_connection_set_framing_type(tb->connection,
                                       SERF_CONNECTION_FRAMING_TYPE_NONE);
  }

  return APR_SUCCESS;
}


static void test_ssl_alpn_negotiate(CuTest *tc)
{
    test_baton_t *tb = tc->testBaton;
    handler_baton_t handler_ctx[1];
    const int num_requests = sizeof(handler_ctx)/sizeof(handler_ctx[0]);
    int expected_failures;
    apr_status_t status;
    static const char *server_cert[] = { "serfservercert.pem",
                                         NULL };

    /* Set up a test context and a https server */
    tb->mh = mhInit();

    InitMockServers(tb->mh)
      SetupServer(WithHTTPS, WithID("server"), WithPort(30080),
                  WithProtocol("http/1.1"),
                  WithCertificateFilesPrefix(get_srcdir_file(tb->pool,
                                                             "test/certs")),
                  WithCertificateKeyFile(server_key),
                  WithCertificateKeyPassPhrase("serftest"),
                  WithCertificateFileArray(server_cert))
    EndInit

    tb->serv_port = mhServerPortNr(tb->mh);
    tb->serv_host = apr_psprintf(tb->pool, "%s:%d", "localhost", tb->serv_port);
    tb->serv_url = apr_psprintf(tb->pool, "https://%s", tb->serv_host);

    status = setup_test_client_https_context(tb,
                                             http11_alpn_setup,
                                             ssl_server_cert_cb_expect_failures,
                                             tb->pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    expected_failures = SERF_SSL_CERT_UNKNOWNCA;
    tb->user_baton = &expected_failures;

    Given(tb->mh)
      GETRequest(URLEqualTo("/"), ChunkedBodyEqualTo("1"),
                 HeaderEqualTo("Host", tb->serv_host))
        Respond(WithCode(200), WithChunkedBody(""))
    EndGiven

    create_new_request(tb, &handler_ctx[0], "GET", "/", 1);

    run_client_and_mock_servers_loops_expect_ok(tc, tb, num_requests,
                                                handler_ctx, tb->pool);
}

CuSuite *test_ssl(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

    SUITE_ADD_TEST(suite, test_ssl_init);
    SUITE_ADD_TEST(suite, test_ssl_load_cert_file);
    SUITE_ADD_TEST(suite, test_ssl_cert_subject);
    SUITE_ADD_TEST(suite, test_ssl_cert_issuer);
    SUITE_ADD_TEST(suite, test_ssl_cert_certificate);
    SUITE_ADD_TEST(suite, test_ssl_cert_export);
    SUITE_ADD_TEST(suite, test_ssl_cert_import);
    SUITE_ADD_TEST(suite, test_ssl_handshake);
    SUITE_ADD_TEST(suite, test_ssl_handshake_nosslv2);
    SUITE_ADD_TEST(suite, test_ssl_trust_rootca);
    SUITE_ADD_TEST(suite, test_ssl_application_rejects_cert);
    SUITE_ADD_TEST(suite, test_ssl_certificate_chain_with_anchor);
    SUITE_ADD_TEST(suite, test_ssl_certificate_chain_all_from_server);
    SUITE_ADD_TEST(suite, test_ssl_no_servercert_callback_allok);
    SUITE_ADD_TEST(suite, test_ssl_no_servercert_callback_fail);
    SUITE_ADD_TEST(suite, test_ssl_large_response);
    SUITE_ADD_TEST(suite, test_ssl_large_request);
    SUITE_ADD_TEST(suite, test_ssl_client_certificate);
    SUITE_ADD_TEST(suite, test_ssl_expired_server_cert);
    SUITE_ADD_TEST(suite, test_ssl_future_server_cert);
    SUITE_ADD_TEST(suite, test_ssl_revoked_server_cert);
    SUITE_ADD_TEST(suite, test_setup_ssltunnel);
    SUITE_ADD_TEST(suite, test_ssltunnel_no_creds_cb);
    SUITE_ADD_TEST(suite, test_ssltunnel_basic_auth);
    SUITE_ADD_TEST(suite, test_ssltunnel_basic_auth_server_has_keepalive_off);
    SUITE_ADD_TEST(suite, test_ssltunnel_basic_auth_proxy_has_keepalive_off);
    SUITE_ADD_TEST(suite, test_ssltunnel_basic_auth_proxy_close_conn_on_200resp);
    SUITE_ADD_TEST(suite, test_ssltunnel_basic_auth_2ndtry);
    SUITE_ADD_TEST(suite, test_ssltunnel_digest_auth);
    SUITE_ADD_TEST(suite, test_ssltunnel_spnego_authn);
    SUITE_ADD_TEST(suite, test_server_spnego_authn);
    SUITE_ADD_TEST(suite, test_ssl_missing_client_certificate);
    SUITE_ADD_TEST(suite, test_connect_to_non_http_server);
    SUITE_ADD_TEST(suite, test_ssl_ocsp_response_error_and_override);
    SUITE_ADD_TEST(suite, test_ssl_server_cert_with_cn_nul_byte);
    SUITE_ADD_TEST(suite, test_ssl_server_cert_with_san_nul_byte);
    SUITE_ADD_TEST(suite, test_ssl_server_cert_with_cnsan_nul_byte);
    SUITE_ADD_TEST(suite, test_ssl_server_cert_with_san_and_empty_cb);
    SUITE_ADD_TEST(suite, test_ssl_renegotiate);
    SUITE_ADD_TEST(suite, test_ssl_alpn_negotiate);

    return suite;
}
