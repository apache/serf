/* Copyright 2008 Justin Erenkrantz and Greg Stein
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

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_env.h>

#include "serf.h"
#include "serf_bucket_types.h"

/* Access to internal functions, for DER decoding. */
#include "buckets/bucket_private.h"

#include "test_serf.h"

#if defined(WIN32) && defined(_DEBUG)
/* Include this file to allow running a Debug build of serf with a Release
   build of OpenSSL. */
#include <openssl/applink.c>
#endif

/* Test setting up the openssl library. */
static void test_ssl_init(CuTest *tc)
{
    serf_bucket_t *bkt, *stream;
    serf_ssl_context_t *ssl_context;
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(test_pool, NULL,
                                                              NULL);

    stream = SERF_BUCKET_SIMPLE_STRING("", alloc);

    bkt = serf_bucket_ssl_decrypt_create(stream, NULL,
                                         alloc);
    ssl_context = serf_bucket_ssl_decrypt_context_get(bkt);

    bkt = serf_bucket_ssl_encrypt_create(stream, ssl_context,
                                         alloc);

    status = serf_ssl_use_default_certificates(ssl_context);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
}


static const char * get_ca_file(apr_pool_t *pool, const char * file)
{
    char *srcdir = "";

    if (apr_env_get(&srcdir, "srcdir", pool) == APR_SUCCESS) {
        return apr_pstrcat(pool, srcdir, "/", file, NULL);
    }
    else {
        return file;
    }
}


/* Test that loading a custom CA certificate file works. */
static void test_ssl_load_cert_file(CuTest *tc)
{
    serf_ssl_certificate_t *cert = NULL;

    apr_pool_t *test_pool = tc->testBaton;
    apr_status_t status = serf_ssl_load_cert_file(
        &cert, get_ca_file(test_pool, "test/serftestca.pem"), test_pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);
}

typedef struct
{
    const char *cn;
    const char *o;
    const char *ou;
    const char *l;
    const char *st;
    const char *c;
    const char *e;
} test_dn_t;

typedef struct {
    test_dn_t issuer;
    test_dn_t subject;
    const char *sha1;
    const char *notBefore;
    const char *notAfter;
    /* serial number, subjectAltNames */
} test_cert_t;

static void
validate_dn(CuTest *tc, const test_dn_t *expected, const apr_hash_t *actual)
{
    apr_hash_t *dn = (apr_hash_t *)actual;

    CuAssertStrEquals(tc, expected->cn,
                      apr_hash_get(dn, "CN", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->ou,
                      apr_hash_get(dn, "OU", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->o,
                      apr_hash_get(dn, "O", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->l,
                      apr_hash_get(dn, "L", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->st,
                      apr_hash_get(dn, "ST", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->c,
                      apr_hash_get(dn, "C", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->e,
                      apr_hash_get(dn, "E", APR_HASH_KEY_STRING));
}

static void
validate_cert(CuTest *tc, const test_cert_t *expected, const apr_hash_t *actual)
{
    const apr_hash_t *subject, *issuer;
    apr_hash_t *cert = (apr_hash_t *)actual;

    subject = apr_hash_get(cert, "subject", APR_HASH_KEY_STRING);
    CuAssertPtrNotNullMsg(tc, "Expected subject", subject);

    validate_dn(tc, &expected->subject, subject);

    issuer = apr_hash_get(cert, "issuer", APR_HASH_KEY_STRING);
    CuAssertPtrNotNullMsg(tc, "Expected issuer", issuer);

    validate_dn(tc, &expected->issuer, issuer);
    /*
     TODO: sha1sum of DER encoded cert for signature.
     CuAssertStrEquals(tc, expected->sha1,
     apr_hash_get(cert, "sha1", APR_HASH_KEY_STRING));
     */
    CuAssertStrEquals(tc, expected->notBefore,
                      apr_hash_get(cert, "notBefore", APR_HASH_KEY_STRING));
    CuAssertStrEquals(tc, expected->notAfter,
                      apr_hash_get(cert, "notAfter", APR_HASH_KEY_STRING));
    /* TODO: subjectAltNames */
}

/* Test that reading the subject from a custom CA certificate file works. */
static void test_ssl_cert_subject(CuTest *tc)
{
    apr_hash_t *subject;
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status;
    const test_dn_t exp_subject = { "Serf", "In Serf we trust, Inc.",
        "Test Suite", "Mechelen", "Antwerp", "BE", "serf@example.com" };

    apr_pool_t *test_pool = tc->testBaton;

    status = serf_ssl_load_cert_file(&cert, get_ca_file(test_pool,
                                                        "test/serftestca.pem"),
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    subject = serf_ssl_cert_subject(cert, test_pool);
    CuAssertPtrNotNull(tc, subject);

    validate_dn(tc, &exp_subject, subject);
}

/* Test that reading the issuer from a custom CA certificate file works. */
static void test_ssl_cert_issuer(CuTest *tc)
{
    apr_hash_t *issuer;
    serf_ssl_certificate_t *cert = NULL;
    apr_status_t status;
    const test_dn_t exp_issuer = { "Serf", "In Serf we trust, Inc.",
        "Test Suite", "Mechelen", "Antwerp", "BE", "serf@example.com" };

    apr_pool_t *test_pool = tc->testBaton;

    status = serf_ssl_load_cert_file(&cert, get_ca_file(test_pool,
                                                        "test/serftestca.pem"),
                                     test_pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    issuer = serf_ssl_cert_issuer(cert, test_pool);
    CuAssertPtrNotNull(tc, issuer);

    validate_dn(tc, &exp_issuer, issuer);
}

/* Test that reading the notBefore,notAfter,sha1 fingerprint and subjectAltNames
   from a custom CA certificate file works. */
static void test_ssl_cert_certificate(CuTest *tc)
{
    apr_hash_t *kv;
    serf_ssl_certificate_t *cert = NULL;
    apr_array_header_t *san_arr;
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;

    status = serf_ssl_load_cert_file(&cert, get_ca_file(test_pool,
                                                        "test/serftestca.pem"),
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    kv = serf_ssl_cert_certificate(cert, test_pool);
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

static void test_ssl_load_CA_cert_from_file(CuTest *tc)
{
    serf_ssl_certificate_t *cert = NULL;
    serf_bucket_t *bkt, *stream;
    serf_ssl_context_t *ssl_context;
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(test_pool, NULL,
                                                              NULL);

    stream = SERF_BUCKET_SIMPLE_STRING("", alloc);
    bkt = serf_bucket_ssl_decrypt_create(stream, NULL, alloc);
    ssl_context = serf_bucket_ssl_decrypt_context_get(bkt);

    status = serf_ssl_load_CA_cert_from_file(ssl_context,
                                             &cert,
                                             get_ca_file(test_pool, "test/serftestca.pem"),
                                             test_pool);

    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);
}

static const char *extract_cert_from_pem(const char *pemdata,
                                         apr_size_t *pemlen,
                                         int copy_delimiters,
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
        int delimiter = FALSE;

        status = serf_bucket_readline(pembkt, SERF_NEWLINE_ANY, &found,
                                      &data, &len);
        if (SERF_BUCKET_READ_ERROR(status))
            return NULL;

        if (state == INIT) {
            if (strncmp(begincert, data, strlen(begincert)) != 0)
                continue;

            state = CERT_BEGIN;
            delimiter = TRUE;
            if (!copy_delimiters)
                continue;
        } else if (state == CERT_BEGIN) {
            if (strncmp(endcert, data, strlen(endcert)) == 0)
            {
                state = CERT_FOUND;
                delimiter = TRUE;
                if (!copy_delimiters)
                    break;
                certdata = apr_pstrcat(pool, certdata, CRLF, NULL);
                certlen += 2;
            }
        }
        /* Copy the line to the output buffer. Remove linefeeds from the
         base64 DER encoded certificate. */
        certdata = apr_pstrcat(pool, certdata, data, NULL);
        certlen += len;
        switch (found && !delimiter)
        {
            case SERF_NEWLINE_CR:
            case SERF_NEWLINE_LF:
                certdata[certlen-1] = '\0';
                certlen--;
                break;
            case SERF_NEWLINE_CRLF:
                certdata[certlen-2] = '\0';
                certlen-=2;
                break;
        }
    }

    if (state == CERT_FOUND) {
        *pemlen = certlen;
        return certdata;
    }
    else
        return NULL;
}

static void test_ssl_cert_export(CuTest *tc)
{
    serf_ssl_certificate_t *cert = NULL;
    apr_file_t *fp;
    apr_finfo_t file_info;
    const char *base64derbuf;
    char *pembuf;
    apr_size_t pemlen;
    apr_status_t status;

    apr_pool_t *test_pool = tc->testBaton;

    status = serf_ssl_load_cert_file(&cert, get_ca_file(test_pool,
                                                        "test/serftestca.pem"),
                                     test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);
    CuAssertPtrNotNull(tc, cert);

    /* A .pem file contains a Base64 encoded DER certificate, which is exactly
       what serf_ssl_cert_export is supposed to be returning. */
    status = apr_file_open(&fp, "test/serftestca.pem",
                           APR_FOPEN_READ | APR_FOPEN_BINARY,
                           APR_FPROT_OS_DEFAULT, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    apr_file_info_get(&file_info, APR_FINFO_SIZE, fp);
    pembuf = apr_palloc(test_pool, file_info.size);

    status = apr_file_read_full(fp, pembuf, file_info.size, &pemlen);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    base64derbuf = serf_ssl_cert_export(cert, test_pool);

    CuAssertStrEquals(tc,
                      extract_cert_from_pem(pembuf, &pemlen, 0, test_pool),
                      base64derbuf);
}

/****************************************************************************/
/* Test the DER decoding with certificates collected in file
   test/certificates.pem.
 */

static apr_status_t read_certificate(serf_bucket_t *bkt,
                                     char *buf,
                                     apr_size_t buf_len,
                                     apr_size_t *read_len)
{
    apr_size_t total_read;
    apr_status_t status;

    const char *delimiter = "=========================";

    total_read = 0;
    int acceptable = SERF_NEWLINE_CRLF | SERF_NEWLINE_LF | SERF_NEWLINE_CR;

    do
    {
        const char *data;
        apr_size_t len;
        int found;

        status = serf_bucket_readline(bkt, acceptable, &found,
                                      &data, &len);
        if (!SERF_BUCKET_READ_ERROR(status))
        {
            if (len >= sizeof(delimiter) &&
                strncmp(delimiter, data, sizeof(delimiter)) == 0)
            {
                /* end of certificate found, return current data. */
                status = APR_SUCCESS;
                break;
            }
            if (total_read + len > buf_len)
            {
                /* Buffer is not large enough to read all data */
                status = SERF_ERROR_ISSUE_IN_TESTSUITE;
            }
            memcpy(buf + total_read, data, len);
            total_read += len;
        }
    } while(status == APR_SUCCESS);

    *read_len = total_read;
    return status;
}

const test_cert_t test_certs[] =
{
    { { "Serf CA", "In Serf we trust, Inc.", "Test Suite CA",
        "Mechelen", "Antwerp", "BE", "serfca@example.com"},
      { "Serf Server", "In Serf we trust, Inc.", "Test Suite Server",
        "Mechelen", "Antwerp", "BE", "serfserver@example.com"},
      "", "Apr 18 19:50:11 2013 GMT", "Apr 18 19:50:11 2014 GMT",
    },
    { { "Serf Root CA", "In Serf we trust, Inc.", "Test Suite Root CA",
        "Mechelen", "Antwerp", "BE", "serfrootca@example.com"},
      { "Serf Root CA", "In Serf we trust, Inc.", "Test Suite Root CA",
        "Mechelen", "Antwerp", "BE", "serfrootca@example.com"},
      "", "Apr 13 11:19:14 2013 GMT", "Apr 11 11:19:14 2023 GMT",
    },
    { { "Belgium Root CA", NULL, NULL, NULL, NULL, "BE", NULL},
      { "Belgium Root CA", NULL, NULL, NULL, NULL, "BE", NULL},
        "", "Jan 26 23:00:00 2003 GMT", "Jan 26 23:00:00 2014 GMT",
    },
    { { "Belgium Root CA2", NULL, NULL, NULL, NULL, "BE", NULL},
      { "Belgium Root CA2", NULL, NULL, NULL, NULL, "BE", NULL},
      "", "Oct 04 10:00:00 2007 GMT", "Dec 15 08:00:00 2021 GMT",
    },
};

static void test_sectrans_DER_decoding(CuTest *tc)
{
#ifdef SERF_HAVE_SECURETRANSPORT
    serf_bucket_t *filebkt;
    apr_file_t *fp;
    char buf[16384];
    apr_size_t len;
    apr_status_t status;
    int current_cert;

    apr_pool_t *test_pool = tc->testBaton;
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(test_pool,
                                                              NULL, NULL);

    status = apr_file_open(&fp, "test/certificates.pem",
                           APR_FOPEN_READ | APR_FOPEN_BINARY,
                           APR_FPROT_OS_DEFAULT, test_pool);
    CuAssertIntEquals(tc, APR_SUCCESS, status);

    filebkt = serf_bucket_file_create(fp, alloc);

    current_cert = 0;
    do
    {
        status = read_certificate(filebkt, buf, sizeof(buf), &len);
        CuAssertIntEquals(tc, SERF_BUCKET_READ_ERROR(status), 0);

        /* A certificate was read from test/certificates.pem */
        if (status == APR_SUCCESS)
        {
            apr_size_t pemlen;
            const char *pemdata = extract_cert_from_pem(buf, &pemlen, 1, test_pool);
            serf_ssl_certificate_t *cert;
            apr_hash_t *actual;
            
            test_cert_t thiscert = test_certs[current_cert];

/*            printf("Certificate found: %.*s\n\n", pemlen, pemdata);**/
            status = load_CA_cert_from_buffer(&cert, pemdata, pemlen, test_pool);
            CuAssertIntEquals(tc, APR_SUCCESS, status);

            status = serf__sectrans_read_X509_DER_certificate(&actual,
                                                              cert->impl_cert,
                                                              test_pool);
            CuAssertIntEquals(tc, APR_SUCCESS, status);

            validate_cert(tc, &thiscert, actual);

            current_cert++;
        }
    } while (status == APR_SUCCESS &&
             current_cert < sizeof(test_certs) / sizeof(test_certs[0]));

#endif
}

CuSuite *test_ssl(void)
{
    CuSuite *suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(suite, test_setup, test_teardown);

#ifdef SERF_HAVE_OPENSSL
    CuSuite *openssl_suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(openssl_suite, test_openssl_setup,
                                     test_openssl_teardown);

    SUITE_ADD_TEST(openssl_suite, test_ssl_init);
    SUITE_ADD_TEST(openssl_suite, test_ssl_load_cert_file);
    SUITE_ADD_TEST(openssl_suite, test_ssl_cert_subject);
    SUITE_ADD_TEST(openssl_suite, test_ssl_cert_issuer);
    SUITE_ADD_TEST(openssl_suite, test_ssl_cert_certificate);
    SUITE_ADD_TEST(openssl_suite, test_ssl_load_CA_cert_from_file);
    SUITE_ADD_TEST(openssl_suite, test_ssl_cert_export);
    SUITE_ADD_TEST(openssl_suite, test_sectrans_DER_decoding);

    CuSuiteAddSuite(suite, openssl_suite);
#endif
#ifdef SERF_HAVE_SECURETRANSPORT
    CuSuite *sectransssl_suite = CuSuiteNew();

    CuSuiteSetSetupTeardownCallbacks(sectransssl_suite, test_sectransssl_setup,
                                     test_sectransssl_teardown);

    SUITE_ADD_TEST(sectransssl_suite, test_ssl_init);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_load_cert_file);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_cert_subject);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_cert_issuer);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_cert_certificate);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_load_CA_cert_from_file);
    SUITE_ADD_TEST(sectransssl_suite, test_ssl_cert_export);
    SUITE_ADD_TEST(sectransssl_suite, test_sectrans_DER_decoding);

    CuSuiteAddSuite(suite, sectransssl_suite);
#endif

    return suite;
}
