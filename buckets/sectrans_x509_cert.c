/* Copyright 2013 Justin Erenkrantz and Greg Stein
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

#ifdef SERF_HAVE_SECURETRANSPORT

#include <stdlib.h>

#include "serf.h"
#include "serf_private.h"
#include "serf_bucket_util.h"
#include "bucket_private.h"

#include <apr_strings.h>
#include <apr_sha1.h>

#include <Security/SecCertificate.h>
#include <Security/SecCertificateOIDs.h>

#define ST_DEBUG 0

/* This code reads all items DER-encoded certificate in X.509 format, as
   provided by the Keychain services API. */

/* Read ASN.1 data type OID from a DER encoded buffer. */
static const char *
read_DER_OID(const unsigned char* ptr, int clen, apr_pool_t *pool)
{
    unsigned char b;
    char *value;

    /* First two components of the OID are encoded in the first byte. */
    b = *ptr++;
    clen--;

    value = apr_psprintf(pool, "%d.%d", b/40, b%40);


    /* one or two bytes per component */
    while (clen > 0) {
        b = *ptr++;
        clen--;

        if (! (b & 0x80)) {
            value = apr_psprintf(pool, "%s.%d", value, b);
        } else {
            unsigned comp = 0;

            while (b & 0x80 && clen > 0) {
                comp <<= 7;
                comp |= (b & 0x7f);
                b = *ptr++;
                clen--;
            }
            comp <<= 7;
            comp |= (b & 0x7f);

            value = apr_psprintf(pool, "%s.%d", value, comp);
        }
    }

    serf__log(ST_DEBUG, __FILE__, "OID of length %d, value: %s .\n",
              clen, value);

    return value;
}

/* Read ASN.1 data type PrintableString from a DER encoded buffer.
   TODO: currently also used for UTF8String, use specific function for those. */
static const char *
read_DER_string(const unsigned char* ptr, int clen, apr_pool_t *pool)
{
    const char *value = apr_pstrndup(pool, (const char*)ptr, clen);

    serf__log(ST_DEBUG, __FILE__, "string of length %d, value: %s.\n",
              clen, value);

    return value;
}

/* Read ASN.1 data type BOOLEAN from a DER encoded buffer. */
static const char *
read_DER_boolean(const unsigned char* ptr, int clen, apr_pool_t *pool)
{
    unsigned char v = *ptr++;

    serf__log(ST_DEBUG, __FILE__, "Boolean of length %d, value: %s.\n",
              clen, v ? "TRUE" : "FALSE");

    return v ? "TRUE" : "FALSE";
}

/* Read ASN.1 data type BIT STRING from a DER encoded buffer. */
static const char *
read_DER_bitstring(const unsigned char* ptr, int clen, apr_pool_t *pool)
{
    char *value = "";

    /* TODO: take into account unused_bits. */
    /*    unsigned char unused_bits = *ptr++; */
    ptr++;
    clen--;

    while (clen-- > 0) {
        unsigned char b = *ptr++;
        value = apr_psprintf(pool, "%s %2x", value, b);
    }

    serf__log(ST_DEBUG, __FILE__, "Bitstring of length %d, value: %s.\n",
              clen, value);

    return value;
}

/* Read ASN.1 data type INTEGER from a DER encoded buffer. */
static const char *
read_DER_integer(const unsigned char* ptr, int clen, apr_pool_t *pool)
{
    unsigned char lb = *ptr++;
    int positive = 0;
    int i;
    unsigned long value = 0;

    if (lb == 0x00) {
        positive = 1;
        clen -= positive;


        if (clen <= sizeof(long))
            for (i = 0; i < clen; i++)
                value = (value << 8) + *ptr++;
    } else if (! (lb & 0x80)) {
        positive = 1;
        value = lb;
    } else {
        /* negative number */
        return apr_psprintf(pool, "Negative integer not supported.");
    }

    serf__log(ST_DEBUG, __FILE__, "%s integer of length %d, value: %lx.\n",
              positive ? "Positive" : "Negative", clen, value);

    return apr_psprintf(pool, "%lx", value);
}

/* Read DER Tag and Length from a DER encoded buffer. */
static apr_status_t
read_DER_TL(const unsigned char* ptr, unsigned char *tag,
            long *value_len, long *consumed)
{
    int constr_enc;
    char lb1;
    long clen = 0;

    /* read tag */
    *tag = *ptr++;
    constr_enc = *tag & 0x20;
    *consumed = 1;

    /* read length */
    lb1 = *ptr++;
    if (! (lb1 & 0x80)) {
        clen = lb1;
        (*consumed)++;
    } else {
        int i;
        lb1 &= 0x7f;
        if (lb1 > sizeof(long))
            return APR_ENOTIMPL;
        for (i = 0; i < lb1; i++)
            clen = (clen << 8) + *ptr++;
        *consumed += (lb1 + 1);
    }

    *value_len = clen;

    serf__log(ST_DEBUG, __FILE__,
              "tag: %x, value length: %d, header length: %d.\n",
              *tag, *value_len, *consumed);

    return APR_SUCCESS;
}

/* Read DER Tag, Length and primitive Value from a DER encoded buffer.
   Don't use this for constructed types SEQUENCE or SET! */
static apr_status_t
read_DER_TLvalue(const unsigned char *ptr, unsigned char *tag, long *consumed,
                 const char **value, apr_pool_t *pool)
{
    long tl_len, value_len;

    read_DER_TL(ptr, tag, &value_len, &tl_len);
    ptr += tl_len;

    switch (*tag) {
        case 0x01:
            *value = read_DER_boolean(ptr, value_len, pool);
            break;
        case 0x02:
            *value = read_DER_integer(ptr, value_len, pool);
            break;
        case 0x03:
            *value = read_DER_bitstring(ptr, value_len, pool);
            break;
        case 0x05:
            *value = "";
            serf__log(ST_DEBUG, __FILE__, "NULL value.\n");
            break;
        case 0x06:
            *value = read_DER_OID(ptr, value_len, pool);
            break;
        case 0x17: /* Date */
        case 0x16: /* IA5String */
        case 0x13: /* PrintableString */
        case 0x14: /* TeletexString */
        case 0x0c: /* UTF8String */
            *value = read_DER_string(ptr, value_len, pool);
            break;

        case 0xa0: /* Explicit tag 0, in X509 used for version. */
        default:
        {
            *value = "ERROR";
            serf__log(ST_DEBUG, __FILE__, "UNSUPPORTED TAG TYPE %2x.\n", *tag);
            return APR_ENOTIMPL;
            break;
        }
    }

    *consumed = tl_len + value_len;

    return APR_SUCCESS;
}

/* Recursively skip an entire Tag-Length-Value block. */
static apr_status_t
skip_DER_TLV(const unsigned char *ptr, unsigned char *tag, long *consumed)
{
    long tl_len, value_len;
    apr_status_t status;

    status = read_DER_TL(ptr, tag, &value_len, &tl_len);
    if (status)
        return status;

    *consumed = tl_len + value_len;

    return APR_SUCCESS;
}

#define SERF_ERR(x) status = (x);\
                    if (status) goto cleanup;

/* Reads an issuer or subject structure from PTR, which should point to the
   value of tag type 0x30 grouping either issuer or subject.
   Caller should clean up out_der. */
static apr_status_t
read_X509_DER_DistinguishedName(apr_hash_t **o, CFDataRef *out_der,
                                const unsigned char *ptr,
                                long *total_len, apr_pool_t *pool)
{
    unsigned char tag;
    long len, object_len, consumed;
    apr_status_t status;
    apr_hash_t *tgt;
    char *tmp;

    tgt = apr_hash_make(pool);

    /* RelativeDistinguishedName Sequence. */
    SERF_ERR(read_DER_TL(ptr, &tag, &object_len, &consumed));

    /* Copy this whole structure in out_der. */
    tmp = apr_palloc(pool, object_len);
    memcpy(tmp, ptr, object_len);
    *out_der = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                           (unsigned char *)tmp,
                                           object_len,
                                           kCFAllocatorNull);

    ptr += consumed;

    *total_len = object_len + consumed;
    /* For each component */
    while (object_len > 0) {
        const char *key, *value;
        long consumed;
        CFStringRef keyref;

        /* RelativeDistinguishedName Set. */
        SERF_ERR(read_DER_TL(ptr, &tag, &len, &consumed));
        ptr += consumed; object_len -= consumed;

        /* AttributeTypeAndValue, containing OID-value pair. */
        SERF_ERR(read_DER_TL(ptr, &tag, &len, &consumed));
        ptr += consumed; object_len -= consumed;

        /* Read key OID */
        SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &key, pool));
        ptr += consumed; object_len -= consumed;

        /* OID constants are CFStringRef, so need to use CFStringCompare. */
        keyref = CFStringCreateWithBytesNoCopy(kCFAllocatorDefault,
                                               (unsigned char *)key,
                                               strlen(key),
                                               kCFStringEncodingMacRoman,
                                               false,
                                               kCFAllocatorNull);
        
        if (CFStringCompare(keyref,
                kSecOIDOrganizationalUnitName, 0) == kCFCompareEqualTo)
            key = "OU";
        else if (CFStringCompare(keyref,
                kSecOIDOrganizationName, 0) == kCFCompareEqualTo)
            key = "O";
        else if (CFStringCompare(keyref,
                kSecOIDLocalityName, 0) == kCFCompareEqualTo)
            key = "L";
        else if (CFStringCompare(keyref,
                kSecOIDStateProvinceName, 0) == kCFCompareEqualTo)
            key = "ST";
        else if (CFStringCompare(keyref,
                kSecOIDCountryName, 0) == kCFCompareEqualTo)
            key = "C";
        else if (CFStringCompare(keyref,
                kSecOIDEmailAddress, 0) == kCFCompareEqualTo)
            key = "E";
        else if (CFStringCompare(keyref,
                kSecOIDCommonName, 0) == kCFCompareEqualTo)
            key = "CN";

        CFRelease(keyref);

        /* Read value */
        SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &value, pool));
        ptr += consumed; object_len -= consumed;

        serf__log(ST_DEBUG, __FILE__, "Remaining: %d.\n", object_len);

        apr_hash_set(tgt, key, APR_HASH_KEY_STRING, value);
    }

    *o = tgt;
    return APR_SUCCESS;

cleanup:
    return status;
}

/* Reads date/time string formatted as "YYMMDDHHmmSSZ" and converts it to
   "MMM dd HH:mm:ss yyyy GMT". Allocate output string from pool.
   Example: in: 130821204210Z out:Aug 13 20:42:10 2013 GMT . */
static const char *
convert_cert_date(const char *in, apr_pool_t *pool)
{
    apr_size_t len;
    apr_time_exp_t te;
    const int bufsize = 64;
    char *datestr;

    memset(&te, 0, sizeof(te));

    datestr = apr_palloc(pool, bufsize);

    /* Read 2000+yy into 1900+100+yy */
    te.tm_year = 100 + (*in -'0') * 10 + *(in+1) - '0'; in+=2;
    te.tm_mon  = (*in -'0') * 10 + *(in+1) - '0' - 1; in+=2;
    te.tm_mday = (*in -'0') * 10 + *(in+1) - '0'; in+=2;
    te.tm_hour = (*in -'0') * 10 + *(in+1) - '0'; in+=2;
    te.tm_min  = (*in -'0') * 10 + *(in+1) - '0'; in+=2;
    te.tm_sec  = (*in -'0') * 10 + *(in+1) - '0'; in+=2;

    apr_strftime(datestr, &len, bufsize, "%b %d %T %Y GMT", &te);

    return datestr;
}

/* Calculate the sha1 hash value of data of length len. Resulting string will be
   allocated from pool and encoded as hex bytes : separated (A1:81:3F ... ). */
static const unsigned char *
sha1digest(const unsigned char *data, long len, apr_pool_t *pool)
{
    apr_sha1_ctx_t context;
    unsigned char *sha1 = apr_pcalloc(pool, APR_SHA1_DIGESTSIZE);
    unsigned char *sha1hex = apr_pcalloc(pool, APR_SHA1_DIGESTSIZE * 3);
    unsigned char *inptr = sha1, *outptr = sha1hex;
    const char al[] = "0123456789ABCDEF";
    int i;

    apr_sha1_init(&context);
    apr_sha1_update_binary(&context, data, len);
    apr_sha1_final(sha1, &context);

    /* concert to :-separated hex bytes */
    for (i = 0; i < APR_SHA1_DIGESTSIZE; i++) {
        unsigned char c = *inptr++;

        *outptr++ = al[(c & 0xf0) >> 4];
        *outptr++ = al[c & 0x0f];
        *outptr++ = ':';
    }
    *(outptr-1) = '\0';
    
    return sha1hex;
}

static apr_status_t dataref_cleanup(void *data)
{
    CFDataRef derdata = data;

    CFRelease(derdata);

    return APR_SUCCESS;
}

/* Read a Distinquished Name from a DER-encoded DN in X.509 format.
   The resulting hash table will have following keys:
   - CN, O, OU, L, ST, C, E.
   Internal use only:
   - _der
 */

apr_status_t
serf__sectrans_read_X509_DER_DN(apr_hash_t **o, CFDataRef dndata,
                                apr_pool_t *pool)
{
    CFDataRef dnder;
    apr_hash_t *dn;
    long consumed;
    const unsigned char *data = CFDataGetBytePtr(dndata);
    apr_status_t status;

    SERF_ERR(read_X509_DER_DistinguishedName(&dn, &dnder,
                                             data, &consumed, pool));

    apr_hash_set(dn, "_der", APR_HASH_KEY_STRING, dnder);

    *o = dn;

cleanup:
    return status;
}

/* Read all interesting data from a DER-encoded certificate in X.509 format.
   The resulting hash table will have following keys:
   - sha1
   - serial_number (TODO: not used, can be removed if that remains so. )
   - issuer: hash table with keys CN, O, OU, L, ST, C, E.
   - subject: hash table with keys CN, O, OU, L, ST, C, E. 
   - notBefore
   - notAfter
   Internal use only:
   - _issuer_der
   - _subject_der
 */
apr_status_t
serf__sectrans_read_X509_DER_certificate(apr_hash_t **o,
                                         const sectrans_certificate_t *cert,
                                         apr_pool_t *pool)
{
    apr_hash_t *x509_cert, *issuer, *subject;
    CFDataRef issuer_der, subject_der;
    long consumed, x509_len, value_len, signature_start;
    unsigned char tag;
    apr_status_t status;
    const char *serial, *tmp, *key, *value;
    const unsigned char *ptr, *sha1;
    int version;

    SecCertificateRef certref = cert->certref;
    CFDataRef dataref = SecCertificateCopyData(certref);
    const unsigned char *data = CFDataGetBytePtr(dataref);
    CFIndex totlen = CFDataGetLength(dataref);

    if (!totlen)
        return SERF_ERROR_SSL_CERT_FAILED;

    x509_cert = apr_hash_make(pool);

    /* SHA1 fingerprint of the full DER encoded cert. */
    sha1 = sha1digest(data, totlen, pool);
    apr_hash_set(x509_cert, "sha1", APR_HASH_KEY_STRING, sha1);
    serf__log(ST_DEBUG, __FILE__, "SHA1 fingerprint:%s.\n", sha1);

    ptr = data;
    /* 4.1.1  Certificate sequence */
    SERF_ERR(read_DER_TL(ptr, &tag, &x509_len, &consumed));
    ptr += consumed;
    signature_start = consumed;

    serf__log(ST_DEBUG, __FILE__, "Parsing DER encoding of cert length: %d.\n",
              x509_len + consumed);

    /* 4.1.2  TBSCertificate (required) */
    serf__log(ST_DEBUG, __FILE__, "---- TBSCertificate ----.\n");
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    ptr += consumed; x509_len -= consumed;
    signature_start += (value_len + consumed);

    /* 4.1.2.1  Version (optional, default v1 (0x00)) */
    serf__log(ST_DEBUG, __FILE__, "---- Version ----.\n");
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    if (tag == 0xa0) {
        ptr += consumed; x509_len -= consumed;
        SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &tmp, pool));
        version = atoi(tmp) + 1;
        ptr += consumed; x509_len -= consumed;
    } else {
        /* this was another tag than expected. Means that version wasn't set,
           used the default v1. */
        version = 1;
    }

    /* 4.1.2.2  Serial number */
    serf__log(ST_DEBUG, __FILE__, "---- Serial Number ----.\n");
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &serial, pool));
    ptr += consumed; x509_len -= consumed;
    apr_hash_set(x509_cert, "serial_number", APR_HASH_KEY_STRING, serial);

    /* 4.1.2.3  Signature (it's actually the Algorithm used to sign). */
    serf__log(ST_DEBUG, __FILE__, "---- Algorithm ----.\n");
    skip_DER_TLV(ptr, &tag, &consumed);
    ptr += consumed; x509_len -= consumed;

    /* 4.1.2.4  Issuer */
    serf__log(ST_DEBUG, __FILE__, "---- Issuer ----.\n");
    SERF_ERR(read_X509_DER_DistinguishedName(&issuer, &issuer_der,
                                             ptr, &consumed, pool));
    ptr += consumed; x509_len -= consumed;
    apr_hash_set(x509_cert, "issuer", APR_HASH_KEY_STRING, issuer);
    /* store the original der data buffer of the issuer, for internal use
       (comparison of certificates). */
    apr_hash_set(x509_cert, "_issuer_der", APR_HASH_KEY_STRING, issuer_der);

    /* 4.1.2.5  Validity */
    serf__log(ST_DEBUG, __FILE__, "---- Validity ----.\n");
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    ptr += consumed; x509_len -= consumed;

    /*          notBefore */
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &tmp, pool));
    ptr += consumed; x509_len -= consumed;
    apr_hash_set(x509_cert, "notBefore", APR_HASH_KEY_STRING,
                 convert_cert_date(tmp, pool));

    /*          notAfter */
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &tmp, pool));
    ptr += consumed; x509_len -= consumed;
    apr_hash_set(x509_cert, "notAfter", APR_HASH_KEY_STRING,
                 convert_cert_date(tmp, pool));

    /* 4.1.2.6  Subject */
    serf__log(ST_DEBUG, __FILE__, "---- Subject ----.\n");
    SERF_ERR(read_X509_DER_DistinguishedName(&subject, &subject_der,
                                             ptr, &consumed, pool));
    ptr += consumed; x509_len -= consumed;
    apr_hash_set(x509_cert, "subject", APR_HASH_KEY_STRING, subject);
    /* store the original der data buffer of the subject, for internal use
       (comparison of certificates). */
    apr_hash_set(x509_cert, "_subject_der", APR_HASH_KEY_STRING, subject_der);

    /* 4.1.2.7  Subject Public Key Info */
    serf__log(ST_DEBUG, __FILE__, "---- Subject Public Key Info ----.\n");
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    ptr += consumed; x509_len -= consumed;
    /*          AlgorithmIdentifier */
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    ptr += consumed; x509_len -= consumed;
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &key, pool));
    ptr += consumed; x509_len -= consumed;
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &value, pool));
    ptr += consumed; x509_len -= consumed;

    /* TODO: read subjectAltName's from extensions. */

    /* Skip the remainder of TBSCertificate*/
    ptr = data + signature_start;

#if 0 /* Not needed, cleanup if this remains so. */
    /* 4.1.1.2  signatureAlgorithm (required) */
    SERF_ERR(read_DER_TL(ptr, &tag, &value_len, &consumed));
    ptr += consumed; x509_len -= consumed;
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &key, pool));
    ptr += consumed; x509_len -= consumed;
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &value, pool));
    ptr += consumed; x509_len -= consumed;

    /* 4.1.1.3  signatureValue (required) */
    SERF_ERR(read_DER_TLvalue(ptr, &tag, &consumed, &value, pool));
    ptr += consumed; x509_len -= consumed;

    serf__log(ST_DEBUG, __FILE__, "Remaining to read: %d.\n", x509_len);
#endif

    *o = x509_cert;

    apr_pool_cleanup_register(pool, issuer_der, dataref_cleanup,
                              dataref_cleanup);
    apr_pool_cleanup_register(pool, subject_der, dataref_cleanup,
                              dataref_cleanup);

    return APR_SUCCESS;

cleanup:
    CFRelease(dataref);

    return status;
}

#endif /* SERF_HAVE_SECURETRANSPORT */
