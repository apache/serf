/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#ifndef SERF_METHODS_H
#define SERF_METHODS_H

/**
 * @file serf_methods.h
 * @brief Serf supported methods
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Methods List of Methods recognized by the serf client library.
 * @{
 */

typedef int serf_method_t;

/**
 * Commonly used methods.
 */
#define SERF_METHOD_GET                0      /* RFC 2616: HTTP */
#define SERF_METHOD_HEAD               1      /*  :             */
#define SERF_METHOD_PUT                2
#define SERF_METHOD_POST               3
#define SERF_METHOD_DELETE             4
#define SERF_METHOD_CONNECT            5
#define SERF_METHOD_OPTIONS            6
#define SERF_METHOD_TRACE              7      /* RFC 2616: HTTP */
#define SERF_METHOD_PROPFIND           8      /* RFC 2518: WebDAV */
#define SERF_METHOD_PROPPATCH          9      /*  :               */
#define SERF_METHOD_MKCOL             10
#define SERF_METHOD_COPY              11
#define SERF_METHOD_MOVE              12
#define SERF_METHOD_LOCK              13
#define SERF_METHOD_UNLOCK            14      /* RFC 2518: WebDAV */
#define SERF_METHOD_VERSION_CONTROL   15      /* RFC 3253: WebDAV Versioning */
#define SERF_METHOD_CHECKOUT          16      /*  :                          */
#define SERF_METHOD_UNCHECKOUT        17
#define SERF_METHOD_CHECKIN           18
#define SERF_METHOD_UPDATE            19
#define SERF_METHOD_LABEL             20
#define SERF_METHOD_REPORT            21
#define SERF_METHOD_MKWORKSPACE       22
#define SERF_METHOD_MKACTIVITY        23
#define SERF_METHOD_BASELINE_CONTROL  24
#define SERF_METHOD_MERGE             25
#define SERF_METHOD_INVALID           26      /* RFC 3253: WebDAV Versioning */

/**
 * SERF_BUILTIN_METHODS needs to be equal to the number of bits
 * we are using for limit masks.
 */
#define SERF_BUILTIN_METHODS     64

/**
 * The method mask bit to shift for anding with a bitmask.
 */
#define SERF_METHOD_BIT ((apr_int64_t)1)
/** @} */

/**
 * Structure for handling HTTP methods.  Methods known to the library are
 * accessed via a bitmask shortcut; extension methods are handled by an
 * array.
 */
struct serf_method_list_t {
    /* The bitmask used for known methods */
    apr_int64_t method_mask;
    /* the array used for extension methods */
    apr_array_header_t *method_list;
};
typedef struct serf_method_list_t serf_method_list_t;

/**
 * Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns SERF_METHOD_INVALID if not recognized.
 * @param method A string containing a valid HTTP method
 * @return The method number
 */
serf_method_t serf_method_number_of(const char *method);

/**
 * Get the method name associated with the given internal method
 * number.  Returns NULL if not recognized.
 * @param p A pool to use for temporary allocations.
 * @param methnum An integer value corresponding to an internal method number
 * @return The name corresponding to the method number
 */
const char * serf_method_name_of(apr_pool_t *pool, serf_method_t methnum);

#ifdef __cplusplus
}
#endif

#endif	/* !SERF_METHODS_H */
