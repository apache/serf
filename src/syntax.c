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
#include <apr_hash.h>

#define APR_WANT_STRFUNC
#include <apr_want.h>

#include "serf.h"
#include "serf_private.h"


/*******************************************************************/
/* Character class lookup */

static APR_INLINE int ct_isalnum(char c)
{
    return ((c >= '0' && c <= '9')
            || (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z'));
}

/* A `token` is a sequence of ASCII digits, lowercase and uppercase letters,
   and the following punctiation marks:

       ! # $ % & ' * + - . ^ _ ` | ~

   See: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2
*/
static APR_INLINE int ct_istoken(char c)
{
    static const char punct[] = "!#$%&'*+-.^_`|~";
    return c && (ct_isalnum(c) || strchr(punct, c));
}

/* A `token68` is a sequence of ASCII digits, lowercase and uppercase letters,
   and the following punctiation marks:

       - . _ ~ + /

   followed by zero or more `=` signs.
   See: https://www.rfc-editor.org/rfc/rfc9110.html#section-11.2
*/
static APR_INLINE int ct_istoken68(char c)
{
    static const char punct[] = "-._~+/";
    return c && (ct_isalnum(c) || strchr(punct, c));
}

/*******************************************************************/
/* Syntactic elements. */

/* Fold ASCII to lowercase. */
static APR_INLINE char ct_tolower(char c)
{
    /* FIXME: Shouid this just be replaced by apr_tolower?
              On the other hand, we should only case-fold ASCII letters,
              while apr_tolower() may be sensitive to the locale. */
    if (c >= 'A' && c <= 'Z')
        return (char)(c + 'a' - 'A');
    return c;
}

/* Skip spaces. */
static const char *skip_space(const char *src)
{
    /* In HTTP land, only tab and space count as whitespace. */
    return src + strspn(src, " \t");
}

/* Skip token68 */
static const char *skip_token68(const char *src)
{
    while (ct_istoken68(*src))
        ++src;
    while (*src == '=')
        ++src;
    return src;
}

#if 0
static const char *skip_comment(const char *src)
{
    if (*src != '(')
        return NULL;

    ++src;
    while (*src && *src != ')')
    {
        if (*src == '(') {
            src = skip_comment(src);
            if (!src)
                return NULL;
        }
        else {
            if (*src == '\\')
                ++src;          /* Skip escape from quoted-pair */
            if (*src)
                ++src;
        }
    }

    if (!*src)
        return NULL;
    return src + 1;
}
#endif

static const char *copy_quoted_string(char **dst, const char *src)
{
    if (*src != '"')
        return NULL;

    ++src;
    while (*src && *src != '"')
    {
        if (*src == '\\')
            ++src;              /* Skip escape from quoted-pair */
        if (*src)
            *((*dst)++) = *src++;
    }

    if (!*src)
        return NULL;
    return src + 1;
}

static const char *copy_token_key(char **dst, const char *src)
{
    if (!ct_istoken(*src))
        return NULL;

    do { *((*dst)++) = ct_tolower(*src++); } while (ct_istoken(*src));
    return src;
}

static const char *copy_token(char **dst, const char *src)
{
    if (!ct_istoken(*src))
        return NULL;

    do { *((*dst)++) = *src++; } while (ct_istoken(*src));
    return src;
}

/*******************************************************************/
/* Internal API */

apr_hash_t *serf__parse_authn_parameters(const char *attrs, apr_pool_t *pool)
{
    apr_hash_t *dict = apr_hash_make(pool);
    char *dst = apr_palloc(pool, strlen(attrs) + 1);
    const char *src = skip_space(attrs);
    const char *const end = skip_token68(src);

    /* Check if the parameters are a single token68. */
    if (end != src && !*skip_space(end)) {
        const apr_size_t len = end - src;
        memcpy(dst, src, len);
        dst[len] = '\0';
        apr_hash_set(dict, "", 0, dst);
        return dict;
    }

    while (src && *src)
    {
        const char *key;
        apr_ssize_t keylen;
        const char *value;

        /* Parse the key, a lower-cased token. */
        key = dst;
        src = copy_token_key(&dst, src);
        if (!src || key == dst || *src != '=')
            break;
        keylen = dst - key;
        *dst++ = '\0';

        /* Parse the value, either a token or a quoted string. */
        ++src;
        value = dst;
        if (*src == '"') {
            src = copy_quoted_string(&dst, src);
            if (!src)
                break;
        } else {
            src = copy_token(&dst, src);
            if (!src || value == dst)
                break;
        }
        *dst++ = '\0';

        /* Must be at the end of the string or at a valid separator. */
        src = skip_space(src);
        if (*src) {
            if (*src != ',')
                break;
            /* Skip the separator and any spaces after the separator. */
            src = skip_space(src + 1);
        }

        /* Put the new key/value pair into the dict. */
        apr_hash_set(dict, key, keylen, value);
    }

    return dict;
}


void serf__tolower_inplace(char *dst, apr_size_t length)
{
    apr_size_t i;
    for (i = 0; i < length; ++i)
        dst[i] = ct_tolower(dst[i]);
}


const char *serf__tolower(const char *src, apr_pool_t *pool)
{
    const apr_size_t len = strlen(src) + 1;
    apr_size_t i;

    char *dst = apr_palloc(pool, len);
    for (i = 0; i < len; ++i)
        dst[i] = ct_tolower(src[i]); /* The NUL byte is copied, too. */
    return dst;
}
