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

#include <stdlib.h>

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"
#include "protocols/http2_buckets.h"

#include "hpack_huffman.inc"
#define EOS_CHAR (256)

/* Callback for bsearch() */
static int
hpack_hm_compare(const void *k,
                 const void *i)
{
  const apr_uint32_t *key = k;
  const struct serf_hpack_huffman_item_t *it = i;

  apr_uint32_t k1 = (*key & it->hmask);
  apr_uint32_t k2 = it->hval;

  if (k1 < k2)
    return -1;
  else if (k1 > k2)
    return 1;
  else
    return 0;
}

/* Convert encoded data in ENCODED of size ENCODED_LEN. If TEXT is not
   NULL, put the result in the buffer pointed to by TEXT which is of size
   TEXT_AVAIL. Sets *TEXT_LEN to the resulting length.

   If TEXT_AVAIL allows it a final '\0' is added at TEXT[*TEXT_LEN].

   If TEXT is not large enough return APR_ENOMEM. If ENCODED isn't properly
   encoded return APR_EINVAL.
 */
apr_status_t
serf__hpack_huffman_decode(const unsigned char *encoded,
                           apr_size_t encoded_len,
                           apr_size_t text_avail,
                           char *text,
                           apr_size_t *text_len)
{
  apr_uint64_t stash = 0;
  apr_int16_t bits_left = 0;
  apr_size_t result_len = 0;

  while (encoded_len || bits_left)
    {
      apr_uint32_t match;
      struct serf_hpack_huffman_item_t *r;

      while (bits_left < 30 && encoded_len)
        {
          stash |= (apr_uint64_t)*encoded << (64 - 8 - bits_left);
          bits_left += 8;
          encoded_len--;
          encoded++;
        }

      match = stash >> 32;
      r = bsearch(&match, &serf_hpack_hm_map,
                  sizeof(serf_hpack_hm_map) / sizeof(serf_hpack_hm_map[0]),
                  sizeof(serf_hpack_hm_map[0]), hpack_hm_compare);

      if (!r || (r->bits > bits_left))
        {
          /* With a canonical huffman code we can only reach this state
             at the end of the string */
          break;
        }

      if (r->cval == EOS_CHAR)
        return APR_EINVAL;

      if (text)
        {
          if (result_len < text_avail)
            text[result_len] = (char)r->cval;
          else
            return APR_ENOMEM;
        }

      result_len++;
      stash <<= r->bits;
      bits_left -= r->bits;
    }

  if (bits_left)
    {
      /* https://tools.ietf.org/html/rfc7541#section-5.2

         Upon decoding, an incomplete code at the end of the encoded data is
         to be considered as padding and discarded.  A padding strictly longer
         than 7 bits MUST be treated as a decoding error.  A padding not
         corresponding to the most significant bits of the code for the EOS
         symbol MUST be treated as a decoding error.  A Huffman-encoded string
         literal containing the EOS symbol MUST be treated as a decoding
         error. */
      const struct serf_hpack_huffman_item_t *eos;
      apr_uint64_t exp_stash;

      eos = &serf_hpack_hm_map[serf_hpack_hm_rmap[EOS_CHAR]];

      /* Trim EOS value to the bits we need */
      exp_stash = ((apr_uint32_t)eos->hval >> (32 - bits_left));
      /* And move it to the right position */
      exp_stash <<= 64 - bits_left;

      if (exp_stash != stash)
        return APR_EINVAL;
    }

  *text_len = result_len;
  if (text && result_len < text_avail)
    text[result_len] = 0;

  return APR_SUCCESS;
}

/* Encodes data in TEXT of size TEXT_LEN.

   Sets ENCODED_LEN to the required length.

   If ENCODED is not NULL, it specifies an output buffer of size
   ENCODED_AVAIL into which the data will be encoded.

   If ENCODE is not NULL and the data doesn't fit returns APR_ENOMEM.
 */
apr_status_t
serf__hpack_huffman_encode(const char *text,
                           apr_size_t text_len,
                           apr_size_t encoded_avail,
                           unsigned char *encoded,
                           apr_size_t *encoded_len)
{
  apr_uint64_t stash = 0;
  apr_int16_t bits_left = 0;
  apr_size_t result_len = 0;

  if (! encoded)
    {
      /* Just calculating size needed. Avoid bit handling */
      apr_int64_t result_bits = 0;
      while (text_len)
        {
          const struct serf_hpack_huffman_item_t *r;

          r = &serf_hpack_hm_map[serf_hpack_hm_rmap[*(unsigned char*)text]];

          result_bits += r->bits;
          text_len--;
          text++;
        }

      *encoded_len = (apr_size_t)((result_bits+7) / 8);
      return APR_SUCCESS;
    }

  while (text_len)
    {
      if (text_len)
        {
          const struct serf_hpack_huffman_item_t *r;

          r = &serf_hpack_hm_map[serf_hpack_hm_rmap[*(unsigned char*)text]];

          stash |= (apr_uint64_t)r->hval << (64 - 32 - bits_left);
          bits_left += r->bits;
          text_len--;
          text++;
        }

      while (bits_left > 8)
        {
          if (! encoded_avail)
            return APR_ENOMEM;

          *encoded = (unsigned char)(stash >> (64 - 8));
          encoded++;
          stash <<= 8;
          bits_left -= 8;

          encoded_avail--;
          result_len++;
        }
    }

  if (bits_left)
    {
      /* https://tools.ietf.org/html/rfc7541#section-5.2

         As the Huffman-encoded data doesn't always end at an octet boundary,
         some padding is inserted after it, up to the next octet boundary.  To
         prevent this padding from being misinterpreted as part of the string
         literal, the most significant bits of the code corresponding to the
         EOS (end-of-string) symbol are used. */
      const struct serf_hpack_huffman_item_t *r;

      if (! encoded_avail)
        return APR_ENOMEM;

      r = &serf_hpack_hm_map[serf_hpack_hm_rmap[EOS_CHAR]];
      stash |= (apr_uint64_t)r->hval << (64 - 32 - bits_left);
      /* bits_left += r->bits; */

      *encoded = (unsigned char)(stash >> (64 - 8));
      /* encoded++ */
      /* stash <<= 8; */
      /* bits_left -= 8; */
      /* encoded_avail--; */
      result_len++;
    }

  *encoded_len = result_len;

  return APR_SUCCESS;
}

/* ==================================================================== */

typedef struct serf_hpack_entry_t
{
  const char *key;
  apr_size_t key_len;
  const char *value;
  apr_size_t value_len;

  struct serf_hpack_entry_t *next;
  struct serf_hpack_entry_t *prev;

  char free_key; /* Key must be freed */
  char free_val; /* Value must be freed */
  char dont_index; /* 0=index, 1=no-index, 2=never-index */
} serf_hpack_entry_t;

static void hpack_free_entry(serf_hpack_entry_t *entry,
                             serf_bucket_alloc_t *alloc)
{
  if (entry->free_key)
    serf_bucket_mem_free(alloc, (char*)entry->key);
  if (entry->free_val)
    serf_bucket_mem_free(alloc, (char*)entry->value);
  serf_bucket_mem_free(alloc, entry);
}

/* https://tools.ietf.org/html/rfc7541#section-4.1 

  The size of an entry is the sum of its name's length in octets (as
  defined in Section 5.2), its value's length in octets, and 32.

  The size of an entry is calculated using the length of its name and
  value without any Huffman encoding applied.
*/
#define HPACK_ENTRY_SIZE(hi) ((hi)->key_len + (hi)->value_len + 32)
/* The per key, value variant of HPACK_ENTRY_SIZE */
#define HPACK_KEY_SIZE(key_sz) ((key_sz) + 16)

struct serf_hpack_table_t
{
  apr_pool_t *pool;
  serf_bucket_alloc_t *alloc;

  char lowercase_keys;
  char send_tablesize_update;

  /* The local -> remote 'encoder' list */
  serf_hpack_entry_t *lr_first, *lr_last, *lr_start;
  unsigned int lr_count; /* Number of items (first..last) */
  unsigned int lr_indexable; /* Number of items (start..last) */
  apr_size_t lr_size; /* 'Bytes' in list, calculated by HPACK_ENTRY_SIZE() */
  apr_size_t lr_max_table_size;
  apr_size_t lr_sys_table_size;

  serf_hpack_entry_t *rl_first, *rl_last, *rl_start;
  unsigned int rl_count; /* Number of items (first..last) */
  unsigned int rl_indexable; /* Number of items (start..last) */
  apr_size_t rl_size; /* 'Bytes' in list, calculated by HPACK_ENTRY_SIZE() */
  apr_size_t rl_max_table_size;
  apr_size_t rl_sys_table_size;
};

/* The staticly defined list of pre-encoded entries. All numbers above
   this list are dynamically defined, so some new standard is needed to
   extend this list */
static const serf_hpack_entry_t hpack_static_table[] =
{
#define HPACK_STR(x)   x, (sizeof(x)-1)
  {/* 1*/ HPACK_STR(":authority"),                 HPACK_STR("")},
  {/* 2*/ HPACK_STR(":method"),                    HPACK_STR("GET")},
  {/* 3*/ HPACK_STR(":method"),                    HPACK_STR("POST")},
  {/* 4*/ HPACK_STR(":path"),                      HPACK_STR("/")},
  {/* 5*/ HPACK_STR(":path"),                      HPACK_STR("/index.html") },
  {/* 6*/ HPACK_STR(":scheme"),                    HPACK_STR("http")},
  {/* 7*/ HPACK_STR(":scheme"),                    HPACK_STR("https")},
  {/* 8*/ HPACK_STR(":status"),                    HPACK_STR("200")},
  {/* 9*/ HPACK_STR(":status"),                    HPACK_STR("204")},
  {/*10*/ HPACK_STR(":status"),                    HPACK_STR("206")},
  {/*11*/ HPACK_STR(":status"),                    HPACK_STR("304")},
  {/*12*/ HPACK_STR(":status"),                    HPACK_STR("400")},
  {/*13*/ HPACK_STR(":status"),                    HPACK_STR("404")},
  {/*14*/ HPACK_STR(":status"),                    HPACK_STR("500")},
  {/*15*/ HPACK_STR("accept-charset"),             HPACK_STR("")},
  {/*16*/ HPACK_STR("accept-encoding"),            HPACK_STR("gzip, deflate")},
  {/*17*/ HPACK_STR("accept-language"),            HPACK_STR("")},
  {/*18*/ HPACK_STR("accept-ranges"),              HPACK_STR("")},
  {/*19*/ HPACK_STR("accept"),                     HPACK_STR("")},
  {/*20*/ HPACK_STR("access-control-allow-origin"),HPACK_STR("")},
  {/*21*/ HPACK_STR("age"),                        HPACK_STR("")},
  {/*22*/ HPACK_STR("allow"),                      HPACK_STR("")},
  {/*23*/ HPACK_STR("authorization"),              HPACK_STR("")},
  {/*24*/ HPACK_STR("cache-control"),              HPACK_STR("")},
  {/*25*/ HPACK_STR("content-disposition"),        HPACK_STR("")},
  {/*26*/ HPACK_STR("content-encoding"),           HPACK_STR("")},
  {/*27*/ HPACK_STR("content-language"),           HPACK_STR("")},
  {/*28*/ HPACK_STR("content-length"),             HPACK_STR("")},
  {/*29*/ HPACK_STR("content-location"),           HPACK_STR("")},
  {/*30*/ HPACK_STR("content-range"),              HPACK_STR("")},
  {/*31*/ HPACK_STR("content-type"),               HPACK_STR("")},
  {/*32*/ HPACK_STR("cookie"),                     HPACK_STR("")},
  {/*33*/ HPACK_STR("date"),                       HPACK_STR("")},
  {/*34*/ HPACK_STR("etag"),                       HPACK_STR("")},
  {/*35*/ HPACK_STR("expect"),                     HPACK_STR("")},
  {/*36*/ HPACK_STR("expires"),                    HPACK_STR("")},
  {/*37*/ HPACK_STR("from"),                       HPACK_STR("")},
  {/*38*/ HPACK_STR("host"),                       HPACK_STR("")},
  {/*39*/ HPACK_STR("if-match"),                   HPACK_STR("")},
  {/*40*/ HPACK_STR("if-modified-since"),          HPACK_STR("")},
  {/*41*/ HPACK_STR("if-none-match"),              HPACK_STR("")},
  {/*42*/ HPACK_STR("if-range"),                   HPACK_STR("")},
  {/*43*/ HPACK_STR("if-unmodified-since"),        HPACK_STR("")},
  {/*44*/ HPACK_STR("last-modified"),              HPACK_STR("")},
  {/*45*/ HPACK_STR("link"),                       HPACK_STR("")},
  {/*46*/ HPACK_STR("location"),                   HPACK_STR("")},
  {/*47*/ HPACK_STR("max-forwards"),               HPACK_STR("")},
  {/*48*/ HPACK_STR("proxy-authenticate"),         HPACK_STR("")},
  {/*49*/ HPACK_STR("proxy-authorization"),        HPACK_STR("")},
  {/*50*/ HPACK_STR("range"),                      HPACK_STR("")},
  {/*51*/ HPACK_STR("referer"),                    HPACK_STR("")},
  {/*52*/ HPACK_STR("refresh"),                    HPACK_STR("")},
  {/*53*/ HPACK_STR("retry-after"),                HPACK_STR("")},
  {/*54*/ HPACK_STR("server"),                     HPACK_STR("")},
  {/*55*/ HPACK_STR("set-cookie"),                 HPACK_STR("")},
  {/*56*/ HPACK_STR("strict-transport-security"),  HPACK_STR("")},
  {/*57*/ HPACK_STR("transfer-encoding"),          HPACK_STR("")},
  {/*58*/ HPACK_STR("user-agent"),                 HPACK_STR("")},
  {/*59*/ HPACK_STR("vary"),                       HPACK_STR("")},
  {/*60*/ HPACK_STR("via"),                        HPACK_STR("")},
  {/*61*/ HPACK_STR("www-authenticate"),           HPACK_STR("")}
#undef HPACK_STR
};
static const apr_uint64_t hpack_static_table_count =
      (sizeof(hpack_static_table) / sizeof(hpack_static_table[0]));

static apr_status_t
cleanup_hpack_table(void *data)
{
#ifdef _DEBUG
  serf_hpack_table_t *tbl = data;
  serf_hpack_entry_t *hi, *next;

  /* This is not really necessary, as we create our own allocator,
     which lives in the same pool. But it helps tracking down
     memory leaks in different locations */
  for (hi = tbl->lr_first; hi; hi = next)
    {
      next = hi->next;

      hpack_free_entry(hi, tbl->alloc);
    }
  tbl->lr_first = tbl->lr_start = tbl->lr_last = NULL;
  tbl->lr_size = 0;

  for (hi = tbl->rl_first; hi; hi = next)
    {
      next = hi->next;

      hpack_free_entry(hi, tbl->alloc);
    }
  tbl->rl_first = tbl->rl_start = tbl->rl_last = NULL;
  tbl->rl_size = 0;
#endif
  return APR_SUCCESS;
}


serf_hpack_table_t *
serf__hpack_table_create(int for_http2,
                         apr_size_t default_max_table_size,
                         apr_pool_t *result_pool)
{
  serf_hpack_table_t *tbl = apr_pcalloc(result_pool, sizeof(*tbl));

  tbl->pool = result_pool;
  tbl->alloc = serf_bucket_allocator_create(result_pool, NULL, NULL);

  /* We register this this after creating the allocator, or we would touch
     memory that is already freed.*/
  apr_pool_cleanup_register(result_pool, tbl, cleanup_hpack_table,
                            apr_pool_cleanup_null);

  tbl->lr_sys_table_size = tbl->lr_max_table_size = default_max_table_size;
  tbl->rl_sys_table_size = tbl->rl_max_table_size = default_max_table_size;

  tbl->lowercase_keys = FALSE;
  tbl->send_tablesize_update = FALSE;

  if (for_http2)
    {
      /* HTTP2 (aka RFC7540) has some additional rules on how it uses HPACK
         (aka RFC7541), most notably that all header keys *MUST* be lowercase.

         Let's keep this thing generic and keep this as a configuration knob.
       */
      tbl->lowercase_keys = TRUE;
    }

  return tbl;
}

static void
hpack_shrink_table(serf_hpack_entry_t **first,
                   serf_hpack_entry_t **start,
                   serf_hpack_entry_t **last,
                   apr_size_t *size,
                   apr_size_t max_size,
                   serf_bucket_alloc_t *allocator)
{
  while (*last && (*size > max_size))
    {
      serf_hpack_entry_t *entry = *last;

      *last = entry->prev;

      if (start && (*start == entry))
        *start = NULL;
      if (first && (*first == entry))
        *first = NULL;

      if (entry->prev)
        entry->prev->next = NULL;

      *size -= HPACK_ENTRY_SIZE(entry);
      hpack_free_entry(entry, allocator);
    }
}

void
serf__hpack_table_set_max_table_size(serf_hpack_table_t *hpack_tbl,
                                     apr_size_t max_decoder_size,
                                     apr_size_t max_encoder_size)
{
  if (max_decoder_size != hpack_tbl->rl_sys_table_size)
    {
      hpack_tbl->rl_sys_table_size = max_decoder_size;
    }

  if (max_encoder_size != hpack_tbl->lr_max_table_size)
    {
      hpack_tbl->lr_sys_table_size = max_encoder_size;

      if (max_encoder_size > (128 * 1024))
        max_encoder_size = (128 * 1024);

      if (max_encoder_size < hpack_tbl->lr_max_table_size)
        hpack_tbl->send_tablesize_update = TRUE;

      hpack_shrink_table(&hpack_tbl->lr_first, &hpack_tbl->lr_start,
                         &hpack_tbl->lr_last, &hpack_tbl->lr_size,
                         hpack_tbl->lr_max_table_size, hpack_tbl->alloc);
    }
}

static apr_status_t
hpack_table_size_update(serf_hpack_table_t *hpack_tbl,
                        apr_size_t size)
{
  if (size <= hpack_tbl->rl_sys_table_size)
    {
      hpack_tbl->rl_max_table_size = size;

      hpack_shrink_table(&hpack_tbl->rl_first, &hpack_tbl->rl_start,
                         &hpack_tbl->rl_last, &hpack_tbl->rl_size,
                         hpack_tbl->rl_max_table_size, hpack_tbl->alloc);
    }
  else
    return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

  return APR_SUCCESS;
}

static apr_status_t
hpack_table_get(apr_uint32_t v,
                serf_hpack_table_t *tbl,
                const char **key,
                apr_size_t *key_size,
                const char **value,
                apr_size_t *value_size)
{
  const serf_hpack_entry_t *entry = NULL;
  if (v == 0)
    return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

  v--;
  if (v < hpack_static_table_count)
    entry = &hpack_static_table[v];
  else
    {
      serf_hpack_entry_t *i;
      v -= sizeof(hpack_static_table) / sizeof(hpack_static_table[0]);

      for (i = tbl->rl_start; i; i = i->next)
        {
          if (!v)
            {
              entry = i;
              break;
            }
          v--;
        }
    }

  if (!entry)
    return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

  if (key)
    *key = entry->key;
  if (key_size)
    *key_size = entry->key_len;
  if (value)
    *value = entry->value;
  if (value_size)
    *value_size = entry->value_len;

  return APR_SUCCESS;
}

typedef struct serf_hpack_context_t
{
  serf_hpack_table_t *tbl;

  serf_hpack_entry_t *first;
  serf_hpack_entry_t *last;
} serf_hpack_context_t;

static apr_status_t
hpack_copy_from_headers(void *baton,
                        const char *key,
                        const char *value)
{
  serf_bucket_t *hpack = baton;
  apr_size_t key_sz = strlen(key);

  /* TODO: Others? */
  if ((key_sz == 4 && !strcasecmp(key, "Host"))
      || (key_sz == 7 && !strcasecmp(key, "Upgrade"))
      || (key_sz == 10 && !strcasecmp(key, "Keep-Alive"))
      || (key_sz == 10 && !strcasecmp(key, "Connection"))
      || (key_sz > 11 && !strncasecmp(key, "Connection-", 11))
      || (key_sz == 16 && !strcasecmp(key, "Proxy-Connection"))
      || (key_sz == 17 && !strcasecmp(key, "Transfer-Encoding")))
    {
      return APR_SUCCESS;
    }

  serf__bucket_hpack_setc(hpack, key, value);

  return APR_SUCCESS;
}


apr_status_t
serf__bucket_hpack_create_from_request(serf_bucket_t **new_hpack_bucket,
                                       serf_hpack_table_t *hpack_table,
                                       serf_bucket_t *request,
                                       const char *scheme,
                                       serf_bucket_alloc_t *allocator)
{
  const char *uri, *method, *host;

  serf_bucket_t *hpack = serf__bucket_hpack_create(hpack_table, allocator);

  serf_bucket_t *headers = serf_bucket_request_get_headers(request);

  host = serf_bucket_headers_get(headers, "Host");

  serf__bucket_request_read(request, NULL, &uri, &method);

  serf__bucket_hpack_setc(hpack, ":method", method);
  serf__bucket_hpack_setc(hpack, ":scheme", scheme);
  serf__bucket_hpack_setc(hpack, ":authority", host);
  serf__bucket_hpack_setc(hpack, ":path", uri);

  serf_bucket_headers_do(headers, hpack_copy_from_headers, hpack);

  *new_hpack_bucket = hpack;

  return APR_SUCCESS;
}


serf_bucket_t *
serf__bucket_hpack_create(serf_hpack_table_t *hpack_table,
                          serf_bucket_alloc_t *allocator)
{
  serf_hpack_context_t *ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));

  ctx->tbl = hpack_table;
  ctx->first = ctx->last = NULL;

  return serf_bucket_create(&serf_bucket_type__hpack, allocator, ctx);
}

void 
serf__bucket_hpack_setc(serf_bucket_t *hpack_bucket,
                        const char *key,
                        const char *value)
{
  serf__bucket_hpack_setx(hpack_bucket,
                          key, strlen(key), TRUE,
                          value, strlen(value), TRUE,
                          FALSE, FALSE);
}

void
serf__bucket_hpack_setx(serf_bucket_t *bucket,
                        const char *key,
                        apr_size_t key_size,
                        int key_copy,
                        const char *value,
                        apr_size_t value_size,
                        int value_copy,
                        int dont_index,
                        int never_index)
{
  serf_hpack_context_t *ctx = bucket->data;
  serf_hpack_entry_t *entry;
  apr_size_t i;

  for (entry = ctx->first; entry; entry = entry->next)
    {
      if (key_size == entry->key_len
          && !strncasecmp(key, entry->key, key_size))
        {
          break;
        }
    }

  /* TODO: Handle *_copy by keeping some flags */

  if (entry && value[0] == ':')
    {
      if (entry->free_val)
        serf_bucket_mem_free(bucket->allocator, (void*)entry->value);

      entry->value = serf_bstrmemdup(bucket->allocator, value, value_size);
      entry->value_len = value_size;
      entry->free_val = TRUE;
      entry->dont_index = never_index ? 2 : (dont_index ? 1 : 0);

      return;
    }
  else if (entry)
    {
      /* We probably want to allow duplicate *and* join behavior? */
    }

  entry = serf_bucket_mem_calloc(bucket->allocator, sizeof(*entry));

  if (ctx->tbl && ctx->tbl->lowercase_keys)
    {
      /* https://tools.ietf.org/html/rfc7540#section-8.1.2
         Just as in HTTP/1.x, header field names are strings of ASCII
         characters that are compared in a case-insensitive fashion.  However,
         header field names MUST be converted to lowercase prior to their
         encoding in HTTP/2.  A request or response containing uppercase
         header field names MUST be treated as malformed (Section 8.1.2.6). */

      char *ckey = serf_bstrmemdup(bucket->allocator, key, key_size);
      for (i = 0; i < key_size; i++)
        {
          if (ckey[i] >= 'A' && key[i] <= 'Z')
            ckey[i] += ('a' - 'A');
        }
      entry->key = ckey;
      entry->free_key = TRUE;
    }
  else if (!key_copy)
    {
      entry->key = key;
      entry->free_key = FALSE;
    }
  else
    {
      entry->key = serf_bstrmemdup(bucket->allocator, key, key_size);
      entry->free_key = TRUE;
    }

  entry->key_len = key_size;
  if (value_copy)
    {
      entry->value = serf_bstrmemdup(bucket->allocator, value, value_size);
      entry->free_val = TRUE;
    }
  else
    {
      entry->value = value;
      entry->free_val = FALSE;
    }
  entry->value_len = value_size;
  entry->dont_index = never_index ? 2 : (dont_index ? 1 : 0);

  entry->prev = ctx->last;
  entry->next = NULL;
  if (ctx->last)
    {
      ctx->last->next = entry;
      ctx->last = entry;
    }
  else
    ctx->first = ctx->last = entry;
}

const char *serf__bucket_hpack_getc(serf_bucket_t *hpack_bucket,
                                    const char *key)
{
  serf_hpack_context_t *ctx = hpack_bucket->data;
  serf_hpack_entry_t *entry;
  apr_size_t key_len = strlen(key);

  for (entry = ctx->first; entry; entry = entry->next)
    {
      if (key_len == entry->key_len
          && !strncasecmp(key, entry->key, key_len))
      {
        return entry->value;
      }
    }

  return NULL;
}

void serf__bucket_hpack_do(serf_bucket_t *hpack_bucket,
                           serf_bucket_hpack_do_callback_fn_t func,
                           void *baton)
{
  serf_hpack_context_t *ctx = hpack_bucket->data;
  serf_hpack_entry_t *entry;

  for (entry = ctx->first; entry; entry = entry->next)
    {
      if (func(baton, entry->key, entry->key_len, entry->value, entry->value_len))
        break;
    }
}

static void hpack_int(unsigned char flags, int bits, apr_uint32_t value, char to[6], apr_size_t *used)
{
  unsigned char max_direct;
  apr_size_t u;

  flags = flags & ~((1 << bits) - 1);

  max_direct = (unsigned char)(((apr_uint16_t)1 << bits) - 1);

  if (value < max_direct)
    {
      to[0] = flags | (unsigned char)value;
      *used = 1;
      return;
    }

  to[0] = flags | max_direct;
  value -= max_direct;
  u = 1;

  while (value >= 0x80)
    {
      to[u++] = (value & 0x7F) | 0x80;
      value >>= 7;
    }

  to[u++] = (unsigned char)value;
  *used = u;
}

static apr_status_t
serialize(serf_bucket_t *bucket)
{
  /* Quick and dirty write out headers for V2

     Needs A LOT of improvement.

     Currently implements a complete in memory copy to the least
     efficient HTTP2 / HPACK header format 
   */
  serf_hpack_context_t *ctx = bucket->data;
  serf_bucket_alloc_t *alloc = bucket->allocator;
  serf_hpack_table_t *tbl = ctx->tbl;

  serf_hpack_entry_t *entry;
  serf_hpack_entry_t *next;

  char *buffer = NULL;
  apr_size_t offset = 0;
  const apr_size_t chunksize = 2048; /* Wild guess */

  /* Put on our aggregate bucket cloak */
  serf_bucket_aggregate_become(bucket);

  /* Is there a tablesize update queued? */
  if (tbl && tbl->send_tablesize_update)
    {
      apr_size_t len;

      buffer = serf_bucket_mem_alloc(alloc, chunksize);

      hpack_int(0x20, 5, tbl->lr_max_table_size, buffer+offset, &len);
      offset += len;
      tbl->send_tablesize_update = FALSE;
    }

  for (entry = ctx->first; entry; entry = next)
    {
      apr_status_t status;
      apr_size_t len;

      next = entry->next;

      /* Make 100% sure the next entry will fit.
         ### Temporarily wastes ram
       */
      if (!buffer || (HPACK_ENTRY_SIZE(entry) > chunksize - offset))
        {
          if (offset)
            {
              serf_bucket_aggregate_append(
                    bucket,
                    serf_bucket_simple_own_create(buffer, offset, alloc));
            }

          buffer = serf_bucket_mem_alloc(alloc, MAX(chunksize,
                                                    HPACK_ENTRY_SIZE(entry)));
          offset = 0;
        }

      /* Literal header, no indexing (=has a name) */
      hpack_int(0x40, 6, 0, buffer+offset, &len);
      offset += len;

      /* ### TODO: Check if we can refer key or key+value by index */

      /* To huff or not... */
      status = serf__hpack_huffman_encode(entry->key, entry->key_len,
                                          0, NULL, &len);
      if (!status && len < entry->key_len)
        {
          apr_size_t int_len;

          /* It is more efficient to huffman encode */
          hpack_int(0x80, 7, len, buffer + offset, &int_len);
          offset += int_len;

          status = serf__hpack_huffman_encode(entry->key, entry->key_len,
                                              len,
                                              (void*)(buffer + offset), &len);
          offset += len;

          if (status)
            return status;
        }
      else
        {
          /* It is more efficient not to encode */
          hpack_int(0, 7, entry->key_len, buffer + offset, &len);
          offset += len;

          memcpy(buffer + offset, entry->key, entry->key_len);
          offset += entry->key_len;
        }

      /* To huff or not... */
      status = serf__hpack_huffman_encode(entry->value, entry->value_len,
                                          0, NULL, &len);
      if (!status && len < entry->key_len)
        {
          apr_size_t int_len;

          /* It is more efficient to huffman encode */
          hpack_int(0x80, 7, len, buffer + offset, &int_len);
          offset += int_len;

          status = serf__hpack_huffman_encode(entry->value, entry->value_len,
                                              len,
                                              (void*)(buffer + offset), &len);
          offset += len;

          if (status)
            return status;
        }
      else
        {
          /* It is more efficient not to encode */
          hpack_int(0, 7, entry->value_len, buffer + offset, &len);
          offset += len;

          memcpy(buffer + offset, entry->value, entry->value_len);
          offset += entry->value_len;
        }

      /* And now free the item */
      hpack_free_entry(entry, alloc);
    }
  ctx->first = ctx->last = NULL;

  if (buffer)
    {
      if (offset)
        {
          serf_bucket_aggregate_append(
            bucket,
            serf_bucket_simple_own_create(buffer, offset, alloc));
        }
      else
        serf_bucket_mem_free(alloc, buffer);
    }

  serf_bucket_mem_free(alloc, ctx);

  return APR_SUCCESS;
}

static apr_status_t
serf_hpack_read(serf_bucket_t *bucket,
                apr_size_t requested,
                const char **data,
                apr_size_t *len)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return bucket->type->read(bucket, requested, data, len);
}

static apr_status_t
serf_hpack_read_iovec(serf_bucket_t *bucket,
                      apr_size_t requested,
                      int vecs_size,
                      struct iovec *vecs,
                      int *vecs_used)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return bucket->type->read_iovec(bucket, requested, vecs_size, vecs,
                                  vecs_used);
}

static apr_status_t
serf_hpack_peek(serf_bucket_t *bucket,
                const char **data,
                apr_size_t *len)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return bucket->type->peek(bucket, data, len);
}


static apr_uint64_t
serf_hpack_get_remaining(serf_bucket_t *bucket)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return SERF_LENGTH_UNKNOWN;

  /* This assumes that the aggregate is a v2 bucket */
  return bucket->type->get_remaining(bucket);
}


static void
serf_hpack_destroy_and_data(serf_bucket_t *bucket)
{
  serf_hpack_context_t *ctx = bucket->data;
  serf_hpack_entry_t *hi;
  serf_hpack_entry_t *next;

  for (hi = ctx->first; hi; hi = next)
    {
      next = hi->next;

      hpack_free_entry(hi, bucket->allocator);
    }

  serf_default_destroy_and_data(bucket);
}


/* ### need to implement */
#define serf_hpack_readline NULL

const serf_bucket_type_t serf_bucket_type__hpack = {
  "HPACK",
  serf_hpack_read,
  serf_hpack_readline,
  serf_hpack_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_hpack_peek,
  serf_hpack_destroy_and_data,
  serf_default_read_bucket,
  serf_hpack_get_remaining,
  serf_default_ignore_config,
};

/* ==================================================================== */

typedef struct serf_hpack_decode_ctx_t
{
  serf_hpack_table_t *tbl;

  serf_bucket_t *stream;
  apr_size_t header_allowed;

  apr_status_t(*item_callback)(void *baton,
                               const char *key,
                               apr_size_t key_size,
                               const char *value,
                               apr_size_t value_size);
  void *item_baton;

  char *buffer;
  apr_size_t buffer_size;
  apr_size_t buffer_used;

  const char *key; /* Allocated in tbl->alloc */
  apr_size_t key_size;
  const char *val; /* Allocated in tbl->alloc */
  apr_size_t val_size;
  char index_item;
  char key_hm;
  char val_hm;
  apr_uint32_t reuse_item;

  enum
  {
    HPACK_DECODE_STATE_INITIAL = 0,
    HPACK_DECODE_STATE_INDEX,
    HPACK_DECODE_STATE_KEYINDEX,
    HPACK_DECODE_STATE_KEY_LEN,
    HPACK_DECODE_STATE_KEY,
    HPACK_DECODE_STATE_VALUE_LEN,
    HPACK_DECODE_STATE_VALUE,
    HPACK_DECODE_TABLESIZE_UPDATE
  } state;
  
  /* When producing HTTP/1.1 style output */
  serf_bucket_t *agg;
  serf_databuf_t databuf;
  serf_config_t *config;

  char wrote_header;
  char hit_eof;
} serf_hpack_decode_ctx_t;

/* Forward definition */
static apr_status_t
hpack_decode_databuf_reader(void *baton,
                            apr_size_t bufsize,
                            char *buf,
                            apr_size_t *len);

serf_bucket_t *
serf__bucket_hpack_decode_create(serf_bucket_t *stream,
                                 apr_status_t (*item_callback)(
                                        void *baton,
                                        const char *key,
                                        apr_size_t key_size,
                                        const char *value,
                                        apr_size_t value_size),
                                 void *item_baton,
                                 apr_size_t max_header_size,
                                 serf_hpack_table_t *hpack_table,
                                 serf_bucket_alloc_t *alloc)
{
  serf_hpack_decode_ctx_t *ctx = serf_bucket_mem_calloc(alloc, sizeof(*ctx));

  ctx->tbl = hpack_table;
  ctx->stream = stream;
  ctx->header_allowed = max_header_size;

  /* The buffer should be large enough to keep a *compressed* key
     or value and will be resized if necessary.

     Longer keys are more likely to use compression, so the default
     should be enough for simple requests.

     (It is also used for compressed integer values, but there 10 bytes
      should be enough to store a uint64 with 7 bits/byte) */
  ctx->buffer_size = 128;
  ctx->buffer_used = 0;
  ctx->buffer = serf_bucket_mem_alloc(alloc, ctx->buffer_size);

  if (item_callback)
    {
      ctx->item_callback = item_callback;
      ctx->item_baton = item_baton;
      ctx->agg = NULL;
    }
  else
    {
      ctx->item_callback = NULL;
      ctx->item_baton = NULL;
      ctx->agg = serf_bucket_aggregate_create(alloc);

      serf_databuf_init(&ctx->databuf);
      ctx->databuf.read = hpack_decode_databuf_reader;
      ctx->databuf.read_baton = ctx;
    }

  /* Prepare TBL for decoding */
  ctx->tbl->rl_start = ctx->tbl->rl_first;
  ctx->tbl->rl_indexable = ctx->tbl->rl_count;

  return serf_bucket_create(&serf_bucket_type__hpack_decode, alloc, ctx);
}

static void
hpack_decode_buffer_ensure(serf_bucket_t *bucket,
                           apr_size_t minsize)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  char *new_buffer;

  if (minsize < ctx->buffer_size)
    return;

  while (minsize < ctx->buffer_size)
    {
      ctx->buffer_size *= 2;
    }

  new_buffer = serf_bucket_mem_alloc(bucket->allocator,
                                     ctx->buffer_size);

  /* In general only a small part of the old buffer is used at this point */
  memcpy(new_buffer, ctx->buffer, ctx->buffer_used);
  serf_bucket_mem_free(bucket->allocator, ctx->buffer);
  ctx->buffer = new_buffer;
}

static apr_status_t
read_hpack_int(apr_uint32_t *v,
               unsigned char *flags,
               serf_bucket_t *bucket,
               int bits)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status;
  apr_uint16_t value_mask;
  apr_uint64_t vv;

  if (!ctx->buffer_used)
    {
      const char *data;
      apr_size_t len;

      status = serf_bucket_read(ctx->stream, 1, &data, &len);
      if (status || len == 0)
        return status ? status : APR_EAGAIN;

      ctx->buffer[0] = *data;
      ctx->buffer_used++;
    }

  value_mask = (1 << bits) - 1;

  if (((unsigned char)ctx->buffer[0] & value_mask) != value_mask)
    {
      /* Everything fits in the initial byte :-) */
      vv = ((unsigned char)ctx->buffer[0] & value_mask);
    }
  else
    {
      apr_size_t i;

      /* Here we read the necessary bytes for the integer upto the
         first byte that doesn't have the 0x80 bit set.

         We could try to be smart by peeking, getting the size if
         possible, etc.... but that would optimize for large ints
         while the value typically fits in 1 or 2 bytes max.

         My guess is that trying to be smart will be more expensive
         here. */
      do
        {
          const char *data;
          apr_size_t len;

          /* We already have all the bits we can store */
          if ((7 * (ctx->buffer_used - 1) + bits) >= 32)
            return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

          status = serf_bucket_read(ctx->stream, 1, &data, &len);
          if (status || len == 0)
            return status ? status : APR_EAGAIN;

          ctx->buffer[ctx->buffer_used] = *data;
          ctx->buffer_used++;
        }
      while (ctx->buffer[ctx->buffer_used - 1] & 0x80);

      /* Check if the value could have been stored more efficiently. If it
         can then this is a compression error.

         The value where all the bits in the first byte are 1 really
         needs the next byte as 0, to encode that. */
      if (ctx->buffer_used > 2 && ctx->buffer[ctx->buffer_used - 1] == 0)
        return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

      vv = value_mask;

      for (i = 1; i < ctx->buffer_used; i++)
        vv += (apr_uint64_t)((unsigned char)ctx->buffer[i] & 0x7F) << (7 * (i - 1));

      if ((vv & APR_UINT32_MAX) != vv)
        return SERF_ERROR_HTTP2_COMPRESSION_ERROR;
    }

  *v = (apr_uint32_t)vv;

  if (flags)
    *flags = (((unsigned char)ctx->buffer[0]) & ~value_mask);

  ctx->buffer_used = 0; /* Done with buffer */

  return APR_SUCCESS;
}

static apr_status_t
handle_read_entry_and_clear(serf_hpack_decode_ctx_t *ctx,
                            serf_bucket_alloc_t *alloc)
{
  serf_hpack_table_t *tbl = ctx->tbl;
  const char *keep_key = NULL;
  const char *keep_val = NULL;
  apr_status_t status;
  char own_key;
  char own_val;

  serf__log(LOGLVL_INFO, SERF_LOGCOMP_PROTOCOL, __FILE__, ctx->config,
            "Parsed from HPACK: %.*s: %.*s\n",
            ctx->key_size, ctx->key, ctx->val_size, ctx->val);

  if (ctx->item_callback)
    {
      status = ctx->item_callback(ctx->item_baton,
                                  ctx->key, ctx->key_size,
                                  ctx->val, ctx->val_size);

      if (status)
        return status;
    }
  else if (!ctx->wrote_header)
    {
      serf_bucket_t *b;

      if (ctx->key_size == 7 && !strcmp(ctx->key, ":status"))
        {
          ctx->wrote_header = TRUE;

          b = SERF_BUCKET_SIMPLE_STRING("HTTP/2.0 ", alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          b = serf_bucket_simple_copy_create(ctx->val, ctx->val_size, alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          b = SERF_BUCKET_SIMPLE_STRING(" <http2>\r\n", alloc);
          serf_bucket_aggregate_append(ctx->agg, b);
        }
      else if (ctx->key_size && ctx->key[0] == ':')
        {
          /* Ignore all magic headers */
        }
      else
        {
          /* Write some header with some status code first */
          ctx->wrote_header = TRUE;

          b = SERF_BUCKET_SIMPLE_STRING(
                      "HTTP/2.0 505 Missing ':status' header\r\n",
                      alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          /* And now the actual header */
          b = serf_bucket_simple_copy_create(ctx->key, ctx->key_size, alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          b = SERF_BUCKET_SIMPLE_STRING(": ", alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          b = serf_bucket_simple_copy_create(ctx->val, ctx->val_size, alloc);
          serf_bucket_aggregate_append(ctx->agg, b);

          b = SERF_BUCKET_SIMPLE_STRING("\r\n", alloc);
          serf_bucket_aggregate_append(ctx->agg, b);
        }
    }
  else if (ctx->key_size && ctx->key[0] != ':')
    {
      serf_bucket_t *b;

      /* Write header */
      b = serf_bucket_simple_copy_create(ctx->key, ctx->key_size, alloc);
      serf_bucket_aggregate_append(ctx->agg, b);

      b = SERF_BUCKET_SIMPLE_STRING(": ", alloc);
      serf_bucket_aggregate_append(ctx->agg, b);

      b = serf_bucket_simple_copy_create(ctx->val, ctx->val_size, alloc);
      serf_bucket_aggregate_append(ctx->agg, b);

      b = SERF_BUCKET_SIMPLE_STRING("\r\n", alloc);
      serf_bucket_aggregate_append(ctx->agg, b);
    }

  if (ctx->reuse_item)
    {
      status = hpack_table_get(ctx->reuse_item, tbl,
                               &keep_key, NULL,
                               &keep_val, NULL);
    }

  own_key = (ctx->key && ctx->key != keep_key);
  own_val = (ctx->val && ctx->val != keep_val);

  if (ctx->index_item)
    {
      serf_hpack_entry_t *entry = serf_bucket_mem_calloc(tbl->alloc,
                                                         sizeof(*entry));

      entry->key = own_key ? ctx->key : serf_bstrmemdup(tbl->alloc, ctx->key,
                                                        ctx->key_size);
      entry->key_len = ctx->key_size;
      entry->value = own_val ? ctx->val : serf_bstrmemdup(tbl->alloc,
                                                          ctx->val,
                                                          ctx->val_size);
      entry->value_len = ctx->val_size;
      entry->free_key = entry->free_val = TRUE;
      entry->next = tbl->rl_first;
      tbl->rl_first = entry;
      tbl->rl_count++;
      tbl->rl_size += HPACK_ENTRY_SIZE(entry);
      if (entry->next)
        entry->next->prev = entry;
      else
        tbl->rl_last = entry;

      /* We don't update lr_start... that is the idea */
    }
  else
    {
      if (own_key)
        serf_bucket_mem_free(tbl->alloc, (void*)ctx->key);
      if (own_val)
        serf_bucket_mem_free(tbl->alloc, (void*)ctx->val);
    }
  return APR_SUCCESS;
}

/* Reads the exact amount of bytes, buffered if necessary.

   Note: APR_EOF is not returned in case we have everything
         we need. The callers depend on this behavior
 */
static apr_status_t hpack_read_bytes(serf_bucket_t *bucket,
                                     apr_size_t required,
                                     const void **data)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status = APR_SUCCESS;
  apr_size_t len;
  const char *some_data;

  /* assert(required < ctx->buffer_used); */

  if (required == 0)
    {
      *data = ctx->buffer;
      return APR_SUCCESS;
    }

  if (!ctx->buffer_used)
    {
      status = serf_bucket_read(ctx->stream, required, &some_data, &len);

      if (SERF_BUCKET_READ_ERROR(status) || (len == required))
        {
          if (APR_STATUS_IS_EOF(status) && len == required)
            status = APR_SUCCESS;
          *data = some_data;
          return status;
        }

      hpack_decode_buffer_ensure(bucket, required);

      memcpy(ctx->buffer, data, len);
      ctx->buffer_used = len;

      if (status)
        return status;

      /* Fall through: Try to continue reading*/
    }
  else
    {
      /* Ensure that the buffer is large enough to hold everything */
      hpack_decode_buffer_ensure(bucket, required);
    }

  while (ctx->buffer_used < required)
    {
      status = serf_bucket_read(ctx->stream, required - ctx->buffer_used,
                                &some_data, &len);

      if (SERF_BUCKET_READ_ERROR(status))
        return status;

      memcpy(ctx->buffer + ctx->buffer_used, some_data, len);
      ctx->buffer_used += len;

      if (status)
        break;
    }

  if (ctx->buffer_used == required)
    {
      *data = ctx->buffer;
      ctx->buffer_used = 0; /* Done with buffer */
      status = APR_SUCCESS;
    }

  return status;
}

static apr_status_t
hpack_process(serf_bucket_t *bucket)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status = APR_SUCCESS;

  if (ctx->hit_eof)
    return APR_EOF;

  while (status == APR_SUCCESS)
    {
      switch (ctx->state)
        {
          case HPACK_DECODE_STATE_INITIAL:
            {
              unsigned char uc;
              const char *data;
              apr_size_t len;

              status = serf_bucket_read(ctx->stream, 1, &data, &len);
              if (status || !len)
                continue;

              ctx->key_hm = ctx->val_hm = FALSE;
              ctx->reuse_item = 0;

              uc = *data;
              if (uc & 0x80)
                {
                  /* 6.1.  Indexed Header Field Representation
                     https://tools.ietf.org/html/rfc7541#section-6.1 */

                  ctx->state = HPACK_DECODE_STATE_INDEX;
                  ctx->buffer[0] = *data;
                  ctx->buffer_used = 1; /* Initial state for read_hpack_int */
                  ctx->index_item = FALSE;
                }
              else if (uc == 0x40 || uc == 0x00 || uc == 0x10)
                {
                  /* 0x40: Literal Header Field with Incremental Indexing
                           -- New Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.1
                     0x00: Literal Header Field without Indexing
                           -- New Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.2
                     0x10: Literal Header Field Never Indexed
                           -- New Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.3 */

                  ctx->state = HPACK_DECODE_STATE_KEY_LEN;
                  ctx->index_item = (uc == 0x40);
                }
              else if ((uc & 0x60) == 0x20)
                {
                  /* 6.3.  Dynamic Table Size Update
                     https://tools.ietf.org/html/rfc7541#section-6.3 */
                  ctx->state = HPACK_DECODE_TABLESIZE_UPDATE;
                  ctx->buffer[0] = *data;
                  ctx->buffer_used = 1; /* Initial state for read_hpack_int */
                }
              else
                {
                  /* 6.2.1 Literal Header Field with Incremental Indexing
                            -- Indexed Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.1
                     6.2.2: Literal Header Field without Indexing
                            -- Indexed Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.2
                     6.2.3. Literal Header Field Never Indexed
                            -- Indexed Name
                     https://tools.ietf.org/html/rfc7541#section-6.2.3 */

                  ctx->state = HPACK_DECODE_STATE_KEYINDEX;
                  ctx->buffer[0] = *data;
                  ctx->buffer_used = 1; /* Initial state for read_hpack_int */
                  ctx->index_item = (uc & 0x40) != 0;
                }
              continue;
            }
          case HPACK_DECODE_STATE_INDEX:
            {
              apr_uint32_t v;
              status = read_hpack_int(&v, NULL, bucket, 7);
              if (status)
                continue;
              if (v == 0)
                return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

              ctx->reuse_item = v;
              status = hpack_table_get(v, ctx->tbl,
                                       &ctx->key, &ctx->key_size,
                                       &ctx->val, &ctx->val_size);
              if (status)
                return status;

              if (ctx->header_allowed <= HPACK_KEY_SIZE(ctx->key_size)
                                         + HPACK_KEY_SIZE(ctx->val_size))
                {
                  return SERF_ERROR_HTTP2_COMPRESSION_ERROR;
                }
              ctx->header_allowed -= HPACK_KEY_SIZE(ctx->key_size)
                                     + HPACK_KEY_SIZE(ctx->val_size);

              status = handle_read_entry_and_clear(ctx, bucket->allocator);
              if (status)
                return status;

              /* Get key and value from table and handle result */
              ctx->state = HPACK_DECODE_STATE_INITIAL;
              continue;
            }
          case HPACK_DECODE_STATE_KEYINDEX:
            {
              apr_uint32_t v;
              status = read_hpack_int(&v, NULL, bucket,
                                      ctx->index_item ? 6 : 4);
              if (status)
                continue;

              ctx->reuse_item = v;
              status = hpack_table_get(v, ctx->tbl,
                                       &ctx->key, &ctx->key_size,
                                       NULL, NULL);
              if (status)
                return status;

              /* Get key from table */
              ctx->state = HPACK_DECODE_STATE_VALUE_LEN;
              if (HPACK_KEY_SIZE(ctx->key_size) >= ctx->header_allowed)
                return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

              ctx->header_allowed -= HPACK_KEY_SIZE(ctx->key_size);
              continue;
            }
          case HPACK_DECODE_STATE_KEY_LEN:
            {
              apr_uint32_t v;
              unsigned char flags;
              status = read_hpack_int(&v, &flags, bucket, 7);
              if (status)
                continue;

              ctx->key_hm = (flags & 0x80) != 0;

              /* Just check compressed size first. If the result is
                 smaller the encoder shouldn't have used compression */
              if (HPACK_KEY_SIZE(v) >= ctx->header_allowed)
                return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

              ctx->key_size = (apr_size_t)v;
              ctx->state = HPACK_DECODE_STATE_KEY;
              /* Fall through */
            }
          case HPACK_DECODE_STATE_KEY:
            {
              const void *data;

              status = hpack_read_bytes(bucket, ctx->key_size, &data);
              if (status)
                continue;

              if (ctx->key_hm)
                {
                  apr_size_t ks;
                  char *key;

                  status = serf__hpack_huffman_decode(data, ctx->key_size,
                                                      0, NULL, &ks);

                  if (status)
                    return status;

                  if (HPACK_KEY_SIZE(ks) >= ctx->header_allowed)
                    return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

                  key = serf_bucket_mem_alloc(ctx->tbl->alloc, ks + 1);

                  status = serf__hpack_huffman_decode(data, ctx->key_size,
                                                       ks + 1, key,
                                                       &ctx->key_size);
                  if (status)
                    return status;

                  ctx->key = key;
                }
              else
                ctx->key = serf_bstrmemdup(ctx->tbl->alloc, data,
                                           ctx->key_size);

              ctx->state = HPACK_DECODE_STATE_VALUE_LEN;
              ctx->header_allowed -= HPACK_KEY_SIZE(ctx->key_size);
              /* Fall through */
            }
          case HPACK_DECODE_STATE_VALUE_LEN:
            {
              apr_uint32_t v;
              unsigned char flags;
              status = read_hpack_int(&v, &flags, bucket, 7);
              if (status)
                continue;

              ctx->val_hm = (flags & 0x80) != 0;

              /* Just check compressed size first. If the result is
                 smaller the encoder shouldn't have used compression */
              if (HPACK_KEY_SIZE(v) >= ctx->header_allowed)
                return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

              ctx->val_size = v;
              ctx->state = HPACK_DECODE_STATE_VALUE;
              /* Fall through */
            }
          case HPACK_DECODE_STATE_VALUE:
            {
              const void *data;

              status = hpack_read_bytes(bucket, ctx->val_size, &data);
              if (status)
                continue;

              if (ctx->val_hm)
                {
                  apr_size_t ks;
                  char *val;

                  status = serf__hpack_huffman_decode(data, ctx->val_size,
                                                       0, NULL, &ks);
                  if (status)
                    return status;

                  if (HPACK_KEY_SIZE(ks) >= ctx->header_allowed)
                    return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

                  val = serf_bucket_mem_alloc(ctx->tbl->alloc, ks + 1);

                  status = serf__hpack_huffman_decode(data, ctx->val_size,
                                                      ks + 1, val,
                                                      &ctx->val_size);
                  if (status)
                    return status;

                  ctx->val = val;
                }
              else
                ctx->val = serf_bstrmemdup(ctx->tbl->alloc, data,
                                           ctx->val_size);

              ctx->header_allowed -= HPACK_KEY_SIZE(ctx->val_size);

              status = handle_read_entry_and_clear(ctx, bucket->allocator);
              if (status)
                continue;

              ctx->state = HPACK_DECODE_STATE_INITIAL;
              continue;
            }
          case HPACK_DECODE_TABLESIZE_UPDATE:
            {
              apr_uint32_t v;

              status = read_hpack_int(&v, NULL, bucket, 5);
              if (status)
                continue;

              /* Send remote tablesize update to our table */
              if (v >= APR_SIZE_MAX)
                return SERF_ERROR_HTTP2_COMPRESSION_ERROR;
              status = hpack_table_size_update(ctx->tbl, (apr_size_t)v);

              ctx->state = HPACK_DECODE_STATE_INITIAL;
              continue;
            }
        default:
          abort();
      }
    }

  if (APR_STATUS_IS_EOF(status))
    {
      serf_bucket_t *b;
      if (ctx->state != HPACK_DECODE_STATE_INITIAL)
        return SERF_ERROR_HTTP2_COMPRESSION_ERROR;

      if (!ctx->hit_eof)
        {
          serf_hpack_table_t *tbl = ctx->tbl;
          ctx->hit_eof = TRUE;

          hpack_shrink_table(&tbl->rl_first, &tbl->rl_start,
                             &tbl->rl_last, &tbl->rl_size,
                             tbl->rl_max_table_size, tbl->alloc);

          if (!ctx->item_callback)
            {
              /* Write the final "\r\n" for http/1.1 compatibility */
              b = SERF_BUCKET_SIMPLE_STRING("\r\n", bucket->allocator);
              serf_bucket_aggregate_append(ctx->agg, b);
            }
        }
    }

  return status;
}

static apr_status_t
hpack_decode_databuf_reader(void *baton,
                            apr_size_t bufsize,
                            char *buf,
                            apr_size_t *len)
{
  serf_hpack_decode_ctx_t *ctx = baton;
  apr_status_t status;
  const char *data;

  status = serf_bucket_read(ctx->agg, bufsize, &data, len);

  if (SERF_BUCKET_READ_ERROR(status))
    return status;

  if (*len)
    memcpy(buf, data, *len);

  if (APR_STATUS_IS_EOF(status) && ctx->hit_eof)
    return APR_EOF;
  else
    return status;
}

static apr_status_t
serf_hpack_decode_read(serf_bucket_t *bucket,
                       apr_size_t requested,
                       const char **data,
                       apr_size_t *len)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status;

  status = hpack_process(bucket);
  if (SERF_BUCKET_READ_ERROR(status))
    {
      *len = 0;
      return status;
    }

  if (ctx->agg)
    status = serf_databuf_read(&ctx->databuf,
                               requested, data, len);
  else
    *len = 0;

  return status;
}

static apr_status_t
serf_hpack_decode_readline(serf_bucket_t *bucket,
                           int acceptable,
                           int *found,
                           const char **data,
                           apr_size_t *len)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status;

  status = hpack_process(bucket);
  if (SERF_BUCKET_READ_ERROR(status))
    {
      *len = 0;
      return status;
    }

  if (ctx->agg)
    status = serf_databuf_readline(&ctx->databuf, acceptable,
                                   found, data, len);
  else
    *len = 0;

  return status;
}

static apr_status_t
serf_hpack_decode_peek(serf_bucket_t *bucket,
                       const char **data,
                       apr_size_t *len)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status;

  status = hpack_process(bucket);
  if (SERF_BUCKET_READ_ERROR(status))
    {
      *len = 0;
      return status;
    }

  if (ctx->agg)
    status = serf_databuf_peek(&ctx->databuf, data, len);

  return status;
}

static apr_status_t
serf_hpack_decode_set_config(serf_bucket_t *bucket,
                             serf_config_t *config)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  apr_status_t status;

  ctx->config = config;

  status = serf_bucket_set_config(ctx->stream, config);
  if (status)
    return status;

  if (ctx->agg)
    {
      status = serf_bucket_set_config(ctx->agg, config);
      if (status)
        return status;
    }
  return APR_SUCCESS;
}

static void
serf_hpack_decode_destroy(serf_bucket_t *bucket)
{
  serf_hpack_decode_ctx_t *ctx = bucket->data;
  serf_bucket_destroy(ctx->stream);

  if (ctx->agg)
    serf_bucket_destroy(ctx->agg);

  serf_bucket_mem_free(bucket->allocator, ctx->buffer);

  /* Key and value are handled by table. If we fail reading
     table can't be used anyway, so the allocator cleanup will
     handle the leak */

  serf_default_destroy_and_data(bucket);
}

const serf_bucket_type_t serf_bucket_type__hpack_decode = {
  "HPACK-DECODE",
  serf_hpack_decode_read,
  serf_hpack_decode_readline,
  serf_default_read_iovec,
  serf_default_read_for_sendfile,
  serf_buckets_are_v2,
  serf_hpack_decode_peek,
  serf_hpack_decode_destroy,
  serf_default_read_bucket,
  serf_default_get_remaining,
  serf_hpack_decode_set_config
};
