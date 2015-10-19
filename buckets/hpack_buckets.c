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

typedef struct serf_hpack_item_t
{
  const char *key;
  apr_size_t key_len;
  const char *value;
  apr_size_t value_len;

  struct serf_hpack_item_t *next;
  struct serf_hpack_item_t *prev;
} serf_hpack_item_t;

typedef struct serf_hpack_context_t
{
  serf_bucket_alloc_t *alloc;

  serf_hpack_item_t *first;
  serf_hpack_item_t *last;
} serf_hpack_context_t;

static apr_status_t
hpack_copy_from_headers(void *baton,
                        const char *key,
                        const char *value)
{
  serf_bucket_t *hpack = baton;

  if (!strcasecmp(key, "Host")
      || !strcasecmp(key, "Connection")
      || !strncasecmp(key, "Connection-", 11))
    {
      return APR_SUCCESS;
    }

  serf_bucket_hpack_setc(hpack, key, value);

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

  serf_bucket_t *hpack = serf_bucket_hpack_create(hpack_table, allocator);

  serf_bucket_t *headers = serf_bucket_request_get_headers(request);

  host = serf_bucket_headers_get(headers, "Host");

  serf__bucket_request_read(request, NULL, &uri, &method);

  serf_bucket_hpack_setc(hpack, ":method", method);
  serf_bucket_hpack_setc(hpack, ":scheme", scheme);
  serf_bucket_hpack_setc(hpack, ":authority", host);
  serf_bucket_hpack_setc(hpack, ":path", uri);

  serf_bucket_headers_do(headers, hpack_copy_from_headers, hpack);

  *new_hpack_bucket = hpack;

  return APR_SUCCESS;
}


serf_bucket_t *
serf_bucket_hpack_create(serf_hpack_table_t *hpack_table,
                         serf_bucket_alloc_t *allocator)

{
  serf_hpack_context_t *ctx = serf_bucket_mem_alloc(allocator, sizeof(*ctx));

  ctx->alloc = allocator;
  ctx->first = ctx->last = NULL;

  return serf_bucket_create(&serf_bucket_type_hpack, allocator, ctx);
}

void serf_bucket_hpack_setc(serf_bucket_t *hpack_bucket,
                            const char *key,
                            const char *value)
{
  serf_bucket_hpack_setx(hpack_bucket,
                         key, strlen(key), TRUE,
                         value, strlen(value), TRUE);
}

void serf_bucket_hpack_setx(serf_bucket_t *hpack_bucket,
                            const char *key,
                            apr_size_t key_size,
                            int header_copy,
                            const char *value,
                            apr_size_t value_size,
                            int value_copy)
{
  serf_hpack_context_t *ctx = hpack_bucket->data;
  serf_hpack_item_t *hi;

  for (hi = ctx->first; hi; hi = hi->next)
    {
      if (key_size == hi->key_len
          && !strncasecmp(key, hi->key, key_size))
        {
          break;
        }
    }

  /* TODO: Handle *_copy by keeping some flags */

  if (hi && value[0] == ':')
    {
      serf_bucket_mem_free(ctx->alloc, (void*)hi->value);
      hi->value = serf_bstrmemdup(ctx->alloc, value, value_size);
      hi->value_len = value_size;

      return;
    }
  else if (hi)
    {
      /* We probably want to allow duplicate *and* join behavior? */
    }

  hi = serf_bucket_mem_alloc(ctx->alloc, sizeof(*hi));

  /* Convert keys to lower case as in RFC? Or keep case for
     1.1 like compatibility */

  hi->key = serf_bstrmemdup(ctx->alloc, key, key_size);
  hi->key_len = key_size;
  hi->value = serf_bstrmemdup(ctx->alloc, value, value_size);
  hi->value_len = value_size;

  hi->prev = ctx->last;
  hi->next = NULL;
  if (ctx->last)
    {
      ctx->last->next = hi;
      ctx->last = hi;
    }
  else
    ctx->first = ctx->last = hi;
}

static void hpack_int(unsigned char flags, int bits, apr_uint64_t value, char to[10], apr_size_t *used)
{
  unsigned char max_direct;
  flags = flags & ~((1 << bits) - 1);
  apr_size_t u;

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
  serf_bucket_alloc_t *alloc = ctx->alloc;

  /* Put on our aggregate bucket cloak */
  serf_bucket_aggregate_become(bucket);

  serf_hpack_item_t *hi;
  serf_hpack_item_t *next;

  for (hi = ctx->first; hi; hi = next)
    {
      char intbuf[10];
      apr_size_t intbuf_len;

      next = hi->next;

      /* Literal header, no indexing (=has a name) */
      hpack_int(0x40, 6, 0, intbuf, &intbuf_len);

      serf_bucket_aggregate_append(bucket,
              serf_bucket_simple_copy_create(intbuf, intbuf_len, alloc));

      /* Name is literal, no huffman encoding */
      hpack_int(0, 7, hi->key_len, intbuf, &intbuf_len);
      serf_bucket_aggregate_append(bucket,
              serf_bucket_simple_copy_create(intbuf, intbuf_len, alloc));

      serf_bucket_aggregate_append(bucket,
              serf_bucket_simple_own_create(hi->key, hi->key_len, alloc));

      /* Value is literal, no huffman encoding */
      hpack_int(0, 7, hi->value_len, intbuf, &intbuf_len);
      serf_bucket_aggregate_append(bucket,
              serf_bucket_simple_copy_create(intbuf, intbuf_len, alloc));

      serf_bucket_aggregate_append(bucket,
              serf_bucket_simple_own_create(hi->value, hi->value_len, alloc));

      /* We handed ownership of key and value, so we only have to free item */
      serf_bucket_mem_free(alloc, hi);
    }
  ctx->first = ctx->last = NULL;

  serf_bucket_mem_free(alloc, ctx);

  return APR_SUCCESS;
}

apr_status_t
serf_hpack_read(serf_bucket_t *bucket,
                apr_size_t requested,
                const char **data,
                apr_size_t *len)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return serf_bucket_read(bucket, requested, data, len);
}

apr_status_t
serf_hpack_read_iovec(serf_bucket_t *bucket,
                      apr_size_t requested,
                      int vecs_size,
                      struct iovec *vecs,
                      int *vecs_used)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return serf_bucket_read_iovec(bucket, requested, vecs_size, vecs, vecs_used);
}

static apr_status_t
serf_hpack_peek(serf_bucket_t *bucket,
                const char **data,
                apr_size_t *len)
{
  apr_status_t status = serialize(bucket);

  if (status)
    return status;

  return serf_bucket_peek(bucket, data, len);
}

static void
serf_hpack_destroy_and_data(serf_bucket_t *bucket)
{
  serf_hpack_context_t *ctx = bucket->data;
  serf_hpack_item_t *hi;
  serf_hpack_item_t *next;

  for (hi = ctx->first; hi; hi = next)
    {
      next = hi->next;

      /* TODO: Implement conditional free */

      serf_bucket_mem_free(ctx->alloc, (char*)hi->key);
      serf_bucket_mem_free(ctx->alloc, (char*)hi->value);
      serf_bucket_mem_free(ctx->alloc, hi);
    }

  serf_default_destroy_and_data(bucket);
}


/* ### need to implement */
#define serf_hpack_readline NULL

const serf_bucket_type_t serf_bucket_type_hpack = {
  "HPACK",
  serf_hpack_read,
  serf_hpack_readline,
  serf_hpack_read_iovec,
  serf_default_read_for_sendfile,
  serf_default_read_bucket,
  serf_hpack_peek,
  serf_hpack_destroy_and_data,
};
