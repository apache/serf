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
