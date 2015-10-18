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

/* Convert raw data in RAW of size RAW_LEN. If RESULT is not NULL,
   put the result in the buffer pointed to by RESULT which is of size
   BUF_LEN. Sets *RESULT_LEN to the resulting length.

   If RESULT is not large enough return APR_EINVAL.
   */
apr_status_t
serf__hpack_huffman_decode(const unsigned char *raw,
                           apr_size_t raw_len,
                           char *result,
                           apr_size_t buf_len,
                           apr_size_t *result_len)
{
  apr_uint64_t stash = 0;
  apr_int16_t bits_left = 0;
  *result_len = 0;

  while (raw_len || bits_left)
    {
      apr_uint32_t match;
      struct serf_hpack_huffman_item_t *r;

      while (bits_left < 30 && raw_len)
        {
          stash |= (apr_uint64_t)*raw << (64 - 8 - bits_left);
          bits_left += 8;
          raw_len--;
          raw++;
        }

      match = stash >> 32;
      r = bsearch(&match, &serf_hpack_hm_map,
                  sizeof(serf_hpack_hm_map) / sizeof(serf_hpack_hm_map[0]),
                  sizeof(serf_hpack_hm_map[0]), hpack_hm_compare);

      if (!r)
        {
          if (!raw_len)
            break;
          else
            return SERF_ERROR_HTTP2_PROTOCOL_ERROR;
        }
      else if (r->bits > bits_left)
        break;

      if (result)
        {
          if (*result_len < buf_len)
            result[*result_len] = (char)r->cval;
          else
            return APR_EINVAL;
        }

      (*result_len)++;
      stash <<= r->bits;
      if (bits_left )
      bits_left -= r->bits;
    }

  if (result && *result_len < buf_len)
    result[*result_len] = 0;

  return APR_SUCCESS;
}

