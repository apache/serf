/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
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

#include <stdlib.h>  /* for abort() */

#include <apr_pools.h>
#include <apr_hash.h>

#include "serf.h"
#include "serf_bucket_util.h"


/* ### maybe allocate this along with the basic bucket? see the "combined"
   ### structure in modules/dav/fs/repos.c for the concept */
struct serf_metadata_t {
    apr_hash_t *hash;
};


SERF_DECLARE(serf_bucket_t *) serf_bucket_create(
    const serf_bucket_type_t *type,
    serf_bucket_alloc_t *allocator,
    void *data)
{
    serf_bucket_t *bkt = serf_bucket_mem_alloc(allocator, sizeof(*bkt));

    bkt->type = type;
    bkt->data = data;
    bkt->metadata = NULL;
    bkt->allocator = allocator;

    return bkt;
}

SERF_DECLARE(apr_status_t) serf_default_set_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void *md_value)
{
    apr_hash_t *md_hash;

    if (bucket->metadata == NULL) {
        if (md_value == NULL) {
            /* If we're trying to delete the value, then we're already done
             * since there isn't any metadata in the bucket. */
            return APR_SUCCESS;
        }

        /* Create the metadata container. */
        bucket->metadata = serf_bucket_mem_alloc(bucket->allocator,
                                                 sizeof(*bucket->metadata));

        /* ### pool usage! */
        bucket->metadata->hash =
            apr_hash_make(serf_bucket_allocator_get_pool(bucket->allocator));
    }

    /* Look up the hash table for this md_type */
    md_hash = apr_hash_get(bucket->metadata->hash, md_type,
                           APR_HASH_KEY_STRING);

    if (!md_hash) {
        if (md_value == NULL) {
            /* The hash table isn't present, so there is no work to delete
             * a value.
             */
            return APR_SUCCESS;
        }

        /* Create the missing hash table. */
        /* ### pool usage! */
        md_hash =
            apr_hash_make(serf_bucket_allocator_get_pool(bucket->allocator));

        /* Put the new hash table back into the type hash. */
        apr_hash_set(bucket->metadata->hash, md_type, APR_HASH_KEY_STRING,
                     md_hash);
    }

    apr_hash_set(md_hash, md_name, APR_HASH_KEY_STRING, md_value);

    return APR_SUCCESS;
}


SERF_DECLARE(apr_status_t) serf_default_get_metadata(serf_bucket_t *bucket,
                                                     const char *md_type,
                                                     const char *md_name,
                                                     const void **md_value)
{
    /* Initialize return value to not being found. */
    *md_value = NULL;

    if (bucket->metadata) {
        apr_hash_t *md_hash;

        md_hash = apr_hash_get(bucket->metadata->hash, md_type,
                               APR_HASH_KEY_STRING);

        if (md_hash) {
            if (md_name) {
                *md_value = apr_hash_get(md_hash, md_name, 
                                         APR_HASH_KEY_STRING);
            }
            else {
                *md_value = md_hash;
            }
        }
    }

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_default_read_iovec(
    serf_bucket_t *bucket,
    apr_size_t requested,
    int vecs_size,
    struct iovec *vecs,
    int *vecs_used)
{
    const char *data;
    apr_size_t len;

    /* Read some data from the bucket. */
    apr_status_t status = serf_bucket_read(bucket, requested, &data, &len);

    /* assert that vecs_size >= 1 ? */

    /* Return that data as a single iovec. */
    vecs[0].iov_base = (void *)data; /* loses the 'const' */
    vecs[0].iov_len = len;
    *vecs_used = 1;

    return status;
}

SERF_DECLARE(apr_status_t) serf_default_read_for_sendfile(
    serf_bucket_t *bucket,
    apr_size_t requested,
    apr_hdtr_t *hdtr,
    apr_file_t **file,
    apr_off_t *offset,
    apr_size_t *len)
{
    /* Read a bunch of stuff into the headers. */
    apr_status_t status = serf_bucket_read_iovec(bucket, requested,
                                                 hdtr->numheaders,
                                                 hdtr->headers,
                                                 &hdtr->numheaders);

    /* There isn't a file, and there are no trailers. */
    *file = NULL;
    hdtr->numtrailers = 0;

    return status;
}

SERF_DECLARE(serf_bucket_t *) serf_default_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    return NULL;
}

SERF_DECLARE(void) serf_default_destroy(serf_bucket_t *bucket)
{
#ifdef SERF_DEBUG_BUCKET_USE
    serf_debug__bucket_destroy(bucket);
#endif

    if (bucket->metadata != NULL) {
        serf_bucket_mem_free(bucket->allocator, bucket->metadata);
    }
    serf_bucket_mem_free(bucket->allocator, bucket);
}

SERF_DECLARE(void) serf_default_destroy_and_data(serf_bucket_t *bucket)
{
    serf_bucket_mem_free(bucket->allocator, bucket->data);
    serf_default_destroy(bucket);
}


/* ==================================================================== */


SERF_DECLARE(char *) serf_bstrmemdup(serf_bucket_alloc_t *allocator,
                                     const char *str, apr_size_t size)
{
    char *newstr = serf_bucket_mem_alloc(allocator, size + 1);
    memcpy(newstr, str, size);
    newstr[size] = '\0';
    return newstr;
}

SERF_DECLARE(void *) serf_bmemdup(serf_bucket_alloc_t *allocator,
                                  const void *mem,
                                  apr_size_t size)
{
    void *newmem = serf_bucket_mem_alloc(allocator, size);
    memcpy(newmem, mem, size);
    return newmem;
}

SERF_DECLARE(char *) serf_bstrdup(serf_bucket_alloc_t *allocator,
                                  const char *str)
{
    apr_size_t size = strlen(str) + 1;
    char *newstr = serf_bucket_mem_alloc(allocator, size);
    memcpy(newstr, str, size);
    return newstr;
}


/* ==================================================================== */


static void find_crlf(const char **data, apr_size_t *len, int *found)
{
    const char *start = *data;
    const char *end = start + *len;

    while (start < end) {
        const char *cr = memchr(start, '\r', *len);

        if (cr == NULL) {
            break;
        }
        ++cr;

        if (cr < end && cr[0] == '\n') {
            *len -= cr + 1 - start;
            *data = cr + 1;
            *found = SERF_NEWLINE_CRLF;
            return;
        }
        if (cr == end) {
            *len = 0;
            *data = end;
            *found = SERF_NEWLINE_CRLF_SPLIT;
            return;
        }

        /* It was a bare CR without an LF. Just move past it. */
        *len -= cr - start;
        start = cr;
    }

    *found = SERF_NEWLINE_NONE;
}

SERF_DECLARE(void) serf_util_readline(const char **data, apr_size_t *len,
                                      int acceptable, int *found)
{
    const char *start;
    const char *cr;
    const char *lf;
    int want_cr;
    int want_crlf;
    int want_lf;

    /* If _only_ CRLF is acceptable, then the scanning needs a loop to
     * skip false hits on CR characters. Use a separate function.
     */
    if (acceptable == SERF_NEWLINE_CRLF) {
        find_crlf(data, len, found);
        return;
    }

    start = *data;
    cr = lf = NULL;
    want_cr = acceptable & SERF_NEWLINE_CR;
    want_crlf = acceptable & SERF_NEWLINE_CRLF;
    want_lf = acceptable & SERF_NEWLINE_LF;

    if (want_cr || want_crlf) {
        cr = memchr(start, '\r', *len);
    }
    if (want_lf) {
        lf = memchr(start, '\n', *len);
    }

    if (cr != NULL) {
        if (lf != NULL) {
            if (cr + 1 == lf)
                *found = want_crlf ? SERF_NEWLINE_CRLF : SERF_NEWLINE_CR;
            else if (want_cr && cr < lf)
                *found = SERF_NEWLINE_CR;
            else
                *found = SERF_NEWLINE_LF;
        }
        else if (cr == start + *len - 1) {
            /* the CR occurred in the last byte of the buffer. this could be
             * a CRLF split across the data boundary.
             * ### FIX THIS LOGIC? does caller need to detect?
             */
            *found = want_crlf ? SERF_NEWLINE_CRLF_SPLIT : SERF_NEWLINE_CR;
        }
        else if (want_cr)
            *found = SERF_NEWLINE_CR;
        else /* want_crlf */
            *found = SERF_NEWLINE_NONE;
    }
    else if (lf != NULL)
        *found = SERF_NEWLINE_LF;
    else
        *found = SERF_NEWLINE_NONE;

    switch (*found) {
      case SERF_NEWLINE_LF:
        *data = lf + 1;
        break;
      case SERF_NEWLINE_CR:
      case SERF_NEWLINE_CRLF:
      case SERF_NEWLINE_CRLF_SPLIT:
        *data = cr + 1 + (*found == SERF_NEWLINE_CRLF);
        break;
      case SERF_NEWLINE_NONE:
        break;
      default:
        abort();
    }

    *len -= *data - start;
}


/* ==================================================================== */


SERF_DECLARE(void) serf_databuf_init(serf_databuf_t *databuf)
{
    /* nothing is sitting in the buffer */
    databuf->remaining = 0;

    /* avoid thinking we have hit EOF */
    databuf->status = APR_SUCCESS;
}

/* Ensure the buffer is prepared for reading. Will return APR_SUCCESS,
 * APR_EOF, or some failure code. *len is only set for EOF. */
static apr_status_t common_databuf_prep(serf_databuf_t *databuf,
                                        apr_size_t *len)
{
    apr_size_t readlen;
    apr_status_t status;

    /* if there is data in the buffer, then we're happy. */
    if (databuf->remaining > 0)
        return APR_SUCCESS;

    /* if we already hit EOF, then keep returning that. */
    if (APR_STATUS_IS_EOF(databuf->status)) {
        /* *data = NULL;   ?? */
        *len = 0;
        return APR_EOF;
    }

    /* refill the buffer */
    status = (*databuf->read)(databuf->read_baton, sizeof(databuf->buf),
                              databuf->buf, &readlen);
    if (SERF_BUCKET_READ_ERROR(status)) {
        return status;
    }

    databuf->current = databuf->buf;
    databuf->remaining = readlen;
    databuf->status = status;

    return APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_databuf_read(serf_databuf_t *databuf,
                                             apr_size_t requested,
                                             const char **data,
                                             apr_size_t *len)
{
    apr_status_t status = common_databuf_prep(databuf, len);
    if (status)
        return status;

    /* peg the requested amount to what we have remaining */
    if (requested == SERF_READ_ALL_AVAIL || requested > databuf->remaining)
        requested = databuf->remaining;

    /* return the values */
    *data = databuf->current;
    *len = requested;

    /* adjust our internal state to note we've consumed some data */
    databuf->current += requested;
    databuf->remaining -= requested;

    /* If we read everything, then we need to return whatever the data
     * read returned to us. This is going to be APR_EOF or APR_EGAIN.
     * If we have NOT read everything, then return APR_SUCCESS to indicate
     * that we're ready to return some more if asked.
     */
    return databuf->remaining ? databuf->status : APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_databuf_readline(serf_databuf_t *databuf,
                                                 int acceptable, int *found,
                                                 const char **data,
                                                 apr_size_t *len)
{
    apr_status_t status = common_databuf_prep(databuf, len);
    if (status)
        return status;

    /* the returned line will start at the current position. */
    *data = databuf->current;

    /* read a line from the buffer, and adjust the various pointers. */
    serf_util_readline(&databuf->current, &databuf->remaining, acceptable,
                       found);

    /* the length matches the amount consumed by the readline */
    *len = databuf->current - *data;

    /* see serf_databuf_read's return condition */
    return databuf->remaining ? databuf->status : APR_SUCCESS;
}

SERF_DECLARE(apr_status_t) serf_databuf_peek(serf_databuf_t *databuf,
                                             const char **data,
                                             apr_size_t *len)
{
    apr_status_t status = common_databuf_prep(databuf, len);
    if (status)
        return status;

    /* return everything we have */
    *data = databuf->current;
    *len = databuf->remaining;

    /* If the last read returned EOF, then the peek should return the same.
     * The other possibility in databuf->status is APR_EAGAIN, which we
     * should never return. Thus, just return APR_SUCCESS for non-EOF cases.
     */
    if (APR_STATUS_IS_EOF(databuf->status))
        return APR_EOF;
    return APR_SUCCESS;
}
