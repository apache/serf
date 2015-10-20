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

#define APR_WANT_MEMFUNC
#include <apr_want.h>

#include <apr_pools.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

serf_bucket_t *serf_bucket_create(
    const serf_bucket_type_t *type,
    serf_bucket_alloc_t *allocator,
    void *data)
{
    serf_bucket_t *bkt = serf_bucket_mem_alloc(allocator, sizeof(*bkt));

    bkt->type = type;
    bkt->data = data;
    bkt->allocator = allocator;

    return bkt;
}


apr_status_t serf_default_read_iovec(
    serf_bucket_t *bucket,
    apr_size_t requested,
    int vecs_size,
    struct iovec *vecs,
    int *vecs_used)
{
    const char *data;
    apr_size_t len;

    /* Read some data from the bucket.
     *
     * Because we're an internal 'helper' to the bucket, we can't call the
     * normal serf_bucket_read() call because the debug allocator tracker will
     * end up marking the bucket as read *twice* - once for us and once for
     * our caller - which is reading the same bucket.  This leads to premature
     * abort()s if we ever see EAGAIN.  Instead, we'll go directly to the
     * vtable and bypass the debug tracker.
     */
    apr_status_t status = bucket->type->read(bucket, requested, &data, &len);

    /* assert that vecs_size >= 1 ? */

    /* Return that data as a single iovec. */
    if (len) {
        vecs[0].iov_base = (void *)data; /* loses the 'const' */
        vecs[0].iov_len = len;
        *vecs_used = 1;
    }
    else {
        *vecs_used = 0;
    }

    return status;
}


apr_status_t serf_default_read_for_sendfile(
    serf_bucket_t *bucket,
    apr_size_t requested,
    apr_hdtr_t *hdtr,
    apr_file_t **file,
    apr_off_t *offset,
    apr_size_t *len)
{
    /* Read a bunch of stuff into the headers.
     *
     * See serf_default_read_iovec as to why we call into the vtable
     * directly.
     */
    apr_status_t status = bucket->type->read_iovec(bucket, requested,
                                                   hdtr->numheaders,
                                                   hdtr->headers,
                                                   &hdtr->numheaders);

    /* There isn't a file, and there are no trailers. */
    *file = NULL;
    hdtr->numtrailers = 0;

    return status;
}


serf_bucket_t *serf_default_read_bucket(
    serf_bucket_t *bucket,
    const serf_bucket_type_t *type)
{
    return NULL;
}

apr_status_t serf_default_peek(
    serf_bucket_t *bucket,
    const char **data,
    apr_size_t *len)
{
    /* State: no data available */
    *data = "";
    *len = 0;
    return APR_SUCCESS;
}


void serf_default_destroy(serf_bucket_t *bucket)
{
#ifdef SERF_DEBUG_BUCKET_USE
    serf_debug__bucket_destroy(bucket);
#endif

    serf_bucket_mem_free(bucket->allocator, bucket);
}


void serf_default_destroy_and_data(serf_bucket_t *bucket)
{
    serf_bucket_mem_free(bucket->allocator, bucket->data);
    serf_default_destroy(bucket);
}

apr_uint64_t serf_default_get_remaining(serf_bucket_t *bucket)
{
    return SERF_LENGTH_UNKNOWN;
}

/* serf_bucket_type_t that is only used for version checking
   between serf_buckets_are_v2() and serf_get_type().

  Use a specific value for the name that API users can't depend
  on, but that the compiler and linker can't optimize away
  as 100% the same as another instance */
static const serf_bucket_type_t v2_check =
{
  "\0serf_buckets_are_v2",
  NULL /* read */,
  NULL /* readline */,
  NULL /* read_iovec */,
  NULL /* read_for_sendfile */,
  NULL /* buckets_are_v2 */,
  NULL /* peek */,
  NULL /* destroy */,
  NULL /* read_bucket_v2 */,
  NULL /* get_remaining */,
  NULL /* set_config */
};

serf_bucket_t * serf_buckets_are_v2(serf_bucket_t *bucket,
                                    const serf_bucket_type_t *type)
{
    if (type == &v2_check)
        return bucket;

    return bucket->type->read_bucket_v2(bucket, type);
}

apr_status_t serf_default_ignore_config(serf_bucket_t *bucket,
                                        serf_config_t *config)
{
    return APR_SUCCESS;
}

/* Fallback type definition to return for buckets that don't implement
   a specific version of the bucket spec */
static const serf_bucket_type_t fallback_bucket_type =
{
  "\0serf_buckets_old",
  NULL /* read */,
  NULL /* readline */,
  NULL /* read_iovec */,
  NULL /* read_for_sendfile */,
  NULL /* read_bucket */,
  NULL /* peek */,
  NULL /* destroy */,
  serf_buckets_are_v2,
  serf_default_get_remaining,
  serf_default_ignore_config,
};

const serf_bucket_type_t *serf_get_type(serf_bucket_t *bucket,
                                        int min_version)
{
    const serf_bucket_t *r;

    switch (min_version) {
        case 1:
            r = bucket; /* Always supported */
            break;
#if 0
        case 3:
            r = bucket->type->read_bucket(bucket, &v3_check);
            break;
#endif

        case 2:
            r = bucket->type->read_bucket(bucket, &v2_check);
            break;

        default:
            abort();
    }

    if (r != NULL)
        return r->type;

    return &fallback_bucket_type;
}

/* ==================================================================== */


char *serf_bstrmemdup(serf_bucket_alloc_t *allocator,
                      const char *str,
                      apr_size_t size)
{
    char *newstr = serf_bucket_mem_alloc(allocator, size + 1);
    memcpy(newstr, str, size);
    newstr[size] = '\0';
    return newstr;
}


void *serf_bmemdup(serf_bucket_alloc_t *allocator,
                   const void *mem,
                   apr_size_t size)
{
    void *newmem = serf_bucket_mem_alloc(allocator, size);
    memcpy(newmem, mem, size);
    return newmem;
}


char *serf_bstrdup(serf_bucket_alloc_t *allocator,
                   const char *str)
{
    apr_size_t size = strlen(str) + 1;
    char *newstr = serf_bucket_mem_alloc(allocator, size);
    memcpy(newstr, str, size);
    return newstr;
}

char *serf_bstrcatv(serf_bucket_alloc_t *allocator, struct iovec *vec,
                    int vecs, apr_size_t *bytes_written)
{
    int i;
    apr_size_t new_len = 0;
    char *c, *newstr;

    for (i = 0; i < vecs; i++) {
        new_len += vec[i].iov_len;
    }

    /* It's up to the caller to free this memory later. */
    newstr = serf_bucket_mem_alloc(allocator, new_len);

    c = newstr;
    for (i = 0; i < vecs; i++) {
        memcpy(c, vec[i].iov_base, vec[i].iov_len);
        c += vec[i].iov_len;
    }

    if (bytes_written) {
        *bytes_written = c - newstr;
    }

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

    *data = start + *len;
    *len -= *data - start;
    *found = SERF_NEWLINE_NONE;
}


void serf_util_readline(
    const char **data,
    apr_size_t *len,
    int acceptable,
    int *found)
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
        *data += *len;
        break;
      default:
        /* Not reachable */
        return;
    }

    *len -= *data - start;
}


/* ==================================================================== */


void serf_databuf_init(serf_databuf_t *databuf)
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


apr_status_t serf_databuf_read(
    serf_databuf_t *databuf,
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
    return databuf->remaining ? APR_SUCCESS : databuf->status;
}


apr_status_t serf_databuf_readline(
    serf_databuf_t *databuf,
    int acceptable,
    int *found,
    const char **data,
    apr_size_t *len)
{
    apr_status_t status = common_databuf_prep(databuf, len);
    if (status) {
        *found = SERF_NEWLINE_NONE;
        return status;
    }

    /* the returned line will start at the current position. */
    *data = databuf->current;

    /* read a line from the buffer, and adjust the various pointers. */
    serf_util_readline(&databuf->current, &databuf->remaining, acceptable,
                       found);

    /* the length matches the amount consumed by the readline */
    *len = databuf->current - *data;

    /* see serf_databuf_read's return condition */
    return databuf->remaining ? APR_SUCCESS : databuf->status;
}


apr_status_t serf_databuf_peek(
    serf_databuf_t *databuf,
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


/* ==================================================================== */


void serf_linebuf_init(serf_linebuf_t *linebuf)
{
    linebuf->state = SERF_LINEBUF_EMPTY;
    linebuf->used = 0;
    linebuf->line[0] = '\0';
}


apr_status_t serf_linebuf_fetch(
    serf_linebuf_t *linebuf,
    serf_bucket_t *bucket,
    int acceptable)
{
    /* If we had a complete line, then assume the caller has used it, so
     * we can now reset the state.
     */
    if (linebuf->state == SERF_LINEBUF_READY) {
        linebuf->state = SERF_LINEBUF_EMPTY;

        /* Reset the line_used, too, so we don't have to test the state
         * before using this value.
         */
        linebuf->used = 0;
        linebuf->line[0] = '\0';
    }

    while (1) {
        apr_status_t status;
        const char *data;
        apr_size_t len;

        if (linebuf->state == SERF_LINEBUF_CRLF_SPLIT) {
            /* On the previous read, we received just a CR. The LF might
             * be present, but the bucket couldn't see it. We need to
             * examine a single character to determine how to handle the
             * split CRLF.
             */

            status = serf_bucket_peek(bucket, &data, &len);
            if (SERF_BUCKET_READ_ERROR(status))
                return status;

            if (len > 0) {
                if (*data == '\n') {
                    /* We saw the second part of CRLF. We don't need to
                     * save that character, so do an actual read to suck
                     * up that character.
                     */
                    /* ### check status */
                    (void) serf_bucket_read(bucket, 1, &data, &len);
                }
                /* else:
                 *   We saw the first character of the next line. Thus,
                 *   the current line is terminated by the CR. Just
                 *   ignore whatever we peeked at. The next reader will
                 *   see it and handle it as appropriate.
                 */

                /* Whatever was read, the line is now ready for use. */
                linebuf->state = SERF_LINEBUF_READY;
            } else {
                /* no data available, try again later. */
                return APR_EAGAIN;
            }
        }
        else {
            int found;

            status = serf_bucket_readline(bucket, acceptable, &found,
                                          &data, &len);
            if (SERF_BUCKET_READ_ERROR(status)) {
                return status;
            }
            /* Some bucket types (socket) might need an extra read to find
               out EOF state, so they'll return no data in that read. This
               means we're done reading, return what we got. */
            if (APR_STATUS_IS_EOF(status) && len == 0) {
                return status;
            }
            if (linebuf->used + len + 1 > sizeof(linebuf->line)) {
                return SERF_ERROR_LINE_TOO_LONG;
            }

            /* Note: our logic doesn't change for SERF_LINEBUF_PARTIAL. That
             * only affects how we fill the buffer. It is a communication to
             * our caller on whether the line is ready or not.
             */

            /* If we didn't see a newline, then we should mark the line
             * buffer as partially complete.
             */
            if (found == SERF_NEWLINE_NONE) {
                linebuf->state = SERF_LINEBUF_PARTIAL;
            }
            else if (found == SERF_NEWLINE_CRLF_SPLIT) {
                linebuf->state = SERF_LINEBUF_CRLF_SPLIT;

                /* Toss the partial CR. We won't ever need it. */
                if (len > 0)
                    --len;
            }
            else {
                /* We got a newline (of some form). We don't need it
                 * in the line buffer, so back up the length. Then
                 * mark the line as ready.
                 */
                len -= 1 + (found == SERF_NEWLINE_CRLF);

                linebuf->state = SERF_LINEBUF_READY;
            }

            /* The C99 standard (7.21.1/2) requires valid data pointer
             * even for zero length array for all functions unless explicitly
             * stated otherwise. So don't copy data even most mempy()
             * implementations have special handling for zero length copy. */
            if (len > 0) {
                /* ### it would be nice to avoid this copy if at all possible,
                   ### and just return the a data/len pair to the caller. we're
                   ### keeping it simple for now. */
                memcpy(&linebuf->line[linebuf->used], data, len);
                linebuf->line[linebuf->used + len] = '\0';
                linebuf->used += len;
            }
        }

        /* If we saw anything besides "success. please read again", then
         * we should return that status. If the line was completed, then
         * we should also return.
         */
        if (status || linebuf->state == SERF_LINEBUF_READY)
            return status;

        /* We got APR_SUCCESS and the line buffer is not complete. Let's
         * loop to read some more data.
         */
    }
    /* NOTREACHED */
}
