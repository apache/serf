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


typedef struct node_header_t {
    apr_size_t size;
    union {
        struct node_header_t *next;      /* if size == 0 (freed/inactive) */
        /* no data                          if size == STANDARD_NODE_SIZE */
        apr_memnode_t *memnode;          /* if size > STANDARD_NODE_SIZE */
    } u;
} node_header_t;

/* The size of a node_header_t, properly aligned. Note that (normally)
 * this macro will round the size to a multiple of 8 bytes. Keep this in
 * mind when altering the node_header_t structure. Also, keep in mind that
 * node_header_t is an overhead for every allocation performed through
 * the serf_bucket_mem_alloc() function.
 */
#define SIZEOF_NODE_HEADER_T  APR_ALIGN_DEFAULT(sizeof(node_header_t))


/* STANDARD_NODE_SIZE is manually set to an allocation size that will
 * capture most allocators performed via this API. It must be "large
 * enough" to avoid lots of spillage to allocating directly from the
 * apr_allocator associated with the bucket allocator. The apr_allocator
 * has a minimum size of 8k, which can be expensive if you missed the
 * STANDARD_NODE_SIZE by just a few bytes.
 */
/* ### we should define some rules or ways to determine how to derive
 * ### a "good" value for this. probably log some stats on allocs, then
 * ### analyze them for size "misses". then find the balance point between
 * ### wasted space due to min-size allocator, and wasted-space due to
 * ### size-spill to the 8k minimum.
 */
#define STANDARD_NODE_SIZE 128

/* When allocating a block of memory from the allocator, we should go for
 * an 8k block, minus the overhead that the allocator needs.
 */
#define ALLOC_AMT (8192 - APR_MEMNODE_T_SIZE)

/* Define DEBUG_DOUBLE_FREE if you're interested in debugging double-free
 * calls to serf_bucket_mem_free().
 */
#define DEBUG_DOUBLE_FREE


struct serf_bucket_alloc_t {
    apr_pool_t *pool;
    apr_allocator_t *allocator;

    serf_unfreed_func_t unfreed;
    void *unfreed_baton;

    apr_uint32_t num_alloc;

    node_header_t *freelist;    /* free STANDARD_NODE_SIZE blocks */
    apr_memnode_t *blocks;      /* blocks we allocated for subdividing */
};

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
        bucket->metadata->hash = apr_hash_make(bucket->allocator->pool);
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
        md_hash = apr_hash_make(bucket->allocator->pool);

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


static apr_status_t allocator_cleanup(void *data)
{
    serf_bucket_alloc_t *allocator = data;

    /* If there are no outstanding allocations, then we're already done. */
    if (allocator->num_alloc == 0) {
        /* apr_allocator_free() will toss the entire chain of blocks */
        apr_allocator_free(allocator->allocator, allocator->blocks);

        return APR_SUCCESS;
    }

    if (allocator->unfreed) {
        /* ### walk the list. call the callback. etc. */
        /* return APR_SUCCESS; */
    }

    abort();
    /* NOTREACHED */
}

SERF_DECLARE(serf_bucket_alloc_t *) serf_bucket_allocator_create(
    apr_pool_t *pool,
    serf_unfreed_func_t unfreed,
    void *unfreed_baton)
{
    serf_bucket_alloc_t *allocator = apr_pcalloc(pool, sizeof(*allocator));

    allocator->pool = pool;
    allocator->allocator = apr_pool_allocator_get(pool);
    allocator->unfreed = unfreed;
    allocator->unfreed_baton = unfreed_baton;

    /* ### this implies buckets cannot cross a fork/exec. desirable? */
    apr_pool_cleanup_register(pool, allocator,
                              allocator_cleanup, allocator_cleanup);

    return allocator;
}

SERF_DECLARE(apr_pool_t *) serf_bucket_allocator_get_pool(
    const serf_bucket_alloc_t *allocator)
{
    return allocator->pool;
}

SERF_DECLARE(void *) serf_bucket_mem_alloc(
    serf_bucket_alloc_t *allocator,
    apr_size_t size)
{
    node_header_t *node;

    ++allocator->num_alloc;

    size += SIZEOF_NODE_HEADER_T;
    if (size <= STANDARD_NODE_SIZE) {
        if (allocator->freelist) {
            /* just pull a node off our freelist */
            node = allocator->freelist;
            allocator->freelist = node->u.next;
#ifdef DEBUG_DOUBLE_FREE
            /* When we free an item, we set its size to zero. Thus, when
             * we return it to the caller, we must ensure the size is set
             * properly.
             */
            node->size = STANDARD_NODE_SIZE;
#endif
        }
        else {
            apr_memnode_t *active = allocator->blocks;

            if (active == NULL
                || active->first_avail + STANDARD_NODE_SIZE >= active->endp) {
                apr_memnode_t *head = allocator->blocks;

                /* ran out of room. grab another block. */
                active = apr_allocator_alloc(allocator->allocator, ALLOC_AMT);

                /* link the block into our tracking list */
                allocator->blocks = active;
                active->next = head;
            }

            node = (node_header_t *)active->first_avail;
            node->size = STANDARD_NODE_SIZE;
            active->first_avail += STANDARD_NODE_SIZE;
        }
    }
    else {
        apr_memnode_t *memnode = apr_allocator_alloc(allocator->allocator,
                                                     size);

        node = (node_header_t *)memnode->first_avail;
        node->u.memnode = memnode;
        node->size = size;
    }

    return ((char *)node) + SIZEOF_NODE_HEADER_T;
}

SERF_DECLARE(void) serf_bucket_mem_free(
    serf_bucket_alloc_t *allocator,
    void *block)
{
    node_header_t *node;

    --allocator->num_alloc;

    node = (node_header_t *)((char *)block - SIZEOF_NODE_HEADER_T);

    if (node->size == STANDARD_NODE_SIZE) {
        /* put the node onto our free list */
        node->u.next = allocator->freelist;
        allocator->freelist = node;

#ifdef DEBUG_DOUBLE_FREE
        /* note that this thing was freed. */
        node->size = 0;
    }
    else if (node->size == 0) {
        /* damn thing was freed already. */
        abort();
#endif
    }
    else {
#ifdef DEBUG_DOUBLE_FREE
        /* note that this thing was freed. */
        node->size = 0;
#endif

        /* now free it */
        apr_allocator_free(allocator->allocator, node->u.memnode);
    }
}

SERF_DECLARE(char *) serf_bstrmemdup(serf_bucket_alloc_t *allocator,
                                     const char *str, apr_size_t size)
{
    char *n;
    n = serf_bucket_mem_alloc(allocator, size + 1);
    memcpy(n, str, size);
    n[size] = '\0';
    return n;
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
