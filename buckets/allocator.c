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

#include <stdlib.h>

#include <apr_pools.h>

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


typedef struct {
    serf_bucket_t *bucket;
    apr_status_t last;
} read_status_t;

#define TRACK_BUCKET_COUNT 100  /* track N buckets' status */

typedef struct {
    int cur_index;      /* the info[] is organized in a ring */
    int num_used;

    read_status_t info[TRACK_BUCKET_COUNT];
} track_state_t;


struct serf_bucket_alloc_t {
    apr_pool_t *pool;
    apr_allocator_t *allocator;

    serf_unfreed_func_t unfreed;
    void *unfreed_baton;

    apr_uint32_t num_alloc;

    node_header_t *freelist;    /* free STANDARD_NODE_SIZE blocks */
    apr_memnode_t *blocks;      /* blocks we allocated for subdividing */

    track_state_t *track;
};

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
    track_state_t *track;

    allocator->pool = pool;
    allocator->allocator = apr_pool_allocator_get(pool);
    allocator->unfreed = unfreed;
    allocator->unfreed_baton = unfreed_baton;

    track = allocator->track = apr_palloc(pool, sizeof(*allocator->track));
    track->cur_index = 0;
    track->num_used = 0;
    track->info[0].bucket = NULL;       /* see __record_read() */

    /* ### this implies buckets cannot cross a fork/exec. desirable?
     *
     * ### hmm. it probably also means that buckets cannot be AROUND
     * ### during a fork/exec. the new process will try to clean them
     * ### up and figure out there are unfreed blocks...
     */
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


/* ==================================================================== */


#ifdef SERF_DEBUG_BUCKET_USE

static read_status_t *find_read_status(
    track_state_t *track,
    serf_bucket_t *bucket,
    int create_rs)
{
    read_status_t *rs;

    /* Note that if num_used == 0, we still probe into info[]. We always
     * ensure that info[0].bucket == NULL when num_used == 0.
     */
    if ((rs = &track->info[track->cur_index])->bucket != bucket) {
        int count = track->num_used;
        int idx = track->cur_index;
        int found = 0;

        /* Search backwards. In all likelihood, the bucket which just got
         * read was read very recently.
         *
         * Don't enter the while loop for num_used == 0 or 1.
         */
        while (--count > 0) {
            if (!idx--)
                idx = track->num_used - 1;
            if ((rs = &track->info[idx])->bucket == bucket) {
                found = 1;
                break;
            }
        }

        if (!found) {
            /* Only create a new read_status_t when asked. */
            if (!create_rs)
                return NULL;

            if (track->num_used < TRACK_BUCKET_COUNT) {
                /* We're still filling up the ring. This is easy. */
                ++track->num_used;
                ++track->cur_index;
            }
            else {
                if (++track->cur_index == TRACK_BUCKET_COUNT)
                    track->cur_index = 0;
            }
            rs = &track->info[track->cur_index];
            rs->bucket = bucket;
            rs->last = APR_SUCCESS;     /* ### the right initial value? */
        }
    }
    /* assert: rs->bucket == bucket */

    return rs;
}

#endif /* SERF_DEBUG_BUCKET_USE */


SERF_DECLARE(apr_status_t) serf_debug__record_read(
    serf_bucket_t *bucket,
    apr_status_t status)
{
#ifndef SERF_DEBUG_BUCKET_USE
    return status;
#else

    track_state_t *track = bucket->allocator->track;
    read_status_t *rs = find_read_status(track, bucket, 1);

    /* Validate that the previous status value allowed for another read. */
    if (APR_STATUS_IS_EAGAIN(rs->last) /* ### or APR_EOF? */) {
        /* Somebody read when they weren't supposed to. Bail. */
        abort();
    }

    /* Save the current status for later. */
    rs->last = status;

    return status;
#endif
}

SERF_DECLARE(void) serf_debug__entered_loop(serf_bucket_alloc_t *allocator)
{
#ifdef SERF_DEBUG_BUCKET_USE

    track_state_t *track = allocator->track;
    read_status_t *rs = &track->info[0];

    for ( ; track->num_used; --track->num_used, ++rs ) {
        if (rs->last == APR_SUCCESS) {
            /* Somebody should have read this bucket again. */
            abort();
        }

        /* ### other status values? */
    }

    /* num_used was reset. But we don't want a false positive on [0] in
     * record_read(), so clear out the bucket field.
     */
    track->info[0].bucket = NULL;

#endif
}

SERF_DECLARE(void) serf_debug__closed_conn(serf_bucket_alloc_t *allocator)
{
#ifdef SERF_DEBUG_BUCKET_USE

    /* Just reset the number used so that we don't examine the info[] */
    allocator->track->num_used = 0;

#endif
}

SERF_DECLARE(void) serf_debug__bucket_destroy(serf_bucket_t *bucket)
{
#ifdef SERF_DEBUG_BUCKET_USE

    track_state_t *track = bucket->allocator->track;
    read_status_t *rs = find_read_status(track, bucket, 0);

    if (rs != NULL && rs->last != APR_EOF) {
        /* The bucket was destroyed before it was read to completion. */

        /* Special exception for socket buckets. If a connection remains
         * open, they are not read to completion.
         */
        if (SERF_BUCKET_IS_SOCKET(bucket))
            return;

        abort();
    }

#endif
}
