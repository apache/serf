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
#if APR_HAS_THREADS
#  include <apr_atomic.h>
#  include <apr_time.h>
#endif

#include "serf_private.h"


enum init_once_state
{
    INIT_ONCE_NONE = SERF__INIT_ONCE_NONE,
    INIT_ONCE_BUSY,
    INIT_ONCE_DONE
};

static apr_uint32_t cas(volatile apr_uint32_t *mem,
                        apr_uint32_t val,
                        apr_uint32_t cmp)
{
#if APR_HAS_THREADS
    return apr_atomic_cas32(mem, val, cmp);
#else
    const apr_uint32_t prev = *mem;
    if (prev == cmp) {
        *mem = val;
    }
    return prev;
#endif
}

apr_status_t serf__init_once(struct serf__init_once_context *init_ctx,
                             serf__init_once_func_t init_func,
                             void *init_baton)
{
    apr_uint32_t state = cas(&init_ctx->state, INIT_ONCE_BUSY, INIT_ONCE_NONE);
    for (;;)
    {
        switch (state)
        {
        case INIT_ONCE_DONE:
            /* Already initialized. */
            return init_ctx->status;

        case INIT_ONCE_BUSY:
            /* Spin while the initializer is working. */
            apr_sleep(APR_USEC_PER_SEC / 500);
            state = cas(&init_ctx->state, INIT_ONCE_NONE, INIT_ONCE_NONE);
            continue;

        case INIT_ONCE_NONE:
            /* We're the single initializer, invoke the init code. */
            init_ctx->status = init_func(init_baton);
            cas(&init_ctx->state, INIT_ONCE_DONE, INIT_ONCE_BUSY);
            return init_ctx->status;

        default:
            /* Not reached, can't happen. */
            return APR_EGENERAL; /* FIXME: Just abort()? */
        }
    }
}
