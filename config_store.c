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

#include <apr_strings.h>

#include "serf.h"
#include "serf_bucket_util.h"
#include "serf_private.h"

/* Use a linked list to store the config values, as we'll only store a couple
   of values per context. */
struct serf__config_hdr_t {
    struct config_entry_t *first;
};

typedef void (*config_free_cb_t)(serf_bucket_alloc_t *alloc, void *value);

typedef struct config_entry_t {
    apr_uint32_t key;
    void *value;
    struct config_entry_t *next;
    config_free_cb_t free_cb;
} config_entry_t;

static serf__config_hdr_t *create_config_hdr(serf_bucket_alloc_t *allocator)
{
    serf__config_hdr_t *hdr = serf_bucket_mem_calloc(allocator, sizeof(*hdr));
    return hdr;
}

static apr_status_t
add_or_replace_entry(serf_config_t *config,
                     serf__config_hdr_t *hdr, serf_config_key_t key, void *value,
                     config_free_cb_t free_cb)
{
    config_entry_t *iter = hdr->first;
    config_entry_t *last = iter;
    int found = FALSE;

    /* Find the entry with the matching key. If it exists, replace its value. */
    while (iter != NULL) {
        if (iter->key == key) {
            found = TRUE;
            break;
        }
        last = iter;
        iter = iter->next;
    }

    if (found) {
        iter->key = key;
        if (iter->free_cb)
            iter->free_cb(config->allocator, iter->value);
        iter->value = value;
        iter->free_cb = free_cb;
    } else {
        /* Not found, create a new entry and append it to the list. */
        config_entry_t *entry = serf_bucket_mem_alloc(config->allocator,
                                                      sizeof(*entry));

        entry->key = key;
        entry->value = value;
        entry->free_cb = free_cb;
        entry->next = NULL;

        if (last)
            last->next = entry;
        else
            hdr->first = entry;
    }

    return APR_SUCCESS;
}

static apr_status_t config_set_object(serf_config_t *config,
                                      serf_config_key_t key,
                                      void *value,
                                      config_free_cb_t free_cb)
{
    serf__config_hdr_t *target;

    /* Set the value in the hash table of the selected category */
    if (key & SERF_CONFIG_PER_CONTEXT) {
        target = config->per_context;
    }
    else if (key & SERF_CONFIG_PER_HOST) {
        target = config->per_host;
    }
    else {
        target = config->per_conn;
    }

    if (!target) {
        /* Config object doesn't manage keys in this category */
        return APR_EINVAL;
    }

    return add_or_replace_entry(config, target, key, value, free_cb);
}

static void cleanup_hdr(serf__config_store_t *store, serf__config_hdr_t *hdr)
{
    config_entry_t *e = hdr->first;

    serf_bucket_mem_free(store->allocator, hdr);

    while (e) {
        config_entry_t *next = e->next;

        if (e->free_cb)
            e->free_cb(store->allocator, e->value);

        serf_bucket_mem_free(store->allocator, e);
        e = next;
    }
}

static apr_status_t cleanup_store(void *baton)
{
    serf__config_store_t *store = baton;
    apr_hash_index_t *hi;

    for (hi = apr_hash_first(store->pool, store->global_per_host);
         hi;
         hi = apr_hash_next(hi))
      {
          const char *key;
          void *val;

          apr_hash_this(hi, &key, NULL, &val);

          serf_bucket_mem_free(store->allocator, (void *)key);

          cleanup_hdr(store, val);
      }

    for (hi = apr_hash_first(store->pool, store->global_per_conn);
         hi;
         hi = apr_hash_next(hi))
      {
          const char *key;
          void *val;

          apr_hash_this(hi, &key, NULL, &val);

          serf_bucket_mem_free(store->allocator, (void *)key);

          cleanup_hdr(store, val);
      }

    cleanup_hdr(store, store->global_per_context);

    return APR_SUCCESS;
}

/*** Config Store ***/
apr_status_t serf__config_store_init(serf_context_t *ctx)
{
    apr_pool_t *pool = ctx->pool;
    serf_bucket_alloc_t *alloc = serf_bucket_allocator_create(pool,
                                                              NULL, NULL);

    ctx->config_store.pool = pool;
    ctx->config_store.allocator = alloc;
    ctx->config_store.global_per_context = create_config_hdr(alloc);
    ctx->config_store.global_per_host = apr_hash_make(pool);
    ctx->config_store.global_per_conn = apr_hash_make(pool);

    apr_pool_cleanup_register(pool, &ctx->config_store, cleanup_store,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

/* Defines the key to use for per host settings */
static const char * host_key_for_conn(serf_connection_t *conn,
                                      apr_pool_t *pool)
{
    /* SCHEME://HOSTNAME:PORT, e.g. http://localhost:12345 */
    return conn->host_url;
}

/* Defines the key to use for per connection settings */
static const char * conn_key_for_conn(serf_connection_t *conn,
                                      apr_pool_t *pool)
{
    /* Key needs to be unique per connection, so stringify its pointer value */
    return apr_psprintf(pool, "%pp", conn);
}

/* Defines the key to use for per connection settings */
static const char * conn_key_for_client(serf_incoming_t *incoming,
                                        apr_pool_t *pool)
{
    /* Key needs to be unique per connection, so stringify its pointer value */
    return apr_psprintf(pool, "%pp", incoming);
}

/* Defines the key to use for per connection settings */
static const char * conn_key_for_listener(serf_listener_t *listener,
                                          apr_pool_t *pool)
{
    /* Key needs to be unique per connection, so stringify its pointer value */
    return apr_psprintf(pool, "%pp", listener);
}

apr_status_t serf__config_store_create_ctx_config(serf_context_t *ctx,
                                                  serf_config_t **config)
{
    serf__config_store_t *config_store = &ctx->config_store;

    serf_config_t *cfg = apr_pcalloc(ctx->pool, sizeof(serf_config_t));
    cfg->ctx_pool = config_store->pool;
    cfg->allocator = config_store->allocator;
    cfg->per_context = config_store->global_per_context;

    *config = cfg;
    return APR_SUCCESS;
}

apr_status_t serf__config_store_create_conn_config(serf_connection_t *conn,
                                                   serf_config_t **config)
{
    serf__config_store_t *config_store = &conn->ctx->config_store;
    const char *host_key, *conn_key;
    serf__config_hdr_t *per_conn, *per_host;
    apr_pool_t *tmp_pool;
    apr_status_t status;

    serf_config_t *cfg = apr_pcalloc(conn->pool, sizeof(serf_config_t));
    cfg->ctx_pool = config_store->pool;
    cfg->allocator = config_store->allocator;
    cfg->per_context = config_store->global_per_context;

    if ((status = apr_pool_create(&tmp_pool, cfg->ctx_pool)) != APR_SUCCESS)
        return status;

    /* Find the config values for this connection, create empty structure
        if needed */
    conn_key = conn_key_for_conn(conn, tmp_pool);
    per_conn = apr_hash_get(config_store->global_per_conn, conn_key,
                            APR_HASH_KEY_STRING);
    if (!per_conn) {
        per_conn = create_config_hdr(cfg->allocator);
        apr_hash_set(config_store->global_per_conn,
                     serf_bstrdup(cfg->allocator, conn_key),
                     APR_HASH_KEY_STRING, per_conn);
    }
    cfg->per_conn = per_conn;

    /* Find the config values for this host, create empty structure
        if needed */
    host_key = host_key_for_conn(conn, tmp_pool);
    per_host = apr_hash_get(config_store->global_per_host,
                            host_key,
                            APR_HASH_KEY_STRING);
    if (!per_host) {
        per_host = create_config_hdr(cfg->allocator);
        apr_hash_set(config_store->global_per_host,
                     serf_bstrdup(cfg->allocator, host_key),
                     APR_HASH_KEY_STRING, per_host);
    }
    cfg->per_host = per_host;

    apr_pool_destroy(tmp_pool);

    *config = cfg;

    return APR_SUCCESS;
}

apr_status_t serf__config_store_create_client_config(serf_incoming_t *client,
                                                     serf_config_t **config)
{
    serf__config_store_t *config_store = &client->ctx->config_store;
    const char *client_key;
    serf__config_hdr_t *per_conn;
    apr_pool_t *tmp_pool;
    apr_status_t status;

    serf_config_t *cfg = apr_pcalloc(client->pool, sizeof(serf_config_t));
    cfg->ctx_pool = config_store->pool;
    cfg->allocator = config_store->allocator;
    cfg->per_context = config_store->global_per_context;

    if ((status = apr_pool_create(&tmp_pool, client->pool)) != APR_SUCCESS)
        return status;

    /* Find the config values for this connection, create empty structure
    if needed */
    client_key = conn_key_for_client(client, tmp_pool);
    per_conn = apr_hash_get(config_store->global_per_conn, client_key,
                            APR_HASH_KEY_STRING);
    if (!per_conn) {
        per_conn = create_config_hdr(cfg->allocator);
        apr_hash_set(config_store->global_per_conn,
                     serf_bstrdup(cfg->allocator, client_key),
                     APR_HASH_KEY_STRING, per_conn);
    }
    cfg->per_conn = per_conn;
    cfg->per_host = NULL;

    apr_pool_destroy(tmp_pool);

    *config = cfg;

    return APR_SUCCESS;
}

apr_status_t serf__config_store_create_listener_config(serf_listener_t *listener,
                                                       serf_config_t **config)
{
    serf__config_store_t *config_store = &listener->ctx->config_store;
    const char *client_key;
    serf__config_hdr_t *per_conn;
    apr_pool_t *tmp_pool;
    apr_status_t status;

    serf_config_t *cfg = apr_pcalloc(listener->pool, sizeof(serf_config_t));
    cfg->ctx_pool = config_store->pool;
    cfg->allocator = config_store->allocator;
    cfg->per_context = config_store->global_per_context;

    if ((status = apr_pool_create(&tmp_pool, listener->pool)) != APR_SUCCESS)
        return status;

    /* Find the config values for this connection, create empty structure
    if needed */
    client_key = conn_key_for_listener(listener, tmp_pool);
    per_conn = apr_hash_get(config_store->global_per_conn, client_key,
                            APR_HASH_KEY_STRING);
    if (!per_conn) {
        per_conn = create_config_hdr(cfg->allocator);
        apr_hash_set(config_store->global_per_conn,
                     serf_bstrdup(cfg->allocator, client_key),
                     APR_HASH_KEY_STRING, per_conn);
    }
    cfg->per_conn = per_conn;
    cfg->per_host = NULL;

    apr_pool_destroy(tmp_pool);

    *config = cfg;

    return APR_SUCCESS;
}

apr_status_t
serf__config_store_remove_connection(serf__config_store_t config_store,
                                     serf_connection_t *conn)
{
    return APR_ENOTIMPL; /* Mem leak? */
}

apr_status_t
serf__config_store_remove_client(serf__config_store_t config_store,
                                 serf_incoming_t *client)
{
    return APR_ENOTIMPL; /* Mem leak? */
}


apr_status_t
serf__config_store_remove_host(serf__config_store_t config_store,
                               const char *hostname_port)
{
    return APR_ENOTIMPL; /* Mem leak? */
}

/*** Config ***/
apr_status_t serf_config_set_string(serf_config_t *config,
                                    serf_config_key_t key,
                                    const char *value)
{
    /* Cast away const is ok here, the callers should always use
       serf_config_get_string for this key. */
    return serf_config_set_object(config, key, (void *)value);
}

apr_status_t serf_config_set_stringc(serf_config_t *config,
                                     serf_config_key_t key,
                                     const char *value)
{
    char *cvalue;

    cvalue = serf_bstrdup(config->allocator, value);

    return config_set_object(config, key, cvalue,
                             serf_bucket_mem_free);
}

apr_status_t serf_config_set_stringf(serf_config_t *config,
                                     serf_config_key_t key,
                                     apr_pool_t *scratch_pool,
                                     const char *fmt, ...)
{
    va_list argp;
    char *cvalue;

    va_start(argp, fmt);
    cvalue = apr_pvsprintf(scratch_pool, fmt, argp);
    va_end(argp);

    return serf_config_set_stringc(config, key, cvalue);
}

apr_status_t serf_config_set_object(serf_config_t *config,
                                    serf_config_key_t key,
                                    void *value)
{
    return config_set_object(config, key, value, NULL);
}

apr_status_t serf_config_get_string(serf_config_t *config,
                                    serf_config_key_t key,
                                    const char **value)
{
    return serf_config_get_object(config, key, (void**)value);
}

apr_status_t serf_config_get_object(serf_config_t *config,
                                    serf_config_key_t key,
                                    void **value)
{
    serf__config_hdr_t *target;

    if (config == NULL) {
        *value = NULL;
        return APR_EINVAL;
    }
    if (key & SERF_CONFIG_PER_CONTEXT)
        target = config->per_context;
    else if (key & SERF_CONFIG_PER_HOST)
        target = config->per_host;
    else
        target = config->per_conn;

    *value = NULL;
    if (target) {
        config_entry_t *iter = target->first;
        /* Find the matching key and return its value */
        while (iter != NULL) {
            if (iter->key == key) {
                *value = iter->value;
                return APR_SUCCESS;
            }
            iter = iter->next;
        }
        return APR_SUCCESS;
    } else {
        /* Config object doesn't manage keys in this category */
        return APR_EINVAL;
    }
}

apr_status_t serf_config_remove_value(serf_config_t *config,
                                      serf_config_key_t key)
{
    return serf_config_set_object(config, key, NULL);
}
