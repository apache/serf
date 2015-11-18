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
    apr_pool_t *pool;
    struct config_entry_t *first;
};

typedef struct config_entry_t {
    apr_uint32_t key;
    void *value;
    struct config_entry_t *next;
} config_entry_t;

static serf__config_hdr_t *create_config_hdr(apr_pool_t *pool)
{
    serf__config_hdr_t *hdr = apr_pcalloc(pool, sizeof(serf__config_hdr_t));
    hdr->pool = pool;
    return hdr;
}

static apr_status_t
add_or_replace_entry(serf__config_hdr_t *hdr, serf_config_key_t key, void *value)
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
        iter->value = value;
    } else {
        /* Not found, create a new entry and append it to the list. */
        config_entry_t *entry = apr_palloc(hdr->pool, sizeof(config_entry_t));
        entry->key = key;
        entry->value = value;
        entry->next = NULL;

        if (last)
            last->next = entry;
        else
            hdr->first = entry;
    }

    return APR_SUCCESS;
}

/*** Config Store ***/
apr_status_t serf__config_store_init(serf_context_t *ctx)
{
    apr_pool_t *pool = ctx->pool;

    ctx->config_store.pool = pool;
    ctx->config_store.global_per_context = create_config_hdr(pool);
    ctx->config_store.global_per_host = apr_hash_make(pool);
    ctx->config_store.global_per_conn = apr_hash_make(pool);

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


/* TODO: when will this be released? Related config to a specific lifecyle:
   connection or context */
apr_status_t serf__config_store_get_config(serf_context_t *ctx,
                                           serf_connection_t *conn,
                                           serf_config_t **config,
                                           apr_pool_t *out_pool)
{
    serf__config_store_t *config_store = &ctx->config_store;

    serf_config_t *cfg = apr_pcalloc(out_pool, sizeof(serf_config_t));
    cfg->ctx_pool = ctx->pool;
    cfg->per_context = config_store->global_per_context;

    if (conn) {
        const char *host_key, *conn_key;
        serf__config_hdr_t *per_conn, *per_host;
        apr_pool_t *tmp_pool;
        apr_status_t status;

        cfg->conn_pool = conn->pool;

        if ((status = apr_pool_create(&tmp_pool, out_pool)) != APR_SUCCESS)
            return status;

        /* Find the config values for this connection, create empty structure
           if needed */
        conn_key = conn_key_for_conn(conn, tmp_pool);
        per_conn = apr_hash_get(config_store->global_per_conn, conn_key,
                                APR_HASH_KEY_STRING);
        if (!per_conn) {
            per_conn = create_config_hdr(conn->pool);
            apr_hash_set(config_store->global_per_conn,
                         apr_pstrdup(conn->pool, conn_key),
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
            per_host = create_config_hdr(config_store->pool);
            apr_hash_set(config_store->global_per_host,
                         apr_pstrdup(config_store->pool, host_key),
                         APR_HASH_KEY_STRING, per_host);
        }
        cfg->per_host = per_host;

        apr_pool_destroy(tmp_pool);
    }

    *config = cfg;

    return APR_SUCCESS;
}

apr_status_t serf__config_store_get_client_config(serf_context_t *ctx,
                                                  serf_incoming_t *client,
                                                  serf_config_t **config,
                                                  apr_pool_t *out_pool)
{
    serf__config_store_t *config_store = &ctx->config_store;

    serf_config_t *cfg = apr_pcalloc(out_pool, sizeof(serf_config_t));
    cfg->ctx_pool = ctx->pool;
    cfg->per_context = config_store->global_per_context;

    if (client) {
        const char *client_key;
        serf__config_hdr_t *per_conn;
        apr_pool_t *tmp_pool;
        apr_status_t status;

        cfg->conn_pool = client->pool;

        if ((status = apr_pool_create(&tmp_pool, out_pool)) != APR_SUCCESS)
            return status;

        /* Find the config values for this connection, create empty structure
        if needed */
        client_key = conn_key_for_client(client, tmp_pool);
        per_conn = apr_hash_get(config_store->global_per_conn, client_key,
                                APR_HASH_KEY_STRING);
        if (!per_conn) {
            per_conn = create_config_hdr(client->pool);
            apr_hash_set(config_store->global_per_conn,
                         apr_pstrdup(client->pool, client_key),
                         APR_HASH_KEY_STRING, per_conn);
        }
        cfg->per_conn = per_conn;
        cfg->per_host = NULL;

        apr_pool_destroy(tmp_pool);
    }

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
    const char *cvalue;
    apr_pool_t *pool;

    if (key & SERF_CONFIG_PER_CONTEXT ||
        key & SERF_CONFIG_PER_HOST) {
        pool = config->ctx_pool;
    } else {
        pool = config->conn_pool;
    }

    cvalue = apr_pstrdup(pool, value);

    return serf_config_set_string(config, key, cvalue);
}

apr_status_t serf_config_set_stringf(serf_config_t *config,
                                     serf_config_key_t key,
                                     const char *fmt, ...)
{
    apr_pool_t *pool;
    va_list argp;
    char *cvalue;

    if (key & SERF_CONFIG_PER_CONTEXT)
        pool = config->ctx_pool;
    else if (key & SERF_CONFIG_PER_HOST)
        pool = config->ctx_pool;
    else
        pool = config->conn_pool;

    va_start(argp, fmt);
    cvalue = apr_pvsprintf(pool, fmt, argp);
    va_end(argp);

    return serf_config_set_string(config, key, cvalue);
}

apr_status_t serf_config_set_object(serf_config_t *config,
                                    serf_config_key_t key,
                                    void *value)
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

    return add_or_replace_entry(target, key, value);
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
