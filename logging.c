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

#include "serf.h"
#include "serf_private.h"

/* For optimizations, we allow logging to be disabled entirely. */
#ifdef SERF_LOGGING_ENABLED

typedef struct log_baton_t {
    apr_array_header_t *output_list;
} log_baton_t;

typedef apr_status_t (*log_to_output_t)(serf_log_output_t *output,
                                        serf_config_t *config,
                                        apr_uint32_t level,
                                        apr_uint32_t comp,
                                        int header,
                                        const char *prefix,
                                        const char *fmt,
                                        va_list argp);

struct serf_log_output_t {
    apr_uint32_t level;
    apr_uint32_t comps;
    serf_log_layout_t *layout;
    log_to_output_t logger;
    void *baton;
};

const char * loglvl_labels[] = {
    "",
    "ERROR", /* 0x0001 */
    "WARN ", /* 0x0002 */
    "",
    "INFO ", /* 0x0004 */
    "",
    "",
    "",
    "DEBUG", /* 0x0008 */
};

apr_status_t serf__log_init(serf_context_t *ctx)
{
    log_baton_t *log_baton;
    serf_config_t *config = ctx->config;

    log_baton = apr_palloc(ctx->pool, sizeof(log_baton_t));
    log_baton->output_list = apr_array_make(ctx->pool, 1,
                                            sizeof(serf_log_output_t *));

    /* TODO: remove before next serf release, FOR TESTING ONLY */
    {
        serf_log_output_t *output;
        apr_status_t status;

        status = serf_logging_create_stream_output(&output, ctx,
                                                   ACTIVE_LOGLEVEL,
                                                   ACTIVE_LOGCOMPS,
                                                   SERF_LOG_DEFAULT_LAYOUT,
                                                   stderr, ctx->pool);
        if (status)
            return status;

        status = serf_config_set_object(config, SERF_CONFIG_CTX_LOGBATON,
                                        log_baton);
        if (status)
            return status;

        status = serf_logging_add_output(ctx, output);
        if (status)
            return status;
    }

    return APR_SUCCESS;
}

static void log_time(FILE *logfp)
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(logfp, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void serf__log_nopref(apr_uint32_t level, apr_uint32_t comp,
                      serf_config_t *config, const char *fmt, ...)
{
    va_list argp;
    log_baton_t *log_baton;
    apr_status_t status;

    if (!config) {
        /* If we can't get the log baton we have no choice but to silently
           return without logging. */
        return;
    }

    status = serf_config_get_object(config, SERF_CONFIG_CTX_LOGBATON,
                                    (void **)&log_baton);

    if (!status && log_baton) {
        int i;

        for (i = 0; i < log_baton->output_list->nelts; i++) {
            serf_log_output_t *output = APR_ARRAY_IDX(log_baton->output_list,
                                                      i, serf_log_output_t *);
            if ((output->level >= level) && (comp & output->comps)) {
                va_start(argp, fmt);
                output->logger(output, config, level, comp, 0, "", fmt, argp);
                va_end(argp);

            }
        }
    }
}

void serf__log(apr_uint32_t level, apr_uint32_t comp, const char *prefix,
               serf_config_t *config, const char *fmt, ...)
{
    va_list argp;
    log_baton_t *log_baton;
    apr_status_t status;

    if (!config) {
        /* If we can't get the log baton we have no choice but to silently
           return without logging. */
        return;
    }

    status = serf_config_get_object(config, SERF_CONFIG_CTX_LOGBATON,
                                    (void **)&log_baton);

    if (!status && log_baton) {
        int i;

        for (i = 0; i < log_baton->output_list->nelts; i++) {
            serf_log_output_t *output = APR_ARRAY_IDX(log_baton->output_list,
                                                      i, serf_log_output_t *);
            if ((output->level >= level) && (comp & output->comps)) {
                va_start(argp, fmt);
                output->logger(output, config, level, comp, 1, prefix, fmt, argp);
                va_end(argp);

            }
        }
    }
}

/*** Output to system stream (stderr or stdout) or a file ***/

static apr_status_t log_to_stream_output(serf_log_output_t *output,
                                         serf_config_t *config,
                                         apr_uint32_t level,
                                         apr_uint32_t comp,
                                         int header,
                                         const char *prefix,
                                         const char *fmt,
                                         va_list argp)
{
    if (output && output->baton) {
        FILE *logfp = output->baton;

        if (output->layout == SERF_LOG_DEFAULT_LAYOUT && header) {
            const char *localip, *remoteip;
            apr_status_t status;

            log_time(logfp);

            /* Log local and remote ip address:port */
            fprintf(logfp, "%s [l:", loglvl_labels[level]);
            status = serf_config_get_string(config, SERF_CONFIG_CONN_LOCALIP,
                                            &localip);
            if (!status && localip) {
                fprintf(logfp, "%s", localip);
            }

            fprintf(logfp, " r:");
            status = serf_config_get_string(config, SERF_CONFIG_CONN_REMOTEIP,
                                            &remoteip);
            if (!status && remoteip) {
                fprintf(logfp, "%s", remoteip);
            }
            fprintf(logfp, "] ");
            
            if (prefix)
                fprintf(logfp, "%s: ", prefix);
        }

        vfprintf(logfp, fmt, argp);

        return APR_SUCCESS;
    }

    return APR_EINVAL;
}

apr_status_t serf_logging_create_stream_output(serf_log_output_t **output,
                                               serf_context_t *ctx,
                                               apr_uint32_t level,
                                               apr_uint32_t comp_mask,
                                               serf_log_layout_t *layout,
                                               FILE *fp,
                                               apr_pool_t *pool)
{
    serf_log_output_t *baton;

    baton = apr_palloc(pool, sizeof(serf_log_output_t));
    baton->baton = fp;
    baton->logger = log_to_stream_output;
    baton->level = level;
    baton->comps = comp_mask;
    baton->layout = layout;

    *output = baton;
    return APR_SUCCESS;
}

apr_status_t serf_logging_add_output(serf_context_t *ctx,
                                     const serf_log_output_t *output)
{
    apr_status_t status;
    log_baton_t *log_baton;

    status = serf_config_get_object(ctx->config, SERF_CONFIG_CTX_LOGBATON,
                                    (void **)&log_baton);
    if (!status && log_baton) {
        APR_ARRAY_PUSH(log_baton->output_list, const serf_log_output_t *) = output;
    }

    return status;
}

#else

/* We wish to compile out all logging stubs. */

apr_status_t serf__log_init(serf_context_t *ctx)
{
    return APR_SUCCESS;
}

void serf__log_nopref(apr_uint32_t level, apr_uint32_t comp,
                      serf_config_t *config, const char *fmt, ...)
{
}

void serf__log(apr_uint32_t level, apr_uint32_t comp, const char *prefix,
               serf_config_t *config, const char *fmt, ...)
{
}

apr_status_t serf_logging_create_stream_output(serf_log_output_t **output,
                                               serf_context_t *ctx,
                                               apr_uint32_t level,
                                               apr_uint32_t comp_mask,
                                               serf_log_layout_t *layout,
                                               FILE *fp,
                                               apr_pool_t *pool)
{
    return APR_SUCCESS;
}

apr_status_t serf_logging_add_output(serf_context_t *ctx,
                                     const serf_log_output_t *output)
{
    return APR_SUCCESS;
}

#endif
