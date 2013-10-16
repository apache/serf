/* Copyright 2013 Justin Erenkrantz and Greg Stein
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

/* Logging functions.
   Use with one of the [COMP]_VERBOSE defines so that the compiler knows to
   optimize this code out when no logging is needed. */

#include "serf.h"
#include "serf_private.h"

struct log_baton_t {
    FILE *fp;
    apr_uint32_t level;
    apr_uint32_t comps;
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
#ifdef SERF_LOGGING_ENABLED
    log_baton_t *log_baton;
    serf_config_t *config;
    apr_status_t status;

    log_baton = apr_palloc(ctx->pool, sizeof(log_baton_t));
    log_baton->fp = stderr;
    log_baton->level = SERF_LOG_NONE;
    log_baton->comps = SERF_LOGCOMP_NONE;

    /* TODO: remove before next serf release, FOR TESTING ONLY */
    log_baton->level = ACTIVE_LOGLEVEL;
    log_baton->comps = ACTIVE_LOGCOMPS;

    status = serf__config_store_get_config(ctx, NULL, &config, ctx->pool);
    if (status)
        return status;

    return serf_config_set_object(config, SERF_CONFIG_CTX_LOGBATON, log_baton);
#else
    return APR_SUCCESS;
#endif
}

/* Logging functions.
   Use with one of the [COMP]_VERBOSE defines so that the compiler knows to
   optimize this code out when no logging is needed. */
#ifdef SERF_LOGGING_ENABLED
static void log_time(FILE *logfp)
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(logfp, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}
#endif

void serf__log_nopref(apr_uint32_t level, apr_uint32_t comp,
                      serf_config_t *config, const char *fmt, ...)
{
#ifdef SERF_LOGGING_ENABLED
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

    if (!status && log_baton &&
        (log_baton->level >= level) && (comp & log_baton->comps))
    {
        if (log_baton->fp) {
            va_start(argp, fmt);
            vfprintf(log_baton->fp, fmt, argp);
            va_end(argp);
        }
    }
#endif
}

void serf__log(apr_uint32_t level, apr_uint32_t comp, const char *filename,
               serf_config_t *config, const char *fmt, ...)
{
#ifdef SERF_LOGGING_ENABLED
    va_list argp;
    const char *localip, *remoteip;
    log_baton_t *log_baton;
    apr_status_t status;

    if (!config) {
        /* If we can't get the log baton we have no choice but to silently
           return without logging. */
        return;
    }

    status = serf_config_get_object(config, SERF_CONFIG_CTX_LOGBATON,
                                    (void **)&log_baton);

    if (!status && log_baton &&
        (log_baton->level >= level) && (comp & log_baton->comps))
    {
        if (log_baton->fp) {
            FILE *logfp = log_baton->fp;

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

            if (filename)
                fprintf(logfp, "%s: ", filename);
            
            va_start(argp, fmt);
            vfprintf(logfp, fmt, argp);
            va_end(argp);
        }
    }
#endif
}
