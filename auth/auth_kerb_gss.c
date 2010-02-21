/* Copyright 2009 Justin Erenkrantz and Greg Stein
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

#include "auth_kerb.h"

#ifdef SERF_USE_GSSAPI
#include <apr_strings.h>
#include <gssapi/gssapi.h>
#include <stdlib.h>

struct serf__kerb_context_t
{
    /* GSSAPI context */
    gss_ctx_id_t gss_ctx;

    /* Mechanism used to authenticate, should be Kerberos. */
    gss_OID gss_mech;
};

apr_status_t
serf__kerb_init_sec_context(serf__kerb_context_t **ctx_p,
                              const char *service,
                              const char *hostname,
                              serf__kerb_buffer_t *input_buf,
                              serf__kerb_buffer_t *output_buf,
                              apr_pool_t *scratch_pool
                              )
{
    gss_buffer_desc gss_input_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc gss_output_buf;
    OM_uint32 gss_min_stat, gss_maj_stat;
    gss_name_t host_gss_name;
    gss_buffer_desc bufdesc;
    serf__kerb_context_t *ctx = *ctx_p;

    /* Get the name for the HTTP service at the target host. */
    bufdesc.value = apr_pstrcat(scratch_pool, service, "@", hostname, NULL);
    bufdesc.length = strlen(bufdesc.value);
    gss_maj_stat = gss_import_name (&gss_min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
                                    &host_gss_name);
    if(GSS_ERROR(gss_maj_stat)) {
        return APR_EGENERAL;
    }

    if (ctx == SERF__KERB_NO_CONTEXT)
    {
        ctx = malloc(sizeof(*ctx));
        ctx->gss_ctx = GSS_C_NO_CONTEXT;
        ctx->gss_mech = GSS_C_NO_OID;
        *ctx_p = ctx;
    }

    /* If the server sent us a token, pass it to gss_init_sec_token for
       validation. */
    gss_input_buf.value = input_buf->value;
    gss_input_buf.length = input_buf->length;

    /* Establish a security context to the server. */
    gss_maj_stat = gss_init_sec_context
        (&gss_min_stat,             /* minor_status */
         GSS_C_NO_CREDENTIAL,       /* XXXXX claimant_cred_handle */
         &ctx->gss_ctx,              /* gssapi context handle */
         host_gss_name,             /* HTTP@server name */
         ctx->gss_mech,             /* mech_type (0 ininitially */
         GSS_C_MUTUAL_FLAG,         /* ensure the peer authenticates itself */
         0,                         /* default validity period */
         GSS_C_NO_CHANNEL_BINDINGS, /* do not use channel bindings */
         &gss_input_buf,            /* server token, initially empty */
         &ctx->gss_mech,            /* actual mech type */
         &gss_output_buf,           /* output_token */
         NULL,                      /* ret_flags */
         NULL                       /* not interested in remaining validity */
         );

    output_buf->value = gss_output_buf.value;
    output_buf->length = gss_output_buf.length;

    switch(gss_maj_stat) {
    case GSS_S_COMPLETE:
        return APR_SUCCESS;
    case GSS_S_CONTINUE_NEEDED:
        return APR_EAGAIN;
    default:
        return APR_EGENERAL;
    }
}

apr_status_t serf__kerb_delete_sec_context(serf__kerb_context_t *ctx)
{
    OM_uint32 min_stat;

    if (ctx->gss_ctx != GSS_C_NO_CONTEXT) {
        if (gss_delete_sec_context(&min_stat, &ctx->gss_ctx,
                                   GSS_C_NO_BUFFER) == GSS_S_FAILURE)
            return APR_EGENERAL;
    }

    free(ctx);

    return APR_SUCCESS;
}

apr_status_t serf__kerb_release_buffer(serf__kerb_buffer_t *buf)
{
    OM_uint32 min_stat;
    gss_buffer_desc gss_buf;

    gss_buf.length = buf->length;
    gss_buf.value = buf->value;

    gss_release_buffer(&min_stat, &gss_buf);

    return APR_SUCCESS;
}

#endif /* SERF_USE_GSSAPI */
