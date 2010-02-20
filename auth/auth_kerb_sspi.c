/* Copyright 2010 Justin Erenkrantz and Greg Stein
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

#ifdef SERF_USE_SSPI
#include <apr.h>
#include <apr_strings.h>

#define SECURITY_WIN32
#include <sspi.h>

struct serf__kerb_context_t
{
    CredHandle sspi_credentials;
    CtxtHandle sspi_context;
    BOOL initalized;
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
    SECURITY_STATUS status;
    ULONG actual_attr;
    SecBuffer sspi_in_buffer;
    SecBufferDesc sspi_in_buffer_desc;
    SecBuffer sspi_out_buffer;
    SecBufferDesc sspi_out_buffer_desc;
    serf__kerb_context_t *context = *ctx_p;
    char *target_name;

    if (context == SERF__KERB_NO_CONTEXT) {
        context = malloc(sizeof(*context));
        SecInvalidateHandle(&context->sspi_context);
        SecInvalidateHandle(&context->sspi_credentials);
        context->initalized = FALSE;

        status = AcquireCredentialsHandle(
            NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
            NULL, NULL, NULL, NULL,
            &context->sspi_credentials, NULL);

        if (FAILED(status)) {
            return APR_EGENERAL;
        }

        *ctx_p = context;
    }

    target_name = apr_pstrcat(scratch_pool, service, "/", hostname, NULL);

    /* Prepare input buffer description. */
    sspi_in_buffer.BufferType = SECBUFFER_TOKEN;
    sspi_in_buffer.pvBuffer = input_buf->value;
    sspi_in_buffer.cbBuffer = input_buf->length; 

    sspi_in_buffer_desc.cBuffers = 1;
    sspi_in_buffer_desc.pBuffers = &sspi_in_buffer;
    sspi_in_buffer_desc.ulVersion = SECBUFFER_VERSION;

    /* Output buffers. Output buffer will be allocated by system. */
    sspi_out_buffer.BufferType = SECBUFFER_TOKEN;
    sspi_out_buffer.pvBuffer = NULL; 
    sspi_out_buffer.cbBuffer = 0;

    sspi_out_buffer_desc.cBuffers = 1;
    sspi_out_buffer_desc.pBuffers = &sspi_out_buffer;
    sspi_out_buffer_desc.ulVersion = SECBUFFER_VERSION;

    status = InitializeSecurityContext(
        &context->sspi_credentials,
        context->initalized ? &context->sspi_context : NULL,
        target_name,
        ISC_REQ_ALLOCATE_MEMORY
        | ISC_REQ_MUTUAL_AUTH
        | ISC_REQ_CONFIDENTIALITY,
        0,                          /* Reserved1 */
        SECURITY_NETWORK_DREP,
        &sspi_in_buffer_desc,
        0,                          /* Reserved2 */
        &context->sspi_context,
        &sspi_out_buffer_desc,
        &actual_attr,
        NULL);

    context->initalized = TRUE;

    /* Finish authentication if SSPI requires so. */
    if (status == SEC_I_COMPLETE_NEEDED
        || status == SEC_I_COMPLETE_AND_CONTINUE)
    {
        CompleteAuthToken(&context->sspi_context, &sspi_out_buffer_desc);
    }

    output_buf->value = sspi_out_buffer.pvBuffer;
    output_buf->length = sspi_out_buffer.cbBuffer;

    switch(status) {
    case SEC_I_COMPLETE_AND_CONTINUE:
    case SEC_I_CONTINUE_NEEDED:
        return APR_EAGAIN;

    case SEC_I_COMPLETE_NEEDED:
    case SEC_E_OK:
        return APR_SUCCESS;

    default:
        return APR_EGENERAL;
    }
}

apr_status_t
serf__kerb_release_buffer(serf__kerb_buffer_t *buf)
{
    if (buf->length > 0 && buf->value != NULL) {
        FreeContextBuffer(buf->value);
        buf->length = 0;
        buf->value = NULL;
    }

    return APR_SUCCESS;
}

apr_status_t
serf__kerb_delete_sec_context(serf__kerb_context_t *ctx)
{
    if (SecIsValidHandle(&ctx->sspi_context)) {
        DeleteSecurityContext(&ctx->sspi_context);
        SecInvalidateHandle(&ctx->sspi_context);
    }

    if (SecIsValidHandle(&ctx->sspi_credentials)) {
        FreeCredentialsHandle(&ctx->sspi_context);
        SecInvalidateHandle(&ctx->sspi_context);
    }

    free(ctx);

    return APR_SUCCESS;
}

#endif /* SERF_USE_SSPI */