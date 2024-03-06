
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "tss2/tss2_sys.h"
#include "tss2/tss2_tpm2_types.h"
#include "tss2/tss2_tcti.h"
#include "tss2/tss2_common.h"
#include "tss2/tss2_tctildr.h"

// #include "context-util.h"
#include "sys-util.h"
#include "session-util.h"

#define TPM20_INDEX_PASSWORD_TEST    0x01500020

#define NV_DATA         "bound/unsalt with param encrypt"
#define NV_DATA_SIZE    strlen(NV_DATA)

#define NV_AUTH_DATA     "passNvAuth"
#define NV_AUTH_SIZE     strlen(NV_AUTH_DATA)

#define BIND_AUTH_DATA  "passBindAuth"
#define BIND_AUTH_SIZE  strlen(BIND_AUTH_DATA)

// bind and unsalted session with param encryption
TSS2_RC _nv_write_session_ParamEncry ( 
    TSS2_SYS_CONTEXT *sys_ctx,
    const TPM2B_DIGEST *authPolicy,
    TPMA_NV nvAttributes,
    TPM2_SE session_type)
{
    TSS2_RC rc;
    TPM2B_AUTH  nvAuth = { 0 };
    TPM2B_AUTH  bindAuth = { 0 };

    SESSION *nvSession = NULL;
    TPM2B_NAME nvName;
    TPM2B_NONCE nonceCaller = { 0, };
    TPM2B_MAX_NV_BUFFER nvWriteData={ 0 };

    TPM2B_MAX_NV_BUFFER nvReadData = { .size = TPM2B_SIZE (nvReadData), };
    TPM2B_ENCRYPTED_SECRET encryptedSalt = { 0, };
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2L_SYS_AUTH_RESPONSE nvRspAuths;
    TSS2L_SYS_AUTH_COMMAND nvCmdAuths = {
        .count = 1,
        .auths= {
            {
                .nonce = {
                    .size = 1,
                    .buffer = { 0xa5, },
                },
                .sessionHandle = TPM2_RH_PW,
                .sessionAttributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT,
            }
        }
    };

    nvWriteData.size = NV_DATA_SIZE;
    memcpy(nvWriteData.buffer, NV_DATA, NV_DATA_SIZE);

    nvAuth.size = NV_AUTH_SIZE;
    memcpy(nvAuth.buffer, NV_AUTH_DATA, NV_AUTH_SIZE);

    bindAuth.size = BIND_AUTH_SIZE,
    memcpy(bindAuth.buffer, BIND_AUTH_DATA, BIND_AUTH_SIZE);

    rc = Tss2_Sys_GetTctiContext (sys_ctx, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS || tcti_ctx == NULL) {
        printf ("Failed to get TCTI from Sys context, got RC: 0x%x\n", rc);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    rc = AddEntity(TPM20_INDEX_PASSWORD_TEST, &nvAuth);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("AddEntity failed with RC: 0x%x\n", rc);
        return rc;
    }

    /* Get the name of the NV index. */
    rc = tpm_handle_to_name (tcti_ctx,
                             TPM20_INDEX_PASSWORD_TEST,
                             &nvName);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("tpm_handle_to_name failed with RC: 0x%x\n", rc);
        return rc;
    }

    symmetric.algorithm = TPM2_ALG_AES;
    symmetric.keyBits.aes = 128;
    symmetric.mode.aes = TPM2_ALG_CFB;

    /*
     * Start HMAC or real (non-trial) policy authorization session:
     * it's an unbound and unsalted session, no symmetric
     * encryption algorithm, and SHA256 is the session's
     * hash algorithm.
     */
    rc = create_auth_session (&nvSession,
                              TPM2_RH_NULL,
                              0,
                              TPM2_RH_OWNER,
                              &bindAuth,
                              &nonceCaller,
                              &encryptedSalt,
                              session_type,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("create_auth_session failed with RC: 0x%x\n", rc);
        return rc;
    }

    /* set handle in command auth */
    nvCmdAuths.auths[0].sessionHandle = nvSession->sessionHandle;

    /*
     * Get the name of the session and save it in
     * the nvSession structure.
     */
    rc = tpm_handle_to_name (tcti_ctx,
                             nvSession->sessionHandle,
                             &nvSession->name);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("tpm_handle_to_name failed with RC: 0x%x", rc);
        return rc;
    }

    /* First call prepare in order to create cpBuffer. */
    rc = Tss2_Sys_NV_Write_Prepare (sys_ctx,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    &nvWriteData,
                                    0);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("Tss2_Sys_NV_Write_Prepare failed with RC: 0x%x\n", rc);
        return rc;
    }

    /* Roll nonces for command */
    roll_nonces (nvSession, &nvCmdAuths.auths[0].nonce);

    TPM2B_MAX_BUFFER encrypted_param, decrypted_param;
    size_t decrypt_param_size, encrypt_param_size;
    const uint8_t *decrypt_param_ptr, *encrypt_param_ptr;

    rc = Tss2_Sys_GetDecryptParam(sys_ctx, &decrypt_param_size, &decrypt_param_ptr);
    if (rc) {
        printf("Tss2_Sys_GetDecryptParam failed 0x%" PRIx32 "\n", rc);
        return rc;
    }

    rc = encrypt_command_param(nvSession, &encrypted_param,
                            (TPM2B_MAX_BUFFER *)&nvWriteData, &nvAuth);
    if (rc) {
        printf("encrypt_command_param failed 0x%" PRIx32 "\n", rc);
        return rc;
    }

    printf("encrypted_param.size: %d\n", encrypted_param.size);
    for(int i=0; i<encrypted_param.size; i++){
        printf("0x%02X ", encrypted_param.buffer[i]);
    }
    printf("\n");

    rc = Tss2_Sys_SetDecryptParam(sys_ctx, encrypted_param.size,
                                encrypted_param.buffer);
    if (rc) {
        printf("Tss2_Sys_SetDecryptParam failed 0x%" PRIx32, rc);
        return rc;
    }

    rc = compute_command_hmac(sys_ctx,
                            TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST,
                            TPM2_RH_NULL,
                            &nvCmdAuths);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("compute_command_hmac failed with RC: 0x%x\n", rc);
        return rc;
    }

    rc = Tss2_Sys_SetCmdAuths(sys_ctx, &nvCmdAuths);
    if (rc) {
        printf("Tss2_Sys_SetCmdAuths failed 0x%" PRIx32"\n", rc);
        return rc;
    }

    rc = Tss2_Sys_Execute(sys_ctx);
    if (rc) {
        if ((rc & 0x0000ffff) == TPM2_RC_RETRY) {
            printf("Tss2_Sys_Execute returned retry 0x%" PRIx32 "\n", rc);
            Tss2_Sys_FlushContext(sys_ctx, nvSession->sessionHandle);
            end_auth_session(nvSession);
            return rc;
        }

        printf("Tss2_Sys_Execute failed 0x%" PRIx32 "\n", rc);
        return rc;
    }

    rc = Tss2_Sys_GetRspAuths(sys_ctx, &nvRspAuths);
    if (rc) {
        printf("Tss2_Sys_GetRspAuths failed 0x%" PRIx32 "\n", rc);
        return rc;
    }

    /* Roll nonces for response */
    roll_nonces (nvSession, &nvRspAuths.auths[0].nonce);

    /*
     * If the command was successful, check the
     * response HMAC to make sure that the
     * response was received correctly.
     */
    rc = check_response_hmac (sys_ctx,
                              &nvCmdAuths,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM20_INDEX_PASSWORD_TEST,
                              TPM2_RH_NULL,
                              &nvRspAuths);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("check_response_hmac failed with RC: 0x%x\n", rc);
        return rc;
    }

    /* Delete the NV index's entry in the entity table. */
    DeleteEntity (TPM20_INDEX_PASSWORD_TEST);

    /* Flush Context */
    rc = Tss2_Sys_FlushContext(sys_ctx, nvSession->sessionHandle);
    if (rc)
        printf("Tss2_Sys_FlushContext failed 0x%" PRIx32 "\n", rc);

    /* Remove the real session from sessions table. */
    end_auth_session (nvSession);
    return rc;
}

int tpm_clear(TSS2_SYS_CONTEXT *sysContext){
    TSS2_RC rc=0;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray={0};
    TSS2L_SYS_AUTH_COMMAND sessionsData = {
        .count = 1,
        .auths = {{.sessionHandle = TPM2_RH_PW,
            .nonce={.size=0},
            .hmac={.size=1, .buffer={0}}
            }
            }
    };

	rc = Tss2_Sys_Clear(sysContext, TPM2_RH_PLATFORM, &sessionsData, &rspAuthsArray);
	if (rc != TSS2_RC_SUCCESS) {
        printf("Tss2_Sys_Clear failes ..\n");
        return rc;
	}
    printf("Tss2_Sys_Clear complete\n");
    return TSS2_RC_SUCCESS;
}

int tpm_session_test() {
	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_SYS_CONTEXT *sys_ctx = NULL;
    TSS2_RC rc=0;
    size_t size;
    // ESYS_CONTEXT *esys_context;
    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

    printf("bound/unsalted with param encryption code start.... \n");

	rc = Tss2_TctiLdr_Initialize(NULL, &tcti_ctx);
	if (rc != TSS2_RC_SUCCESS || !tcti_ctx) {
		printf("Tss2_TctiLdr_Initialize Failed with error code: %d\n", rc);
		return rc;
	}
    printf("Tss2_TctiLdr_Initialize complete\n");

    size = Tss2_Sys_GetContextSize(0);
    sys_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
    if (sys_ctx == NULL) {
        printf("Tss2_Sys_GetContextSize Failed to allocate 0x%zx bytes for the SYS context\n", size);
        return rc;
    }
    printf("Tss2_Sys_GetContextSize complete\n");

	rc = Tss2_Sys_Initialize(sys_ctx, size, tcti_ctx, &abi_version);
	if (rc != TSS2_RC_SUCCESS) {
		printf("Tss2_Sys_Initialize failes ..\n");
		return rc;
	}

	rc = Tss2_Sys_Startup(sys_ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
            printf("Tss2_Sys_Startup failes ..\n");
	}

    // rc = tpm_clear(sys_ctx);
	// if (rc != TSS2_RC_SUCCESS) {
    //     printf("tpm_clear failes ..\n");
	// }
    // printf("tpm_clear completed.....\n");

    TPM2B_DIGEST authPolicy = { 0, };
    TPMA_NV nvAttributes=0;

    printf ("HMAC session test\n");
    rc = _nv_write_session_ParamEncry (sys_ctx, &authPolicy, nvAttributes, TPM2_SE_HMAC);
    if (rc != TSS2_RC_SUCCESS)
        return rc;

    printf("tpm_session_test :: Finished...\n");

    return rc;
}


int main(int argc, char* argv[])
{
    printf("main StartUp....\n");

    tpm_session_test();

    while (true) {
        printf("Hello from app_main!\n");
        return 0;
    }
}