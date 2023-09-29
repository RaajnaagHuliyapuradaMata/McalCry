#define MCALCRY_AEAD_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_AeadEncrypt.hpp"
#include "McalCry_AeadDecrypt.hpp"

#define MCALCRY_AESGCM_MAX_OUT_SIZE                           (16u)
#define MCALCRY_AESCCM_MAX_OUT_SIZE                           (16u)

#define MCALCRY_CHACHA20POLY1305_KEY_LENGTH                   ESL_SIZEOF_ChaCha20_KEY
#define MCALCRY_CHACHA20POLY1305_NONCE_LENGTH                 ESL_SIZEOF_ChaCha20_NONCE
#define MCALCRY_POLY1305_OUT_SIZE                             ESL_SIZEOF_Poly1305_TAG

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_AESGCMENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Start(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Update(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Finish(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

#endif

#if(MCALCRY_AESGCMDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Start(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Update(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Finish(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_AESCCMENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Update(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Finish(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

#endif

#if(MCALCRY_AESCCMDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Update(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Finish(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if((MCALCRY_AESCCMENCRYPT == STD_ON) || (MCALCRY_AESCCMDECRYPT == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcm_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  uint8 authenticationFieldSize);
#endif

#if(MCALCRY_AESGCMENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Start(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[2];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CIPHER_KEY);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CIPHER_IV);

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_GCM, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initEncryptGCM(workspace
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,       (eslt_Length)keyElements[0u].keyElementLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex)
   ,       (eslt_Length)keyElements[1u].keyElementLength);
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Update(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));

  if(((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength + (MCALCRY_AESGCM_MAX_OUT_SIZE - 1u)) & 0xFFFFFFF0u) > (*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr)){
    retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
  }
  else{
    retValCv = ESL_ERC_NO_ERROR;
  }

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;

  if((retValCv == ESL_ERC_NO_ERROR) && (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength != 0u)){
    retValCv = esl_updateAuthDataEncryptGCM(workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_updatePlaintextEncryptGCM(workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,     (P2VAR(eslt_Size32, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

  }

  McalCry_SetWrittenLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  McalCry_SetBufferLength(objectId, McalCry_GetBufferLength(objectId) - McalCry_GetWrittenLength(objectId));

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt_Finish(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  uint8 authTagTempBuffer[MCALCRY_AESGCM_MAX_OUT_SIZE] = { 0u };

  if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode & CRYPTO_OPERATIONMODE_UPDATE) != CRYPTO_OPERATIONMODE_UPDATE){
    McalCry_SetWrittenLength(objectId, 0u);
    McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  }

  if(McalCry_GetBufferLength(objectId) < MCALCRY_AESGCM_MAX_OUT_SIZE){
    retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
  }
  else{
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = McalCry_GetWrittenLength(objectId);

    retValCv = esl_finalizeEncryptGCM(workspace
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]
   ,     (P2VAR(eslt_Size32, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))authTagTempBuffer);

    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr > MCALCRY_AESGCM_MAX_OUT_SIZE){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr = MCALCRY_AESGCM_MAX_OUT_SIZE;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputPtr, authTagTempBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_AESGCMDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Start(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[2];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CIPHER_KEY);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CIPHER_IV);

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_GCM, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);

    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initDecryptGCM(workspace
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,       (eslt_Length)keyElements[0u].keyElementLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex)
   ,       (eslt_Length)keyElements[1u].keyElementLength);
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Update(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));

  if(((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength + (MCALCRY_AESGCM_MAX_OUT_SIZE - 1u)) & 0xFFFFFFF0u) > (*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr)){
    retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
  }
  else{
    retValCv = ESL_ERC_NO_ERROR;
  }

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;

  if((retValCv == ESL_ERC_NO_ERROR) && (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength != 0u)){
    retValCv = esl_updateAuthDataDecryptGCM(workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_updateCiphertextDecryptGCM(workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,     (P2VAR(eslt_Size32, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
  }

  McalCry_SetWrittenLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  McalCry_SetBufferLength(objectId, McalCry_GetBufferLength(objectId) - McalCry_GetWrittenLength(objectId));

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt_Finish(
  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode & CRYPTO_OPERATIONMODE_UPDATE) != CRYPTO_OPERATIONMODE_UPDATE){
    McalCry_SetWrittenLength(objectId, 0u);
    McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  }

  if(McalCry_GetBufferLength(objectId) < MCALCRY_AESGCM_MAX_OUT_SIZE){
    retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
  }
  else{
    retValCv = ESL_ERC_NO_ERROR;
  }

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = McalCry_GetWrittenLength(objectId);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_finalizeDecryptGCM(workspace
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]
   ,     (P2VAR(eslt_Size32, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputPtr);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_OK;
  }
  else if(retValCv == ESL_ERC_GCM_TAG_VERIFICATION_FAILED){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_NOT_OK;
    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_AESCCMENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_Dispatch_AesCcm_Start(
    workspace
   ,   job
   ,   (uint8)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Update(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  eslt_Length outlength;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));

  outlength = (eslt_Length)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr;

  retValCv = esl_updateAESCCMEncrypt(workspace
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outlength);

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outlength;

  McalCry_SetWrittenLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  McalCry_SetBufferLength(objectId, McalCry_GetBufferLength(objectId) - McalCry_GetWrittenLength(objectId));

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt_Finish(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  eslt_Length outlength, secOutlength;

  outlength = (eslt_Length)McalCry_GetBufferLength(objectId);
  secOutlength = (eslt_Length)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr;

  retValCv = esl_finalizeAESCCMEncrypt(workspace
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outlength
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputPtr
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&secOutlength);

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr += outlength;

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_AESCCMDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_Dispatch_AesCcm_Start(
    workspace
   ,   job
   ,   (uint8)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputLength);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Update(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  eslt_Length outlength;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));

  outlength = (eslt_Length)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr;

  retValCv = esl_updateAESCCMDecrypt(workspace
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outlength);

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outlength;

  McalCry_SetWrittenLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  McalCry_SetBufferLength(objectId, McalCry_GetBufferLength(objectId) - McalCry_GetWrittenLength(objectId));

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt_Finish(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  eslt_Length outlength;
  Std_ReturnType retVal = E_NOT_OK;

  outlength = (eslt_Length)McalCry_GetBufferLength(objectId);

  retValCv = esl_finalizeAESCCMDecrypt(workspace
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outlength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputPtr);

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr += outlength;

  if(retValCv == ESL_ERC_NO_ERROR){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_OK;
  }
  else if(retValCv == ESL_ERC_INCORRECT_TAG){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_NOT_OK;
    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if((MCALCRY_AESCCMENCRYPT == STD_ON) || (MCALCRY_AESCCMDECRYPT == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcm_Start(
  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  uint8 authenticationFieldSize){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[2];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CIPHER_KEY);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CIPHER_IV);

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_SIZEOF_WS_AESCCM, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      eslt_Byte lengthFieldSize;
      retVal = E_NOT_OK;
      lengthFieldSize = (eslt_Byte)(MCALCRY_AESCCM_SUM_OF_NONCE_LENGTH_AND_L - keyElements[1u].keyElementLength);

      retValCv = esl_initAESCCM(workspace
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,       (eslt_Length)keyElements[0u].keyElementLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex)
   ,       (eslt_Length)keyElements[1u].keyElementLength
   ,       (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,       (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,       (eslt_Byte)authenticationFieldSize
   ,       lengthFieldSize);
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_AESGCMENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmEncrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesGcmEncrypt(McalCry_GetAesGcmEncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceGCM));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_Dispatch_AesGcmEncrypt_Start(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_Dispatch_AesGcmEncrypt_Update(workspace, objectId, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_Dispatch_AesGcmEncrypt_Finish(workspace, objectId, job);
      break;
    }

    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_AESGCMDECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceGCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesGcmDecrypt(McalCry_GetAesGcmDecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceGCM));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_Dispatch_AesGcmDecrypt_Start(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_Dispatch_AesGcmDecrypt_Update(workspace, objectId, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_Dispatch_AesGcmDecrypt_Finish(workspace, objectId, job);
      break;
    }

    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_AESCCMENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmEncrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesCcmEncrypt(McalCry_GetAesCcmEncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceAESCCM));

  if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_SINGLECALL)){
    switch(mode){
      case CRYPTO_OPERATIONMODE_START:
      {
        retVal = McalCry_Dispatch_AesCcmEncrypt_Start(workspace, job);
        break;
      }

      case CRYPTO_OPERATIONMODE_UPDATE:
      {
        retVal = McalCry_Dispatch_AesCcmEncrypt_Update(workspace, objectId, job);
        break;
      }

      case CRYPTO_OPERATIONMODE_FINISH:
      {
        retVal = McalCry_Dispatch_AesCcmEncrypt_Finish(workspace, objectId, job);
        break;
      }

      default:
      {
        break;
      }
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_AESCCMDECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceAESCCM, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesCcmDecrypt(McalCry_GetAesCcmDecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceAESCCM));

  if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_SINGLECALL)){
    switch(mode){
      case CRYPTO_OPERATIONMODE_START:
      {
        retVal = McalCry_Dispatch_AesCcmDecrypt_Start(workspace, job);
        break;
      }

      case CRYPTO_OPERATIONMODE_UPDATE:
      {
        retVal = McalCry_Dispatch_AesCcmDecrypt_Update(workspace, objectId, job);
        break;
      }

      case CRYPTO_OPERATIONMODE_FINISH:
      {
        retVal = McalCry_Dispatch_AesCcmDecrypt_Finish(workspace, objectId, job);
        break;
      }

      default:
      {
        break;
      }
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_AEADCHACHAPOLY1305ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AEADChaChaPoly1305Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceChaChaPoly, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAEADChaChaPoly1305Encrypt(McalCry_GetAEADChaChaPoly1305EncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceChaChaPoly));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_CIPHER_KEY, MCALCRY_CHACHA20POLY1305_KEY_LENGTH);
      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 1u, CRYPTO_KE_CIPHER_IV, MCALCRY_CHACHA20POLY1305_NONCE_LENGTH);

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_SIZEOF_WS_AEAD_ChaCha_Poly, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_EQUAL);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;
          retValCv = esl_initEncryptChaChaPoly(workspace
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex));
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      eslt_Length outputLength;
      outputLength = (eslt_Length)*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

      if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength) > (outputLength))
      {
        retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
      }
      else
      {
        retValCv = ESL_ERC_NO_ERROR;
      }

      if((retValCv == ESL_ERC_NO_ERROR) && (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength != 0u))
      {
        retValCv = esl_updateAADChaChaPoly(workspace
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,         (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
      }

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_updateDataChaChaPoly(workspace
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,         (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,         (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,         (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength);

        *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) = outputLength;
      }

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      uint8 authTagTempBuffer[MCALCRY_POLY1305_OUT_SIZE] = { 0u };

      retValCv = esl_finalizeChaChaPoly(workspace
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))authTagTempBuffer);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr > MCALCRY_POLY1305_OUT_SIZE)
        {
          *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr = MCALCRY_POLY1305_OUT_SIZE;
        }

        McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputPtr, authTagTempBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr);
      }
      break;
    }

    default:
    {
      break;
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_AEADCHACHAPOLY1305DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AEADChaChaPoly1305Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceChaChaPoly, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAEADChaChaPoly1305Decrypt(McalCry_GetAEADChaChaPoly1305DecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceChaChaPoly));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_CIPHER_KEY, MCALCRY_CHACHA20POLY1305_KEY_LENGTH);
      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 1u, CRYPTO_KE_CIPHER_IV, MCALCRY_CHACHA20POLY1305_NONCE_LENGTH);

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_SIZEOF_WS_AEAD_ChaCha_Poly, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_EQUAL);

        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;
          retValCv = esl_initDecryptChaChaPoly(workspace
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex));
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      eslt_Length outputLength;
      outputLength = (eslt_Length)*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

      if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength) > (outputLength))
      {
        retValCv = ESL_ERC_OUTPUT_SIZE_TOO_SHORT;
      }
      else
      {
        retValCv = ESL_ERC_NO_ERROR;
      }

      if((retValCv == ESL_ERC_NO_ERROR) && (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength != 0u))
      {
        retValCv = esl_updateAADChaChaPoly(workspace
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,         (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
      }

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_updateDataChaChaPoly(workspace
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,         (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,         (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,         (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength);

        *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) = outputLength;
      }

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputLength == MCALCRY_POLY1305_OUT_SIZE)
      {
        retValCv = esl_verifyChaChaPoly(workspace
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputPtr);
      }
      else
      {
        retValCv = ESL_ERC_INCORRECT_TAG;
      }

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_OK;
      }
      else if(retValCv == ESL_ERC_INCORRECT_TAG)
      {
        *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_NOT_OK;
        retValCv = ESL_ERC_NO_ERROR;
      }
      else
      {
      }

      break;
    }

    default:
    {
      break;
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

