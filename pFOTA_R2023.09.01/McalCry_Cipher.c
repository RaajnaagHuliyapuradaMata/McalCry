

#define MCALCRY_CIPHER_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_Encrypt.hpp"
#include "McalCry_Decrypt.hpp"

#define ESL_BM_CTR                                                   0x04u

#define MCALCRY_AES128_KEY_LENGTH                             MCALCRY_AES_BLOCK_SIZE
#define MCALCRY_AES128_IV_LENGTH                              MCALCRY_AES_BLOCK_SIZE
#define MCALCRY_AES256_KEY_LENGTH                             (32u)
#define MCALCRY_AES256_IV_LENGTH                              MCALCRY_AES_BLOCK_SIZE
#define MCALCRY_AES_MODE_128                                  (0u)
#define MCALCRY_AES_MODE_256                                  (1u)

#define MCALCRY_RSA_DECRYPT_MODE_PRIVATE                      (0u)

#define MCALCRY_RSA_DECRYPT_MODE_PUBLIC                       (1u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if((MCALCRY_AESENCRYPT == STD_ON) || (MCALCRY_AESDECRYPT == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesKey(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) keyIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) ivIndexPtr);
#endif

#if(MCALCRY_AESENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptStart(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptUpdate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);
#endif

#if(MCALCRY_AESDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptStart(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptUpdate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);
#endif

#if(MCALCRY_ENCRYPT_RSA == STD_ON) || (MCALCRY_DECRYPT_RSA == STD_ON)

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_DispatchCipherRsa_Finish(
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_RSAPKCS1DECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Decrypt_Start(
  P2VAR(eslt_WorkSpaceRSAdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Decrypt_Update(
  P2VAR(eslt_WorkSpaceRSAdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON) || (MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepEncrypt_Start(
  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepEncrypt_Update(
  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);
#endif

#if(MCALCRY_RSAOAEPSHA1DECRYPT == STD_ON) || (MCALCRY_RSAOAEPSHA256DECRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepDecrypt_Start(
  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepDecrypt_Update(
  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);
#endif

#if(MCALCRY_RSAOAEPCRTSHA1DECRYPT == STD_ON) || (MCALCRY_RSAOAEPCRTSHA256DECRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepCrtDecrypt_Start(
  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepCrtDecrypt_Update(
  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily);
#endif

#if((MCALCRY_AESDECRYPT == STD_ON) || (MCALCRY_AESENCRYPT == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesKey(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) keyIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) ivIndexPtr){
  uint32 aesKeyLength, aesIvLength;
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
#if(MCALCRY_ENABLE_AES256 != STD_ON)
  uint8 errorId = CRYPTO_E_NO_ERROR;
#endif

  localRetVal = McalCry_Local_KeyElementGetStorageIndexExtended(job->cryptoKeyId, CRYPTO_KE_CIPHER_KEY, keyIndexPtr, &aesKeyLength, MCALCRY_LENGTH_CHECK_NONE, MCALCRY_SHE_SERVICE_ENCRYPT_DECRYPT);

  if(localRetVal == E_OK){
    if(aesKeyLength == MCALCRY_AES128_KEY_LENGTH){
      workspace->mode = MCALCRY_AES_MODE_128;
      aesIvLength = MCALCRY_AES128_IV_LENGTH;
    }
    else if(aesKeyLength == MCALCRY_AES256_KEY_LENGTH){
#if(MCALCRY_ENABLE_AES256 == STD_ON)
      workspace->mode = MCALCRY_AES_MODE_256;
      aesIvLength = MCALCRY_AES256_IV_LENGTH;
#else
      errorId = CRYPTO_E_PARAM_HANDLE;
      localRetVal = E_NOT_OK;
#endif

    }
    else{
      localRetVal = E_NOT_OK;
    }

    if(localRetVal == E_OK){
      if((job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CBC)
       || (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CTR))
      {
        retVal = McalCry_Local_KeyElementGetStorageIndexJob(job->cryptoKeyId, CRYPTO_KE_CIPHER_IV, ivIndexPtr, &aesIvLength, MCALCRY_LENGTH_CHECK_EQUAL);
      }
      else
      {
        retVal = E_OK;
      }
    }
  }
  else if(localRetVal == CRYPTO_E_KEY_NOT_VALID){
    retVal = CRYPTO_E_KEY_NOT_VALID;
  }
  else{
  }

#if(MCALCRY_ENABLE_AES256 != STD_ON)
#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError(MCALCRY_MODULE_ID, MCALCRY_INSTANCE_ID, MCALCRY_SID_PROCESS_JOB, errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif
#endif

  return retVal;
}
#endif

#if(MCALCRY_AESENCRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptStart(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  McalCry_SizeOfKeyStorageType aesEncryptKeyIndex;
  McalCry_SizeOfKeyStorageType aesEncryptIvIndex;

  eslt_BlockMode blockMode;
  eslt_PaddingMode paddingMode = ESL_PM_OFF;

  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) aesEncryptIvPtr = NULL_PTR;

  McalCry_SetBufferLength(objectId, 0u);
  McalCry_SetWrittenLength(objectId, 0u);

  retVal = McalCry_DispatchCipherAesKey(job, workspace, &aesEncryptKeyIndex, &aesEncryptIvIndex);

  if(retVal == E_OK){
    retVal = E_NOT_OK;

    if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CBC){
      blockMode = ESL_BM_CBC;
      aesEncryptIvPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesEncryptIvIndex);
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CTR){
      blockMode = ESL_BM_CTR;
      aesEncryptIvPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesEncryptIvIndex);
    }
    else{
      blockMode = ESL_BM_ECB;
    }

    if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_CUSTOM_PADDING_PKCS7){
      paddingMode = ESL_PM_PKCS5;
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_PADDING_PKCS7){
      paddingMode = ESL_PM_PKCS5;
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS){
      paddingMode = ESL_PM_ONEWITHZEROES;
    }
    else{
    }

#if(MCALCRY_ENABLE_AES256 == STD_ON)
    if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
    {
      if(esl_initWorkSpaceHeader(&workspace->wsAES.wsAES128.header, ESL_MAXSIZEOF_WS_AES128, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_initEncryptAES128(&workspace->wsAES.wsAES128
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesEncryptKeyIndex)
   ,                                        blockMode
   ,                                        paddingMode
   ,                                        aesEncryptIvPtr);
      }
    }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
    else{
      if(esl_initWorkSpaceHeader(&workspace->wsAES.wsAES256.header, ESL_MAXSIZEOF_WS_AES256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_initEncryptAES256(&workspace->wsAES.wsAES256
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesEncryptKeyIndex)
   ,                                        blockMode
   ,                                        paddingMode
   ,                                        aesEncryptIvPtr);
      }
    }
#endif

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptUpdate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  eslt_Length outputLength;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));

  outputLength = (eslt_Length)*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

#if(MCALCRY_ENABLE_AES256 == STD_ON)
  if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
  {
    retValCv = esl_encryptAES128(&workspace->wsAES.wsAES128
   ,                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
  else{
    retValCv = esl_encryptAES256(&workspace->wsAES.wsAES256
   ,                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#endif

  *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) = outputLength;

  McalCry_SetWrittenLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  McalCry_SetBufferLength(objectId, McalCry_GetBufferLength(objectId) - McalCry_GetWrittenLength(objectId));

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesEncryptFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  eslt_Length outputLength;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode & CRYPTO_OPERATIONMODE_UPDATE) != CRYPTO_OPERATIONMODE_UPDATE){
    McalCry_SetWrittenLength(objectId, 0u);
    McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  }

  outputLength = (eslt_Length)(McalCry_GetBufferLength(objectId));

#if(MCALCRY_ENABLE_AES256 == STD_ON)
  if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
  {
    retValCv = esl_finalizeEncryptAES128(&workspace->wsAES.wsAES128
   ,                                        (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]);
  }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
  else{
    retValCv = esl_finalizeEncryptAES256(&workspace->wsAES.wsAES256
   ,                                        (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]);
  }
#endif

  if(retValCv == ESL_ERC_NO_ERROR){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outputLength + McalCry_GetWrittenLength(objectId);
    retVal = E_OK;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesEncrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesEncrypt(McalCry_GetAesEncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_WorkSpaceAES));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    retVal = McalCry_DispatchCipherAesEncryptStart(objectId, job, workspace);
    break;

    case CRYPTO_OPERATIONMODE_UPDATE:
    retVal = McalCry_DispatchCipherAesEncryptUpdate(objectId, job, workspace);
    break;

    case CRYPTO_OPERATIONMODE_FINISH:
    retVal = McalCry_DispatchCipherAesEncryptFinish(objectId, job, workspace);
    break;

    default:

    break;
  }

  return retVal;
}
#endif

#if(MCALCRY_AESDECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptStart(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  McalCry_SizeOfKeyStorageType aesDecryptKeyIndex;
  McalCry_SizeOfKeyStorageType aesDecryptIvIndex;

  eslt_BlockMode blockMode;
  eslt_PaddingMode paddingMode = ESL_PM_OFF;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) aesDecryptIvPtr = NULL_PTR;

  McalCry_SetWrittenLength(objectId, 0u);
  McalCry_SetBufferLength(objectId, 0u);

  retVal = McalCry_DispatchCipherAesKey(job, workspace, &aesDecryptKeyIndex, &aesDecryptIvIndex);

  if(retVal == E_OK){
    retVal = E_NOT_OK;
    if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CBC){
      blockMode = ESL_BM_CBC;
      aesDecryptIvPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesDecryptIvIndex);
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CTR){
      blockMode = ESL_BM_CTR;
      aesDecryptIvPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesDecryptIvIndex);
    }
    else{
      blockMode = ESL_BM_ECB;
    }

    if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_CUSTOM_PADDING_PKCS7){
      paddingMode = ESL_PM_PKCS5;
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_PADDING_PKCS7){
      paddingMode = ESL_PM_PKCS5;
    }
    else if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS){
      paddingMode = ESL_PM_ONEWITHZEROES;
    }
    else{
    }

#if(MCALCRY_ENABLE_AES256 == STD_ON)
    if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
    {
      if(esl_initWorkSpaceHeader(&(workspace->wsAES.wsAES128.header), ESL_MAXSIZEOF_WS_AES128, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_initDecryptAES128(&workspace->wsAES.wsAES128
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesDecryptKeyIndex)
   ,                                        blockMode
   ,                                        paddingMode
   ,                                        aesDecryptIvPtr);
      }
    }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
    else{
      if(esl_initWorkSpaceHeader(&(workspace->wsAES.wsAES256.header), ESL_MAXSIZEOF_WS_AES256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retValCv = esl_initDecryptAES256(&workspace->wsAES.wsAES256
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(aesDecryptKeyIndex)
   ,                                        blockMode
   ,                                        paddingMode
   ,                                        aesDecryptIvPtr);
      }
    }
#endif

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptUpdate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  eslt_Length outputLength;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  outputLength = (eslt_Length)*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

#if(MCALCRY_ENABLE_AES256 == STD_ON)
  if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
  {
    retValCv = esl_decryptAES128(&workspace->wsAES.wsAES128
   ,                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
  else{
    retValCv = esl_decryptAES256(&workspace->wsAES.wsAES256
   ,                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#endif

  McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) - outputLength);
  McalCry_SetWrittenLength(objectId, outputLength);

  *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) = outputLength;

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherAesDecryptFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  eslt_Length outputLength;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode & CRYPTO_OPERATIONMODE_UPDATE) != CRYPTO_OPERATIONMODE_UPDATE){
    McalCry_SetWrittenLength(objectId, 0u);
    McalCry_SetBufferLength(objectId, *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr));
  }

  outputLength = (eslt_Length)McalCry_GetBufferLength(objectId);

#if(MCALCRY_ENABLE_AES256 == STD_ON)
  if(workspace->mode == MCALCRY_AES_MODE_128)
#endif
  {
    retValCv = esl_finalizeDecryptAES128(&workspace->wsAES.wsAES128
   ,                                        (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]);
  }
#if(MCALCRY_ENABLE_AES256 == STD_ON)
  else{
    retValCv = esl_finalizeDecryptAES256(&workspace->wsAES.wsAES256
   ,                                        (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[McalCry_GetWrittenLength(objectId)]);
  }
#endif

  if(retValCv == ESL_ERC_NO_ERROR){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outputLength + McalCry_GetWrittenLength(objectId);
    retVal = E_OK;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesDecrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(McalCry_WorkSpaceAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfAesDecrypt(McalCry_GetAesDecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_WorkSpaceAES));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    retVal = McalCry_DispatchCipherAesDecryptStart(objectId, job, workspace);
    break;

    case CRYPTO_OPERATIONMODE_UPDATE:
    retVal = McalCry_DispatchCipherAesDecryptUpdate(objectId, job, workspace);
    break;

    case CRYPTO_OPERATIONMODE_FINISH:
    retVal = McalCry_DispatchCipherAesDecryptFinish(objectId, job, workspace);
    break;

    default:

    break;
  }

  return retVal;
}
#endif

#if(MCALCRY_RSAPKCS1ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceRSAenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPkcs1Encrypt(McalCry_GetRsaPkcs1EncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAenc));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
      McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT);

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_ENC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;
          retValCv = esl_initEncryptRSA_V15(workspace,

                                            (eslt_Length)keyElements[0u].keyElementLength
   ,                                           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex),

                                            (eslt_Length)keyElements[1u].keyElementLength
   ,                                           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex));
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      eslt_Length outputLength;
      outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

      retValCv = esl_encryptRSA_V15(workspace
   ,                                   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);

      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = E_OK;
      McalCry_DispatchCipherRsa_Finish(job);
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

#if(MCALCRY_RSAPKCS1DECRYPT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Decrypt_Start(
  P2VAR(eslt_WorkSpaceRSAdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  Std_ReturnType retValKey;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[2];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT);

  retValKey = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);
  if(retValKey == E_OK){
    retValKey = McalCry_Local_KeyElementGetStorageIndexJobOptional(job->cryptoKeyId, CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT, &keyElements[1u].keyElementIndex, &keyElements[1u].keyElementLength, MCALCRY_LENGTH_CHECK_NONE);

    if(retValKey == CRYPTO_E_KEY_NOT_AVAILABLE){
      McalCry_SetWrittenLength(objectId, MCALCRY_RSA_DECRYPT_MODE_PUBLIC);
      retValKey = McalCry_Local_KeyElementGetStorageIndexJobOptional(job->cryptoKeyId, CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT, &keyElements[1u].keyElementIndex, &keyElements[1u].keyElementLength, MCALCRY_LENGTH_CHECK_NONE);
    }
    else{
      McalCry_SetWrittenLength(objectId, MCALCRY_RSA_DECRYPT_MODE_PRIVATE);
    }

    if(retValKey == CRYPTO_E_KEY_NOT_AVAILABLE){
      retValKey = E_NOT_OK;
    }
  }

  if(retValKey == E_OK){
    if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_DEC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      retValCv = esl_initDecryptRSA_V15(workspace,

                                        (eslt_Length)keyElements[0u].keyElementLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex),

                                        (eslt_Length)keyElements[1u].keyElementLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex));
    }
  }
  else{
    retVal = retValKey;
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Decrypt_Update(
  P2VAR(eslt_WorkSpaceRSAdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  eslt_Length outputLength;
  outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

  if(McalCry_GetWrittenLength(objectId) == MCALCRY_RSA_DECRYPT_MODE_PRIVATE){
    retValCv = esl_decryptRSA_V15(workspace
   ,                                 (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                 (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                 (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
  else{
    retValCv = esl_decryptPubRSA_V15(workspace
   ,                                    (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                    (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(eslt_WorkSpaceRSAdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPkcs1Decrypt(McalCry_GetRsaPkcs1DecryptIdxOfObjectInfo(objectId));

  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAdec));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_Dispatch_RsaPkcs1Decrypt_Start(workspace, objectId, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_Dispatch_RsaPkcs1Decrypt_Update(workspace, objectId, job);

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = E_OK;
      McalCry_DispatchCipherRsa_Finish(job);
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

#if(MCALCRY_ENCRYPT_RSA == STD_ON) || (MCALCRY_DECRYPT_RSA == STD_ON)

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_DispatchCipherRsa_Finish(
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode == CRYPTO_OPERATIONMODE_FINISH){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;
  }
}
#endif

#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON) || (MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepEncrypt_Start(
  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[2];

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_OAEP_ENC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
    McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT);

    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);

    if(retVal == E_OK){
      switch(secondaryFamily)
      {
#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA1:
        {
          retValCv = esl_initEncryptRSASHA1_OAEP(workspace,

                                                 (eslt_Length)keyElements[0].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex),

                                                 (eslt_Length)keyElements[1].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          break;
        }
#endif
#if(MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA2_256:
        {
          retValCv = esl_initEncryptRSASHA256_OAEP(workspace
   ,                                                  (eslt_Length)keyElements[0].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                                  (eslt_Length)keyElements[1].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          break;
        }
#endif

        default:
        break;
      }

      if(retValCv != ESL_ERC_NO_ERROR)
      {
        retVal = E_NOT_OK;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepEncrypt_Update(
  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint32 labelLength = 0;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) labelPtr = NULL_PTR;
  McalCry_SizeOfKeyStorageType labelIndex;
  boolean process = FALSE;

  eslt_Length outputLength;
  outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

  localRetVal = McalCry_Local_KeyElementGetStorageIndexJobOptional(job->cryptoKeyId, CRYPTO_KE_CUSTOM_LABEL, &labelIndex, &labelLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRetVal == E_OK){
    labelPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(labelIndex);
    process = TRUE;
  }
  else if(localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE){
    process = TRUE;
  }
  else{
    retVal = localRetVal;
  }

  if(process == TRUE){
    switch(secondaryFamily){
#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA1:
      {
        retValCv = esl_encryptRSASHA1_OAEP_Label(workspace
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                (eslt_Length)labelLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif
#if(MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA2_256:
      {
        retValCv = esl_encryptRSASHA256_OAEP_Label(workspace
   ,                                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                  (eslt_Length)labelLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                  (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                  (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif

      default:
      break;
    }

    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha1Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfRsaOaepSha1Encrypt(McalCry_GetRsaOaepSha1EncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAOAEPenc));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepEncrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepEncrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#if(MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha256Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSAOAEPenc, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfRsaOaepSha256Encrypt(McalCry_GetRsaOaepSha256EncryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAOAEPenc));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepEncrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepEncrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#if(MCALCRY_RSAOAEPSHA1DECRYPT == STD_ON) || (MCALCRY_RSAOAEPSHA256DECRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepDecrypt_Start(
  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  McalCry_KeyElementGetType keyElements[2];

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_OAEP_DEC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
    McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT);

    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);

    if(retVal == E_OK){
      switch(secondaryFamily)
      {
#if(MCALCRY_RSAOAEPSHA1DECRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA1:
        {
          retValCv = esl_initDecryptRSASHA1_OAEP(workspace,

                                                 (eslt_Length)keyElements[0].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex),

                                                 (eslt_Length)keyElements[1].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          break;
        }
#endif
#if(MCALCRY_RSAOAEPSHA256DECRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA2_256:
        {
          retValCv = esl_initDecryptRSASHA256_OAEP(workspace
   ,                                                  (eslt_Length)keyElements[0].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                                  (eslt_Length)keyElements[1].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          break;
        }
#endif

        default:
        break;
      }

      if(retValCv != ESL_ERC_NO_ERROR)
      {
        retVal = E_NOT_OK;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepDecrypt_Update(
  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint32 labelLength = 0;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) labelPtr = NULL_PTR;
  McalCry_SizeOfKeyStorageType labelIndex;
  boolean process = FALSE;

  eslt_Length outputLength;
  outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

  localRetVal = McalCry_Local_KeyElementGetStorageIndexJobOptional(job->cryptoKeyId, CRYPTO_KE_CUSTOM_LABEL, &labelIndex, &labelLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRetVal == E_OK){
    labelPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(labelIndex);
    process = TRUE;
  }
  else if(localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE){
    process = TRUE;
  }
  else{
    retVal = localRetVal;
  }

  if(process == TRUE){
    switch(secondaryFamily){
#if(MCALCRY_RSAOAEPSHA1DECRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA1:
      {
        retValCv = esl_decryptRSASHA1_OAEP_Label(workspace
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                (eslt_Length)labelLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif
#if(MCALCRY_RSAOAEPSHA256DECRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA2_256:
      {
        retValCv = esl_decryptRSASHA256_OAEP_Label(workspace
   ,                                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                  (eslt_Length)labelLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                  (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                  (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif

      default:
      break;
    }

    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_RSAOAEPSHA1DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha1Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfRsaOaepSha1Decrypt(McalCry_GetRsaOaepSha1DecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAOAEPdec));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepDecrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepDecrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#if(MCALCRY_RSAOAEPSHA256DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha256Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSAOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfRsaOaepSha256Decrypt(McalCry_GetRsaOaepSha256DecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAOAEPdec));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepDecrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepDecrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#if(MCALCRY_RSAOAEPCRTSHA1DECRYPT == STD_ON) || (MCALCRY_RSAOAEPCRTSHA256DECRYPT == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepCrtDecrypt_Start(
  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_KeyElementGetType keyElements[5];

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_CRT_OAEP_DEC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_PRIME_P);
    McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PRIME_Q);
    McalCry_Local_ElementGetterSetId(keyElements, 2u, CRYPTO_KE_CUSTOM_RSA_EXPONENT_DP);
    McalCry_Local_ElementGetterSetId(keyElements, 3u, CRYPTO_KE_CUSTOM_RSA_EXPONENT_DQ);
    McalCry_Local_ElementGetterSetId(keyElements, 4u, CRYPTO_KE_CUSTOM_RSA_INVERSE_QI);
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 5u, MCALCRY_LENGTH_CHECK_NONE);

    if(retVal == E_OK){
      switch(secondaryFamily)
      {
#if(MCALCRY_RSAOAEPCRTSHA1DECRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA1:
        {
          retValCv = esl_initDecryptRSACRTSHA1_OAEP(
            workspace,

            (eslt_Length)keyElements[0].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex),

            (eslt_Length)keyElements[1].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex),

            (eslt_Length)keyElements[2].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[2].keyElementIndex),

            (eslt_Length)keyElements[3].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[3].keyElementIndex),

            (eslt_Length)keyElements[4].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[4].keyElementIndex));
          break;
        }
#endif
#if(MCALCRY_RSAOAEPCRTSHA256DECRYPT == STD_ON)
        case CRYPTO_ALGOFAM_SHA2_256:
        {
          retValCv = esl_initDecryptRSACRTSHA256_OAEP(
            workspace,

            (eslt_Length)keyElements[0].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex),

            (eslt_Length)keyElements[1].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex),

            (eslt_Length)keyElements[2].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[2].keyElementIndex),

            (eslt_Length)keyElements[3].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[3].keyElementIndex),

            (eslt_Length)keyElements[4].keyElementLength
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[4].keyElementIndex));
          break;
        }
#endif

        default:
        break;
      }

      if(retValCv != ESL_ERC_NO_ERROR)
      {
        retVal = E_NOT_OK;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchCipherRsaOaepCrtDecrypt_Update(
  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_AlgorithmSecondaryFamilyType secondaryFamily){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint32 labelLength = 0;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) labelPtr = NULL_PTR;
  McalCry_SizeOfKeyStorageType labelIndex;
  boolean process = FALSE;

  eslt_Length outputLength;
  outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

  localRetVal = McalCry_Local_KeyElementGetStorageIndexJobOptional(job->cryptoKeyId, CRYPTO_KE_CUSTOM_LABEL, &labelIndex, &labelLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRetVal == E_OK){
    labelPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(labelIndex);
    process = TRUE;
  }
  else if(localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE){
    process = TRUE;
  }
  else{
    retVal = localRetVal;
  }

  if(process == TRUE){
    switch(secondaryFamily){
#if(MCALCRY_RSAOAEPCRTSHA1DECRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA1:
      {
        retValCv = esl_decryptRSACRTSHA1_OAEP_Label(workspace
   ,                                                   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                   (eslt_Length)labelLength
   ,                                                   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif
#if(MCALCRY_RSAOAEPCRTSHA256DECRYPT == STD_ON)
      case CRYPTO_ALGOFAM_SHA2_256:
      {
        retValCv = esl_decryptRSACRTSHA256_OAEP_Label(workspace
   ,                                                     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                     (eslt_Length)labelLength
   ,                                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) labelPtr
   ,                                                     (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        break;
      }
#endif

      default:
      break;
    }

    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_RSAOAEPCRTSHA1DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepCrtSha1Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;
  workspace = McalCry_GetWorkspaceOfRsaOaepCrtSha1Decrypt(McalCry_GetRsaOaepCrtSha1DecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSACRTOAEPdec));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepCrtDecrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepCrtDecrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#if(MCALCRY_RSAOAEPCRTSHA256DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepCrtSha256Decrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;

  P2VAR(eslt_WorkSpaceRSACRTOAEPdec, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;
  workspace = McalCry_GetWorkspaceOfRsaOaepCrtSha256Decrypt(McalCry_GetRsaOaepCrtSha256DecryptIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSACRTOAEPdec));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchCipherRsaOaepCrtDecrypt_Start(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchCipherRsaOaepCrtDecrypt_Update(workspace, job, secAlgoFam);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_DispatchCipherRsa_Finish(job);
      retVal = E_OK;
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

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

