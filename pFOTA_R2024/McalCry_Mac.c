

#define MCALCRY_MAC_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_MacGenerate.hpp"
#include "McalCry_MacVerify.hpp"

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
# include "actICMACAES.hpp"
#endif

#define MCALCRY_MODULO_8(x)                                   ((x) & (8u - 1u))
#define MCALCRY_SIP_HASH_KEY_LENGTH                           (16u)
#define MCALCRY_SIPHASH_MAC_SIZE                              (8u)
#define MCALCRY_SHA2_256_KEY_LENGTH                           (32u)
#define MCALCRY_GMAC_MAX_OUT_TAG_SIZE                         (16u)

#define MCALCRY_CMAC_AES_MODE_128                             (0u)
#define MCALCRY_CMAC_AES_MODE_256                             (1u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_SERVICE_MAC_VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Crypto_VerifyResultType, MCALCRY_CODE) McalCry_CompareMac(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) mac1,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) mac2,
  uint32 lengthInBit);
#endif

#if((MCALCRY_CMACAESVERIFY == STD_ON) || (MCALCRY_CMACAESGENERATE == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_InitializeCmacAes(
  uint32 objectId,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  P2VAR(McalCry_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace,
  McalCry_ServiceType sheService);
#endif

#if(MCALCRY_HMACSHA1GENERATE == STD_ON) || (MCALCRY_HMACSHA1VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA1ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA1GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA256GENERATE == STD_ON) || (MCALCRY_HMACSHA256VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA256ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA256GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA384GENERATE == STD_ON) || (MCALCRY_HMACSHA384VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA384ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA384GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA1VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA256VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACSHA384VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_GMACAESGENERATE == STD_ON) || (MCALCRY_GMACAESVERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchGmacAesModeStart(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesModeUpdate(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_GMACAESGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesGenerateModeFinish(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_GMACAESVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesVerifyModeFinish(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACRIPEMD160GENERATE == STD_ON) || (MCALCRY_HMACRIPEMD160VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160ModeStart(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACRIPEMD160GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_HMACRIPEMD160VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SERVICE_MAC_VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Crypto_VerifyResultType, MCALCRY_CODE) McalCry_CompareMac(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) mac1,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) mac2,
  uint32 lengthInBit){
  Crypto_VerifyResultType result = CRYPTO_E_VER_OK;
  uint8 verifyBitMask;
  uint32 numberBitsInLastByte;
  uint8 numberOfFullBytesInMac = (uint8)(lengthInBit >> 3u);
  uint8 i;

  for (i = 0u; i < (numberOfFullBytesInMac); i++){
    if(mac1[i] != mac2[i]){
      result = CRYPTO_E_VER_NOT_OK;
    }
  }

  numberBitsInLastByte = MCALCRY_MODULO_8(lengthInBit);
  if(numberBitsInLastByte != 0u){
    verifyBitMask = (uint8)~((1u << (8u - numberBitsInLastByte)) - 1u);

    if((mac1[numberOfFullBytesInMac] & verifyBitMask)
        != (mac2[numberOfFullBytesInMac] & verifyBitMask)){
      result = CRYPTO_E_VER_NOT_OK;
    }
  }

  return result;
}
#endif

#if((MCALCRY_CMACAESVERIFY == STD_ON) || (MCALCRY_CMACAESGENERATE == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_InitializeCmacAes(
  uint32 objectId,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  P2VAR(McalCry_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace,
  McalCry_ServiceType sheService){
  uint32 cmacAesKeyLength;
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  McalCry_SizeOfKeyStorageType cmacAesKeyIndex;

  eslt_ErrorCode retValCv;

# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE== STD_ON)
  McalCry_SizeOfKeyElementsType macElementId;
  boolean reCalculate = FALSE;

  localRetVal = McalCry_Local_KeyElementSearch(job->cryptoKeyId, CRYPTO_KE_MAC_KEY, &macElementId);

  if((localRetVal != E_OK) || (!McalCry_IsKeyElementStateByMask(macElementId, MCALCRY_KEYELEMENTSTATE_VALUE_USED_MASK))){
    reCalculate = TRUE;
  }

  if(McalCry_IsObjectWorkspaceUnchanged(objectId, job) == E_NOT_OK){
    reCalculate = TRUE;
  }

  if(reCalculate == TRUE)
# else
  MCALCRY_DUMMY_STATEMENT(objectId);
  MCALCRY_DUMMY_STATEMENT(job);
# endif
  {
    localRetVal = McalCry_Local_KeyElementGetStorageIndexExtended(job->cryptoKeyId, CRYPTO_KE_MAC_KEY, &cmacAesKeyIndex, &cmacAesKeyLength, MCALCRY_LENGTH_CHECK_NONE, sheService);
    if(localRetVal == E_OK){
      retValCv = esl_initWorkSpaceHeader(&(workspace->wsCMACAES.header), ESL_MAXSIZEOF_WS_CMACAES, MCALCRY_WATCHDOG_PTR);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        if(cmacAesKeyLength == ESL_SIZEOF_AES128_KEY)
        {
          workspace->mode = MCALCRY_CMAC_AES_MODE_128;
          retValCv = esl_initCMACAES128(
            &workspace->wsCMACAES,
            (eslt_Length)cmacAesKeyLength,
            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(cmacAesKeyIndex));
        }
        else
        {
          workspace->mode = MCALCRY_CMAC_AES_MODE_256;
          retValCv = esl_initCMACAES256(
            &workspace->wsCMACAES,
            (eslt_Length)cmacAesKeyLength,
            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(cmacAesKeyIndex));
        }

# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

        if(retValCv == ESL_ERC_NO_ERROR)
        {
          McalCry_SetKeyElementStateByMask(macElementId, MCALCRY_KEYELEMENTSTATE_VALUE_USED_MASK);
        }
# endif
      }
    }
    else{
      retValCv = ESL_ERC_ERROR;
      if(localRetVal == CRYPTO_E_KEY_NOT_VALID)
      {
        retVal = CRYPTO_E_KEY_NOT_VALID;
      }
    }
  }
# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
  else{
    retValCv = ESL_ERC_NO_ERROR;
  }
# endif

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_CMACAESGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_CmacAesGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(McalCry_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfCmacAesGenerate(McalCry_GetCmacAesGenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_WorkSpaceCMACAES));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_InitializeCmacAes(objectId, job, workspace, MCALCRY_SHE_SERVICE_MAC_GENERATE);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      if(workspace->mode == MCALCRY_CMAC_AES_MODE_128)
      {
        retValCv = esl_updateCMACAES128(&workspace->wsCMACAES,
          (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
      else
      {
        retValCv = esl_updateCMACAES256(&workspace->wsCMACAES,
          (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      eslt_Byte macBuffer[MCALCRY_CMACAES_MAC_SIZE];
# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
      if(actCMACAESFinalize(
        (P2VAR(actCMACAESSTRUCT, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace->wsCMACAES.wsCMACAES,
        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer, workspace->wsCMACAES.header.watchdog)
        == (actRETURNCODE)actOK)
# else
      eslt_Length macBufferLength = MCALCRY_CMACAES_MAC_SIZE;
      if(workspace->mode == MCALCRY_CMAC_AES_MODE_128)
      {
        retValCv = esl_finalizeCMACAES128(&workspace->wsCMACAES, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer);
      }
      else
      {
        retValCv = esl_finalizeCMACAES256(&workspace->wsCMACAES, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer, &macBufferLength);
        if(macBufferLength != MCALCRY_CMACAES_MAC_SIZE)
        {
          retValCv = ESL_ERC_INPUT_INVALID;
        }
      }

      if(retValCv == ESL_ERC_NO_ERROR)
# endif
      {
        if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > MCALCRY_CMACAES_MAC_SIZE)
        {
          *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = MCALCRY_CMACAES_MAC_SIZE;
        }

        McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

        McalCry_ClearData(((P2VAR(actCMACAESSTRUCT, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace->wsCMACAES.wsCMACAES)->buffer, actAES_BLOCK_SIZE);
# endif

        retValCv = ESL_ERC_NO_ERROR;
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

#if(MCALCRY_CMACAESVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_CmacAesVerify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(McalCry_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfCmacAesVerify(McalCry_GetCmacAesVerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_WorkSpaceCMACAES));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_InitializeCmacAes(objectId, job, workspace, MCALCRY_SHE_SERVICE_MAC_VERIFY);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      if(workspace->mode == MCALCRY_CMAC_AES_MODE_128)
      {
        retValCv = esl_updateCMACAES128(&workspace->wsCMACAES,
          (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
      else
      {
        retValCv = esl_updateCMACAES256(&workspace->wsCMACAES,
          (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      eslt_Byte macBuffer[MCALCRY_CMACAES_MAC_SIZE];
      uint32 macLength;
# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
      if(actCMACAESFinalize(
        (P2VAR(actCMACAESSTRUCT, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace->wsCMACAES.wsCMACAES,
        (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer, workspace->wsCMACAES.header.watchdog)
        == (actRETURNCODE)actOK)
# else
      eslt_Length macBufferLength = MCALCRY_CMACAES_MAC_SIZE;
      if(workspace->mode == MCALCRY_CMAC_AES_MODE_128)
      {
        retValCv = esl_finalizeCMACAES128(&workspace->wsCMACAES, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer);
      }
      else
      {
        retValCv = esl_finalizeCMACAES256(&workspace->wsCMACAES, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer, &macBufferLength);
        if(macBufferLength != MCALCRY_CMACAES_MAC_SIZE)
        {
          retValCv = ESL_ERC_INPUT_INVALID;
        }
      }

      if(retValCv == ESL_ERC_NO_ERROR)
# endif
      {
        macLength = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength;

        if(macLength <= (MCALCRY_CMACAES_MAC_SIZE << 3u))
        {
          *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
            McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, macLength);
          retValCv = ESL_ERC_NO_ERROR;
        }
        else
        {
          retValCv = ESL_ERC_ERROR;
        }
# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

        McalCry_ClearData(((P2VAR(actCMACAESSTRUCT, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace->wsCMACAES.wsCMACAES)->buffer, actAES_BLOCK_SIZE);
# endif
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

#if(MCALCRY_SIPHASHGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SipHashGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceSipHash, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfSipHashGenerate(McalCry_GetSipHashGenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSipHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[1];

      McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_SIPHASH, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);

        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;
          retValCv = esl_initSipHash(workspace,
                                     (eslt_Length)keyElements[0u].keyElementLength,
                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = esl_updateSipHash(workspace,
                                   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      eslt_Byte macBuffer[MCALCRY_SIPHASH_MAC_SIZE];

      retValCv = esl_finalizeSipHash(workspace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer);
      if(retValCv == ESL_ERC_NO_ERROR)
      {
        if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > MCALCRY_SIPHASH_MAC_SIZE)
        {
          *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = MCALCRY_SIPHASH_MAC_SIZE;
        }

        McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
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

#if(MCALCRY_SIPHASHVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SipHashVerify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceSipHash, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfSipHashVerify(McalCry_GetSipHashVerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSipHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[1];

      McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_SIPHASH, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);

        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;
          retValCv = esl_initSipHash(workspace,
                                     (eslt_Length)keyElements[0u].keyElementLength,
                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = esl_updateSipHash(workspace,
                                   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      eslt_Byte macBuffer[MCALCRY_SIPHASH_MAC_SIZE];
      uint32 macLength;
      retValCv = esl_finalizeSipHash(workspace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))macBuffer);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        macLength = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength;
        if(macLength <= (MCALCRY_SIPHASH_MAC_SIZE << 3u))
        {
          *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
            McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, macLength);
        }
        else
        {
          retValCv = ESL_ERC_ERROR;
        }
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

#if(MCALCRY_HMACSHA1GENERATE == STD_ON) || (MCALCRY_HMACSHA1VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA1ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyElementGetType keyElements[1];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

  if(esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_HMACSHA1, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initHashMACSHA1(workSpace,
                                     (eslt_Length)keyElements[0u].keyElementLength,
                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;

  retValCv = esl_updateHashMACSHA1(workSpace,
                                   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  return retValCv;
}
#endif

#if(MCALCRY_HMACSHA1GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint8 macBuffer[ESL_SIZEOF_SHA1_DIGEST];

  if(esl_finalizeHashMACSHA1(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer) == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA1_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA1_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha1Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacSha1Generate(McalCry_GetHmacSha1GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA1));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA1ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA1ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA1GenerateModeFinish(workspace, job);
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

#if(MCALCRY_HMACSHA256GENERATE == STD_ON) || (MCALCRY_HMACSHA256VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA256ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyElementGetType keyElements[1];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

  if(esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_HMACSHA256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initHashMACSHA256(workSpace,
                                       (eslt_Length)keyElements[0u].keyElementLength,
                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;

  retValCv = esl_updateHashMACSHA256(workSpace,
                                     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  return retValCv;
}
#endif

#if(MCALCRY_HMACSHA256GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint8 macBuffer[ESL_SIZEOF_SHA256_DIGEST];

  if(esl_finalizeHashMACSHA256(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer) == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA256_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA256_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha256Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacSha256Generate(McalCry_GetHmacSha256GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA256));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA256ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA256ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA256GenerateModeFinish(workspace, job);
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

#if(MCALCRY_HMACSHA384GENERATE == STD_ON) || (MCALCRY_HMACSHA384VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacSHA384ModeStart(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyElementGetType keyElements[1];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

  if(esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_HMACSHA384, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initHashMACSHA384(workSpace,
                                       (eslt_Length)keyElements[0u].keyElementLength,
                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;

  retValCv = esl_updateHashMACSHA384(workSpace,
                                     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  return retValCv;
}
#endif

#if(MCALCRY_HMACSHA384GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint8 macBuffer[ESL_SIZEOF_SHA384_DIGEST];

  if(esl_finalizeHashMACSHA384(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer) == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA384_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA384_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha384Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacSha384Generate(McalCry_GetHmacSha384GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA384));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA384ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA384ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA384GenerateModeFinish(workspace, job);
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

#if(MCALCRY_HMACSHA1VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA1VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 macBuffer[ESL_SIZEOF_SHA1_DIGEST];

  retValCv = esl_finalizeHashMACSHA1(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer);
  if(retValCv == ESL_ERC_NO_ERROR){
    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength <= McalCry_Byte2Bit(ESL_SIZEOF_SHA1_DIGEST)){
      *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
        McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha1Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacSha1Verify(McalCry_GetHmacSha1VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA1));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA1ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA1ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA1VerifyModeFinish(workspace, job);
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

#if(MCALCRY_HMACSHA256VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA256VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 macBuffer[ESL_SIZEOF_SHA256_DIGEST];

  retValCv = esl_finalizeHashMACSHA256(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer);
  if(retValCv == ESL_ERC_NO_ERROR){
    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength <= McalCry_Byte2Bit(ESL_SIZEOF_SHA256_DIGEST)){
      *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
        McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha256Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA256, AUTOMATIC, MCALCRY_VAR_NOINIT) workspace = McalCry_GetWorkspaceOfHmacSha256Verify(McalCry_GetHmacSha256VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA256));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA256ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA256ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA256VerifyModeFinish(workspace, job);
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

#if(MCALCRY_HMACSHA384VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacSHA384VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 macBuffer[ESL_SIZEOF_SHA384_DIGEST];

  retValCv = esl_finalizeHashMACSHA384(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer);
  if(retValCv == ESL_ERC_NO_ERROR){
    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength <= McalCry_Byte2Bit(ESL_SIZEOF_SHA384_DIGEST)){
      *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
        McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha384Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACSHA384, AUTOMATIC, MCALCRY_VAR_NOINIT) workspace = McalCry_GetWorkspaceOfHmacSha384Verify(McalCry_GetHmacSha384VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACSHA384));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacSHA384ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacSHA384ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacSHA384VerifyModeFinish(workspace, job);
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

#if(MCALCRY_GMACAESGENERATE == STD_ON) || (MCALCRY_GMACAESVERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchGmacAesModeStart(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyElementGetType keyElements[2];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CIPHER_KEY);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CIPHER_IV);

  if(esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_GMAC, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initGMAC(workSpace,
                              (eslt_Length)keyElements[0u].keyElementLength,
                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex),
                              (eslt_Length)keyElements[1u].keyElementLength,
                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex));
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesModeUpdate(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;

  retValCv = esl_updateGMAC(workSpace,
                            (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  return retValCv;
}
#endif

#if(MCALCRY_GMACAESGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesGenerateModeFinish(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  eslt_Byte authTagTempBuffer[MCALCRY_GMAC_MAX_OUT_TAG_SIZE] = { 0u };

  if(esl_finalizeGMAC(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&authTagTempBuffer[0])
      == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > MCALCRY_GMAC_MAX_OUT_TAG_SIZE){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = MCALCRY_GMAC_MAX_OUT_TAG_SIZE;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, authTagTempBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retValCv = ESL_ERC_NO_ERROR;
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_GmacAesGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfGmacAesGenerate(McalCry_GetGmacAesGenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceGMAC));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchGmacAesModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchGmacAesModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchGmacAesGenerateModeFinish(workspace, job);
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

#if(MCALCRY_GMACAESVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchGmacAesVerifyModeFinish(
  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  eslt_Byte authTagTempBuffer[MCALCRY_GMAC_MAX_OUT_TAG_SIZE] = { 0u };
  uint32 authTagTempBufferLength;

  if(esl_finalizeGMAC(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&authTagTempBuffer[0])
      == ESL_ERC_NO_ERROR){
    authTagTempBufferLength = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength;

    if(authTagTempBufferLength <= (MCALCRY_GMAC_MAX_OUT_TAG_SIZE << 3u)){
      *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
        McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, authTagTempBuffer, authTagTempBufferLength);
      retValCv = ESL_ERC_NO_ERROR;
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_GmacAesVerify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceGMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfGmacAesVerify(McalCry_GetGmacAesVerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceGMAC));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchGmacAesModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchGmacAesModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchGmacAesVerifyModeFinish(workspace, job);
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

#if(MCALCRY_HMACRIPEMD160GENERATE == STD_ON) || (MCALCRY_HMACRIPEMD160VERIFY == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160ModeStart(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyElementGetType keyElements[1];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_MAC_KEY);

  if(esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_HMACRIPEMD160, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;
      retValCv = esl_initHashMACRIPEMD160(workSpace,
                                         (eslt_Length)keyElements[0u].keyElementLength,
                                         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex));
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160ModeUpdate(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;

  retValCv = esl_updateHashMACRIPEMD160(workSpace,
                                       (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength,
                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  return retValCv;
}
#endif

#if(MCALCRY_HMACRIPEMD160GENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160GenerateModeFinish(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  uint8 macBuffer[ESL_SIZEOF_SHA1_DIGEST];

  if(esl_finalizeHashMACRIPEMD160(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer) == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_RIPEMD160_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_RIPEMD160_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, macBuffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retValCv = ESL_ERC_NO_ERROR;
  }
  else{
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = 0u;
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacRipeMd160Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacRipeMd160Generate(McalCry_GetHmacRipeMd160GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACRIPEMD160));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacRipeMd160ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacRipeMd160ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacRipeMd160GenerateModeFinish(workspace, job);
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

#if(MCALCRY_HMACRIPEMD160VERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchHmacRipeMd160VerifyModeFinish(
  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 macBuffer[ESL_SIZEOF_RIPEMD160_DIGEST];

  retValCv = esl_finalizeHashMACRIPEMD160(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) macBuffer);
  if(retValCv == ESL_ERC_NO_ERROR){
    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength <= McalCry_Byte2Bit(ESL_SIZEOF_RIPEMD160_DIGEST)){
      *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr) =
        McalCry_CompareMac(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, macBuffer, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  return retValCv;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacRipeMd160Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceHMACRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfHmacRipeMd160Verify(McalCry_GetHmacRipeMd160VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceHMACRIPEMD160));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHmacRipeMd160ModeStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retValCv = McalCry_DispatchHmacRipeMd160ModeUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retValCv = McalCry_DispatchHmacRipeMd160VerifyModeFinish(workspace, job);
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

