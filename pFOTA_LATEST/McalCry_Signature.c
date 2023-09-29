

#define MCALCRY_SIGNATURE_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_Curve_Int.hpp"
#include "McalCry_SignatureGenerate.hpp"
#include "McalCry_SignatureVerify.hpp"

#define MCALCRY_SIZEOF_SIGNATURE_KEY                          32u

#define MCALCRY_RSA_SALT_LENGTH_SIZE                          (2u)
#define MCALCRY_SIGNATURE_RSA_PSS_SALT_SIZE_AUTO_CALC         (-1)

#define MCALCRY_PREHASH_DIGEST_MAXSIZE                        ESL_SIZEOF_SHA512_DIGEST

#define CRYPTO_E_PARAM_HANDLE_CUSTOM                                  (0x0Fu)

#define McalCry_GetUint16(hiByte, loByte)                     ((uint16)((((uint16)(hiByte)) << 8) | ((uint16)(loByte))))

#if((MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA1 == STD_ON)||(MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA1 == STD_ON))
#define MCALCRY_SIGNATURE_SECFAM_SHA1                        STD_ON
#else
#define MCALCRY_SIGNATURE_SECFAM_SHA1                        STD_OFF
#endif

#if((MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_256 == STD_ON)||(MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_256 == STD_ON))
#define MCALCRY_SIGNATURE_SECFAM_SHA2_256                    STD_ON
#else
#define MCALCRY_SIGNATURE_SECFAM_SHA2_256                    STD_OFF
#endif

#if((MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_384 == STD_ON)||(MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_384 == STD_ON))
#define MCALCRY_SIGNATURE_SECFAM_SHA2_384                    STD_ON
#else
#define MCALCRY_SIGNATURE_SECFAM_SHA2_384                    STD_OFF
#endif

#if((MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_512 == STD_ON)||(MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_512 == STD_ON))
#define MCALCRY_SIGNATURE_SECFAM_SHA2_512                    STD_ON
#else
#define MCALCRY_SIGNATURE_SECFAM_SHA2_512                    STD_OFF
#endif

#if((MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA1 == STD_ON) || (MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_256 == STD_ON) ||  (MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_384 == STD_ON) || (MCALCRY_SIGNATURE_GENERATE_SECFAM_SHA2_512 == STD_ON))
#define MCALCRY_SIGNATURE_GENERATE_PRE_HASH                  STD_ON
#else
#define MCALCRY_SIGNATURE_GENERATE_PRE_HASH                  STD_OFF
#endif

#if((MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA1 == STD_ON) || (MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_256 == STD_ON) ||  (MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_384 == STD_ON) || (MCALCRY_SIGNATURE_VERIFY_SECFAM_SHA2_512 == STD_ON))
#define MCALCRY_SIGNATURE_VERIFY_PRE_HASH                    STD_ON
#else
#define MCALCRY_SIGNATURE_VERIFY_PRE_HASH                    STD_OFF
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA1 == STD_ON) || (MCALCRY_SIGNATURE_SECFAM_SHA2_256 == STD_ON) ||  (MCALCRY_SIGNATURE_SECFAM_SHA2_384 == STD_ON) || (MCALCRY_SIGNATURE_SECFAM_SHA2_512 == STD_ON))
#define MCALCRY_SIGNATURE_PRE_HASH                           STD_ON
#else
#define MCALCRY_SIGNATURE_PRE_HASH                           STD_OFF
#endif

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if((MCALCRY_ECPGENERATE == STD_ON) || (MCALCRY_ECPVERIFY == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashStart(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashUpdate(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

#if((MCALCRY_SIGNATURE_PRE_HASH == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashFinish(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) hashPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) hashLengthPtr);
#endif
#endif

#if(MCALCRY_ECPGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateStart(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateUpdate(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_EccPrimeGenerateSignature(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) messagePtr
   ,  uint32 messageLength);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateFinish(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_ECPVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyStart(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyUpdate(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyFinish(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if((MCALCRY_RSAVERIFY == STD_ON) || (MCALCRY_ECPVERIFY == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchSignatureVerifyResult(
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  eslt_ErrorCode retValCv
   ,  eslt_ErrorCode signatureInvalidValue);
#endif

#if(MCALCRY_RSAPSSVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SignatureRsaPssVerifyGetKeyElements(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) SigExponentIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) SigExponentLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) SigModulusIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) SigModulusLength
   ,  uint32 objectId);
#endif

#if(MCALCRY_RSAPKCS1CRTGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateStart(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateUpdate(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateFinish(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_ED25519GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Ed25519Generate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  eslt_Length outputLength;

  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfEd25519Generate(McalCry_GetEd25519GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceEd25519));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retValCv = esl_initWorkSpaceHeader(&(workspace->header), ESL_SIZEOF_WS_Ed25519, MCALCRY_WATCHDOG_PTR);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512)
        {
          retValCv = esl_initSignEdDSA(workspace
   ,                                      ESL_Curve25519
   ,                                      ESL_INSTANCE_Ed25519ph
   ,                                      (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))NULL_PTR
   ,                                      0u);
        }
        else
        {
          retValCv = esl_initSignEdDSA(workspace
   ,                                      ESL_Curve25519
   ,                                      ESL_INSTANCE_Ed25519
   ,                                      (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))NULL_PTR
   ,                                      0u);
        }
      }

      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512)
      {
        retValCv = esl_updateEdDSA(workspace
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
      }
      else
      {
        if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength != 0u) && (!McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_FINISH)))
        {
          retVal = E_NOT_OK;
        }
        else
        {
          retVal = E_OK;
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_KeyElementGetType keyElements[1];

      uint32 sigGenKeyLength = MCALCRY_SIZEOF_SIGNATURE_KEY;
      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_SIGNATURE_KEY, sigGenKeyLength);

      retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_EQUAL);
      if(retVal == E_OK)
      {
        retVal = E_NOT_OK;
        outputLength = (eslt_Length)*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

        retValCv = esl_signEdDSA(workspace
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                (eslt_Length)((job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512) ? (0u) : (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength))
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))NULL_PTR
   ,                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength);

        *(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) = outputLength;
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

#if(MCALCRY_ED25519VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Ed25519Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfEd25519Verify(McalCry_GetEd25519VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceEd25519));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retValCv = esl_initWorkSpaceHeader(&(workspace->header), ESL_SIZEOF_WS_Ed25519, MCALCRY_WATCHDOG_PTR);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512)
        {
          retValCv = esl_initVerifyEdDSA(workspace
   ,                                        ESL_Curve25519
   ,                                        ESL_INSTANCE_Ed25519ph
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))NULL_PTR
   ,                                        0u);
        }
        else
        {
          retValCv = esl_initVerifyEdDSA(workspace
   ,                                        ESL_Curve25519
   ,                                        ESL_INSTANCE_Ed25519
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))NULL_PTR
   ,                                        0u);
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512)
      {
        retValCv = esl_updateEdDSA(workspace
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
      }
      else
      {
        if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength != 0u) && (!McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_FINISH)))
        {
          retVal = E_NOT_OK;
        }
        else
        {
          retVal = E_OK;
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_KeyElementGetType keyElements[1];

      uint32 sigGenKeyLength = MCALCRY_SIZEOF_SIGNATURE_KEY;
      McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_SIGNATURE_KEY, sigGenKeyLength);

      retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_EQUAL);
      if(retVal == E_OK)
      {
        retVal = E_NOT_OK;
        retValCv = esl_verifyEdDSA(workspace
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                  (eslt_Length)((job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA2_512) ? (0u) : (job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength))
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);

        if(retValCv == ESL_ERC_NO_ERROR)
        {
          *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_OK;
        }
        else
        {
          if((retValCv == ESL_ERC_SIGNATURE_INVALID) || (retValCv == ESL_ERC_ECC_SIGNATURE_INVALID))
          {
            retValCv = ESL_ERC_NO_ERROR;
          }
          *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_NOT_OK;
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

#if((MCALCRY_RSAVERIFY == STD_ON) || (MCALCRY_ECPVERIFY == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_DispatchSignatureVerifyResult(
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  eslt_ErrorCode retValCv
   ,  eslt_ErrorCode signatureInvalidValue){
  eslt_ErrorCode retVal = ESL_ERC_ERROR;

  if(retValCv == ESL_ERC_NO_ERROR){
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_OK;
    retVal = ESL_ERC_NO_ERROR;
  }
  else{
    if((retValCv == signatureInvalidValue) || (retValCv == ESL_ERC_SIGNATURE_INVALID)){
      retVal = ESL_ERC_NO_ERROR;
    }
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr = CRYPTO_E_VER_NOT_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_RSAPSSVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SignatureRsaPssVerifyGetKeyElements(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) SigExponentIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) SigExponentLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) SigModulusIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) SigModulusLength
   ,  uint32 objectId){
  Std_ReturnType retVal;
  Std_ReturnType retValRequired, reValOptional;

  McalCry_KeyElementGetType keyElements[2];

  McalCry_SizeOfKeyStorageType SignatureSaltLengthIndex;
  uint32 SignatureSaltLengthSize = MCALCRY_RSA_SALT_LENGTH_SIZE;

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_MODULUS);

  retValRequired = McalCry_Local_GetElementsIndexJob(cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
  reValOptional = McalCry_Local_KeyElementGetStorageIndexJobOptional(cryptoKeyId, CRYPTO_KE_CUSTOM_RSA_SALT_LENGTH, &SignatureSaltLengthIndex, &SignatureSaltLengthSize, MCALCRY_LENGTH_CHECK_EQUAL);

  if(retValRequired == E_OK){
    *SigExponentIndexPtr = keyElements[0u].keyElementIndex;
    *SigExponentLength = keyElements[0u].keyElementLength;
    *SigModulusIndexPtr = keyElements[1u].keyElementIndex;
    *SigModulusLength = keyElements[1u].keyElementLength;

    if(reValOptional == E_OK){
      McalCry_SetWrittenLength(objectId, (uint32)McalCry_GetUint16(McalCry_GetKeyStorage(SignatureSaltLengthIndex), McalCry_GetKeyStorage(SignatureSaltLengthIndex + 1u)));
      retVal = E_OK;
    }
    else if(reValOptional == CRYPTO_E_KEY_NOT_AVAILABLE){
      McalCry_SetWrittenLength(objectId, (uint32)(eslt_Length)MCALCRY_SIGNATURE_RSA_PSS_SALT_SIZE_AUTO_CALC);
      retVal = E_OK;
    }
    else{
      retVal = reValOptional;
    }
  }
  else{
    retVal = retValRequired;
  }
  return retVal;
}
#endif

#if(MCALCRY_RSAPKCS1GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Generate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;
#endif
#endif
  P2VAR(eslt_WorkSpaceRSAsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPkcs1Generate(McalCry_GetRsaPkcs1GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAsig));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_SIG, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT);
        McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_MODULUS);

        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
          if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
          {
            retValCv = esl_initSignRSASHA1_V15(workspace
   ,                                              (eslt_Length)keyElements[1].keyElementLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex)
   ,                                              (eslt_Length)keyElements[0].keyElementLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex));
          }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
          else
#endif
          {
            retValCv = esl_initSignRSASHA256_V15(workspace
   ,                                                (eslt_Length)keyElements[1].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex)
   ,                                                (eslt_Length)keyElements[0].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex));
          }
#endif
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_updateSignRSASHA1_V15(workspace
   ,                                            (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_updateSignRSASHA256_V15(workspace
   ,                                              (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      eslt_Length outputLength;
      outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_finalizeSignRSASHA1_V15(workspace
   ,                                              &outputLength
   ,                                              (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
      }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_finalizeSignRSASHA256_V15(workspace
   ,                                                &outputLength
   ,                                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
      }
#endif

      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (uint32)outputLength;

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

#if(MCALCRY_RSAPKCS1VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;
#endif
#endif
  P2VAR(eslt_WorkSpaceRSAver, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPkcs1Verify(McalCry_GetRsaPkcs1VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAver));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_VER, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
        McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT);

        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
          if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
          {
            retValCv = esl_initVerifyRSASHA1_V15(workspace
   ,                                                (eslt_Length)keyElements[0].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                                (eslt_Length)keyElements[1].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
          else
#endif
          {
            retValCv = esl_initVerifyRSASHA256_V15(workspace
   ,                                                  (eslt_Length)keyElements[0].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                                  (eslt_Length)keyElements[1].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          }
#endif
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_updateVerifyRSASHA1_V15(workspace
   ,                                              (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_updateVerifyRSASHA256_V15(workspace
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_finalizeVerifyRSASHA1_V15(workspace
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr);

        retValCv = McalCry_DispatchSignatureVerifyResult(job, retValCv, ESL_ERC_RSA_SIGNATURE_INVALID);
      }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PKCS1_v1_5_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_finalizeVerifyRSASHA256_V15(workspace
   ,                                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr);

        retValCv = McalCry_DispatchSignatureVerifyResult(job, retValCv, ESL_ERC_RSA_SIGNATURE_INVALID);
      }
#endif
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

#if(MCALCRY_RSAPSSGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPssGenerate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;
#endif
#endif
  P2VAR(eslt_WorkSpaceRSAPSSsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPssGenerate(McalCry_GetRsaPssGenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAPSSsig));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_KeyElementGetType keyElements[2];

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_PSS_SIG, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_MODULUS);
        McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT);

        retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_NONE);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
          if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
          {
            retValCv = esl_initSignRSASHA1_PSS(workspace
   ,                                              (eslt_Length)keyElements[0].keyElementLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                              (eslt_Length)keyElements[1].keyElementLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
          else
#endif
          {
            retValCv = esl_initSignRSASHA256_PSS(workspace
   ,                                                (eslt_Length)keyElements[0].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex)
   ,                                                (eslt_Length)keyElements[1].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1].keyElementIndex));
          }
#endif
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_updateSignRSASHA1_PSS(workspace
   ,                                            (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_updateSignRSASHA256_PSS(workspace
   ,                                              (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      McalCry_KeyElementGetType keyElements[1];

      McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_SALT);
      retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_NONE);

      if(retVal == E_OK)
      {
        eslt_Length outputLength;
        outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
        retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
        if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
        {
          retValCv = esl_finalizeSignRSASHA1_PSS(workspace
   ,                                                (eslt_Length)keyElements[0u].keyElementLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,                                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_RSASSA_PSS_SHA1 == STD_ON)
        else
#endif
        {
          retValCv = esl_finalizeSignRSASHA256_PSS(workspace
   ,                                                  (eslt_Length)keyElements[0u].keyElementLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,                                                  (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,                                                  (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
        }
#endif
        *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outputLength;
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

#if(MCALCRY_RSAPSSVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPssVerify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
  Crypto_AlgorithmSecondaryFamilyType secAlgoFam = job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily;
#endif
#endif
  P2VAR(eslt_WorkSpaceRSAPSSver, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPssVerify(McalCry_GetRsaPssVerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSAPSSver));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      McalCry_SizeOfKeyStorageType SigExponentIndex;
      uint32 SigExponentLength;
      McalCry_SizeOfKeyStorageType SigModulusIndex;
      uint32 SigModulusLength;

      if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_PSS_VER, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_SignatureRsaPssVerifyGetKeyElements(job->cryptoKeyId, &SigExponentIndex, &SigExponentLength, &SigModulusIndex, &SigModulusLength, objectId);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
          if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
          {
            retValCv = esl_initVerifyRSASHA1_PSS(workspace
   ,                                                (eslt_Length)SigModulusLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(SigModulusIndex)
   ,                                                (eslt_Length)SigExponentLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(SigExponentIndex));
          }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
          else
#endif
          {
            retValCv = esl_initVerifyRSASHA256_PSS(workspace
   ,                                                  (eslt_Length)SigModulusLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(SigModulusIndex)
   ,                                                  (eslt_Length)SigExponentLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(SigExponentIndex));
          }
#endif
        }
      }
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_updateVerifyRSASHA1_PSS(workspace
   ,                                              (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_updateVerifyRSASHA256_PSS(workspace
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
      }
#endif
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
      if(secAlgoFam == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_finalizeVerifyRSASHA1_PSS(workspace
   ,                                                (eslt_Length)McalCry_GetWrittenLength(objectId)
   ,                                                (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,                                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr);

        retValCv = McalCry_DispatchSignatureVerifyResult(job, retValCv, ESL_ERC_RSA_SIGNATURE_INVALID);
      }
#endif
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_VERIFY_RSA_RSASSA_PSS_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_finalizeVerifyRSASHA256_PSS(workspace
   ,                                                  (eslt_Length)McalCry_GetWrittenLength(objectId)
   ,                                                  (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength
   ,                                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr);

        retValCv = McalCry_DispatchSignatureVerifyResult(job, retValCv, ESL_ERC_RSA_SIGNATURE_INVALID);
      }
#endif
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

#if((MCALCRY_ECPGENERATE == STD_ON) || (MCALCRY_ECPVERIFY == STD_ON))

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashStart(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;

  switch(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily){
    case CRYPTO_ALGOFAM_NOT_SET:

    retVal = E_OK;
    break;

#if((MCALCRY_SIGNATURE_SECFAM_SHA1 == STD_ON))
    case CRYPTO_ALGOFAM_SHA1:

    if(esl_initWorkSpaceHeader(&(wsHash->wsSHA1.header), ESL_MAXSIZEOF_WS_SHA1, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      if(esl_initSHA1(&(wsHash->wsSHA1)) == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_256 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_256:

    if(esl_initWorkSpaceHeader(&(wsHash->wsSHA256.header), ESL_MAXSIZEOF_WS_SHA256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      if(esl_initSHA256(&(wsHash->wsSHA256)) == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_384 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_384:

    if(esl_initWorkSpaceHeader(&(wsHash->wsSHA384.header), ESL_MAXSIZEOF_WS_SHA384, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      if(esl_initSHA384(&(wsHash->wsSHA384)) == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_512 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_512:

    if(esl_initWorkSpaceHeader(&(wsHash->wsSHA512.header), ESL_MAXSIZEOF_WS_SHA512, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      if(esl_initSHA512(&(wsHash->wsSHA512)) == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }
    break;
#endif

    default:
    MCALCRY_DUMMY_STATEMENT(wsHash);
    break;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashUpdate(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;

  switch(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily){
    case CRYPTO_ALGOFAM_NOT_SET:

    if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength != 0u) && (!McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_FINISH))){
      retVal = E_NOT_OK;
    }
    else{
      retVal = E_OK;
    }
    break;

#if((MCALCRY_SIGNATURE_SECFAM_SHA1 == STD_ON))
    case CRYPTO_ALGOFAM_SHA1:

    if(esl_updateSHA1(&(wsHash->wsSHA1)
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr) == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_256 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_256:

    if(esl_updateSHA256(&(wsHash->wsSHA256)
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr) == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_384 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_384:

    if(esl_updateSHA384(&(wsHash->wsSHA384)
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr) == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_512 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_512:

    if(esl_updateSHA512(&(wsHash->wsSHA512)
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr) == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
    break;
#endif

    default:
    MCALCRY_DUMMY_STATEMENT(wsHash);
    break;
  }

  return retVal;
}

#if(MCALCRY_SIGNATURE_PRE_HASH == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_PreHashFinish(
  P2VAR(McalCry_UnionWS_PreHash, AUTOMATIC, MCALCRY_APPL_VAR) wsHash
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) hashPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) hashLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;

  switch(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily){
#if((MCALCRY_SIGNATURE_SECFAM_SHA1 == STD_ON))
    case CRYPTO_ALGOFAM_SHA1:

    if(esl_finalizeSHA1((P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(wsHash->wsSHA1), (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))hashPtr) == ESL_ERC_NO_ERROR){
      *hashLengthPtr = ESL_SIZEOF_SHA1_DIGEST;
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_256 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_256:

    if(esl_finalizeSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(wsHash->wsSHA256), (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))hashPtr) == ESL_ERC_NO_ERROR){
      *hashLengthPtr = ESL_SIZEOF_SHA256_DIGEST;
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_384 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_384:

    if(esl_finalizeSHA384((P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(wsHash->wsSHA384), (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))hashPtr) == ESL_ERC_NO_ERROR){
      *hashLengthPtr = ESL_SIZEOF_SHA384_DIGEST;
      retVal = E_OK;
    }
    break;
#endif

#if((MCALCRY_SIGNATURE_SECFAM_SHA2_512 == STD_ON))
    case CRYPTO_ALGOFAM_SHA2_512:

    if(esl_finalizeSHA512((P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(wsHash->wsSHA512), (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))hashPtr) == ESL_ERC_NO_ERROR){
      *hashLengthPtr = ESL_SIZEOF_SHA512_DIGEST;
      retVal = E_OK;
    }
    break;
#endif

    default:
    MCALCRY_DUMMY_STATEMENT(wsHash);
    MCALCRY_DUMMY_STATEMENT(hashPtr);
    MCALCRY_DUMMY_STATEMENT(hashLengthPtr);
    break;
  }
  return retVal;
}
#endif
#endif

#if(MCALCRY_ECPGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateStart(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_PreHashStart(&(workSpace->wsPreHash), job);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateUpdate(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_PreHashUpdate(&(workSpace->wsPreHash), job);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_EccPrimeGenerateSignature(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) messagePtr
   ,  uint32 messageLength){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;
  uint32 expectedKeyLength;
  uint32 messageLengthCut;
  uint32 sigKeyLength;
  eslt_Length sigLength, doubleSigLength, sigLengthR, sigLengthS;
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainPtr;
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainExtPtr;
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcSpeedUpExtPtr;

#if(MCALCRY_ECP160GENERATE == STD_ON)
  boolean outputIsSet = FALSE;
  eslt_Byte privateKeyElementBuffer[MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY];
#endif

  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) privateKeyElementPtr;
  eslt_Byte signatureR[MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY];
  eslt_Byte signatureS[MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY];
  McalCry_KeyElementGetType keyElements[1];

#if(MCALCRY_ECP160GENERATE == STD_ON)
#if((MCALCRY_ECP256GENERATE == STD_ON) || (MCALCRY_ECP384GENERATE == STD_ON))
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CUSTOM_P160R1)
#endif
  {
    EcDomainPtr = McalCry_EccCurveSecP160R1Domain;
    EcDomainExtPtr = McalCry_EccCurveSecP160R1DomainExt;
    EcSpeedUpExtPtr = McalCry_EccCurveSecP160R1SpeedUpExt;
    expectedKeyLength = MCALCRY_SIZEOF_ECC_160_KEY_PRIVATE-1u;
  }
#if(MCALCRY_ECP256GENERATE == STD_ON)
  else
#endif
#endif
#if(MCALCRY_ECP256GENERATE == STD_ON)
#if(MCALCRY_ECP384GENERATE == STD_ON)
    if((job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CUSTOM_P256R1))
#endif
    {
      EcDomainPtr = McalCry_EccCurveNistAnsiSecP256R1Domain;
      EcDomainExtPtr = McalCry_EccCurveNistAnsiSecP256R1DomainExt;
      EcSpeedUpExtPtr = McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt;
      expectedKeyLength = MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE;
    }
#endif
#if(MCALCRY_ECP384GENERATE == STD_ON)
#if((MCALCRY_ECP160GENERATE == STD_ON) || (MCALCRY_ECP256GENERATE == STD_ON))
    else
#endif
    {
      EcDomainPtr = McalCry_EccCurveNistSecP384R1Domain;
      EcDomainExtPtr = McalCry_EccCurveNistSecP384R1DomainExt;
      EcSpeedUpExtPtr = McalCry_EccCurveNistSecP384R1SpeedUpExt;
      expectedKeyLength = MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE;
    }
#endif

  messageLengthCut = messageLength;
#if(MCALCRY_SIGNATURE_GENERATE_PRE_HASH == STD_ON)
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily != CRYPTO_ALGOFAM_NOT_SET){
    if(messageLength > esl_getMaxLengthOfEcPmessage(EcDomainPtr)){
      messageLengthCut = esl_getMaxLengthOfEcPmessage(EcDomainPtr);
    }
  }
#endif

  sigKeyLength = (uint32)(esl_getLengthOfEcPprivateKey(EcDomainPtr));
  McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_SIGNATURE_KEY, sigKeyLength);

  if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(workSpace->wsEcP.header), ESL_MAXSIZEOF_WS_ECP, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_MAX);

    if(keyElements[0].keyElementLength < expectedKeyLength){
      retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
    }

    if(retVal == E_OK){
      retVal = E_NOT_OK;
      if(esl_initSignDSAEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(workSpace->wsEcP), EcDomainPtr, EcDomainExtPtr, EcSpeedUpExtPtr) == ESL_ERC_NO_ERROR)
      {
#if(MCALCRY_ECP160GENERATE == STD_ON)
        if(sigKeyLength == (keyElements[0].keyElementLength + 1u))
        {
          privateKeyElementBuffer[0] = 0u;
          McalCry_CopyData(&privateKeyElementBuffer[1u], McalCry_GetAddrKeyStorage(keyElements[0].keyElementIndex), (keyElements[0].keyElementLength));
          privateKeyElementPtr = privateKeyElementBuffer;
        }
        else
#endif
        {
          privateKeyElementPtr = McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex);
        }

        sigLength = esl_getLengthOfEcPsignature_comp(EcDomainPtr);
        doubleSigLength = (eslt_Length)McalCry_Math_Mul2(sigLength);
        if(*(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr) >= doubleSigLength)
        {
          sigLengthS = sigLength;
          sigLengthR = sigLength;

          retValCv = esl_signDSAEcP_prim(&(workSpace->wsEcP)
   ,           (eslt_Length)messageLengthCut, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))messagePtr
   ,           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))privateKeyElementPtr
   ,           (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&sigLengthR, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))signatureR
   ,           (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&sigLengthS, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))signatureS);

          if(retValCv == ESL_ERC_NO_ERROR)
          {
            if((sigLengthR == sigLength) && (sigLengthS == sigLength))
            {
#if(MCALCRY_ECP160GENERATE == STD_ON)

              if(sigLength == (expectedKeyLength + 1u))
              {
                if((signatureR[0] == 0u) && (signatureS[0] == 0u))
                {
                  McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, &signatureR[1u], (eslt_Length)(sigLengthR - 1u));
                  McalCry_CopyData(&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[sigLengthR - 1u], &signatureS[1u], (eslt_Length)(sigLengthS - 1u));
                  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = (eslt_Length)(doubleSigLength - 2u);

                  outputIsSet = TRUE;
                }
                else
                {
                  outputIsSet = FALSE;
                }
              }
              else
              {
                outputIsSet = FALSE;
              }

              if(outputIsSet == FALSE)
#endif
              {
                McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, signatureR, (sigLengthR));
                McalCry_CopyData(&job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr[sigLengthR], signatureS, (sigLengthS));
                *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = doubleSigLength;
              }

              retVal = E_OK;
            }
          }
        }
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeGenerateFinish(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;
  uint32 messageLength;
  const uint8 *messagePtr;

#if((MCALCRY_SIGNATURE_GENERATE_PRE_HASH == STD_ON))
  uint8 messageBuf[MCALCRY_PREHASH_DIGEST_MAXSIZE];
  Std_ReturnType localRetVal;
#endif

#if((MCALCRY_SIGNATURE_GENERATE_PRE_HASH == STD_ON))
  retVal = E_NOT_OK;
  messageLength = MCALCRY_PREHASH_DIGEST_MAXSIZE;
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_NOT_SET){
#endif

    messagePtr = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr;
    messageLength = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength;
#if((MCALCRY_SIGNATURE_GENERATE_PRE_HASH == STD_ON))
    localRetVal = E_OK;
  }
  else{
    localRetVal = McalCry_PreHashFinish(&(workSpace->wsPreHash), job, messageBuf, &messageLength);
    messagePtr = messageBuf;
  }

  if(localRetVal == E_OK)
#endif
  {
    retVal = McalCry_EccPrimeGenerateSignature(workSpace, job, messagePtr, messageLength);
  }

  return retVal;
}
#endif

#if(MCALCRY_ECP256GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP256Generate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP256Generate(McalCry_GetEcP256GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateFinish(workspace, job);
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

#if(MCALCRY_ECP384GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP384Generate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP384Generate(McalCry_GetEcP384GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateFinish(workspace, job);
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

#if(MCALCRY_ECPVERIFY == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyStart(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_PreHashStart(&(workSpace->wsPreHash), job);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyUpdate(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal;

  retVal = McalCry_PreHashUpdate(&(workSpace->wsPreHash), job);

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSignatureEccPrimeVerifyFinish(
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;
  uint32 sigKeyLength;
  uint32 messageLength;
  const uint8* messagePtr;

#if(MCALCRY_SIGNATURE_VERIFY_PRE_HASH == STD_ON)
  Std_ReturnType localRetVal;
#endif

  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainPtr;
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainExtPtr;

  McalCry_KeyElementGetType keyElements[1];

#if(MCALCRY_SIGNATURE_VERIFY_PRE_HASH == STD_ON)
  uint8 messageBuf[MCALCRY_PREHASH_DIGEST_MAXSIZE];
#endif

#if(MCALCRY_ECP160VERIFY == STD_ON)
#if((MCALCRY_ECP256VERIFY == STD_ON) || (MCALCRY_ECP384VERIFY == STD_ON))
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CUSTOM_P160R1)
#endif
  {
    EcDomainPtr = McalCry_EccCurveSecP160R1Domain;
    EcDomainExtPtr = McalCry_EccCurveSecP160R1DomainExt;
  }
#if(MCALCRY_ECP256VERIFY == STD_ON)
  else
#endif
#endif
#if(MCALCRY_ECP256VERIFY == STD_ON)
#if(MCALCRY_ECP384VERIFY == STD_ON)
  if((job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_CUSTOM_P256R1))
#endif
  {
    EcDomainPtr = McalCry_EccCurveNistAnsiSecP256R1Domain;
    EcDomainExtPtr = McalCry_EccCurveNistAnsiSecP256R1DomainExt;
  }
#endif
#if(MCALCRY_ECP384VERIFY == STD_ON)
#if((MCALCRY_ECP160VERIFY == STD_ON) || (MCALCRY_ECP256VERIFY == STD_ON))
  else
#endif
  {
    EcDomainPtr = McalCry_EccCurveNistSecP384R1Domain;
    EcDomainExtPtr = McalCry_EccCurveNistSecP384R1DomainExt;
  }
#endif

#if(MCALCRY_SIGNATURE_VERIFY_PRE_HASH == STD_ON)
  messageLength = MCALCRY_PREHASH_DIGEST_MAXSIZE;
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_NOT_SET)
#endif
  {
    messagePtr = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr;
    messageLength = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength;
#if(MCALCRY_SIGNATURE_VERIFY_PRE_HASH == STD_ON)
    localRetVal = E_OK;
#endif
  }
#if(MCALCRY_SIGNATURE_VERIFY_PRE_HASH == STD_ON)
  else{
    localRetVal = McalCry_PreHashFinish(&(workSpace->wsPreHash), job, messageBuf, &messageLength);
    messagePtr = messageBuf;
  }

  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily != CRYPTO_ALGOFAM_NOT_SET){
    if(messageLength > esl_getMaxLengthOfEcPmessage(EcDomainPtr)){
      messageLength = esl_getMaxLengthOfEcPmessage(EcDomainPtr);
    }
  }

  if(localRetVal == E_OK)
#endif
  {
    sigKeyLength = (uint32)(McalCry_Math_Mul2((uint32)esl_getLengthOfEcPpublicKey_comp(EcDomainPtr)));
    McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_SIGNATURE_KEY, sigKeyLength);

    if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(workSpace->wsEcP.header), ESL_MAXSIZEOF_WS_ECP, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 1u, MCALCRY_LENGTH_CHECK_EQUAL);

      if(retVal == E_OK)
      {
        retVal = E_NOT_OK;
        retValCv = esl_initVerifyDSAEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(workSpace->wsEcP), EcDomainPtr, EcDomainExtPtr);
        if(retValCv == ESL_ERC_NO_ERROR)
        {
          if(McalCry_Math_IsEven(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength))
          {
            retValCv = esl_verifyDSAEcP_prim(&(workSpace->wsEcP), (eslt_Length)messageLength, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))messagePtr
   ,                                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,                                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex + McalCry_Math_Div2(sigKeyLength))
   ,                                            (eslt_Length)McalCry_Math_Div2(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength), (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr
   ,                                            (eslt_Length)McalCry_Math_Div2(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength), (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr[(eslt_Length)McalCry_Math_Div2(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength)]));

            retValCv = McalCry_DispatchSignatureVerifyResult(job, retValCv, ESL_ERC_ECC_SIGNATURE_INVALID);

            if(retValCv == ESL_ERC_NO_ERROR)
            {
              retVal = E_OK;
            }
          }
        }
      }
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_ECP256VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP256Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP256Verify(McalCry_GetEcP256VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyFinish(workspace, job);
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

#if(MCALCRY_ECP384VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP384Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP384Verify(McalCry_GetEcP384VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyFinish(workspace, job);
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

#if(MCALCRY_RSAPKCS1CRTGENERATE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateStart(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;

  McalCry_KeyElementGetType keyElements[5];

  McalCry_Local_ElementGetterSetId(keyElements, 0u, CRYPTO_KE_CUSTOM_RSA_PRIME_P);
  McalCry_Local_ElementGetterSetId(keyElements, 1u, CRYPTO_KE_CUSTOM_RSA_PRIME_Q);
  McalCry_Local_ElementGetterSetId(keyElements, 2u, CRYPTO_KE_CUSTOM_RSA_EXPONENT_DP);
  McalCry_Local_ElementGetterSetId(keyElements, 3u, CRYPTO_KE_CUSTOM_RSA_EXPONENT_DQ);
  McalCry_Local_ElementGetterSetId(keyElements, 4u, CRYPTO_KE_CUSTOM_RSA_INVERSE_QI);

  if(esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_RSA_CRT_SIG, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_GetElementsIndexJob(job->cryptoKeyId, keyElements, 5u, MCALCRY_LENGTH_CHECK_NONE);
    if(retVal == E_OK){
      retVal = E_NOT_OK;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
      if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA1)
#endif
      {
        retValCv = esl_initSignRSACRTSHA1_V15(
          workspace
   ,         (eslt_Length)keyElements[0u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,         (eslt_Length)keyElements[1u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex)
   ,         (eslt_Length)keyElements[2u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[2u].keyElementIndex)
   ,         (eslt_Length)keyElements[3u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[3u].keyElementIndex)
   ,         (eslt_Length)keyElements[4u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[4u].keyElementIndex));
      }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
      else
#endif
      {
        retValCv = esl_initSignRSACRTSHA256_V15(
          workspace
   ,         (eslt_Length)keyElements[0u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[0u].keyElementIndex)
   ,         (eslt_Length)keyElements[1u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[1u].keyElementIndex)
   ,         (eslt_Length)keyElements[2u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[2u].keyElementIndex)
   ,         (eslt_Length)keyElements[3u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[3u].keyElementIndex)
   ,         (eslt_Length)keyElements[4u].keyElementLength
   ,         (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(keyElements[4u].keyElementIndex));
      }
#endif
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateUpdate(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA1)
#endif
  {
    retValCv = esl_updateSignRSACRTSHA1_V15(
      workspace
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
  }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
  else
#endif
  {
    retValCv = esl_updateSignRSACRTSHA256_V15(
      workspace
   ,     (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);
  }
#endif

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RsaPkcs1CrtGenerateFinish(
  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  eslt_Length outputLength;
  outputLength = (eslt_Length)(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
  if(job->jobPrimitiveInfo->primitiveInfo->algorithm.secondaryFamily == CRYPTO_ALGOFAM_SHA1)
#endif
  {
    retValCv = esl_finalizeSignRSACRTSHA1_V15(
      workspace
   ,     (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#endif
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA2_256 == STD_ON)
#if(MCALCRY_SIGNATURE_GENERATE_RSA_CUSTOM_RSASSA_PKCS1_v1_5_CRT_SHA1 == STD_ON)
  else
#endif
  {
    retValCv = esl_finalizeSignRSACRTSHA256_V15(
      workspace
   ,     (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);
  }
#endif

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
    *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outputLength;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1CrtGenerate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceRSACRTsig, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfRsaPkcs1CrtGenerate(McalCry_GetRsaPkcs1CrtGenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRSACRTsig));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    retVal = McalCry_RsaPkcs1CrtGenerateStart(workspace, job);
    break;

    case CRYPTO_OPERATIONMODE_UPDATE:
    retVal = McalCry_RsaPkcs1CrtGenerateUpdate(workspace, job);
    break;

    case CRYPTO_OPERATIONMODE_FINISH:
    retVal = McalCry_RsaPkcs1CrtGenerateFinish(workspace, job);
    break;

    default:

    break;
  }

  return retVal;
}
#endif

#if(MCALCRY_ECP160GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP160Generate(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP160Generate(McalCry_GetEcP160GenerateIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeGenerateFinish(workspace, job);
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

#if(MCALCRY_ECP160VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP160Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  workspace = McalCry_GetWorkspaceOfEcP160Verify(McalCry_GetEcP160VerifyIdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(McalCry_UnionWS_PreHash));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyStart(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyUpdate(workspace, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSignatureEccPrimeVerifyFinish(workspace, job);
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

