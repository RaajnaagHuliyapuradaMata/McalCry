#define MCALCRY_RANDOM_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_RandomGenerate.hpp"
#include "McalCry_RandomSeed.hpp"

#include "ESLib_types.hpp"
#if(MCALCRY_FIPS186 == STD_ON)
#include "actFIPS186.hpp"
#endif

#define MCALCRY_RANDOM_SEED_SIZEOF_ALGORITHM                  (1u)

#define MCALCRY_FIPS_SEED_LENGTH                              (20u)

#define MCALCRY_RANDOM_RESEED_COUNTER_LEN                     (MCALCRY_SIZEOF_UINT32)

#define MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN         (2u * ESL_HASHDRBG_SHA512_SEED_LEN)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_FIPS186 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomFips186Finish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_Fips(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock);
#endif

#if(MCALCRY_DRBGAES == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgSeedFirst(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgReseed(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgAesGeneratePrepare(
  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedStateElementIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedCounterElementIndexPtr
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist
   ,  uint32 seedLength
   ,  eslt_DRBGMode modeDRBG);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgAes(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  eslt_DRBGMode modeDRBG);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgAes_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  eslt_DRBGMode modeDRBG
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgSeed_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType reseedCtElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

#if(MCALCRY_RANDOM_SOURCE_DRBG_AES == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetRandomNistDrbgAes(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgAesFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_Local_Generate_NistDrbgAes(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Get_And_Set_NistDrbgAesState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RandomNistDrbgAes_Set_Mode_And_SeedLength(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_DRBGMode, AUTOMATIC, MCALCRY_APPL_VAR) modeDRBG
   ,  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) seedLength);
#endif

#if(MCALCRY_DRBGHASHSHA512 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgSeedFirst(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgReseed(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgHash(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgHash_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgSeed_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType reseedCtElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Get_And_Set_NistDrbgHashState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgHashFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgHashGeneratePrepare(
  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedStateElementIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedCounterElementIndexPtr
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist);

MCALCRY_LOCAL FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_Local_Generate_NistDrbgHash(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG);

#if(MCALCRY_RANDOM_SOURCE_DRBG_HASH == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetRandomNistDrbgHash(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist);
#endif
#endif

#if((MCALCRY_DRBGAES == STD_ON) || (MCALCRY_DRBGHASHSHA512 == STD_ON))

MCALCRY_LOCAL FUNC(boolean, MCALCRY_CODE) McalCry_Local_Random_Check_For_Write_Once(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, MCALCRY_APPL_VAR) reseedCtElementIndex);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Set_NistDrbgState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  eslt_ErrorCode retValCv
   ,  eslt_Length seedLength
   ,  eslt_Length expectedSeedLength
   ,  uint32 reseedCntBuf
   ,  eslt_DRBGSeedStatusType seedStatus);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Check_Random_KeyElement_Persist(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist);
#endif

#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_IsRngCalculationValid(uint16 localCount);
#endif

#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_KeyValueChangedCallout(uint32 cryptoKeyId);
#endif

#if(MCALCRY_FIPS186 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomFips186Finish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;
  P2VAR(eslt_WorkSpaceFIPS186, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfFips186(McalCry_GetFips186IdxOfObjectInfo(objectId));
  McalCry_SizeOfKeyStorageType fips186KeyIndex;
  uint32 fips186KeyLength;
  P2VAR(uint8, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) randomSeedBuffer = &McalCry_GetRandomSeedBuffer(McalCry_GetRandomSeedBufferStartIdxOfObjectInfo(objectId));

  retValCv = esl_initWorkSpaceHeader(&(workspace->header), ESL_MAXSIZEOF_WS_FIPS186, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    McalCry_SizeOfKeyElementsType elementIndex;

    if(McalCry_Local_KeyElementSearch(job->cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &elementIndex) == E_OK){
      if(!McalCry_IsKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_VALUE_USED_MASK))
      {
        retVal = McalCry_Local_KeyElementGetStorageIndexJob(job->cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &fips186KeyIndex, &fips186KeyLength, MCALCRY_LENGTH_CHECK_NONE);
        if(retVal == E_OK)
        {
          retVal = E_NOT_OK;

          if(!McalCry_Uint8CheckMask(randomSeedBuffer[0], MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK))
          {
            retValCv = esl_initFIPS186(workspace
   ,                                      (eslt_Length)fips186KeyLength
   ,                                      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(fips186KeyIndex)
   ,                                      NULL_PTR);

            McalCry_Uint8SetMask(randomSeedBuffer[0], MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK);
          }
          else
          {
            retValCv = esl_initFIPS186(workspace
   ,                                      (eslt_Length)fips186KeyLength
   ,                                      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(fips186KeyIndex)
   ,                                      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&randomSeedBuffer[1]);
          }

          McalCry_SetKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_VALUE_USED_MASK);
#if(MCALCRY_NVBLOCK == STD_ON)
          if(McalCry_IsKeyElementPersist(elementIndex) == TRUE)
          {
            McalCry_ProcessJob_Trigger_Write[objectId] = TRUE;
          }
#endif
        }
        else
        {
          retValCv = ESL_ERC_ERROR;

        }
      }
      else
      {
        if(McalCry_Uint8CheckMask(randomSeedBuffer[0], MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK))
        {
          retValCv = esl_initFIPS186(workspace
   ,                                    (eslt_Length)MCALCRY_FIPS_SEED_LENGTH
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&randomSeedBuffer[1]
   ,                                    NULL_PTR);
        }
        else
        {
          retValCv = ESL_ERC_ERROR;
          retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
        }
      }
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }

    if(retValCv == ESL_ERC_NO_ERROR){
      retValCv = esl_getBytesFIPS186(workspace
   ,                                    (eslt_Length)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr);

      McalCry_CopyData(&randomSeedBuffer[1], ((P2VAR(actFIPS186STRUCT, AUTOMATIC, MCALCRY_APPL_VAR))workspace->wsFIPS186)->X_KEY, MCALCRY_FIPS_SEED_LENGTH);
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }
  else if(retVal == CRYPTO_E_KEY_NOT_VALID){
    retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
  }
  else{
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_Fips(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock){
  Std_ReturnType retVal = E_NOT_OK;

  if(McalCry_IsKeyElementWriteOnce(seedStateElementIndex)){
    retVal = E_NOT_OK;
  }

  else if(McalCry_Local_KeyElementSetInternal(cryptoKeyId, seedStateElementIndex, entropyPtr, entropyLength, MCALCRY_WA_ALLOWED) == E_OK){
    McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_NORMAL_MASK);
    *writeBlock = McalCry_SetKeyState(cryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);

    retVal = E_OK;
  }
  else{
    *writeBlock = FALSE;
  }

  return retVal;
}
#endif

#if(MCALCRY_DRBGAES == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgReseed(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG){
  Std_ReturnType retVal = E_NOT_OK, localRetVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType additionalInputIndex = 0u, seedIndex, reseedCounter;
  uint32 reseedCnt, additionalInputLength = 0u;
  uint32 seedLength = ESL_CTRDRBG_AES128_SEEDLEN;
  uint32 reseedCntLength = MCALCRY_RANDOM_RESEED_COUNTER_LEN;

  if((modeDRBG == ESL_DRBGMODE_CTRDRBG_AES256_NODF) || (modeDRBG == ESL_DRBGMODE_CTRDRBG_AES256_DF)){
    seedLength = ESL_CTRDRBG_AES256_SEEDLEN;
  }

  if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &seedIndex, &seedLength, MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
    if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, &reseedCounter, &reseedCntLength, MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
      McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCnt, McalCry_GetAddrKeyStorage(reseedCounter));

      retValCv = esl_restoreStateCTRDRBG(wsDRBG
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(seedIndex)
   ,                                       (eslt_Length) seedLength
   ,                                       (eslt_DRBGReseedCounterType) reseedCnt
   ,                                       (eslt_Byte) ESL_DRBG_SEED_STATUS_SEEDED
   ,                                       modeDRBG);
      if(retValCv == ESL_ERC_NO_ERROR)
      {
        localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT, &additionalInputIndex, &additionalInputLength, MCALCRY_LENGTH_CHECK_NONE);
      }
    }

    if((localRetVal == E_OK) && (additionalInputLength > 0u)){
      retValCv = esl_seedCTRDRBG(wsDRBG
   ,                               (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) entropyPtr
   ,                               (eslt_Length) entropyLength
   ,                               NULL_PTR
   ,                               0u
   ,                               NULL_PTR
   ,                               0u
   ,                               (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(additionalInputIndex)
   ,                               (eslt_Length) additionalInputLength);
    }
    else if((localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE) || (localRetVal == E_OK)){
      retValCv = esl_seedCTRDRBG(wsDRBG
   ,                               (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) entropyPtr
   ,                               (eslt_Length) entropyLength
   ,                               NULL_PTR
   ,                               0u
   ,                               NULL_PTR
   ,                               0u
   ,                               NULL_PTR
   ,                               0u);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgSeedFirst(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG){
  Std_ReturnType retVal = E_NOT_OK, localRetVal = E_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType personalizationStrIndex, nonceIndex = 0u;
  uint32 personalizationStrLength, nonceLength = 0u;

  if((modeDRBG == ESL_DRBGMODE_CTRDRBG_AES128_DF) || (modeDRBG == ESL_DRBGMODE_CTRDRBG_AES256_DF)){
    localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_NONCE, &nonceIndex, &nonceLength, MCALCRY_LENGTH_CHECK_NONE);
  }

  if(localRetVal == E_OK){
    localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_PERSONALIZATION_STRING, &personalizationStrIndex, &personalizationStrLength, MCALCRY_LENGTH_CHECK_NONE);

    if((localRetVal == E_OK) && (personalizationStrLength > 0u)){
      retValCv = esl_seedCTRDRBG(wsDRBG
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) entropyPtr
   ,       (eslt_Length)entropyLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(nonceIndex)
   ,       (eslt_Length)nonceLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(personalizationStrIndex)
   ,       (eslt_Length)personalizationStrLength
   ,       NULL_PTR
   ,       0u);
    }
    else if((localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE) || (localRetVal == E_OK)){
      retValCv = esl_seedCTRDRBG(wsDRBG
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) entropyPtr
   ,       (eslt_Length) entropyLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(nonceIndex)
   ,       (eslt_Length) nonceLength
   ,       NULL_PTR
   ,       0u
   ,       NULL_PTR
   ,       0u);
    }
    else{
    }

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_AesCtrDrbgSeed_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType reseedCtElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  eslt_DRBGMode modeDRBG
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  retValCv = esl_initWorkSpaceHeader(&(wsDRBG->header), ESL_MAXSIZEOF_WS_CTRDRBG, MCALCRY_WATCHDOG_PTR);
  retValCv |= esl_initCTRDRBG(wsDRBG, modeDRBG);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK)){
      retVal = McalCry_AesCtrDrbgReseed(cryptoKeyId, wsDRBG, entropyPtr, entropyLength, modeDRBG);
    }

    else{
      retVal = McalCry_AesCtrDrbgSeedFirst(cryptoKeyId, wsDRBG, entropyPtr, entropyLength, modeDRBG);
    }

    if(retVal == E_OK){
      retVal = McalCry_Local_Get_And_Set_NistDrbgAesState(
        seedStateElementIndex
   ,       reseedCtElementIndex
   ,       wsDRBG);
    }
  }

  if((retValCv != E_OK) || (retVal != E_OK)){
    retVal = E_NOT_OK;
  }
  else{
    McalCry_ClearKeyElementStateByMask(reseedCtElementIndex, MCALCRY_KEYELEMENTSTATE_VALID_INV_MASK);

#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)
    McalCry_KeyValueChangedCallout(cryptoKeyId);
#endif
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgAesGeneratePrepare(
  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedStateElementIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedCounterElementIndexPtr
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist
   ,  uint32 seedLength
   ,  eslt_DRBGMode modeDRBG){
  Std_ReturnType retVal;

  McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_RANDOM_SEED_STATE, seedLength);
  McalCry_Local_ElementGetterSetIdAndLength(keyElements, 1u, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, MCALCRY_RANDOM_RESEED_COUNTER_LEN);
  retVal = McalCry_Local_GetElementsIndexJob(cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_EQUAL);

  if(retVal == E_OK){
    (void)McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, seedStateElementIndexPtr);
    (void)McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, seedCounterElementIndexPtr);

    if(esl_initWorkSpaceHeader(&(ws->header), ESL_MAXSIZEOF_WS_CTRDRBG, MCALCRY_WATCHDOG_PTR) != ESL_ERC_NO_ERROR){
      retVal = E_NOT_OK;
    }
    else{
      if(esl_initCTRDRBG(ws, modeDRBG) == ESL_ERC_NO_ERROR)
      {
        McalCry_Local_Check_Random_KeyElement_Persist(*seedStateElementIndexPtr, *seedCounterElementIndexPtr, persist);
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
  }
  else if(retVal == CRYPTO_E_KEY_NOT_VALID){
    retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
  }
  else{
  }

  return retVal;
}

#if(MCALCRY_RANDOM_SOURCE_DRBG_AES == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetRandomNistDrbgAes(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist){
  eslt_WorkSpaceCTRDRBG ws;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyElementsType seedStateElementIndex = 0u, seedCounterElementIndex = 0u;
  McalCry_DefaultRandomMaxRetriesOfGeneralType retry;
  uint16 localCount;
  McalCry_KeyElementGetType keyElements[2];
  uint32 reseedCntBuf;
  eslt_Byte seedStatus;
  eslt_DRBGMode modeDRBG = 0u;
  eslt_Length seedLength = 0u;

  if(McalCry_RandomNistDrbgAes_Set_Mode_And_SeedLength(cryptoKeyId, &modeDRBG, &seedLength) == E_OK){
    retVal = McalCry_DispatchRandomNistDrbgAesGeneratePrepare(&ws, cryptoKeyId, keyElements, &seedStateElementIndex, &seedCounterElementIndex, persist, (uint32)seedLength, modeDRBG);
  }

  if(retVal == E_OK){
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    for(retry = 0u; retry < MCALCRY_DEFAULT_RANDOM_MAX_RETRIES; retry++){
      localCount = McalCry_RandomSourceGenerateCount;
      McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCntBuf, McalCry_GetAddrKeyStorageOfKeyElements(seedCounterElementIndex));

      if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK))
      {
        seedStatus = ESL_DRBG_SEED_STATUS_SEEDED;
      }
      else
      {
        seedStatus = ESL_DRBG_SEED_STATUS_UNSEEDED;
      }

      retValCv = esl_restoreStateCTRDRBG(
        (P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &ws
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,       seedLength
   ,       reseedCntBuf
   ,       seedStatus
   ,       modeDRBG);
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retValCv = McalCry_Local_Generate_NistDrbgAes(
          cryptoKeyId
   ,         requestBuffer
   ,         requestLength
   ,         &ws);
      }

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if((McalCry_IsRngCalculationValid(localCount)) && (retValCv == ESL_ERC_NO_ERROR))
      {
        retVal = McalCry_Local_Get_And_Set_NistDrbgAesState(
          seedStateElementIndex
   ,         seedCounterElementIndex
   ,         &ws);

        break;
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(retVal != E_OK){
      McalCry_ClearData(requestBuffer, requestLength);
      *persist = FALSE;
    }
  }

  if((retValCv != ESL_ERC_NO_ERROR) || (retVal != E_OK)){
    if(retValCv == ESL_ERC_ENTROPY_EXHAUSTION){
      retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgAesFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK, localRetVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyElementsType seedStateElementIndex = 0u, seedCounterElementIndex = 0u;
  McalCry_KeyElementGetType keyElements[2];
  eslt_DRBGReseedCounterType reseedCntBuf;
  eslt_DRBGMode modeDRBG = 0u;
  eslt_Byte seedStatus;
  eslt_Length seedLength = 0u;
  boolean persist = FALSE;

  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfDRBGAES(McalCry_GetDRBGAESIdxOfObjectInfo(objectId));

  if(McalCry_RandomNistDrbgAes_Set_Mode_And_SeedLength(job->cryptoKeyId, &modeDRBG, &seedLength) == E_OK){
    localRetVal = McalCry_DispatchRandomNistDrbgAesGeneratePrepare(workspace, job->cryptoKeyId, keyElements, &seedStateElementIndex, &seedCounterElementIndex, &persist, (uint32)seedLength, modeDRBG);
  }

  if(localRetVal == E_OK){
    McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCntBuf, McalCry_GetAddrKeyStorageOfKeyElements(seedCounterElementIndex));

    if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK)){
      seedStatus = ESL_DRBG_SEED_STATUS_SEEDED;
    }
    else{
      seedStatus = ESL_DRBG_SEED_STATUS_UNSEEDED;
    }

    retValCv = esl_restoreStateCTRDRBG(
      workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,     seedLength
   ,     reseedCntBuf
   ,     seedStatus
   ,     modeDRBG);

    if(retValCv == ESL_ERC_NO_ERROR){
      retValCv = McalCry_Local_Generate_NistDrbgAes(
        job->cryptoKeyId
   ,       job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,       *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,       workspace);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_Get_And_Set_NistDrbgAesState(
          seedStateElementIndex
   ,         seedCounterElementIndex
   ,         workspace);
      }
    }
  }
  else{
    retVal = localRetVal;
  }

  if(retValCv == ESL_ERC_ENTROPY_EXHAUSTION){
    retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
  }

  if(retVal != E_OK){
    McalCry_ClearData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
  }
  else{
    McalCry_ProcessJob_Trigger_Write[objectId] = persist;
#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

    McalCry_KeyValueChangedCallout(job->cryptoKeyId);
#endif

#if(MCALCRY_KEYVALIDITYSETCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)
    McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(job->cryptoKeyId, TRUE);
#endif
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_Local_Generate_NistDrbgAes(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType additionalInputIndex;
  uint32 additionalInputLength = 0u;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT, &additionalInputIndex, &additionalInputLength, MCALCRY_LENGTH_CHECK_NONE);

  if((localRetVal == E_OK) && (additionalInputLength > 0u)){
    retValCv = esl_getBytesCTRDRBG(
      wsDRBG
   ,     (eslt_Length) requestLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) requestBuffer
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorage(additionalInputIndex)
   ,     (eslt_Length) additionalInputLength);
  }
  else if((localRetVal == E_OK) || (localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE)){
    retValCv = esl_getBytesCTRDRBG(
      wsDRBG
   ,     (eslt_Length) requestLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) requestBuffer
   ,     NULL_PTR
   ,     0u);
  }
  else{
    retValCv = ESL_ERC_ERROR;
  }

  return retValCv;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Get_And_Set_NistDrbgAesState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;
  eslt_DRBGReseedCounterType reseedCntBuf;
  eslt_DRBGSeedStatusType seedStatus;
  eslt_DRBGMode modeDRBG;
  eslt_Length seedLength = ESL_CTRDRBG_AES128_SEEDLEN;
  eslt_Length expectedSeedLength = ESL_CTRDRBG_AES128_SEEDLEN;

  if((wsDRBG->wsDRBG.mode == ESL_DRBGMODE_CTRDRBG_AES256_NODF) || (wsDRBG->wsDRBG.mode == ESL_DRBGMODE_CTRDRBG_AES256_DF)){
    seedLength = ESL_CTRDRBG_AES256_SEEDLEN;
    expectedSeedLength = ESL_CTRDRBG_AES256_SEEDLEN;
  }

  retValCv = esl_getStateCTRDRBG(
    wsDRBG
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &seedLength
   ,   (P2VAR(eslt_DRBGReseedCounterType, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &reseedCntBuf
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &seedStatus
   ,   (P2VAR(eslt_DRBGMode, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &modeDRBG);

  retVal = McalCry_Local_Set_NistDrbgState(
     seedStateElementIndex
   ,    seedCounterElementIndex
   ,    retValCv
   ,    seedLength
   ,    expectedSeedLength
   ,    reseedCntBuf
   ,    seedStatus);

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgAes(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  eslt_DRBGMode modeDRBG){
  eslt_WorkSpaceCTRDRBG wsDRBG;

  return McalCry_Local_RandomSeed_NistDrbgAes_With_Ws(
    cryptoKeyId
   ,   seedStateElementIndex
   ,   entropyPtr
   ,   entropyLength
   ,   writeBlock
   ,   modeDRBG
   ,   &wsDRBG);
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgAes_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  eslt_DRBGMode modeDRBG
   ,  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType reseedCtElementIndex;

  if(McalCry_Local_Random_Check_For_Write_Once(cryptoKeyId, seedStateElementIndex, &reseedCtElementIndex) != TRUE){
  }

  else if(McalCry_AesCtrDrbgSeed_With_Ws(cryptoKeyId, seedStateElementIndex, reseedCtElementIndex, entropyPtr, entropyLength, modeDRBG, wsDRBG) == E_OK){
    McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_VALUE_USED_INV_MASK);
    McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_VALID_INV_MASK);
    *writeBlock = McalCry_SetKeyState(cryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);

    retVal = E_OK;
  }
  else{
    *writeBlock = FALSE;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RandomNistDrbgAes_Set_Mode_And_SeedLength(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_DRBGMode, AUTOMATIC, MCALCRY_APPL_VAR) modeDRBG
   ,  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) seedLength){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType algorithmElementIndex = 0u;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_RANDOM_ALGORITHM, &algorithmElementIndex) == E_OK){
    if(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(algorithmElementIndex)) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128){
      *modeDRBG = ESL_DRBGMODE_CTRDRBG_AES128_NODF;
      *seedLength = ESL_CTRDRBG_AES128_SEEDLEN;
      retVal = E_OK;
    }
    else if(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(algorithmElementIndex)) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128_DF){
      *modeDRBG = ESL_DRBGMODE_CTRDRBG_AES128_DF;
      *seedLength = ESL_CTRDRBG_AES128_SEEDLEN;
      retVal = E_OK;
    }
    else if(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(algorithmElementIndex)) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256){
      *modeDRBG = ESL_DRBGMODE_CTRDRBG_AES256_NODF;
      *seedLength = ESL_CTRDRBG_AES256_SEEDLEN;
      retVal = E_OK;
    }
    else if(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(algorithmElementIndex)) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256_DF){
      *modeDRBG = ESL_DRBGMODE_CTRDRBG_AES256_DF;
      *seedLength = ESL_CTRDRBG_AES256_SEEDLEN;
      retVal = E_OK;
    }
    else{
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_DRBGHASHSHA512 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgHash(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock){
  eslt_WorkSpaceHASHDRBG wsDRBG;

  return McalCry_Local_RandomSeed_NistDrbgHash_With_Ws(
    cryptoKeyId
   ,   seedStateElementIndex
   ,   entropyPtr
   ,   entropyLength
   ,   writeBlock
   ,   &wsDRBG);
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed_NistDrbgHash_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType reseedCtElementIndex;

  if(McalCry_Local_Random_Check_For_Write_Once(cryptoKeyId, seedStateElementIndex, &reseedCtElementIndex) != TRUE){
  }

  else if(McalCry_HashDrbgSeed_With_Ws(cryptoKeyId, seedStateElementIndex, reseedCtElementIndex, entropyPtr, entropyLength, wsDRBG) == E_OK){
    McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_VALUE_USED_INV_MASK);
    McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_VALID_INV_MASK);
    *writeBlock = McalCry_SetKeyState(cryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);

    retVal = E_OK;
  }
  else{
    *writeBlock = FALSE;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgSeed_With_Ws(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType reseedCtElementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;

  retValCv = esl_initWorkSpaceHeader(&(wsDRBG->header), ESL_MAXSIZEOF_WS_HASHDRBG, MCALCRY_WATCHDOG_PTR);
  retValCv |= esl_initHASHDRBG(wsDRBG, ESL_DRBGMODE_HASHDRBG_SHA512);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK)){
      retVal = McalCry_HashDrbgReseed(cryptoKeyId, wsDRBG, entropyPtr, entropyLength);
    }

    else{
      retVal = McalCry_HashDrbgSeedFirst(cryptoKeyId, wsDRBG, entropyPtr, entropyLength);
    }

    if(retVal == E_OK){
      retVal = McalCry_Local_Get_And_Set_NistDrbgHashState(
        seedStateElementIndex
   ,       reseedCtElementIndex
   ,       wsDRBG);
    }
  }

  if((retValCv != E_OK) || (retVal != E_OK)){
    retVal = E_NOT_OK;
  }
  else{
    McalCry_ClearKeyElementStateByMask(reseedCtElementIndex, MCALCRY_KEYELEMENTSTATE_VALID_INV_MASK);
#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

      McalCry_KeyValueChangedCallout(cryptoKeyId);
#endif
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgSeedFirst(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType personalizationStrIndex, nonceIndex = 0u;
  uint32 personalizationStrLength, nonceLength = 0u;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_NONCE, &nonceIndex, &nonceLength, MCALCRY_LENGTH_CHECK_NONE);

  if(localRetVal == E_OK){
    localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_PERSONALIZATION_STRING, &personalizationStrIndex, &personalizationStrLength, MCALCRY_LENGTH_CHECK_NONE);

    if((localRetVal == E_OK) && (personalizationStrLength > 0u)){
      retValCv = esl_seedHASHDRBG(wsDRBG
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))entropyPtr
   ,       (eslt_Length)entropyLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(nonceIndex)
   ,       (eslt_Length)nonceLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(personalizationStrIndex)
   ,       (eslt_Length)personalizationStrLength
   ,       NULL_PTR
   ,       0u);
    }
    else if((localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE) || (localRetVal == E_OK)){
      retValCv = esl_seedHASHDRBG(wsDRBG
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))entropyPtr
   ,       (eslt_Length)entropyLength
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(nonceIndex)
   ,       (eslt_Length)nonceLength
   ,       NULL_PTR
   ,       0u
   ,       NULL_PTR
   ,       0u);
    }
    else{
    }

    if(retValCv == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_HashDrbgReseed(
  uint32 cryptoKeyId
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) wsDRBG
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength){
  Std_ReturnType retVal = E_NOT_OK, localRetVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType additionalInputIndex = 0u, seedIndex, reseedCounter;
  uint32 seedLength = MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN;
  uint32 reseedCntLength = MCALCRY_RANDOM_RESEED_COUNTER_LEN;
  uint32 reseedCnt, additionalInputLength = 0u;

  if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &seedIndex, &seedLength, MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
    if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, &reseedCounter, &reseedCntLength, MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
      McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCnt, McalCry_GetAddrKeyStorage(reseedCounter));

      retValCv = esl_restoreStateHASHDRBG(wsDRBG
   ,                                        (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(seedIndex)
   ,                                        (eslt_Length)seedLength
   ,                                        reseedCnt
   ,                                        (eslt_Byte)ESL_DRBG_SEED_STATUS_SEEDED
   ,                                        (eslt_DRBGMode)ESL_DRBGMODE_HASHDRBG_SHA512);
      if(retValCv == ESL_ERC_NO_ERROR)
      {
        localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT, &additionalInputIndex, &additionalInputLength, MCALCRY_LENGTH_CHECK_NONE);
      }
    }

    if((localRetVal == E_OK) && (additionalInputLength > 0u)){
      retValCv = esl_seedHASHDRBG(wsDRBG
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))entropyPtr
   ,                                (eslt_Length)entropyLength
   ,                                NULL_PTR
   ,                                0u
   ,                                NULL_PTR
   ,                                0u
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(additionalInputIndex)
   ,                                (eslt_Length)additionalInputLength);
    }
    else if((localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE) || (localRetVal == E_OK)){
      retValCv = esl_seedHASHDRBG(wsDRBG
   ,                                (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))entropyPtr
   ,                                (eslt_Length)entropyLength
   ,                                NULL_PTR
   ,                                0u
   ,                                NULL_PTR
   ,                                0u
   ,                                NULL_PTR
   ,                                0u);
    }
    else{
      retValCv = ESL_ERC_ERROR;
    }
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Get_And_Set_NistDrbgHashState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv;
  uint32 reseedCntBuf;
  eslt_Length seedLength = MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN;
  eslt_DRBGSeedStatusType seedStatus;
  eslt_DRBGMode modeDRBG;

  retValCv = esl_getStateHASHDRBG(wsDRBG
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,   &seedLength
   ,   &reseedCntBuf
   ,   &seedStatus
   ,   &modeDRBG);

  retVal = McalCry_Local_Set_NistDrbgState(
     seedStateElementIndex
   ,    seedCounterElementIndex
   ,    retValCv
   ,    seedLength
   ,    MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN
   ,    reseedCntBuf
   ,    seedStatus);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgHashFinish(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyElementsType seedStateElementIndex, seedCounterElementIndex;
  uint32 reseedCntBuf;
  McalCry_KeyElementGetType keyElements[2];
  boolean persist = FALSE;
  eslt_DRBGSeedStatusType seedStatus;

  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfDRBGHashSha512(McalCry_GetDRBGHashSha512IdxOfObjectInfo(objectId));

  localRetVal = McalCry_DispatchRandomNistDrbgHashGeneratePrepare(workspace, job->cryptoKeyId, keyElements, &seedStateElementIndex, &seedCounterElementIndex, &persist);

  if(localRetVal == E_OK){
    McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCntBuf, McalCry_GetAddrKeyStorageOfKeyElements(seedCounterElementIndex));

    if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK)){
      seedStatus = ESL_DRBG_SEED_STATUS_SEEDED;
    }
    else{
      seedStatus = ESL_DRBG_SEED_STATUS_UNSEEDED;
    }

    retValCv = esl_restoreStateHASHDRBG(workspace
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,     (eslt_Length)MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN
   ,     (eslt_DRBGReseedCounterType)reseedCntBuf
   ,     seedStatus
   ,     ESL_DRBGMODE_HASHDRBG_SHA512);

    if(retValCv == ESL_ERC_NO_ERROR){
      retValCv = McalCry_Local_Generate_NistDrbgHash(
        job->cryptoKeyId
   ,       job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,       *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,       workspace);

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retVal = McalCry_Local_Get_And_Set_NistDrbgHashState(
          seedStateElementIndex
   ,         seedCounterElementIndex
   ,         workspace);
      }
    }
  }
  else{
    retVal = localRetVal;
  }

  if(retValCv == ESL_ERC_ENTROPY_EXHAUSTION){
    retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
  }

  if(retVal != E_OK){
    McalCry_ClearData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
  }
  else{
    McalCry_ProcessJob_Trigger_Write[objectId] = persist;
#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

    McalCry_KeyValueChangedCallout(job->cryptoKeyId);
#endif

#if(MCALCRY_KEYVALIDITYSETCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)
    McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(job->cryptoKeyId, TRUE);
#endif
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRandomNistDrbgHashGeneratePrepare(
  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedStateElementIndexPtr
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) seedCounterElementIndexPtr
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist){
  Std_ReturnType retVal;

  McalCry_Local_ElementGetterSetIdAndLength(keyElements, 0u, CRYPTO_KE_RANDOM_SEED_STATE, MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN);
  McalCry_Local_ElementGetterSetIdAndLength(keyElements, 1u, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, MCALCRY_RANDOM_RESEED_COUNTER_LEN);
  retVal = McalCry_Local_GetElementsIndexJob(cryptoKeyId, keyElements, 2u, MCALCRY_LENGTH_CHECK_EQUAL);

  if(retVal == E_OK){
    (void)McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, seedStateElementIndexPtr);
    (void)McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, seedCounterElementIndexPtr);

    if(esl_initWorkSpaceHeader(&(ws->header), ESL_MAXSIZEOF_WS_HASHDRBG, MCALCRY_WATCHDOG_PTR) != ESL_ERC_NO_ERROR){
      retVal = E_NOT_OK;
    }
    else{
      if(esl_initHASHDRBG(ws, ESL_DRBGMODE_HASHDRBG_SHA512) == ESL_ERC_NO_ERROR)
      {
        McalCry_Local_Check_Random_KeyElement_Persist(*seedStateElementIndexPtr, *seedCounterElementIndexPtr, persist);
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
  }
  else if(retVal == CRYPTO_E_KEY_NOT_VALID){
    retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
  }
  else{
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(eslt_ErrorCode, MCALCRY_CODE) McalCry_Local_Generate_NistDrbgHash(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsDRBG){
  Std_ReturnType localRetVal;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyStorageType additionalInputIndex;
  uint32 additionalInputLength = 0u;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT, &additionalInputIndex, &additionalInputLength, MCALCRY_LENGTH_CHECK_NONE);

  if((localRetVal == E_OK) && (additionalInputLength > 0u)){
    retValCv = esl_getBytesHASHDRBG(wsDRBG
   ,     (eslt_Length)requestLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))requestBuffer
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(additionalInputIndex)
   ,     (eslt_Length)additionalInputLength);
  }
  else if((localRetVal == E_OK) || (localRetVal == CRYPTO_E_KEY_NOT_AVAILABLE)){
    retValCv = esl_getBytesHASHDRBG(wsDRBG
   ,     (eslt_Length)requestLength
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) requestBuffer
   ,     NULL_PTR
   ,     0u);
  }
  else{
    retValCv = ESL_ERC_ERROR;
  }

  return retValCv;
}

#if(MCALCRY_RANDOM_SOURCE_DRBG_HASH == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetRandomNistDrbgHash(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) requestBuffer
   ,  uint32 requestLength
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist){
  eslt_WorkSpaceHASHDRBG wsDRBG;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode retValCv = ESL_ERC_ERROR;
  McalCry_SizeOfKeyElementsType seedStateElementIndex = 0u, seedCounterElementIndex = 0u;
  McalCry_DefaultRandomMaxRetriesOfGeneralType retry;
  uint16 localCount;
  McalCry_KeyElementGetType keyElements[2];
  uint32 reseedCntBuf;
  eslt_DRBGSeedStatusType seedStatus;

  retVal = McalCry_DispatchRandomNistDrbgHashGeneratePrepare(&wsDRBG, cryptoKeyId, keyElements, &seedStateElementIndex, &seedCounterElementIndex, persist);

  if(retVal == E_OK){
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    for(retry = 0u; retry < MCALCRY_DEFAULT_RANDOM_MAX_RETRIES; retry++){
      localCount = McalCry_RandomSourceGenerateCount;
      McalCry_Local_Uint8ArrayToUint32BigEndian(&reseedCntBuf, McalCry_GetAddrKeyStorageOfKeyElements(seedCounterElementIndex));

      if(McalCry_IsKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK))
      {
        seedStatus = ESL_DRBG_SEED_STATUS_SEEDED;
      }
      else
      {
        seedStatus = ESL_DRBG_SEED_STATUS_UNSEEDED;
      }

      retValCv = esl_restoreStateHASHDRBG(
        (P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) &wsDRBG
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorageOfKeyElements(seedStateElementIndex)
   ,       (eslt_Length)MCALCRY_RANDOM_HASH_INTERNAL_STATE_BUFFER_LEN
   ,       reseedCntBuf
   ,       seedStatus
   ,       ESL_DRBGMODE_HASHDRBG_SHA512);
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(retValCv == ESL_ERC_NO_ERROR)
      {
        retValCv = McalCry_Local_Generate_NistDrbgHash(
          cryptoKeyId
   ,         requestBuffer
   ,         requestLength
   ,         &wsDRBG);
      }

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if((McalCry_IsRngCalculationValid(localCount)) && (retValCv == ESL_ERC_NO_ERROR))
      {
        retVal = McalCry_Local_Get_And_Set_NistDrbgHashState(
          seedStateElementIndex
   ,         seedCounterElementIndex
   ,         &wsDRBG);

        break;
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(retVal != E_OK){
      McalCry_ClearData(requestBuffer, requestLength);
      *persist = FALSE;
    }
  }

  if((retValCv != ESL_ERC_NO_ERROR) || (retVal != E_OK)){
    if(retValCv == ESL_ERC_ENTROPY_EXHAUSTION){
      retVal = CRYPTO_E_ENTROPY_EXHAUSTION;
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif
#endif

#if((MCALCRY_DRBGHASHSHA512 == STD_ON) || (MCALCRY_DRBGAES == STD_ON))

MCALCRY_LOCAL FUNC(boolean, MCALCRY_CODE) McalCry_Local_Random_Check_For_Write_Once(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, MCALCRY_APPL_VAR) reseedCtElementIndex){
  boolean retVal = FALSE;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER, reseedCtElementIndex) != E_OK){
  }

  else if(McalCry_IsKeyElementWriteOnce(*reseedCtElementIndex)){
    retVal = FALSE;
  }
  else if(McalCry_IsKeyElementWriteOnce(seedStateElementIndex)){
    retVal = FALSE;
  }
  else{
    retVal = TRUE;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Set_NistDrbgState(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  eslt_ErrorCode retValCv
   ,  eslt_Length seedLength
   ,  eslt_Length expectedSeedLength
   ,  uint32 reseedCntBuf
   ,  eslt_DRBGSeedStatusType seedStatus){
  Std_ReturnType retVal = E_NOT_OK;

  if((retValCv == ESL_ERC_NO_ERROR) && (seedLength == expectedSeedLength)){
    McalCry_SetKeyElementWrittenLength(seedStateElementIndex, seedLength);

    if(seedStatus == ESL_DRBG_SEED_STATUS_UNSEEDED){
      McalCry_ClearKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_INV_MASK);
    }
    else{
      McalCry_SetKeyElementStateByMask(seedStateElementIndex, MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK);
    }

    McalCry_Local_Uint32ToUint8ArrayBigEndian(McalCry_GetAddrKeyStorageOfKeyElements(seedCounterElementIndex), reseedCntBuf);
    McalCry_SetKeyElementWrittenLength(seedCounterElementIndex, MCALCRY_RANDOM_RESEED_COUNTER_LEN);
    retVal = E_OK;
  }
  else{
    retVal = E_NOT_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Check_Random_KeyElement_Persist(
  McalCry_SizeOfKeyElementsType seedStateElementIndex
   ,  McalCry_SizeOfKeyElementsType seedCounterElementIndex
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) persist){
#if(MCALCRY_NVBLOCK == STD_ON)
  if(McalCry_IsKeyElementPersist(seedStateElementIndex) || McalCry_IsKeyElementPersist(seedCounterElementIndex)){
    *persist = TRUE;
  }
  else
#else
  MCALCRY_DUMMY_STATEMENT(seedStateElementIndex);
  MCALCRY_DUMMY_STATEMENT(seedCounterElementIndex);
#endif
  {
    *persist = FALSE;
  }
}

#endif

#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_IsRngCalculationValid(uint16 localCount){
  boolean validCalculation;

  if(localCount == McalCry_RandomSourceGenerateCount){
    validCalculation = TRUE;
    McalCry_RandomSourceGenerateCount++;
  }
  else{
    validCalculation = FALSE;
  }

  return validCalculation;
}
#endif

#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_KeyValueChangedCallout(uint32 cryptoKeyId){
  McalCry_GetKeyValueChangedCalloutFctNameOfConfigurableCallouts()(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE);
  McalCry_GetKeyValueChangedCalloutFctNameOfConfigurableCallouts()(cryptoKeyId, CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER);
}
#endif

#if(MCALCRY_FIPS186 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Fips186(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = E_OK;
      break;
    }
    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = E_OK;
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchRandomFips186Finish(objectId, job);
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

#if(MCALCRY_KEYSEEDFIPS186 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedFips186(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  McalCry_SizeOfKeyElementsType elementIndex;
  boolean writeBlock = FALSE;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    if(McalCry_Local_KeyElementSearch(job->cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &elementIndex) == E_OK){
      retVal = McalCry_Local_RandomSeed_Fips(job->cryptoKeyId, elementIndex, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, &writeBlock);

      McalCry_ProcessJob_Trigger_Write[objectId] = writeBlock;
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_DRBGAES == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_DRBGAES(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = E_OK;
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = E_OK;
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchRandomNistDrbgAesFinish(objectId, job);
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

#if(MCALCRY_KEYSEEDDRBGAES == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedDRBGAES(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  McalCry_SizeOfKeyElementsType elementIndex;
  boolean writeBlock = FALSE;
  eslt_DRBGMode modeDRBG = 0u;
  eslt_Length seedLength = 0u;
  P2VAR(eslt_WorkSpaceCTRDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    workspace = McalCry_GetWorkspaceOfKeySeedDRBGAES(McalCry_GetKeySeedDRBGAESIdxOfObjectInfo(objectId));

    if(McalCry_Local_KeyElementSearch(job->cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &elementIndex) == E_OK){
      if(McalCry_RandomNistDrbgAes_Set_Mode_And_SeedLength(job->cryptoKeyId, &modeDRBG, &seedLength) == E_OK)
      {
        retVal = McalCry_Local_RandomSeed_NistDrbgAes_With_Ws(job->cryptoKeyId, elementIndex, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, &writeBlock, modeDRBG, workspace);

        McalCry_ProcessJob_Trigger_Write[objectId] = writeBlock;
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_DRBGHASHSHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_DRBGHashSha512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = E_OK;
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = E_OK;
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchRandomNistDrbgHashFinish(objectId, job);
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

#if(MCALCRY_KEYSEEDDRBGHASHSHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedDRBGHashSha512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceHASHDRBG, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeySeedDRBGHashSha512(McalCry_GetKeySeedDRBGHashSha512IdxOfObjectInfo(objectId));
  McalCry_SizeOfKeyElementsType elementIndex;
  boolean writeBlock = FALSE;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    if(McalCry_Local_KeyElementSearch(job->cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &elementIndex) == E_OK){
      retVal = McalCry_Local_RandomSeed_NistDrbgHash_With_Ws(job->cryptoKeyId, elementIndex, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, &writeBlock, workspace);

      McalCry_ProcessJob_Trigger_Write[objectId] = writeBlock;
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif

#if((MCALCRY_FIPS186 == STD_ON) || (MCALCRY_DRBGAES == STD_ON) || (MCALCRY_DRBGHASHSHA512 == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType elementIndex, algorithmElementIndex;
  uint32 seedAlgorithmLength = MCALCRY_RANDOM_SEED_SIZEOF_ALGORITHM;
  McalCry_SizeOfKeyStorageType seedAlgorithmStorageIndex;
  boolean writeBlock = FALSE;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_RANDOM_SEED_STATE, &elementIndex) == E_OK){
    if(McalCry_Local_KeyWriteLockGet(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      if(McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_RANDOM_ALGORITHM, &algorithmElementIndex) == E_OK)
      {
        if(McalCry_Local_KeyElementGetStorageIndexBasic(algorithmElementIndex, &seedAlgorithmStorageIndex, (P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR))&seedAlgorithmLength, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_OTHER) == E_OK)
        {
#if(MCALCRY_FIPS186 == STD_ON)

          if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_FIPS_186_2_SHA1)
          {
            retVal = McalCry_Local_RandomSeed_Fips(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock);
          }
          else
#endif
#if(MCALCRY_DRBGAES == STD_ON)

            if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128)
            {
              retVal = McalCry_Local_RandomSeed_NistDrbgAes(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock, ESL_DRBGMODE_CTRDRBG_AES128_NODF);
            }
            else if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128_DF)
            {
              retVal = McalCry_Local_RandomSeed_NistDrbgAes(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock, ESL_DRBGMODE_CTRDRBG_AES128_DF);
            }

            else if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256)
            {
              retVal = McalCry_Local_RandomSeed_NistDrbgAes(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock, ESL_DRBGMODE_CTRDRBG_AES256_NODF);
            }
            else if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256_DF)
            {
              retVal = McalCry_Local_RandomSeed_NistDrbgAes(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock, ESL_DRBGMODE_CTRDRBG_AES256_DF);
            }
            else
#endif
#if(MCALCRY_DRBGHASHSHA512 == STD_ON)

              if(McalCry_GetKeyStorage(seedAlgorithmStorageIndex) == MCALCRY_RNG_NIST_800_90A_HASH_DRBG_SHA_512)
              {
                retVal = McalCry_Local_RandomSeed_NistDrbgHash(cryptoKeyId, elementIndex, entropyPtr, entropyLength, &writeBlock);
              }
              else
#endif
              {
              }
        }
      }
      McalCry_Local_KeyWriteLockRelease(cryptoKeyId);
#if(MCALCRY_NVBLOCK == STD_ON)
      if(writeBlock)
      {
        McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(cryptoKeyId));
      }
#else
      MCALCRY_DUMMY_STATEMENT(writeBlock);
#endif

    }
  }
  return retVal;
}
#endif

FUNC(eslt_ErrorCode, MCALCRY_CODE) esl_getBytesRNG(
  const eslt_Length targetLength
   ,  P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR) target){
  eslt_ErrorCode retVal = ESL_ERC_ERROR;
  Std_ReturnType rngResult = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;
#if(MCALCRY_NVBLOCK == STD_ON)
  boolean triggerPersist = FALSE;
#endif

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  if(target != NULL_PTR)
#endif
  {
#if(MCALCRY_RANDOM_SOURCE_DRBG_AES == STD_ON)

    rngResult = McalCry_GetRandomNistDrbgAes(McalCry_GetDefaultRandomKey(), target, targetLength, &triggerPersist);
#endif
#if(MCALCRY_RANDOM_SOURCE_DRBG_HASH == STD_ON)

    rngResult = McalCry_GetRandomNistDrbgHash(McalCry_GetDefaultRandomKey(), target, targetLength, &triggerPersist);
#endif

#if(MCALCRY_NVBLOCK == STD_ON)
    if(triggerPersist){
      McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(McalCry_GetDefaultRandomKey()));
    }
#endif
  }

  if(rngResult == E_OK){
    retVal = ESL_ERC_NO_ERROR;
#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

      McalCry_KeyValueChangedCallout(McalCry_GetDefaultRandomKey());
#endif

#if(MCALCRY_KEYVALIDITYSETCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)
      McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(McalCry_GetDefaultRandomKey(), TRUE);
#endif
  }
  else if(rngResult == CRYPTO_E_ENTROPY_EXHAUSTION){
    errorId = CRYPTO_E_RE_ENTROPY_EXHAUSTED;
  }
  else{
    errorId = CRYPTO_E_RE_GET_BYTES_RNG_ERROR;
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportRuntimeError((uint16)MCALCRY_MODULE_ID
   ,     MCALCRY_INSTANCE_ID
   ,     MCALCRY_SID_ESL_GETBYTESRNG
   ,     errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

