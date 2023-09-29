#define MCALCRY_SOURCE
#ifdef __cplusplus
extern "C"
{
#endif

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "CryIf_Cbk.hpp"

#if((MCALCRY_MAJOR_VERSION != (11u)) \
    || (MCALCRY_MINOR_VERSION != (1u)) \
    || (MCALCRY_PATCH_VERSION != (0u)))
# error "Vendor specific version numbers of McalCry.c and McalCry.h are inconsistent"
#endif

#if(CRYPTO_HASH != 0u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_MACGENERATE != 1u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_MACVERIFY != 2u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_ENCRYPT != 3u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_DECRYPT != 4u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_AEADENCRYPT != 5u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_AEADDECRYPT != 6u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_SIGNATUREGENERATE != 7u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_SIGNATUREVERIFY != 8u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_RANDOMGENERATE != 11u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_RANDOMSEED != 12u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_KEYGENERATE != 13u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_KEYDERIVE != 14u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_KEYEXCHANGECALCPUBVAL != 15u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_KEYEXCHANGECALCSECRET != 16u)
# error "Define is not Autosar conform."
#endif
#if(CRYPTO_KEYSETVALID != 19u)
# error "Define is not Autosar conform."
#endif

#if !defined (MCALCRY_LOCAL)
#define MCALCRY_LOCAL                                        static
#endif

#if !defined (MCALCRY_LOCAL_INLINE)
#define MCALCRY_LOCAL_INLINE                                 LOCAL_INLINE
#endif

#define MCALCRY_DRIVEROBJECTSTATE_IDLE                        (0x00u)
#define MCALCRY_DRIVEROBJECTSTATE_PROCESSING                  (0x01u)

#define MCALCRY_REDIRECTION_MASK_NOT_USED                     (0x00u)
#define McalCry_IsRedirection(redir, mask)                    (((redir) & (mask)) == (mask))

#define McalCry_IsIOLengthInvalid(length)                     ((length) > MCALCRY_UINT16_MAX)
#define McalCry_IsIOMask(value, mask)                         (((value) & (mask)) == (mask))

#define MCALCRY_IOMASK_EMPTY                                  MCALCRY_REDIRECTION_MASK_NOT_USED

#ifdef CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT
#define MCALCRY_IOMASK_PRIMARY_INPUT                         CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT
#else
#define MCALCRY_IOMASK_PRIMARY_INPUT                         (0x01u)
#endif
#define MCALCRY_IOMASK_PRIMARY_INPUT_INV                      (0xFEu)

#ifdef CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT
#define MCALCRY_IOMASK_SECONDARY_INPUT                       CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT
#else
#define MCALCRY_IOMASK_SECONDARY_INPUT                       (0x02u)
#endif

#ifdef CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT
#define MCALCRY_IOMASK_TERTIARY_INPUT                        CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT
#else
#define MCALCRY_IOMASK_TERTIARY_INPUT                        (0x04u)
#endif

#ifdef CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT
#define MCALCRY_IOMASK_PRIMARY_OUTPUT                        CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT
#else
#define MCALCRY_IOMASK_PRIMARY_OUTPUT                        (0x10u)
#endif

#ifdef CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT
#define MCALCRY_IOMASK_SECONDARY_OUTPUT                      CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT
#else
#define MCALCRY_IOMASK_SECONDARY_OUTPUT                      (0x20u)
#endif

#define MCALCRY_IOMASK_VERIFY_OUTPUT                          (0x40u)

#define MCALCRY_OBJECTID_LENGTH                               (0x04u)
#define MCALCRY_ADDITIONAL_INFO_LENGTH                        (0x04u)
#define MCALCRY_WORKSPACE_SETTINGS_LENGTH                     (MCALCRY_OBJECTID_LENGTH + MCALCRY_ADDITIONAL_INFO_LENGTH)

#define MCALCRY_START_SEC_VAR_ZERO_INIT_8BIT
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

VAR(uint8, MCALCRY_VAR_ZERO_INIT) McalCry_ModuleInitialized = MCALCRY_UNINIT;
#endif

#define MCALCRY_STOP_SEC_VAR_ZERO_INIT_8BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_CONST_8BIT
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_REDIRECTION == STD_ON) || (MCALCRY_DEV_ERROR_DETECT == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_IOServiceMaskUpdate[CRYPTO_KEYSETVALID + 1u] = {
      MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_SECONDARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_SECONDARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
};
#endif

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_IOServiceMaskUpdateOptional[CRYPTO_KEYSETVALID + 1u] = {
      MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_SECONDARY_INPUT
   ,     MCALCRY_IOMASK_SECONDARY_INPUT
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
};
#endif

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_IOServiceMaskUpdateOptionalClear[CRYPTO_KEYSETVALID + 1u] = {
     MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_PRIMARY_INPUT_INV
   ,    MCALCRY_IOMASK_PRIMARY_INPUT_INV
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
};
#endif

#if(MCALCRY_REDIRECTION == STD_ON) || (MCALCRY_DEV_ERROR_DETECT == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_IOServiceMaskFinish[CRYPTO_KEYSETVALID + 1u] = {
      MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_SECONDARY_INPUT | MCALCRY_IOMASK_VERIFY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_OUTPUT | MCALCRY_IOMASK_SECONDARY_OUTPUT
   ,     MCALCRY_IOMASK_TERTIARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT | MCALCRY_IOMASK_VERIFY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT | MCALCRY_IOMASK_SECONDARY_INPUT | MCALCRY_IOMASK_VERIFY_OUTPUT
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,    MCALCRY_IOMASK_PRIMARY_INPUT
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_PRIMARY_OUTPUT
   ,    MCALCRY_IOMASK_PRIMARY_INPUT
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_TERTIARY_INPUT | MCALCRY_IOMASK_SECONDARY_OUTPUT
   ,    MCALCRY_IOMASK_EMPTY
};
#endif

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_IOServiceMaskFinishOptional[CRYPTO_KEYSETVALID + 1u] = {
      MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_PRIMARY_INPUT
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,     MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
   ,    MCALCRY_IOMASK_EMPTY
};
#endif

#if(MCALCRY_REDIRECTION == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_RedirectReadAccessRight[CRYPTO_KEYSETVALID + 1u] = {
      MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_ALLOWED
   ,     MCALCRY_RA_ALLOWED
   ,     MCALCRY_RA_ALLOWED
   ,     MCALCRY_RA_ALLOWED
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,     MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_INTERNAL_COPY
   ,    MCALCRY_RA_DENIED
};
#endif
#define MCALCRY_STOP_SEC_CONST_8BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_VAR_NOINIT_8BIT
#include "CompilerCfg_McalCry.hpp"

VAR(boolean, MCALCRY_VAR_NOINIT) McalCry_ProcessJob_Trigger_Write[McalCry_GetSizeOfDriverObjectState()];

#define MCALCRY_STOP_SEC_VAR_NOINIT_8BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_VAR_NOINIT_16BIT
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
VAR(uint16, MCALCRY_VAR_NOINIT) McalCry_RandomSourceGenerateCount;
#endif

#define MCALCRY_STOP_SEC_VAR_NOINIT_16BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_VAR_NOINIT_UNSPECIFIED
#include "CompilerCfg_McalCry.hpp"

MCALCRY_LOCAL VAR(McalCry_SizeOfPrimitiveInfoType, MCALCRY_VAR_NOINIT) McalCry_Dispatch_QueuePrimitiveInfoIdx[McalCry_GetSizeOfDriverObjectState()];

#if(MCALCRY_REDIRECTION == STD_ON)
MCALCRY_LOCAL VAR(McalCry_Redirect_Type, MCALCRY_VAR_NOINIT) McalCry_Redirect_Buffer[McalCry_GetSizeOfDriverObjectState()];
#endif

#define MCALCRY_STOP_SEC_VAR_NOINIT_UNSPECIFIED
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_LONGTERMWS == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsLockGetNotProtected(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsIsLockNotProtected(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_LongWsLockReleaseNotProtected(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfLongTermWsLockType longWsIdx);
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_TryObtainingLock(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_UpdateJobState(
  Std_ReturnType retVal
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SearchService(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_SizeOfPrimitiveInfoType, AUTOMATIC, AUTOMATIC)  primitiveInfoIdx);

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Verify(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2VAR(Crypto_VerifyResultType, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Input(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  uint32 dataLength);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_InputOptional(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  uint32 dataLength);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Output(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  P2CONST(uint32, AUTOMATIC, MCALCRY_APPL_VAR) dataLengthPtr);

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_OutputOptional(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  P2CONST(uint32, AUTOMATIC, MCALCRY_APPL_VAR) dataLengthPtr);
#endif

MCALCRY_LOCAL_INLINE FUNC(uint8, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_All(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  uint8 mask
   ,  uint8 optionalMask);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) errorId);
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Process(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx);

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_UpdateObjectWorkspace(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_ClearObjectWorkspace(
  uint32 objectId);
#endif

#if(MCALCRY_REDIRECTION == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_GetKeyListRedirection(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);

MCALCRY_LOCAL FUNC(boolean, MCALCRY_CODE) McalCry_Local_IsRedirectUsed(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RedirectPreSetBufferForKey(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) elementPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  uint8 readWrite
   ,  Crypto_ServiceInfoType cryptoService);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RedirectPreRedirKeys(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_RedirectPostSaveKeyResult(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 resultLength
   ,  uint32 writtenLength
   ,  Std_ReturnType result);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_RedirectPostRestoreBuffer(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Std_ReturnType result);
#endif

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SaveContextJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RestoreContextJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx);
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchJob(
  uint32 objectId
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) unlockingNecessary
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) contextMode
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx);

#if(MCALCRY_LONGTERMWS == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsLockGetNotProtected(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr){
  Std_ReturnType retVal;
  McalCry_LongTermWsLockIterType id;

  retVal = McalCry_Local_LongWsIsLockNotProtected(cryptoKeyId, longWsIdxPtr);

  if(retVal != E_OK){
    for(id = 0u; id < McalCry_GetSizeOfLongTermWsLock(); id++){
      if(McalCry_GetLongTermWsLock(id) == MCALCRY_LONG_TERM_WS_LOCK_FREE)
      {
        McalCry_SetLongTermWsLock(id, cryptoKeyId);
        *longWsIdxPtr = (McalCry_SizeOfLongTermWsLockType)id;
        retVal = E_OK;
        break;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsIsLockNotProtected(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_LongTermWsLockIterType id;

  for(id = 0u; id < McalCry_GetSizeOfLongTermWsLock(); id++){
    if(McalCry_IsLongTermWsLock(id, cryptoKeyId)){
      *longWsIdxPtr = (McalCry_SizeOfLongTermWsLockType)id;
      retVal = E_OK;
      break;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_LongWsLockReleaseNotProtected(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfLongTermWsLockType longWsIdx){
  if(McalCry_IsLongTermWsLock(longWsIdx, cryptoKeyId)){
    McalCry_SetLongTermWsLock(longWsIdx, MCALCRY_LONG_TERM_WS_LOCK_FREE);
  }

}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsLockGet(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr){
  Std_ReturnType retVal;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  retVal = McalCry_Local_LongWsLockGetNotProtected(cryptoKeyId, longWsIdxPtr);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsIsLock(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr){
  Std_ReturnType retVal;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  retVal = McalCry_Local_LongWsIsLockNotProtected(cryptoKeyId, longWsIdxPtr);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_LongWsLockRelease(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfLongTermWsLockType longWsIdx){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  McalCry_Local_LongWsLockReleaseNotProtected(cryptoKeyId, longWsIdx);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

}
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_TryObtainingLock(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  Std_ReturnType retVal, localRetVal;

  if(McalCry_IsLockOccupiedByJob(objectId, job->jobInfo->jobId)){
    retVal = E_OK;
  }
#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
  else if((McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_START)) || (McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT)))
#else
  else if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_START))
#endif
  {
    retVal = CRYPTO_E_BUSY;
    if(McalCry_IsLockFree(objectId)){
      localRetVal = McalCry_Local_KeyListPreLockKeys(keyList);

      if(localRetVal == E_OK)
      {
        McalCry_SetLock(objectId, job->jobInfo->jobId);
        retVal = E_OK;
      }
    }
  }
  else{
    retVal = E_NOT_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_UpdateJobState(
  Std_ReturnType retVal
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  if(retVal == E_OK){
    job->MCALCRY_JOB_STATE_MEMBER = CRYPTO_JOBSTATE_ACTIVE;
  }
  else{
    job->MCALCRY_JOB_STATE_MEMBER = CRYPTO_JOBSTATE_IDLE;
  }
}

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_IsObjectWorkspaceUnchanged(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  if(job->cryptoKeyId == McalCry_GetKeyIdOfLastJob(objectId)){
    if((job->jobPrimitiveInfo->primitiveInfo->algorithm.family == McalCry_GetFamilyOfLastJob(objectId))&&
        (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == McalCry_GetModeOfLastJob(objectId))){
      retVal = E_OK;
    }
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_ClearObjectWorkspaceForChangedKey(
  uint32 cryptoKeyId){
  uint32 objectId;
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  for(objectId = 0; objectId < McalCry_GetSizeOfObjectInfo(); objectId++){
    if(McalCry_GetKeyIdOfLastJob(objectId) == cryptoKeyId){
      McalCry_SetKeyIdOfLastJob(objectId, MCALCRY_UINT32_MAX);
      McalCry_SetFamilyOfLastJob(objectId, CRYPTO_ALGOFAM_NOT_SET);
      McalCry_SetModeOfLastJob(objectId, CRYPTO_ALGOMODE_NOT_SET);
    }
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_UpdateObjectWorkspace(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  McalCry_SetKeyIdOfLastJob(objectId, job->cryptoKeyId);
  McalCry_SetFamilyOfLastJob(objectId, job->jobPrimitiveInfo->primitiveInfo->algorithm.family);
  McalCry_SetModeOfLastJob(objectId, job->jobPrimitiveInfo->primitiveInfo->algorithm.mode);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_ClearObjectWorkspace(
  uint32 objectId){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  McalCry_SetKeyIdOfLastJob(objectId, MCALCRY_UINT32_MAX);
  McalCry_SetFamilyOfLastJob(objectId, CRYPTO_ALGOFAM_NOT_SET);
  McalCry_SetModeOfLastJob(objectId, CRYPTO_ALGOMODE_NOT_SET);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}
#endif

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Verify(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2VAR(Crypto_VerifyResultType, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr){
  if(dataPtr == NULL_PTR){
    *errorId = CRYPTO_E_PARAM_POINTER;
  }
  else{
    *dataPtr = CRYPTO_E_VER_NOT_OK;
  }

}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Input(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  uint32 dataLength){
  if(dataPtr == NULL_PTR){
    *errorId = CRYPTO_E_PARAM_POINTER;
  }

#if(MCALCRY_VSEC_PRIM_ESLT_LENGTH_32 == STD_ON)
  else if(dataLength == 0u)
#else
  else if((dataLength == 0u) ||
           McalCry_IsIOLengthInvalid(dataLength))
#endif
  {
    *errorId = CRYPTO_E_PARAM_VALUE;
  }
  else{
  }

}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_InputOptional(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  uint32 dataLength){
  if((dataPtr == NULL_PTR) &&
      (dataLength != 0u)){
    *errorId = CRYPTO_E_PARAM_POINTER;
  }
#if(MCALCRY_VSEC_PRIM_ESLT_LENGTH_32 == STD_OFF)

  else if(McalCry_IsIOLengthInvalid(dataLength)){
    *errorId = CRYPTO_E_PARAM_VALUE;
  }
#endif
  else{
  }
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_Output(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  P2CONST(uint32, AUTOMATIC, MCALCRY_APPL_VAR) dataLengthPtr){
  if((dataPtr == NULL_PTR) ||
      (dataLengthPtr == NULL_PTR)){
    *errorId = CRYPTO_E_PARAM_POINTER;
  }

#if(MCALCRY_VSEC_PRIM_ESLT_LENGTH_32 == STD_ON)
  else if(*dataLengthPtr == 0u)
#else
  else if((*dataLengthPtr == 0u) ||
           McalCry_IsIOLengthInvalid(*dataLengthPtr))
#endif
  {
    *errorId = CRYPTO_E_PARAM_VALUE;
  }
  else{
  }

}

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_OutputOptional(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) errorId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  P2CONST(uint32, AUTOMATIC, MCALCRY_APPL_VAR) dataLengthPtr){
  if((dataPtr == NULL_PTR) || (dataLengthPtr == NULL_PTR)){
    *errorId = CRYPTO_E_PARAM_POINTER;
  }
#if(MCALCRY_VSEC_PRIM_ESLT_LENGTH_32 == STD_OFF)

  else if(McalCry_IsIOLengthInvalid(*dataLengthPtr)){
    *errorId = CRYPTO_E_PARAM_VALUE;
  }
#endif
  else{
  }
}
#endif

MCALCRY_LOCAL_INLINE FUNC(uint8, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues_All(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  uint8 mask
   ,  uint8 optionalMask
  ){
  uint8 errorId = CRYPTO_E_NO_ERROR;

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_PRIMARY_INPUT)){
    if(McalCry_IsIOMask(optionalMask, MCALCRY_IOMASK_PRIMARY_INPUT)){
      McalCry_Local_DetChecksServiceValues_InputOptional(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
    }
    else{
      McalCry_Local_DetChecksServiceValues_Input(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
    }
  }

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_SECONDARY_INPUT)){
    if(McalCry_IsIOMask(optionalMask, MCALCRY_IOMASK_SECONDARY_INPUT)){
      McalCry_Local_DetChecksServiceValues_InputOptional(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
    else{
      McalCry_Local_DetChecksServiceValues_Input(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryInputLength);
    }
  }

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_TERTIARY_INPUT)){
    McalCry_Local_DetChecksServiceValues_Input(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.tertiaryInputLength);
  }

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_PRIMARY_OUTPUT)){
#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
    if(McalCry_IsIOMask(optionalMask, MCALCRY_IOMASK_PRIMARY_OUTPUT)){
      McalCry_Local_DetChecksServiceValues_OutputOptional(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
    }
    else
#endif
    {
      McalCry_Local_DetChecksServiceValues_Output(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
    }
  }

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_SECONDARY_OUTPUT)){
    McalCry_Local_DetChecksServiceValues_Output(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.secondaryOutputLengthPtr);
  }

  if(McalCry_IsIOMask(mask, MCALCRY_IOMASK_VERIFY_OUTPUT)){
    McalCry_Local_DetChecksServiceValues_Verify(&errorId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.verifyPtr);
  }

  return errorId;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_DetChecksServiceValues(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) errorId){
  Std_ReturnType retVal = E_OK;
  Crypto_ServiceInfoType cryptoService = job->jobPrimitiveInfo->primitiveInfo->service;
  uint8 mask = MCALCRY_IOMASK_EMPTY;
  uint8 optional = MCALCRY_IOMASK_EMPTY;

  if(job->jobPrimitiveInfo->primitiveInfo->service > CRYPTO_KEYSETVALID){
    *errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else{
    if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_FINISH)){
      mask = McalCry_IOServiceMaskFinish[cryptoService];
      optional = McalCry_IOServiceMaskFinishOptional[cryptoService];
    }

    if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_UPDATE)){
      mask |= McalCry_IOServiceMaskUpdate[cryptoService];
      optional &= McalCry_IOServiceMaskUpdateOptionalClear[cryptoService];
      optional |= McalCry_IOServiceMaskUpdateOptional[cryptoService];
    }

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
    if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_SAVE_CONTEXT)){
      mask |= MCALCRY_IOMASK_PRIMARY_OUTPUT;
      optional |= MCALCRY_IOMASK_PRIMARY_OUTPUT;
    }

    if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT)){
      mask |= MCALCRY_IOMASK_PRIMARY_INPUT;
    }
#endif
#if(MCALCRY_REDIRECTION == STD_ON)

    if(job->jobRedirectionInfoRef != NULL_PTR){
      mask &= (uint8)~(job->jobRedirectionInfoRef->redirectionConfig);
      optional &= (uint8)~(job->jobRedirectionInfoRef->redirectionConfig);
    }
#endif

    if(mask != MCALCRY_IOMASK_EMPTY){
      *errorId = McalCry_Local_DetChecksServiceValues_All(job, mask, optional);
    }
  }

  if((*errorId == CRYPTO_E_PARAM_POINTER) ||
      (*errorId == CRYPTO_E_PARAM_VALUE) || (*errorId == CRYPTO_E_PARAM_HANDLE)){
    retVal = E_NOT_OK;
  }

  return retVal;
}
#endif

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyListAddKey(
  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList
   ,  uint32 cryptoKeyId
   ,  uint8 keyAccess){
  boolean found = FALSE;
  uint8 i;

  for(i = 0; i < keyList->numKeys; i++){
    if(keyList->keyLockList[i].keyId == cryptoKeyId){
      found = TRUE;

      keyList->keyLockList[i].keyAccess = (uint8)(keyList->keyLockList[i].keyAccess + keyAccess);
      break;
    }
  }

  if(found == FALSE){
    keyList->keyLockList[keyList->numKeys].keyId = cryptoKeyId;
    keyList->keyLockList[keyList->numKeys].keyAccess = keyAccess;
    keyList->numKeys++;
  }
}

#if(MCALCRY_REDIRECTION == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_GetKeyListRedirection(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  if(McalCry_Local_IsRedirectUsed(job) == TRUE){
    P2CONST(Crypto_JobRedirectionInfoType, AUTOMATIC, MCALCRY_APPL_VAR) redirInfoRef = job->jobRedirectionInfoRef;
    Crypto_InputOutputRedirectionConfigType redirConfig = redirInfoRef->redirectionConfig;

    if(McalCry_IsRedirection(redirConfig, CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT)){
      McalCry_Local_KeyListAddKey(keyList, redirInfoRef->inputKeyId, MCALCRY_KEY_ACCESS_READ);
    }

    if(McalCry_IsRedirection(redirConfig, CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT)){
      McalCry_Local_KeyListAddKey(keyList, redirInfoRef->secondaryInputKeyId, MCALCRY_KEY_ACCESS_READ);
    }

    if(McalCry_IsRedirection(redirConfig, CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT)){
      McalCry_Local_KeyListAddKey(keyList, redirInfoRef->tertiaryInputKeyId, MCALCRY_KEY_ACCESS_READ);
    }

    if(McalCry_IsRedirection(redirConfig, CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT)){
      McalCry_Local_KeyListAddKey(keyList, redirInfoRef->outputKeyId, MCALCRY_KEY_ACCESS_WRITE);
    }

    if(McalCry_IsRedirection(redirConfig, CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT)){
      McalCry_Local_KeyListAddKey(keyList, redirInfoRef->secondaryOutputKeyId, MCALCRY_KEY_ACCESS_WRITE);
    }
  }
}
#endif

FUNC(void, MCALCRY_CODE) McalCry_Local_GetKeyList(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  keyList->numKeys = 0u;

#if(MCALCRY_REDIRECTION == STD_ON)
  McalCry_Local_GetKeyListRedirection(job, keyList);
#endif

  switch(job->jobPrimitiveInfo->primitiveInfo->service){
#if(MCALCRY_SERVICE_RANDOM == STD_ON)
  case CRYPTO_RANDOMGENERATE:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_KEY_SET_VALID == STD_ON)
  case CRYPTO_KEYSETVALID:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_RANDOM_SEED == STD_ON)
  case CRYPTO_RANDOMSEED:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_KEY_DERIVE == STD_ON)
  case CRYPTO_KEYDERIVE:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_READ);
    McalCry_Local_KeyListAddKey(keyList, job->targetCryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_KEY_EXCHANGE_CALC_PUBVAL == STD_ON)
  case CRYPTO_KEYEXCHANGECALCPUBVAL:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_KEY_EXCHANGE_CALC_SECRET == STD_ON)
  case CRYPTO_KEYEXCHANGECALCSECRET:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
#if(MCALCRY_SERVICE_KEY_GENERATE == STD_ON)
  case CRYPTO_KEYGENERATE:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_WRITE);
    break;
#endif
  default:
    McalCry_Local_KeyListAddKey(keyList, job->cryptoKeyId, MCALCRY_KEY_ACCESS_READ);
    break;
  }
}

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_GetKeyListAndDet(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  Std_ReturnType retVal = E_OK;
  uint8 i;

  McalCry_Local_GetKeyList(job, keyList);

  for(i = 0; i < keyList->numKeys; i++){
    if(keyList->keyLockList[i].keyId >= McalCry_GetSizeOfKey()){
      retVal = E_NOT_OK;
      break;
    }
  }
  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyListPreLockKeys(
  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  Std_ReturnType retVal = E_OK;
  uint8_least i;
  uint8_least j;

  for(i = 0; i < keyList->numKeys; i++){
    if(keyList->keyLockList[i].keyAccess == MCALCRY_KEY_ACCESS_READ){
      retVal = McalCry_Local_KeyReadLockGetNotProtected(keyList->keyLockList[i].keyId);
    }
    else{
      retVal = McalCry_Local_KeyWriteLockGetNotProtected(keyList->keyLockList[i].keyId);
    }

    if(retVal != E_OK){
      break;
    }
  }

  if(retVal != E_OK){
    for(j = 0; j < i; j++){
      if(keyList->keyLockList[j].keyAccess == MCALCRY_KEY_ACCESS_READ)
      {
        McalCry_Local_KeyReadLockReleaseNotProtected(keyList->keyLockList[j].keyId);
      }
      else
      {
        McalCry_Local_KeyWriteLockReleaseNotProtected(keyList->keyLockList[j].keyId);
      }
    }
  }
  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyListPostFreeKeys(
  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList){
  uint8 i;

  for(i = 0; i < keyList->numKeys; i++){
    if(keyList->keyLockList[i].keyAccess == MCALCRY_KEY_ACCESS_READ){
      McalCry_Local_KeyReadLockReleaseNotProtected(keyList->keyLockList[i].keyId);
    }
    else{
      McalCry_Local_KeyWriteLockReleaseNotProtected(keyList->keyLockList[i].keyId);
    }
  }
}

#if(MCALCRY_REDIRECTION == STD_ON)

MCALCRY_LOCAL FUNC(boolean, MCALCRY_CODE) McalCry_Local_IsRedirectUsed(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  boolean retVal = FALSE;

  if(job->jobRedirectionInfoRef != NULL_PTR){
    retVal = TRUE;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RedirectPreSetBufferForKey(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) elementPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  uint8 readWrite
   ,  Crypto_ServiceInfoType cryptoService){
  Std_ReturnType retVal = E_OK;
  McalCry_SizeOfKeyElementsType elementIndex;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex) != E_OK){
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }
  else{
    if(readWrite == MCALCRY_KEY_ACCESS_READ){
      if(McalCry_RedirectReadAccessRight[cryptoService] < (McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))))
      {
        retVal = CRYPTO_E_KEY_READ_FAIL;
      }
      else if(!McalCry_IsKeyElementValid(elementIndex))
      {
        retVal = CRYPTO_E_KEY_NOT_VALID;
      }
      else
      {
      }
    }
    else{
      if((MCALCRY_WA_DENIED == (McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))))||
          (!McalCry_IsKeyElementPartial(elementIndex)) || McalCry_IsKeyElementWriteOnce(elementIndex))
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }
    }

    if(retVal == E_OK){
      retVal = McalCry_Local_KeyElementGetStorageIndexBasic( elementIndex, elementPtr, resultLengthPtr, MCALCRY_LENGTH_CHECK_NONE, MCALCRY_SHE_SERVICE_OTHER);

      if(readWrite == MCALCRY_KEY_ACCESS_WRITE)
      {
        *resultLengthPtr = McalCry_GetKeyElementLength(elementIndex);
      }
      else
      {
        if(*resultLengthPtr == 0u)
        {
          retVal = CRYPTO_E_KEY_EMPTY;
        }
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RedirectPreRedirKeys(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_OK;
  uint32 redirKeyLength = 0u;
  McalCry_SizeOfKeyStorageType elementStorageIndex = 0u;
  P2CONST(Crypto_JobRedirectionInfoType, AUTOMATIC, MCALCRY_APPL_VAR) redirInfoRef = job->jobRedirectionInfoRef;
  P2VAR(Crypto_JobPrimitiveInputOutputType, AUTOMATIC, MCALCRY_APPL_VAR) inOutRef = &job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER;
  Crypto_ServiceInfoType cryptoService = job->jobPrimitiveInfo->primitiveInfo->service;
  Crypto_InputOutputRedirectionConfigType redir;

  if(McalCry_Local_IsRedirectUsed(job) == TRUE){
    redir = job->jobRedirectionInfoRef->redirectionConfig;
    redir &= (McalCry_IOServiceMaskUpdate[cryptoService] | McalCry_IOServiceMaskFinish[cryptoService]);

    if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_START)){
      McalCry_Redirect_Buffer[objectId].firstOutputLengthWritten = 0u;
      McalCry_Redirect_Buffer[objectId].secondaryOutputLengthWritten = 0u;

    }
    McalCry_Redirect_Buffer[objectId].jobPrimitiveInputOutput_Restore = job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER;

    if(McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT)){
      retVal = McalCry_Local_RedirectPreSetBufferForKey(redirInfoRef->inputKeyId, redirInfoRef->inputKeyElementId, &elementStorageIndex, &redirKeyLength, MCALCRY_KEY_ACCESS_READ, cryptoService);
      inOutRef->inputPtr = McalCry_GetAddrKeyStorage(elementStorageIndex);
      inOutRef->inputLength = redirKeyLength;
    }

    if((retVal == E_OK) &&
        (McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT))){
      retVal = McalCry_Local_RedirectPreSetBufferForKey(redirInfoRef->secondaryInputKeyId, redirInfoRef->secondaryInputKeyElementId, &elementStorageIndex, &redirKeyLength, MCALCRY_KEY_ACCESS_READ, cryptoService);
      inOutRef->secondaryInputPtr = McalCry_GetAddrKeyStorage(elementStorageIndex);
      inOutRef->secondaryInputLength = redirKeyLength;
    }

    if((retVal == E_OK) &&
        (McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT))){
      retVal = McalCry_Local_RedirectPreSetBufferForKey(redirInfoRef->tertiaryInputKeyId, redirInfoRef->tertiaryInputKeyElementId, &elementStorageIndex, &redirKeyLength, MCALCRY_KEY_ACCESS_READ, cryptoService);
      inOutRef->tertiaryInputPtr = McalCry_GetAddrKeyStorage(elementStorageIndex);
      inOutRef->tertiaryInputLength = redirKeyLength;
    }

    if((retVal == E_OK) &&
        (McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT))){
      retVal = McalCry_Local_RedirectPreSetBufferForKey(redirInfoRef->outputKeyId, redirInfoRef->outputKeyElementId, &elementStorageIndex, &redirKeyLength, MCALCRY_KEY_ACCESS_WRITE, cryptoService);
      inOutRef->outputPtr = McalCry_GetAddrKeyStorage(elementStorageIndex);
      McalCry_Redirect_Buffer[objectId].firstOutputLength = redirKeyLength - McalCry_Redirect_Buffer[objectId].firstOutputLengthWritten;
      inOutRef->outputLengthPtr = &McalCry_Redirect_Buffer[objectId].firstOutputLength;
    }

    if((retVal == E_OK) &&
        (McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT))){
      retVal = McalCry_Local_RedirectPreSetBufferForKey(redirInfoRef->secondaryOutputKeyId, redirInfoRef->secondaryOutputKeyElementId, &elementStorageIndex, &redirKeyLength, MCALCRY_KEY_ACCESS_WRITE, cryptoService);
      inOutRef->secondaryOutputPtr = McalCry_GetAddrKeyStorage(elementStorageIndex);
      McalCry_Redirect_Buffer[objectId].secondaryOutputLength = redirKeyLength - McalCry_Redirect_Buffer[objectId].secondaryOutputLengthWritten;
      inOutRef->secondaryOutputLengthPtr = &McalCry_Redirect_Buffer[objectId].secondaryOutputLength;
    }

    if(retVal != E_OK){
      job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER = McalCry_Redirect_Buffer[objectId].jobPrimitiveInputOutput_Restore;
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_RedirectPostSaveKeyResult(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 resultLength
   ,  uint32 writtenLength
   ,  Std_ReturnType result){
  McalCry_SizeOfKeyElementsType elementIndex;

  (void)McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex);
  McalCry_ClearKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_NORMAL_MASK);

  if(result == E_OK){
    McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, elementIndex, resultLength + writtenLength);
  }
  else{
    McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, elementIndex, writtenLength);
  }
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_RedirectPostRestoreBuffer(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Std_ReturnType result){
  Crypto_InputOutputRedirectionConfigType redir;
  P2CONST(Crypto_JobRedirectionInfoType, AUTOMATIC, MCALCRY_APPL_VAR) redirInfoRef = job->jobRedirectionInfoRef;

  if(McalCry_Local_IsRedirectUsed(job) == TRUE){
    redir = job->jobRedirectionInfoRef->redirectionConfig;
    redir &= (McalCry_IOServiceMaskUpdate[job->jobPrimitiveInfo->primitiveInfo->service] | McalCry_IOServiceMaskFinish[job->jobPrimitiveInfo->primitiveInfo->service]);

    if(McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT)){
      McalCry_Local_RedirectPostSaveKeyResult(redirInfoRef->outputKeyId, redirInfoRef->outputKeyElementId, McalCry_Redirect_Buffer[objectId].firstOutputLength, McalCry_Redirect_Buffer[objectId].firstOutputLengthWritten, result);
    }

    if(McalCry_IsIOMask(redir, CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT)){
      McalCry_Local_RedirectPostSaveKeyResult(redirInfoRef->secondaryOutputKeyId, redirInfoRef->secondaryOutputKeyElementId, McalCry_Redirect_Buffer[objectId].secondaryOutputLength, McalCry_Redirect_Buffer[objectId].secondaryOutputLengthWritten, result);
    }

    job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER = McalCry_Redirect_Buffer[objectId].jobPrimitiveInputOutput_Restore;
  }
}
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Process(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx){
  Std_ReturnType retVal;
  boolean unlockingNecessary = FALSE;
  boolean contextMode = FALSE;
  McalCry_ProcessJob_Trigger_Write[objectId] = FALSE;

#if(MCALCRY_REDIRECTION == STD_ON)
  retVal = McalCry_Local_RedirectPreRedirKeys(objectId, job);
  if(retVal == E_OK)
#endif
  {
    retVal = McalCry_DispatchJob(objectId, &unlockingNecessary, &contextMode, job, primitiveInfoIdx);

#if(MCALCRY_REDIRECTION == STD_ON)
    McalCry_Local_RedirectPostRestoreBuffer(objectId, job, retVal);
#endif
  }

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
  if(((retVal != E_OK) && (contextMode == FALSE)) || (unlockingNecessary == TRUE))
#else
  if((retVal != E_OK) || (unlockingNecessary == TRUE))
#endif
  {
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    McalCry_FreeLock(objectId);
    McalCry_Local_KeyListPostFreeKeys(keyList);
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
#if(MCALCRY_NVBLOCK == STD_ON)
    if(McalCry_ProcessJob_Trigger_Write[objectId]){
      McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(job->cryptoKeyId));
    }
#endif
  }

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
  if(retVal == E_OK){
    McalCry_UpdateObjectWorkspace(objectId, job);
  }
#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
  else if(contextMode == TRUE){
  }
#endif
  else{
    McalCry_ClearObjectWorkspace(objectId);
  }
#endif

  McalCry_SetDriverObjectState(objectId, MCALCRY_DRIVEROBJECTSTATE_IDLE);

  if(job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_ASYNC){
    McalCry_SetQueue(McalCry_GetQueueIdxOfObjectInfo(objectId), (McalCry_JobPtrType)NULL_PTR);

    CryIf_CallbackNotification(job, retVal);
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SearchService(
  uint32 objectId
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  P2VAR(McalCry_SizeOfPrimitiveInfoType, AUTOMATIC, AUTOMATIC)  primitiveInfoIdx){
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_PrimitiveInfoIterType primitiveInfoStartIdx, primitiveInfoEndIdx, primitiveInfoIteratorIdx;

  McalCry_ObjectInfoIndIterType objectInfoIndStartIdx, objectInfoIndEndIdx, objectInfoIndIdx;

  McalCry_PrimitiveFctIterType functionIdx;

  P2CONST(Crypto_PrimitiveInfoType, AUTOMATIC, MCALCRY_APPL_VAR) primitive = job->jobPrimitiveInfo->primitiveInfo;
  P2CONST(Crypto_AlgorithmInfoType, AUTOMATIC, MCALCRY_APPL_VAR) algo = &primitive->algorithm;

  uint32 combi;

  if(McalCry_IsPrimitiveInfoUsedOfPrimitiveServiceInfo(primitive->service) == TRUE){
    primitiveInfoStartIdx = McalCry_GetPrimitiveInfoStartIdxOfPrimitiveServiceInfo(primitive->service);
    primitiveInfoEndIdx = McalCry_GetPrimitiveInfoEndIdxOfPrimitiveServiceInfo(primitive->service);

    combi = (((uint32)primitive->service << 24) | ((uint32)algo->family << 16) | ((uint32)algo->mode << 8) | ((uint32)algo->secondaryFamily));

    for(primitiveInfoIteratorIdx = primitiveInfoStartIdx; primitiveInfoIteratorIdx < primitiveInfoEndIdx; primitiveInfoIteratorIdx++){
      if(McalCry_GetCombinedOfPrimitiveInfo(primitiveInfoIteratorIdx) == combi)
      {
        functionIdx = McalCry_GetPrimitiveFctIdxOfPrimitiveInfo(primitiveInfoIteratorIdx);

        objectInfoIndStartIdx = McalCry_GetObjectInfoIndStartIdxOfPrimitiveFct(functionIdx);
        objectInfoIndEndIdx = McalCry_GetObjectInfoIndEndIdxOfPrimitiveFct(functionIdx);

        for(objectInfoIndIdx = objectInfoIndStartIdx; objectInfoIndIdx < objectInfoIndEndIdx; objectInfoIndIdx++)
        {
          if(McalCry_GetObjectInfoInd(objectInfoIndIdx) == objectId)
          {
            *primitiveInfoIdx = (McalCry_SizeOfPrimitiveInfoType)primitiveInfoIteratorIdx;
            retVal = E_OK;
            break;
          }
        }
      }

      if(retVal == E_OK)
      {
        break;
      }
    }
  }

  return retVal;
}

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SaveContextJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx){
  uint32 outputLength;
  Std_ReturnType retVal = E_NOT_OK;

  outputLength = MCALCRY_WORKSPACE_SETTINGS_LENGTH + McalCry_GetLengthOfSaveAndRestoreWorkspace(objectId);

  if((job->jobPrimitiveInfo->primitiveInfo->service <= CRYPTO_SIGNATUREVERIFY) && (McalCry_IsContextOfPrimitiveInfo(primitiveInfoIdx))){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr == 0u){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = outputLength;
    }
    else if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr >= outputLength){
      McalCry_Local_Uint32ToUint8ArrayBigEndian(McalCry_GetWorkspaceAddrOfObjectInfo(objectId), objectId);
      retVal = Appl_McalCry_SaveContextCallout(objectId
   ,                                                      job->jobInfo->jobId
   ,                                                      (P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR))McalCry_GetWorkspaceAddrOfObjectInfo(objectId)
   ,                                                      outputLength
   ,                                                      job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                      job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
    }
    else{
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RestoreContextJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx){
  uint32 inputLength;
  uint32 inputObjectId;
  Std_ReturnType retVal = E_NOT_OK;

  if((job->jobPrimitiveInfo->primitiveInfo->service <= CRYPTO_SIGNATUREVERIFY) && (McalCry_IsContextOfPrimitiveInfo(primitiveInfoIdx))){
    retVal = McalCry_GetDispatchOfPrimitiveFct(McalCry_GetPrimitiveFctIdxOfPrimitiveInfo(primitiveInfoIdx))(objectId, job, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT);
    inputLength = MCALCRY_WORKSPACE_SETTINGS_LENGTH + McalCry_GetLengthOfSaveAndRestoreWorkspace(objectId);

    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength >= inputLength){
      retVal = Appl_McalCry_RestoreContextCallout(objectId
   ,                                                         job->jobInfo->jobId
   ,                                                         (P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))McalCry_GetWorkspaceAddrOfObjectInfo(objectId)
   ,                                                         inputLength
   ,                                                         job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                         job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);

      if(retVal == E_OK)
      {
        McalCry_Local_Uint8ArrayToUint32BigEndian(&inputObjectId, McalCry_GetWorkspaceAddrOfObjectInfo(objectId));

        if(inputObjectId == objectId)
        {
          retVal = E_OK;
        }
        else
        {
          retVal = E_NOT_OK;
        }
      }
    }
  }

  return retVal;
}
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchJob(
  uint32 objectId
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) unlockingNecessary
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) contextMode
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx){
  Std_ReturnType retVal = E_NOT_OK;

  if(((job->MCALCRY_JOB_STATE_MEMBER == CRYPTO_JOBSTATE_IDLE) ||
    (job->MCALCRY_JOB_STATE_MEMBER == CRYPTO_JOBSTATE_ACTIVE)) &&
    McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_START)){
    retVal = McalCry_GetDispatchOfPrimitiveFct(McalCry_GetPrimitiveFctIdxOfPrimitiveInfo(primitiveInfoIdx))(objectId, job, CRYPTO_OPERATIONMODE_START);
    McalCry_UpdateJobState(retVal, job);
  }

  if((job->MCALCRY_JOB_STATE_MEMBER == CRYPTO_JOBSTATE_ACTIVE) &&
    McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_UPDATE)){
    retVal = McalCry_GetDispatchOfPrimitiveFct(McalCry_GetPrimitiveFctIdxOfPrimitiveInfo(primitiveInfoIdx))(objectId, job, CRYPTO_OPERATIONMODE_UPDATE);
    McalCry_UpdateJobState(retVal, job);
  }

  if((job->MCALCRY_JOB_STATE_MEMBER == CRYPTO_JOBSTATE_ACTIVE) &&
    McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_FINISH)){
    retVal = McalCry_GetDispatchOfPrimitiveFct(McalCry_GetPrimitiveFctIdxOfPrimitiveInfo(primitiveInfoIdx))(objectId, job, CRYPTO_OPERATIONMODE_FINISH);
    job->MCALCRY_JOB_STATE_MEMBER = CRYPTO_JOBSTATE_IDLE;
    *unlockingNecessary = TRUE;
  }
#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

  if((job->MCALCRY_JOB_STATE_MEMBER == CRYPTO_JOBSTATE_ACTIVE) &&
    McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_SAVE_CONTEXT)){
    retVal = McalCry_SaveContextJob(objectId, job, primitiveInfoIdx);
    job->MCALCRY_JOB_STATE_MEMBER = CRYPTO_JOBSTATE_ACTIVE;
    *contextMode = TRUE;
  }

  if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT)){
    retVal = McalCry_RestoreContextJob(objectId, job, primitiveInfoIdx);
    McalCry_UpdateJobState(retVal, job);
    *contextMode = TRUE;
  }
#else
  MCALCRY_DUMMY_STATEMENT(*contextMode);
#endif

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_InitMemory(void){
#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  McalCry_ModuleInitialized = (uint8)MCALCRY_UNINIT;
#endif
}

FUNC(void, MCALCRY_CODE) McalCry_Init_KeySimple(
  McalCry_KeyElementsIterType elementIndex){
  McalCry_SizeOfKeyStorageType keyStorageIdx;

  McalCry_SetKeyElementExtension(elementIndex, MCALCRY_KEYELEMENTSEXTENSION_CLEAR_ALL_MASK);
  keyStorageIdx = McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements(elementIndex);
  McalCry_SetKeyStorage(keyStorageIdx, 0u);
  McalCry_SetKeyStorage(keyStorageIdx + 1u, 0u);
  McalCry_SetKeyElementState(elementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_ALL_MASK);

}

FUNC(void, MCALCRY_CODE) McalCry_Init_Key(
  McalCry_KeyElementsIterType elementIndex
   ,  boolean initAllBytes){
#if(MCALCRY_INITVALUE == STD_ON)
  McalCry_SizeOfInitValueType initValueIdx;
  uint16 initValueLength;
#endif
  McalCry_SizeOfKeyStorageType keyStorageIdx;
  uint32 keyElementLength;

  keyStorageIdx = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndex);
  keyElementLength = (uint32)McalCry_GetLengthOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex));

#if(MCALCRY_INITVALUE == STD_ON)

  if(McalCry_HasKeyElementInitValue(elementIndex)){
    initValueIdx = McalCry_GetInitValueStartIdxOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex));
    initValueLength = (uint16)McalCry_GetKeyElementInitValueLength(elementIndex);

    McalCry_CopyData(McalCry_GetAddrKeyStorage(keyStorageIdx), McalCry_GetAddrInitValue(initValueIdx), (uint32)initValueLength);

    if(initAllBytes){
      McalCry_ClearData(McalCry_GetAddrKeyStorage(keyStorageIdx + initValueLength), (uint32)(keyElementLength- initValueLength));
    }

    McalCry_SetKeyElementExtension(elementIndex, MCALCRY_KEYELEMENTSEXTENSION_CLEAR_ALL_MASK);

    keyStorageIdx = McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements(elementIndex);
    McalCry_SetKeyStorage(keyStorageIdx, (uint8)(McalCry_GetKeyElementInitValueLength(elementIndex) >> 8));
    McalCry_SetKeyStorage(keyStorageIdx + 1u, (uint8)(McalCry_GetKeyElementInitValueLength(elementIndex)));
    McalCry_SetKeyElementState(elementIndex, MCALCRY_KEYELEMENTSTATE_VALID_MASK);
  }
  else
#endif
  {
    McalCry_Init_KeySimple(elementIndex);
    if(initAllBytes){
      McalCry_ClearData(McalCry_GetAddrKeyStorage(keyStorageIdx), keyElementLength);
    }
  }
}

#if(MCALCRY_SHEKEYS == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_Init_KeySheAdditional(
  McalCry_KeyElementsIterType elementIndex){
  McalCry_SetKeyElementExtension(elementIndex, MCALCRY_KEYELEMENTSEXTENSION_SHE_KEY_MASK);

  McalCry_SetKeyElementState(elementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_ALL_MASK);
}
#endif

FUNC(void, MCALCRY_CODE) McalCry_Init(void){
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleInitialized()){
    errorId = CRYPTO_E_INIT_FAILED;
  }
  else
#endif
  {
    McalCry_KeyElementsIterType elementIndex;
    McalCry_KeyIterType keyIndex;
#if(MCALCRY_SHEKEYS == STD_ON)
    McalCry_SheKeysIterType sheKeyIndex;
#endif
    McalCry_QueueIterType queueIdx;
    McalCry_LockIterType lockIdx;
#if(MCALCRY_LONGTERMWS == STD_ON)
    McalCry_LongTermWsLockIterType longWsLockIdx;
#endif
    McalCry_ObjectInfoIterType objectId;
#if(MCALCRY_NVBLOCK == STD_ON)
    McalCry_SizeOfNvBlockType blockIdx;
#endif

    for(elementIndex = 0u; elementIndex < McalCry_GetSizeOfKeyElements(); elementIndex++){
#if(MCALCRY_NVBLOCK == STD_ON)
      if(McalCry_IsKeyElementPersist(elementIndex))
      {
        McalCry_Init_KeySimple(elementIndex);
      }
      else
#endif
      {
        McalCry_Init_Key(elementIndex, FALSE);
      }
    }

#if(MCALCRY_SHEKEYS == STD_ON)
    for(sheKeyIndex = 0u; sheKeyIndex < McalCry_GetSizeOfSheKeys(); sheKeyIndex++){
      elementIndex = McalCry_GetKeyElementsKeyIdxOfSheKeys(sheKeyIndex);
      McalCry_Init_KeySheAdditional(elementIndex);
    }
#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

    McalCry_She_Debug_Cmd_ChallengeFlag = FALSE;
#endif
#endif
#if(MCALCRY_NVBLOCK == STD_ON)
    for(blockIdx = 0u; blockIdx < McalCry_GetSizeOfNvBlock(); blockIdx++){
      McalCry_NvBlock_State_Init(blockIdx);
    }
#endif
#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
    McalCry_RandomSourceGenerateCount = 0u;
#endif

    for(lockIdx = 0u; lockIdx < McalCry_GetSizeOfLock(); lockIdx++){
      McalCry_FreeLock(lockIdx);
    }

#if(MCALCRY_LONGTERMWS == STD_ON)

    for(longWsLockIdx = 0u; longWsLockIdx < McalCry_GetSizeOfLongTermWsLock(); longWsLockIdx++){
      McalCry_SetLongTermWsLock(longWsLockIdx, MCALCRY_LONG_TERM_WS_LOCK_FREE);
    }
#endif

    for(queueIdx = 0u; queueIdx < McalCry_GetSizeOfQueue(); queueIdx++){
      McalCry_SetQueue(queueIdx, (McalCry_JobPtrType)NULL_PTR);
    }

    for(objectId = 0u; objectId < McalCry_GetSizeOfObjectInfo(); objectId++){
      McalCry_SetDriverObjectState(objectId, MCALCRY_DRIVEROBJECTSTATE_IDLE);
#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

      McalCry_SetKeyIdOfLastJob(objectId, MCALCRY_UINT32_MAX);
      McalCry_SetFamilyOfLastJob(objectId, CRYPTO_ALGOFAM_NOT_SET);
      McalCry_SetModeOfLastJob(objectId, CRYPTO_ALGOMODE_NOT_SET);
#endif

#if(MCALCRY_FIPS186 == STD_ON)
      if(McalCry_GetRandomSeedBufferStartIdxOfObjectInfo(objectId) != MCALCRY_NO_RANDOMSEEDBUFFERENDIDXOFOBJECTINFO)
      {
        McalCry_SetRandomSeedBuffer(McalCry_GetRandomSeedBufferStartIdxOfObjectInfo(objectId), MCALCRY_KEYELEMENTSTATE_CLEAR_ALL_MASK);
      }
#endif

#if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)
      McalCry_ClearData(McalCry_GetWorkspaceAddrOfObjectInfo(objectId), McalCry_GetWorkspaceLengthOfObjectInfo(objectId));
#endif
    }

    for(keyIndex = 0u; keyIndex < McalCry_GetSizeOfKeyLock(); keyIndex++){
      McalCry_SetKeyLock(keyIndex, MCALCRY_KEY_LOCK_FREE);
    }

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
    McalCry_ModuleInitialized = MCALCRY_INITIALIZED;
#endif

  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError(MCALCRY_MODULE_ID, MCALCRY_INSTANCE_ID, MCALCRY_SID_INIT, errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif
}

#if(MCALCRY_VERSION_INFO_API == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_GetVersionInfo(
  P2VAR(Std_VersionInfoType, AUTOMATIC, MCALCRY_APPL_VAR) versioninfo){
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(versioninfo == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else
#endif
  {
    versioninfo->vendorID = (uint16)MCALCRY_VENDOR_ID;
    versioninfo->moduleID = (uint8)MCALCRY_MODULE_ID;
    versioninfo->sw_major_version = (uint8)MCALCRY_MAJOR_VERSION;
    versioninfo->sw_minor_version = (uint8)MCALCRY_MINOR_VERSION;
    versioninfo->sw_patch_version = (uint8)MCALCRY_PATCH_VERSION;
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         (uint8)MCALCRY_SID_GET_VERSION_INFO
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif
}
#endif

FUNC(void, MCALCRY_CODE) McalCry_MainFunction(void){
  McalCry_ObjectInfoIterType objectId;
  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx = 0u;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleInitialized())
#endif
  {
#if(MCALCRY_NVBLOCK == STD_ON)
    McalCry_NvBlock_MainFunction();
#endif

    for(objectId = 0u; objectId < McalCry_GetSizeOfObjectInfo(); objectId++){
      boolean processJob = FALSE;
      P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job;
      McalCry_KeyLockListType keyList;

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
      job = McalCry_GetQueue(McalCry_GetQueueIdxOfObjectInfo(objectId));

      if(job != NULL_PTR)
      {
        McalCry_Local_GetKeyList(job, &keyList);
        primitiveInfoIdx = McalCry_Dispatch_QueuePrimitiveInfoIdx[objectId];

#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
        if(McalCry_IsDefaultRandomSourceOfPrimitiveInfo(primitiveInfoIdx))
        {
          McalCry_Local_KeyListAddKey(&keyList, McalCry_GetDefaultRandomKey(), MCALCRY_KEY_ACCESS_READ);
        }
#endif
        if(McalCry_TryObtainingLock((uint32)objectId, job, &keyList) == E_OK)
        {
          McalCry_SetDriverObjectState(objectId, MCALCRY_DRIVEROBJECTSTATE_PROCESSING);
          processJob = TRUE;
        }
      }
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(processJob == TRUE)
      {
        (void)McalCry_Process((uint32)objectId, job, &keyList, primitiveInfoIdx);
      }
    }
  }
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_ProcessJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;
  McalCry_KeyLockListType keyList;
  McalCry_SizeOfPrimitiveInfoType primitiveInfoIdx = 0u;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(objectId >= McalCry_GetSizeOfObjectInfo()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }

  else if(job == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(McalCry_Local_GetKeyListAndDet(job, &keyList) == E_NOT_OK){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(McalCry_Local_DetChecksServiceValues(job, &errorId) == E_NOT_OK){
  }
  else if(McalCry_SearchService(objectId, job, &primitiveInfoIdx) == E_NOT_OK){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#else
  McalCry_Local_GetKeyList(job, &keyList);
  if(McalCry_SearchService(objectId, job, &primitiveInfoIdx) == E_OK)
#endif
  {
#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
    if(McalCry_IsDefaultRandomSourceOfPrimitiveInfo(primitiveInfoIdx)){
      McalCry_Local_KeyListAddKey(&keyList, McalCry_GetDefaultRandomKey(), MCALCRY_KEY_ACCESS_READ);
    }
#endif

    if(job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC){
      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
      retVal = McalCry_TryObtainingLock(objectId, job, &keyList);
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
      if(retVal == E_OK)
      {
        McalCry_SetDriverObjectState(objectId, MCALCRY_DRIVEROBJECTSTATE_PROCESSING);
        retVal = McalCry_Process(objectId, job, &keyList, primitiveInfoIdx);
      }
    }
    else{
      McalCry_QueueIdxOfObjectInfoType queueIdx = McalCry_GetQueueIdxOfObjectInfo(objectId);
      retVal = CRYPTO_E_QUEUE_FULL;

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(McalCry_GetQueue(queueIdx) == NULL_PTR)
      {
        if((McalCry_IsLockFree(objectId)) ||
            ((McalCry_IsLockOccupiedByJob(objectId, job->jobInfo->jobId)) == TRUE))
        {
          McalCry_SetQueue(queueIdx, job);
          McalCry_Dispatch_QueuePrimitiveInfoIdx[objectId] = (McalCry_SizeOfPrimitiveInfoType)primitiveInfoIdx;
          retVal = E_OK;
        }
      }
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError(MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_PROCESS_JOB
   ,                         errorId);
  }
#if(MCALCRY_SERVICE_RANDOM == STD_ON)
  if(retVal == CRYPTO_E_ENTROPY_EXHAUSTION){
    (void)Det_ReportRuntimeError(MCALCRY_MODULE_ID
   ,                                MCALCRY_INSTANCE_ID
   ,                                MCALCRY_SID_PROCESS_JOB
   ,                                CRYPTO_E_RE_ENTROPY_EXHAUSTED);
  }
#endif
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CancelJob(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(objectId >= McalCry_GetSizeOfObjectInfo()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }

  else if(job == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else
#endif
  {
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(McalCry_GetDriverObjectState(objectId) == MCALCRY_DRIVEROBJECTSTATE_IDLE){
      McalCry_QueueIdxOfObjectInfoType queueIdx = McalCry_GetQueueIdxOfObjectInfo(objectId);
      P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) queuedJob = McalCry_GetQueue(queueIdx);

      if((queuedJob != NULL_PTR) &&
          (queuedJob->jobInfo->jobId == job->jobInfo->jobId))
      {
        McalCry_SetQueue(queueIdx, (McalCry_JobPtrType)NULL_PTR);
        retVal = E_OK;
      }

      if(McalCry_IsLockOccupiedByJob(objectId, job->jobInfo->jobId))
      {
        McalCry_KeyLockListType keyList;
        McalCry_Local_GetKeyList(job, &keyList);

        McalCry_FreeLock(objectId);
        job->MCALCRY_JOB_STATE_MEMBER = CRYPTO_JOBSTATE_IDLE;
        McalCry_Local_KeyListPostFreeKeys(&keyList);
        retVal = E_OK;
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(retVal == E_OK){
#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
      McalCry_ClearObjectWorkspace(objectId);
#endif
      if(job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_ASYNC)
      {
        CryIf_CallbackNotification(job, CRYPTO_E_JOB_CANCELED);
      }
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError(MCALCRY_MODULE_ID, MCALCRY_INSTANCE_ID, MCALCRY_SID_CANCEL_JOB, errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#ifdef __cplusplus
}
#endif
