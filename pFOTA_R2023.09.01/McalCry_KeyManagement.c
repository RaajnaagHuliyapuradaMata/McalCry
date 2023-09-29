

#define MCALCRY_KEYMANAGEMENT_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_Curve.hpp"
#include "McalCry_RandomSeed.hpp"
#include "McalCry_KeyExchange.hpp"
#include "McalCry_KeyGenerate.hpp"
#include "McalCry_KeyDerive.hpp"
#include "McalCry_KeySetValid.hpp"
#include "McalCry_InternalApi.hpp"

#if(MCALCRY_NVBLOCK == STD_ON)
#include "NvM.hpp"
#endif

#if !defined (MCALCRY_LOCAL)
#define MCALCRY_LOCAL                                        static
#endif

#if !defined (MCALCRY_LOCAL_INLINE)
#define MCALCRY_LOCAL_INLINE                                 LOCAL_INLINE
#endif

#define McalCry_GetKeyElementWrittenLength(Index)             ((uint32)(((uint32)McalCry_GetKeyStorage(McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements((Index))) << 8) | (uint32)McalCry_GetKeyStorage(McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements((Index))+1u)))
#define MCALCRY_EMPTY_KEY_LENGTH                              (0u)
#define MCALCRY_SIZEOF_SHE_KEY                                (16u)
#define MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT                    (16u)
#define MCALCRY_SIZEOF_KDF_BUFFER                             (MCALCRY_SIZEOF_SHE_KEY+ MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT)
#define MCALCRY_SIZEOF_ENC_BUFFER                             (MCALCRY_SIZEOF_SHE_KEY+ MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT)

#define MCALCRY_STARTINDEX_SHE_M1_UID                         (0u)
#define MCALCRY_SIZEOF_SHE_M1_UID                             (15u)
#define MCALCRY_STARTINDEX_SHE_M1_IDS                         (MCALCRY_SIZEOF_SHE_M1_UID)
#define MCALCRY_SIZEOF_SHE_M1_IDS                             (1u)
#define MCALCRY_SIZEOF_SHE_M1                                 (MCALCRY_SIZEOF_SHE_M1_UID + MCALCRY_SIZEOF_SHE_M1_IDS)

#define MCALCRY_STARTINDEX_SHE_M2                             (MCALCRY_SIZEOF_SHE_M1)
#define MCALCRY_STARTINDEX_SHE_M2_COUNTER                     (MCALCRY_STARTINDEX_SHE_M2)
#define MCALCRY_MASK_SHE_M2_COUNTER                           (0xFFFFFFF0uL)
#define MCALCRY_SIZEOF_SHE_M2_COUNTER_BIT                     (28u)
#define MCALCRY_STARTINDEX_SHE_M2_KEYFLAG                     (MCALCRY_STARTINDEX_SHE_M2)
#define MCALCRY_SIZEOF_SHE_M2                                 (32u)

#define MCALCRY_STARTINDEX_SHE_M3                             (MCALCRY_STARTINDEX_SHE_M2 + MCALCRY_SIZEOF_SHE_M2)
#define MCALCRY_SIZEOF_SHE_M3                                 (16u)

#define MCALCRY_STARTINDEX_SHE_M4                             (MCALCRY_STARTINDEX_SHE_M3 + MCALCRY_SIZEOF_SHE_M3)
#define MCALCRY_SIZEOF_SHE_M4                                 (32u)
#define MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES              (4u)
#define MCALCRY_SIZEOF_SHE_M4_ENC                             (16u)

#define MCALCRY_SIZEOF_SHE_M5                                 (16u)

#define MCALCRY_SIZEOF_SHE_M1_M3                              (MCALCRY_SIZEOF_SHE_M1 + MCALCRY_SIZEOF_SHE_M2 + MCALCRY_SIZEOF_SHE_M3)
#define MCALCRY_SIZEOF_SHE_M4_M5                              (MCALCRY_SIZEOF_SHE_M4 + MCALCRY_SIZEOF_SHE_M5)
#define MCALCRY_SIZEOF_SHE_M1_M5                              (MCALCRY_SIZEOF_SHE_M1_M3 + MCALCRY_SIZEOF_SHE_M4_M5)

#define MCALCRY_SHE_M1_SECRET_KEY_ID                          (0u)
#define MCALCRY_SHE_M1_ECU_MASTER_KEY_ID                      (1u)
#define MCALCRY_SHE_M1_MAC_KEY_ID                             (2u)
#define MCALCRY_SHE_M1_MAC_ID                                 (3u)
#define MCALCRY_SHE_M1_KEY_N_START_ID                         (4u)
#define MCALCRY_SHE_M1_KEY_N_END_ID                           (13u)
#define MCALCRY_SHE_M1_RAM_KEY_ID                             (14u)
#define MCALCRY_SHE_NUM_KEYS                                  (25u)

#define MCALCRY_SHE_TYPE_SECRET_KEY                           (0u)
#define MCALCRY_SHE_TYPE_MASTER_KEY                           (1u)
#define MCALCRY_SHE_TYPE_MAC_KEY                              (2u)
#define MCALCRY_SHE_TYPE_MAC                                  (3u)
#define MCALCRY_SHE_TYPE_KEY_N                                (4u)
#define MCALCRY_SHE_TYPE_RAM_KEY                              (5u)
#define MCALCRY_SHE_NUM_KEY_TYPES                             (6u)

#define MCALCRY_SHE_UID_WILDCARD_VALUE                        (0x00u)

#define MCALCRY_SHE_PAGE0                                     (0u)
#define MCALCRY_SHE_PAGE1                                     (1u)

#define MCALCRY_SIZEOF_SHE_CHALLENGE                          (16u)
#define MCALCRY_SIZEOF_CMAC                                   (16u)
#define MCALCRY_SIZEOF_SHE_STATUS                             (1u)
#define MCALCRY_SIZEOF_SHE_CMD_GET_ID_OUTPUT                  (MCALCRY_SIZEOF_SHE_STATUS + MCALCRY_SIZEOF_SHE_M1_UID + MCALCRY_SIZEOF_CMAC)

#define MCALCRY_SHE_CLEARED_STATUS                            (0x00u)
#define MCALCRY_SHE_STATUS_BUSY                               (0x01u)
#define MCALCRY_SHE_STATUS_SECURE_BOOT                        (0x02u)
#define MCALCRY_SHE_STATUS_BOOT_INIT                          (0x04u)
#define MCALCRY_SHE_STATUS_BOOT_FINISHED                      (0x08u)
#define MCALCRY_SHE_STATUS_BOOT_OK                            (0x10u)
#define MCALCRY_SHE_STATUS_RND_INIT                           (0x20u)
#define MCALCRY_SHE_STATUS_EXT_DEBUGGER                       (0x40u)
#define MCALCRY_SHE_STATUS_INT_DEBUGGER                       (0x80u)

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)
#define MCALCRY_SHE_FID_MASK_WRITE_PROTECTION               (0x80u)

#if(MCALCRY_KEYELEMENTSBOOTPROTECTIONIDXOFSHEPAGE == STD_ON)
#define MCALCRY_SHE_FID_MASK_BOOT_PROTECTION               (0x40u)
#define MCALCRY_SHE_FID_MASK_BOOT_PROTECTION_INV           (0xBFu)
#else
#define MCALCRY_SHE_FID_MASK_BOOT_PROTECTION               (0x00u)
#endif

#if(MCALCRY_KEYELEMENTSDEBUGGERPROTECTIONIDXOFSHEPAGE == STD_ON)
#define MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION           (0x20u)
#define MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION_INV       (0xDFu)
#else
#define MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION           (0x00u)
#endif
#define MCALCRY_SHE_FID_MASK_KEY_USAGE                      (0x10u)
#define MCALCRY_SHE_FID_MASK_WILDCARD                       (0x08u)
#define MCALCRY_SHE_FID_MASK_CMAC_USAGE                     (0x04u)
#define MCALCRY_SHE_FID_MASK_DENIED                         (0x02u)
#define MCALCRY_SHE_FID_MASK_DEFAULT                        (0x00u)
#endif
#endif

#define MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE                (0x01u)
#define MCALCRY_NVBLOCK_STATE_MASK_WRITE_REQUESTED            (0x02u)
#define MCALCRY_NVBLOCK_STATE_MASK_WRITE_COPIED               (0x04u)
#define MCALCRY_NVBLOCK_STATE_MASK_CLEAR_WRITE_COPIED         (0xFBu)
#define MCALCRY_NVBLOCK_STATE_MASK_CLEAR_WRITE_REQUESTED      (0xFDu)

#define MCALCRY_NVBLOCK_STATE_IDLE                            (0x00u)
#define MCALCRY_NVBLOCK_STATE_WRITE_REQ_PENDING               (MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE)
#define MCALCRY_NVBLOCK_STATE_WRITE_REQ                       (MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE|MCALCRY_NVBLOCK_STATE_MASK_WRITE_REQUESTED)
#define MCALCRY_NVBLOCK_STATE_COPY_DATA                       (MCALCRY_NVBLOCK_STATE_MASK_WRITE_COPIED)
#define MCALCRY_NVBLOCK_STATE_REQ_WHILE_PENDING               (MCALCRY_NVBLOCK_STATE_MASK_WRITE_COPIED|MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE)

#define MCALCRY_POS_NVBLOCK_VERSION                           (0u)
#define MCALCRY_SIZEOF_NVBLOCK_VERSION                        (1u)
#define MCALCRY_POS_NVBLOCK_FLAGS                             (MCALCRY_SIZEOF_NVBLOCK_VERSION)
#define MCALCRY_SIZEOF_NVBLOCK_FLAGS                          (1u)
#define MCALCRY_POS_NVBLOCK_CRC                               (MCALCRY_POS_NVBLOCK_FLAGS+MCALCRY_SIZEOF_NVBLOCK_FLAGS)
#define MCALCRY_SIZEOF_NVBLOCK_CRC                            (4u)
#define MCALCRY_SIZEOF_NVBLOCK_HEADER_CRC                     (MCALCRY_POS_NVBLOCK_CRC + MCALCRY_SIZEOF_NVBLOCK_CRC)

#define MCALCRY_NVBLOCK_VERSION_0                             (0u)
#define MCALCRY_NVBLOCK_FLAGS_0                               (0u)

#ifndef MCALCRY_NVM_WRITE_BLOCK
#define MCALCRY_NVM_WRITE_BLOCK                              (7u)
#endif

#ifndef MCALCRY_NVM_WRITE_ALL
#define MCALCRY_NVM_WRITE_ALL                                (13u)
#endif

#define McalCry_She_M1_GetAuthId(value)                       ((uint8)((value) & 0x0Fu))
#define McalCry_She_M1_GetId(value)                           ((uint8)((value) >> 4))
#define McalCry_She_M1_BuildIds(Id, AuthId)                   (((uint8)(((Id) << 4) & 0xF0u)) | ((uint8)((AuthId) & 0x0Fu)))
#define McalCry_She_IsDebugCmd(cryptoKeyId, elementId)        ((cryptoKeyId == McalCry_GetSheInfoKeyRefOfSheKeyUpdate()) && (elementId == CRYPTO_KE_CUSTOM_SHE_DEBUG_CMD))

#define McalCry_She_ConvertCounter(value)                     (((value) & MCALCRY_MASK_SHE_M2_COUNTER) >> 4)

#define McalCry_She_GetPtrMacConst(indexOfSheKey)             (McalCry_GetAddrSheConstants(McalCry_GetSheConstantsMacStartIdxOfShePage(McalCry_GetShePageIdxOfSheKeys((indexOfSheKey)))))
#define McalCry_She_GetPtrEncConst(indexOfSheKey)             (McalCry_GetAddrSheConstants(McalCry_GetSheConstantsEncStartIdxOfShePage(McalCry_GetShePageIdxOfSheKeys((indexOfSheKey)))))

#define McalCry_GetNvBlockState(blockIdx)                     (McalCry_NvBlock_State[blockIdx])
#define McalCry_SetNvBlockState(blockIdx, state)              ((McalCry_NvBlock_State[blockIdx]) = (state))
#define McalCry_IsNvBlockState(blockIdx, state)               ((McalCry_NvBlock_State[blockIdx]) == (state))
#define McalCry_IsNvBlockStateMask(blockIdx, Mask)            (((McalCry_NvBlock_State[blockIdx]) & (Mask)) == (Mask))
#define McalCry_SetNvBlockStateMask(blockIdx, Mask)           ((McalCry_NvBlock_State[blockIdx]) = (McalCry_NvBlock_State_Type)((McalCry_NvBlock_State[blockIdx]) | (Mask)))
#define McalCry_ClearNvBlockStateMask(blockIdx, Mask)         ((McalCry_NvBlock_State[blockIdx]) = (McalCry_NvBlock_State_Type)((McalCry_NvBlock_State[blockIdx]) & (Mask)))

#ifndef McalCry_NvM_WriteBlock
#define McalCry_NvM_WriteBlock                               McalCry_GetNvWriteBlockFctNameOfNvStorage()
#endif

#if(MCALCRY_SHEKEYS == STD_ON)
typedef uint8 McalCry_SheKeyTypeType;
#endif

#if(MCALCRY_NVBLOCK == STD_ON)
typedef uint8 McalCry_NvBlock_State_Type;
#endif

#define MCALCRY_START_SEC_CONST_8BIT
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)
MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_SheKeyCheckFlags[MCALCRY_SHE_NUM_KEY_TYPES - 1u] =
{
    MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION
   ,   MCALCRY_SHE_FID_MASK_WRITE_PROTECTION | MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_WILDCARD
   ,   MCALCRY_SHE_FID_MASK_WRITE_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_WILDCARD
   ,   MCALCRY_SHE_FID_MASK_WRITE_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_WILDCARD
   ,   MCALCRY_SHE_FID_MASK_WRITE_PROTECTION | MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_KEY_USAGE | MCALCRY_SHE_FID_MASK_WILDCARD | MCALCRY_SHE_FID_MASK_CMAC_USAGE,
};

MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_SheKeySetAccessFlags[MCALCRY_SHE_NUM_KEY_TYPES - 1u] =
{
    MCALCRY_SHE_FID_MASK_DENIED
   ,   MCALCRY_SHE_FID_MASK_DENIED
   ,   MCALCRY_SHE_FID_MASK_KEY_USAGE | MCALCRY_SHE_FID_MASK_CMAC_USAGE
   ,   MCALCRY_SHE_FID_MASK_DENIED
   ,   0u,
};

MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_SheKeyServiceFlags[MCALCRY_SHE_NUM_SERVICES] =
{
    MCALCRY_SHE_FID_MASK_DENIED | MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_KEY_USAGE
   ,   MCALCRY_SHE_FID_MASK_DENIED | MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_KEY_USAGE | MCALCRY_SHE_FID_MASK_CMAC_USAGE
   ,   MCALCRY_SHE_FID_MASK_DENIED | MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION | MCALCRY_SHE_FID_MASK_KEY_USAGE
   ,   MCALCRY_SHE_FID_MASK_BOOT_PROTECTION | MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION
};

MCALCRY_LOCAL CONST(uint8, MCALCRY_CONST) McalCry_SheKeyServiceFlagsResult[MCALCRY_SHE_NUM_SERVICES] =
{
    0u
   ,   MCALCRY_SHE_FID_MASK_KEY_USAGE
   ,   MCALCRY_SHE_FID_MASK_KEY_USAGE
   ,   0u
};
#endif
#endif

#define MCALCRY_STOP_SEC_CONST_8BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_VAR_NOINIT_8BIT
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

MCALCRY_LOCAL VAR(uint8, MCALCRY_VAR_NOINIT) McalCry_She_Debug_Cmd_Challenge[MCALCRY_SIZEOF_SHE_KEY];
#endif
#endif

#if(MCALCRY_NVBLOCK == STD_ON)
MCALCRY_LOCAL VAR(McalCry_NvBlock_State_Type, MCALCRY_VAR_NOINIT) McalCry_NvBlock_State[McalCry_GetSizeOfNvBlock()];
#endif

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

VAR(boolean, MCALCRY_VAR_NOINIT) McalCry_She_Debug_Cmd_ChallengeFlag;
#endif
#endif

#define MCALCRY_STOP_SEC_VAR_NOINIT_8BIT
#include "CompilerCfg_McalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopy_RightsCheck(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopy(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst
   ,  uint32 dstCryptoKeyId);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopyPartial(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst
   ,  uint32 dstCryptoKeyId
   ,  uint32 keyElementSourceOffset
   ,  uint32 keyElementTargetOffset
   ,  uint32 keyElementCopyLength);

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_Local_KeyElementGetLengthCheck(
  P2CONST(uint32, AUTOMATIC, AUTOMATIC) resultLengthptr
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_LengthCheckType lengthCheck);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGet_Standard(
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_LengthCheckType lengthCheck);

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyGetSheId(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) sheIdPtr);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyGetSheIndex(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, AUTOMATIC) indexSheKeyPtr);

MCALCRY_LOCAL_INLINE FUNC(uint8, MCALCRY_CODE) McalCry_SheKeyGetKeyType(
  uint8 sheId);

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyGetElementIndex(
  uint8 sheKeyId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, MCALCRY_APPL_VAR) elementIndex);
#endif

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_Local_KeyElementGetSheCheckFid(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_ServiceType serviceType);
#endif

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateMiyaguchiPreneel(
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) dataPtr
   ,  uint32 length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCmac(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataPtr
   ,  uint32 length
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) outputPtr
   ,  P2VAR(eslt_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateVerifyAndExtract(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  McalCry_SizeOfKeyElementsType outputElement
   ,  Std_ReturnType proofAvailable);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdate(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSetShe(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength
   ,  Std_ReturnType oldRetVal);

#if(MCALCRY_RAM_KEY_EXPORT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetShe(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyExport_M1M2M3(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) encBufferPtr
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) ramKey
   ,  McalCry_SizeOfSheKeysType indexOfSheKey);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyExport(
  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateDecrypt(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m2m3
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateEncrypt(
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) dataPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr
   ,  uint8 numberOfBlocks);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetSheKey(
  uint8 sheKeyId
   ,  McalCry_SizeOfShePageType shePage
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, MCALCRY_APPL_VAR) indexOfSheKeyPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckM1Ids(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, MCALCRY_APPL_VAR) indexOfAuthSheKeyPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckUid(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_SheKeyTypeType sheKeyType);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateVerifyM3(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  uint8 KDFbufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr);

#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckCounter(
  McalCry_SizeOfKeyElementsType elementIndexCounter
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr
   ,  McalCry_SheKeyTypeType sheKeyType);
#endif

#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateCopyCounter(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndexCounter
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr);
#endif

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateCopyFid(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr
   ,  McalCry_SheKeyTypeType sheKeyType);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateExtractKey(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  uint8 KDFbufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateProofM4M5(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType outputElement
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateGenM4M5(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m4m5
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) encBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateFindProof(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementsIterType, AUTOMATIC, AUTOMATIC) outputElementIndexPtr);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateLockKeys(
  uint32 cryptoKeyId
   ,  uint32 authKeyId);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateUnlockKeys(
  uint32 cryptoKeyId
   ,  uint32 authKeyId);

#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_GetChallenge(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_SetAuthorizationAndLock(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_SetAuthorization(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_She_DebugCmd_DeleteKeys(void);

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_She_DebugCmd_IsWriteProtected(void);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_Authorization(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) masterKey
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) challenge
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) authorization);
#endif
#endif

#if(MCALCRY_NVBLOCK == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Trigger_Write_Req(
  McalCry_SizeOfNvBlockType blockIdx);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_CallbackWrittenToBlock(
  McalCry_SizeOfNvBlockType blockIdx);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_WrittenToBlock(
  McalCry_SizeOfNvBlockType blockIdx);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock_Copy(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_Copy(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_DATA) NvMBufferPtr);

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_HeaderCrc(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_DATA) NvMBufferPtr);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock_HeaderCrc(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) writtenLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_Restore(
  McalCry_SizeOfNvBlockType blockIdx);
#endif

#if(MCALCRY_SHECMDGETID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_Cmd_Get_Status(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) statusPtr);
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_BinarySearchCryptoKeyId(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLength(
  McalCry_SizeOfKeyElementsType keyElementIndex
   ,  uint32 keyElementLength){
  McalCry_SetKeyStorage(McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements(keyElementIndex), (uint8)((keyElementLength >> 8) & 0xFFu));
  McalCry_SetKeyStorage(McalCry_GetKeyStorageWrittenLengthStartIdxOfKeyElements(keyElementIndex) + 1u, (uint8)(keyElementLength & 0xFFu));
}

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLengthWithCryptoKeyIdSearch(
  McalCry_SizeOfKeyElementsType keyElementIndex
   ,  uint32 keyElementLength){
  uint32 cryptoKeyId = 0u;

  if(McalCry_Local_BinarySearchCryptoKeyId(keyElementIndex, &cryptoKeyId) == E_OK){
    McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, keyElementIndex, keyElementLength);
  }
}

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType keyElementIndex
   ,  uint32 keyElementLength){
  McalCry_SetKeyElementWrittenLength(keyElementIndex, keyElementLength);

#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

  McalCry_GetKeyValueChangedCalloutFctNameOfConfigurableCallouts()(cryptoKeyId, McalCry_GetIdOfKeyElements(keyElementIndex));
#else
  MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
#endif
}

FUNC(void, MCALCRY_CODE) McalCry_Local_SetKeyElementStateWritten(
  McalCry_SizeOfKeyElementsType elementIndex){
  McalCry_ClearKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_NORMAL_MASK);
  if(McalCry_IsKeyElementWriteOnce(elementIndex)){
    McalCry_SetKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK);
  }
}

FUNC(boolean, MCALCRY_CODE) McalCry_SetKeyState(
  uint32 cryptoKeyId
   ,  uint8 mask){
  McalCry_KeyElementsIterType elementIndex;
  boolean changed = FALSE;

  for(elementIndex = McalCry_GetKeyElementsStartIdxOfKey(cryptoKeyId); elementIndex < McalCry_GetKeyElementsEndIdxOfKey(cryptoKeyId); elementIndex++){
#if(MCALCRY_NVBLOCK == STD_ON)
    if(McalCry_IsKeyElementPersist(elementIndex) && !McalCry_IsKeyElementStateByMask(elementIndex, mask)){
      changed = TRUE;
    }
#endif
    McalCry_SetKeyElementStateByMask(elementIndex, mask);
  }

#if(MCALCRY_KEYVALIDITYSETCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)
  if(mask == MCALCRY_KEYELEMENTSTATE_VALID_MASK){
    McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(cryptoKeyId, TRUE);
  }
  else{
    McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(cryptoKeyId, FALSE);
  }
#endif

  return changed;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopy_RightsCheck(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst){
  Std_ReturnType retVal = E_OK;

  if(((McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndexSrc))) == MCALCRY_RA_DENIED) ||
      ((McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndexSrc))) > (McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndexDst))))){
    retVal = CRYPTO_E_KEY_READ_FAIL;
  }

  else if((McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndexDst))) == MCALCRY_WA_DENIED){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
  }

  else if(McalCry_IsKeyElementStateByMask(elementIndexDst, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK)){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
  }
  else{
#if(MCALCRY_SHEKEYS == STD_ON)
    if(McalCry_IsSheKey(elementIndexSrc)){
      retVal = CRYPTO_E_KEY_READ_FAIL;
    }
    else if(McalCry_IsSheKey(elementIndexDst)){
      retVal = CRYPTO_E_KEY_WRITE_FAIL;
    }
    else{
    }
#endif
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopy(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst
   ,  uint32 dstCryptoKeyId){
  Std_ReturnType retVal;
  McalCry_KeyStorageIterType keyStorageIndexSrc;
  McalCry_KeyStorageIterType keyStorageIndexDst;

  retVal = McalCry_Local_KeyElementCopy_RightsCheck(elementIndexSrc, elementIndexDst);
  if(retVal == E_OK){
    retVal = E_NOT_OK;

    {
      if((McalCry_GetKeyElementWrittenLength(elementIndexSrc) == McalCry_GetKeyElementLength(elementIndexDst)) ||
          ((McalCry_IsKeyElementPartial(elementIndexDst) == TRUE) &&
          (McalCry_GetKeyElementWrittenLength(elementIndexSrc) <= McalCry_GetKeyElementLength(elementIndexDst))))
      {
        keyStorageIndexSrc = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndexSrc);
        keyStorageIndexDst = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndexDst);

        McalCry_CopyData(McalCry_GetAddrKeyStorage(keyStorageIndexDst), McalCry_GetAddrKeyStorage(keyStorageIndexSrc), McalCry_GetKeyElementWrittenLength(elementIndexSrc));

        McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(dstCryptoKeyId, elementIndexDst, McalCry_GetKeyElementWrittenLength(elementIndexSrc));
        McalCry_Local_SetKeyElementStateWritten(elementIndexDst);

        retVal = E_OK;
      }
      else
      {
        retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementCopyPartial(
  McalCry_SizeOfKeyElementsType elementIndexSrc
   ,  McalCry_SizeOfKeyElementsType elementIndexDst
   ,  uint32 dstCryptoKeyId
   ,  uint32 keyElementSourceOffset
   ,  uint32 keyElementTargetOffset
   ,  uint32 keyElementCopyLength){
  Std_ReturnType retVal;
  McalCry_KeyStorageIterType keyStorageIndexSrc, keyStorageIndexDst;
  uint32 writtenLengthSrc, writtenLengthDst;

  retVal = McalCry_Local_KeyElementCopy_RightsCheck(elementIndexSrc, elementIndexDst);
  if(retVal == E_OK){
    retVal = E_NOT_OK;
    {
      writtenLengthSrc = McalCry_GetKeyElementWrittenLength(elementIndexSrc);
      writtenLengthDst = McalCry_GetKeyElementWrittenLength(elementIndexDst);

      if(writtenLengthSrc == MCALCRY_EMPTY_KEY_LENGTH)
      {
        retVal = CRYPTO_E_KEY_EMPTY;
      }
      else if(
        (McalCry_IsKeyElementPartial(elementIndexDst) == TRUE) &&

        ((keyElementSourceOffset + keyElementCopyLength) <= writtenLengthSrc) &&
        ((McalCry_IsUint32Overflow(keyElementSourceOffset, keyElementCopyLength)) == FALSE) &&

        ((keyElementTargetOffset + keyElementCopyLength) <= McalCry_GetKeyElementLength(elementIndexDst)) &&
        ((McalCry_IsUint32Overflow(keyElementTargetOffset, keyElementCopyLength)) == FALSE))
      {
        keyStorageIndexSrc = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndexSrc);
        keyStorageIndexDst = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndexDst);

        if(writtenLengthDst < keyElementTargetOffset)
        {
          McalCry_ClearData(McalCry_GetAddrKeyStorage(keyStorageIndexDst + writtenLengthDst), (uint32)(keyElementTargetOffset - writtenLengthDst));
        }

        McalCry_CopyData(McalCry_GetAddrKeyStorage(keyStorageIndexDst + keyElementTargetOffset), McalCry_GetAddrKeyStorage(keyStorageIndexSrc + keyElementSourceOffset), keyElementCopyLength);

        if(writtenLengthDst < (keyElementTargetOffset + keyElementCopyLength))
        {
          McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(dstCryptoKeyId, elementIndexDst, (keyElementTargetOffset + keyElementCopyLength));
        }
        McalCry_Local_SetKeyElementStateWritten(elementIndexDst);

        retVal = E_OK;
      }
      else
      {
        retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_Local_KeyElementGetLengthCheck(
  P2CONST(uint32, AUTOMATIC, AUTOMATIC) resultLengthptr
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_LengthCheckType lengthCheck){
  boolean retVal = FALSE;

  switch(lengthCheck){
    case MCALCRY_LENGTH_CHECK_NONE:
    retVal = TRUE;
    break;

    case MCALCRY_LENGTH_CHECK_MAX:
    if(McalCry_GetKeyElementWrittenLength(elementIndex) <= *resultLengthptr){
      retVal = TRUE;
    }
    break;

    case MCALCRY_LENGTH_CHECK_EQUAL:
    if(McalCry_GetKeyElementWrittenLength(elementIndex) == *resultLengthptr){
      retVal = TRUE;
    }
    break;

    case MCALCRY_LENGTH_CHECK_MIN:
    if(McalCry_GetKeyElementWrittenLength(elementIndex) >= *resultLengthptr){
      retVal = TRUE;
    }
    break;

    default:
    break;
  }

  return retVal;
}

#if(MCALCRY_SHEKEYS == STD_ON)
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyGetSheId(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) sheIdPtr){
  McalCry_SheKeysIterType i;

  for(i = 0u; i < McalCry_GetSizeOfSheKeys(); i++){
    if(McalCry_GetKeyElementsKeyIdxOfSheKeys(i) == elementIndex){
      *sheIdPtr = McalCry_GetSheIdOfSheKeys(i);
      break;
    }
  }
}
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyGetSheIndex(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, AUTOMATIC) indexSheKeyPtr){
  McalCry_SheKeysIterType i;
  Std_ReturnType retVal = E_NOT_OK;

  for(i = 0u; i < McalCry_GetSizeOfSheKeys(); i++){
    if(McalCry_GetKeyElementsKeyIdxOfSheKeys(i) == elementIndex){
      *indexSheKeyPtr = (McalCry_SizeOfSheKeysType)i;
      retVal = E_OK;
      break;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(uint8, MCALCRY_CODE) McalCry_SheKeyGetKeyType(
  uint8 sheId){
  uint8 keyType;

  if(sheId == MCALCRY_SHE_M1_RAM_KEY_ID){
    keyType = MCALCRY_SHE_TYPE_RAM_KEY;
  }
  else if(sheId >= MCALCRY_SHE_M1_KEY_N_START_ID){
    keyType = MCALCRY_SHE_TYPE_KEY_N;
  }
  else{
    keyType = sheId;
  }
  return keyType;
}

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyGetElementIndex(
  uint8 sheKeyId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, MCALCRY_APPL_VAR) elementIndex){
  Std_ReturnType found = E_NOT_OK;

  McalCry_SheKeysIterType i;

  for(i = 0u; i < McalCry_GetSizeOfSheKeys(); i++){
    if(McalCry_GetSheIdOfSheKeys(i) == sheKeyId){
      *elementIndex = McalCry_GetKeyElementsKeyIdxOfSheKeys(i);
      found = E_OK;
      break;
    }
  }

  return found;
}
#endif

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_Local_KeyElementGetSheCheckFid(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_ServiceType serviceType){
  boolean retVal = FALSE;
  uint8 fid, keyType, sheId = 0u;
  McalCry_SizeOfKeyElementsType localElementIndex;

  McalCry_SheKeyGetSheId(elementIndex, &sheId);
  keyType = McalCry_SheKeyGetKeyType(sheId);

  if(keyType != MCALCRY_SHE_TYPE_RAM_KEY){
    if(keyType == MCALCRY_SHE_TYPE_SECRET_KEY){
      if(McalCry_SheKeyGetElementIndex(MCALCRY_SHE_M1_ECU_MASTER_KEY_ID, &localElementIndex) == E_OK)
      {
        fid = McalCry_GetKeyStorage(McalCry_GetKeyStorageExtensionIdxOfKeyElements(localElementIndex));
      }
      else
      {
        fid = MCALCRY_SHE_FID_MASK_DEFAULT;
      }
    }
    else{
      fid = McalCry_GetKeyStorage(McalCry_GetKeyStorageExtensionIdxOfKeyElements(elementIndex));
    }

    fid &= McalCry_SheKeyCheckFlags[keyType];
    fid |= McalCry_SheKeySetAccessFlags[keyType];
    fid &= McalCry_SheKeyServiceFlags[serviceType];

#if(MCALCRY_KEYELEMENTSBOOTPROTECTIONIDXOFSHEPAGE == STD_ON)
    localElementIndex = McalCry_GetKeyElementsBootProtectionIdxOfShePage(MCALCRY_SHE_PAGE0);
    if((McalCry_IsModuleBootProtected(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(localElementIndex)))) &&
        (McalCry_GetKeyElementWrittenLength(localElementIndex) == 1u)){
      fid &= MCALCRY_SHE_FID_MASK_BOOT_PROTECTION_INV;
    }
#endif

#if(MCALCRY_KEYELEMENTSDEBUGGERPROTECTIONIDXOFSHEPAGE == STD_ON)
    localElementIndex = McalCry_GetKeyElementsDebuggerProtectionIdxOfShePage(MCALCRY_SHE_PAGE0);
    if((McalCry_IsModuleDebuggerProtected(McalCry_GetKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(localElementIndex)))) &&
        (McalCry_GetKeyElementWrittenLength(localElementIndex) == 1u)){
      fid &= MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION_INV;
    }
#endif

    if(fid == McalCry_SheKeyServiceFlagsResult[serviceType]){
      retVal = TRUE;
    }
  }
  else{
    retVal = TRUE;
  }

  return retVal;
}
#endif
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGet_Standard(
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_LengthCheckType lengthCheck){
  Std_ReturnType retVal;

  if(McalCry_Local_KeyElementGetLengthCheck(resultLengthPtr, elementIndex, lengthCheck) == TRUE){
    *resultIndexPtr = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndex);

    *resultLengthPtr = McalCry_GetKeyElementWrittenLength(elementIndex);
    retVal = E_OK;
  }
  else{
    retVal = CRYPTO_E_SMALL_BUFFER;
  }

  return retVal;
}

#if(MCALCRY_SHEKEYS == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateMiyaguchiPreneel(
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) dataPtr
   ,  uint32 length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr){
  eslt_WorkSpaceAES128Block workSpaceAes128Block;
  Std_ReturnType retVal = E_NOT_OK;
  uint32 lengthCount;
  uint8_least i;
  uint8 Out[MCALCRY_SIZEOF_SHE_KEY];
  uint8 Out_last[MCALCRY_SIZEOF_SHE_KEY];
  uint8 tempCalcByte;
  boolean exitLoop = FALSE;
  eslt_ErrorCode eslRetVal;

  P2CONST(uint8, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) tempPlainPtr = dataPtr;

  McalCry_ClearData(Out, MCALCRY_SIZEOF_SHE_KEY);
  McalCry_ClearData(Out_last, MCALCRY_SIZEOF_SHE_KEY);
  lengthCount = length;

  if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128Block.header
   ,   ESL_MAXSIZEOF_WS_AES128
   ,   MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    while((lengthCount > 0u) &&
           (exitLoop == FALSE)){
      eslRetVal = esl_initEncryptAES128Block((P2VAR(eslt_WorkSpaceAES128Block, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128Block
   ,                                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))Out_last);

      if(eslRetVal == ESL_ERC_NO_ERROR)
      {
        eslRetVal = esl_encryptAES128Block((P2VAR(eslt_WorkSpaceAES128Block, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128Block
   ,                                          tempPlainPtr
   ,                                          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))Out);
      }

      if(eslRetVal == ESL_ERC_NO_ERROR)
      {
        for(i = 0u; i < MCALCRY_SIZEOF_SHE_KEY; i++)
        {
          tempCalcByte = (uint8)(Out_last[i] ^ Out[i] ^ tempPlainPtr[i]);
          Out_last[i] = tempCalcByte;
          Out[i] = tempCalcByte;
        }

        tempPlainPtr = &tempPlainPtr[MCALCRY_SIZEOF_SHE_KEY];

        lengthCount -= MCALCRY_SIZEOF_SHE_KEY;
      }
      else
      {
        exitLoop = TRUE;
      }
    }
  }

  if(lengthCount == 0u){
    retVal = E_OK;

    McalCry_CopyData(outputPtr, Out, MCALCRY_SIZEOF_SHE_KEY);
  }

  return retVal;
}

MCALCRY_LOCAL FUNC( Std_ReturnType, MCALCRY_CODE ) McalCry_SheKeyUpdateCmac(
  P2CONST( uint8, AUTOMATIC, MCALCRY_APPL_VAR ) dataPtr
   ,  uint32 length
   ,  P2CONST( uint8, AUTOMATIC, AUTOMATIC ) keyPtr
   ,  P2VAR( uint8, AUTOMATIC, MCALCRY_APPL_VAR ) outputPtr
   ,  P2VAR(eslt_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;

  if(esl_initWorkSpaceHeader(&workspace->header
   ,   ESL_MAXSIZEOF_WS_CMACAES
   ,   MCALCRY_WATCHDOG_PTR ) == ESL_ERC_NO_ERROR){
    if(esl_initCMACAES128( workspace
   ,     MCALCRY_CMACAES_MAX_KEY_SIZE
   ,     (P2CONST( eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR ))keyPtr ) == ESL_ERC_NO_ERROR){
      if(esl_updateCMACAES128(workspace
   ,       (eslt_Length)length
   ,       (P2CONST( eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR ))dataPtr ) == ESL_ERC_NO_ERROR)
      {
        if(esl_finalizeCMACAES128(workspace
   ,         outputPtr ) == ESL_ERC_NO_ERROR)
        {
          retVal = E_OK;
        }
      }
    }
  }
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateDecrypt(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m2m3
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_WorkSpaceAES128 workSpaceAes128;
  eslt_ErrorCode eslRet;
  eslt_Length outLength = 2u * MCALCRY_AES_BLOCK_SIZE;
  eslt_Length written;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128.header
   ,                                  ESL_MAXSIZEOF_WS_AES128
   ,                                  MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initDecryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr
   ,                                  ESL_BM_CBC
   ,                                  ESL_PM_OFF
   ,                                  NULL_PTR);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_decryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                              (eslt_Length)2u * MCALCRY_AES_BLOCK_SIZE
   ,                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))m2m3
   ,                              (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outLength
   ,                              (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))outputPtr);
  }

  written = outLength;
  outLength = (eslt_Length)(((eslt_Length)(2u * MCALCRY_AES_BLOCK_SIZE)) - written);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_finalizeDecryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                                      (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outLength
   ,                                      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputPtr[written]);
  }

  written = (eslt_Length)(written + outLength);

  if((eslRet == ESL_ERC_NO_ERROR) &&
      (written == (2u * MCALCRY_AES_BLOCK_SIZE))){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateEncrypt(
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) dataPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputPtr
   ,  uint8 numberOfBlocks){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  eslt_WorkSpaceAES128 workSpaceAes128;
  eslt_Length outLength = (eslt_Length)((eslt_Length)(numberOfBlocks) * MCALCRY_AES_BLOCK_SIZE);
  eslt_Length written;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(workSpaceAes128.header)
   ,                                  ESL_MAXSIZEOF_WS_AES128
   ,                                  MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initEncryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                                  (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))keyPtr
   ,                                  ESL_BM_CBC
   ,                                  ESL_PM_OFF
   ,                                  NULL_PTR);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_encryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                              (eslt_Length)((eslt_Length)(numberOfBlocks) * MCALCRY_AES_BLOCK_SIZE)
   ,                              (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))dataPtr
   ,                              (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR))&outLength
   ,                              (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))outputPtr);
  }

  written = outLength;
  outLength = (eslt_Length)(((eslt_Length)numberOfBlocks * MCALCRY_AES_BLOCK_SIZE) - written);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_finalizeEncryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceAes128
   ,                                      (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outLength
   ,                                      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputPtr[written]);
  }

  written = (eslt_Length)(written + outLength);

  if((eslRet == ESL_ERC_NO_ERROR) &&
      (written == ((eslt_Length)numberOfBlocks * MCALCRY_AES_BLOCK_SIZE))){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_GetSheKey(
  uint8 sheKeyId
   ,  McalCry_SizeOfShePageType shePage
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, MCALCRY_APPL_VAR) indexOfSheKeyPtr){
  Std_ReturnType found = E_NOT_OK;
  McalCry_SheKeysIterType i;

  for(i = 0u; i < McalCry_GetSizeOfSheKeys(); i++){
    if((McalCry_GetSheIdOfSheKeys(i) == sheKeyId) &&
        (McalCry_GetShePageIdxOfSheKeys(i) == shePage)){
      *indexOfSheKeyPtr = (McalCry_SizeOfSheKeysType)i;
      found = E_OK;
      break;
    }
  }

  return found;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckM1Ids(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2VAR(McalCry_SizeOfSheKeysType, AUTOMATIC, MCALCRY_APPL_VAR) indexOfAuthSheKeyPtr){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 m1AuthId, m1SheId;
  McalCry_SizeOfShePageType authPage;
  boolean loadAuthKey = FALSE;

  m1AuthId = McalCry_She_M1_GetAuthId(m1m2m3[MCALCRY_STARTINDEX_SHE_M1_IDS]);
  m1SheId = McalCry_She_M1_GetId(m1m2m3[MCALCRY_STARTINDEX_SHE_M1_IDS]);

  if(m1SheId == MCALCRY_SHE_M1_SECRET_KEY_ID){
  }

  else if(m1SheId == McalCry_GetSheIdOfSheKeys(indexOfSheKey)){
    authPage = MCALCRY_SHE_PAGE0;

    if((m1SheId != MCALCRY_SHE_M1_MAC_ID) &&
             (m1SheId <= MCALCRY_SHE_M1_KEY_N_END_ID)){
      if(m1AuthId == MCALCRY_SHE_M1_ECU_MASTER_KEY_ID)
      {
        loadAuthKey = TRUE;
      }

      else if(m1AuthId == m1SheId)
      {
        *indexOfAuthSheKeyPtr = indexOfSheKey;
        retVal = E_OK;
      }
      else
      {
      }
    }

    else if(m1SheId == MCALCRY_SHE_M1_MAC_ID){
      if(m1AuthId == MCALCRY_SHE_M1_ECU_MASTER_KEY_ID)
      {
        loadAuthKey = TRUE;
      }

      else if(m1AuthId == MCALCRY_SHE_M1_MAC_KEY_ID)
      {
        loadAuthKey = TRUE;
      }
      else
      {
      }
    }

    else{
      if(m1AuthId == MCALCRY_SHE_M1_SECRET_KEY_ID)
      {
        loadAuthKey = TRUE;
      }

      else if((m1AuthId >= MCALCRY_SHE_M1_KEY_N_START_ID) &&
               (m1AuthId <= MCALCRY_SHE_M1_KEY_N_END_ID))
      {
        loadAuthKey = TRUE;
        authPage = McalCry_GetShePageIdxOfSheKeys(indexOfSheKey);
      }
      else
      {
      }
    }

    if(loadAuthKey == TRUE){
      retVal = McalCry_GetSheKey(m1AuthId, authPage, indexOfAuthSheKeyPtr);
    }
  }
  else{
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckUid(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_SheKeyTypeType sheKeyType){
  uint8 i;
  Std_ReturnType retVal = E_NOT_OK;
  boolean verified;
  uint32 uidLength = MCALCRY_SIZEOF_SHE_M1_UID;
  McalCry_SizeOfKeyStorageType uIdStorageIndex;

  verified = TRUE;

  for(i = 0u; i < MCALCRY_SIZEOF_SHE_M1_UID; i++){
    if(m1m2m3[i] != MCALCRY_SHE_UID_WILDCARD_VALUE){
      verified = FALSE;
      break;
    }
  }

  if(verified == FALSE){
    if(McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_UID, &uIdStorageIndex, &uidLength, MCALCRY_LENGTH_CHECK_MIN) == E_OK){
      verified = TRUE;
      for(i = 0u; i < MCALCRY_SIZEOF_SHE_M1_UID; i++)
      {
        if(m1m2m3[i] != McalCry_GetKeyStorage(uIdStorageIndex + i))
        {
          verified = FALSE;
          break;
        }
      }
    }
  }
  else{
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

    if((McalCry_IsKeyElementExtensionByMask(elementIndex, MCALCRY_SHE_FID_MASK_WILDCARD)) &&
        (sheKeyType != MCALCRY_SHE_TYPE_RAM_KEY)){
      verified = FALSE;
    }
#else
    MCALCRY_DUMMY_STATEMENT(sheKeyType);
    MCALCRY_DUMMY_STATEMENT(elementIndex);
#endif
  }

  if(verified == TRUE){
    retVal = E_OK;
  }
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateVerifyM3(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  uint8 KDFbufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr){
  Std_ReturnType retVal = E_NOT_OK;
  uint8_least i;

  uint8 key[MCALCRY_SIZEOF_SHE_KEY];
  uint32 authKeyLength = MCALCRY_SIZEOF_SHE_KEY;
  McalCry_SizeOfKeyStorageType keyStorageIndex;
  eslt_WorkSpaceCMACAES workSpaceCmacAes;

  if(McalCry_IsKeyElementValid(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfAuthSheKey))){
    if(McalCry_Local_KeyElementGetStorageIndexBasic( McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfAuthSheKey), &keyStorageIndex, &authKeyLength, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE) == E_OK){
      McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrMacConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);

      McalCry_CopyData(KDFbufferPtr, McalCry_GetAddrKeyStorage(keyStorageIndex), MCALCRY_SIZEOF_SHE_KEY);

      if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, KDFbufferLength, key) == E_OK)
      {
        if(McalCry_SheKeyUpdateCmac(m1m2m3, MCALCRY_STARTINDEX_SHE_M3, key, outputBufferPtr, (P2VAR(eslt_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workSpaceCmacAes) == E_OK)
        {
          retVal = E_OK;

          for(i = 0u; i < MCALCRY_SIZEOF_SHE_M3; i++)
          {
            if(m1m2m3[i + MCALCRY_STARTINDEX_SHE_M3] != outputBufferPtr[i])
            {
              retVal = E_NOT_OK;
            }
          }
        }
      }
    }
  }

  return retVal;
}

#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateCheckCounter(
  McalCry_SizeOfKeyElementsType elementIndexCounter
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr
   ,  McalCry_SheKeyTypeType sheKeyType){
  uint32 oldCounter, newCounter;
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyStorageType keyStorage;
  uint32 counterLength = MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES;

  if(sheKeyType == MCALCRY_SHE_TYPE_RAM_KEY){
    retVal = E_OK;
  }
  else{
    (void)McalCry_Local_KeyElementGetStorageIndexBasic( elementIndexCounter, &keyStorage, &counterLength, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE);

    McalCry_Local_Uint8ArrayToUint32BigEndian(&oldCounter, McalCry_GetAddrKeyStorage(keyStorage));
    McalCry_Local_Uint8ArrayToUint32BigEndian(&newCounter, decryptedKeyPtr);
    newCounter = McalCry_She_ConvertCounter(newCounter);

    if((newCounter) > (oldCounter)){
      retVal = E_OK;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateCopyCounter(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndexCounter
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr){
  uint32 newCounter;
  uint8 counterValue[MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES];

  McalCry_Local_Uint8ArrayToUint32BigEndian(&newCounter, decryptedKeyPtr);
  newCounter = McalCry_She_ConvertCounter(newCounter);
  McalCry_Local_Uint32ToUint8ArrayBigEndian(counterValue, newCounter);
  McalCry_KeyElementSetInternalStandardWithCryptoKeyId(cryptoKeyId, elementIndexCounter, counterValue, MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES);
}
#endif

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateCopyFid(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) decryptedKeyPtr
   ,  McalCry_SheKeyTypeType sheKeyType){
  uint8 fid;

  fid = (uint8)(((uint8)(decryptedKeyPtr[3] << 4)) | ((uint8)(decryptedKeyPtr[4] >> 4) & 0x0Cu));

  fid |= MCALCRY_KEYELEMENTSEXTENSION_SHE_KEY_MASK;
  McalCry_SetKeyStorage(McalCry_GetKeyStorageExtensionIdxOfKeyElements(elementIndex), fid);

  if((McalCry_Uint8CheckMask(fid, MCALCRY_SHE_FID_MASK_WRITE_PROTECTION)) &&
      (sheKeyType != MCALCRY_SHE_TYPE_RAM_KEY)){
    McalCry_SetKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK);
  }
  else{
    McalCry_ClearKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_INV_MASK);
  }
}
#endif

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateExtractKey(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  uint8 KDFbufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey){
  Std_ReturnType retVal = E_NOT_OK;
  uint8_least i;

  uint8 key[MCALCRY_SIZEOF_SHE_KEY];
  McalCry_KeyStorageIterType keyStorageIndex = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndex);

  McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrEncConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);

  if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, KDFbufferLength, key) == E_OK){
    McalCry_ClearData(outputBufferPtr, MCALCRY_SIZEOF_SHE_M2);

    if(McalCry_SheKeyUpdateDecrypt(&m1m2m3[MCALCRY_STARTINDEX_SHE_M2], key, outputBufferPtr) == E_OK){
#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)
      McalCry_SheKeyTypeType sheKeyType;
      sheKeyType = McalCry_SheKeyGetKeyType(McalCry_GetSheIdOfSheKeys(indexOfSheKey));
      if(McalCry_SheKeyUpdateCheckCounter(McalCry_GetKeyElementsCounterIdxOfSheKeys(indexOfSheKey), outputBufferPtr, sheKeyType) == E_OK)
#endif
      {
        for(i = 0u; i < MCALCRY_SIZEOF_SHE_KEY; i++)
        {
          McalCry_SetKeyStorage(keyStorageIndex + i, outputBufferPtr[MCALCRY_SIZEOF_SHE_KEY + i]);

          KDFbufferPtr[i] = outputBufferPtr[MCALCRY_SIZEOF_SHE_KEY + i];
        }

        McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, elementIndex, MCALCRY_SIZEOF_SHE_KEY);
        retVal = E_OK;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateGenM4M5(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m4m5
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) encBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey){
  Std_ReturnType retVal = E_NOT_OK;

  uint8 key[MCALCRY_SIZEOF_SHE_KEY];
  eslt_WorkSpaceCMACAES workSpaceCmacAes;

  McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrEncConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);

  if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, MCALCRY_SIZEOF_KDF_BUFFER, key) == E_OK){
    encBufferPtr[MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES - 1u] |= 0x08u;
    encBufferPtr[MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES - 1u] &= 0xF8u;

    McalCry_ClearData(&(encBufferPtr[4]), MCALCRY_SIZEOF_SHE_M4_ENC - MCALCRY_SIZEOF_SHE_M4_COUNTER_FULL_BYTES);

    McalCry_CopyData(m4m5, uid, MCALCRY_SIZEOF_SHE_M1_UID);

    McalCry_CopyData(&m4m5[MCALCRY_STARTINDEX_SHE_M1_IDS], &m1m2m3[MCALCRY_STARTINDEX_SHE_M1_IDS], MCALCRY_SIZEOF_SHE_M1_IDS);

    if(McalCry_SheKeyUpdateEncrypt(encBufferPtr, key, &m4m5[MCALCRY_SIZEOF_SHE_KEY], 1u) == E_OK){
      McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrMacConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);

      if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, MCALCRY_SIZEOF_KDF_BUFFER, key) == E_OK)
      {
        retVal = McalCry_SheKeyUpdateCmac(m4m5, 32u, key, &m4m5[32], &workSpaceCmacAes);
      }
    }
  }
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateProofM4M5(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfKeyElementsType outputElement
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) outputBufferPtr
   ,  McalCry_SizeOfSheKeysType indexOfSheKey){
  Std_ReturnType retVal = E_NOT_OK;
  uint32 uidLength = MCALCRY_SIZEOF_SHE_M1_UID;
  McalCry_SizeOfKeyStorageType uIdStorageIndex;

  uint8 m4m5[MCALCRY_SIZEOF_SHE_M4_M5];

  if(McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_UID, &uIdStorageIndex, &uidLength, MCALCRY_LENGTH_CHECK_MIN) == E_OK){
    retVal = McalCry_SheKeyUpdateGenM4M5(m1m2m3, m4m5, McalCry_GetAddrKeyStorage(uIdStorageIndex), KDFbufferPtr, outputBufferPtr, indexOfSheKey);
    if(retVal == E_OK){
      McalCry_CopyData(McalCry_GetAddrKeyStorageOfKeyElements(outputElement), m4m5, MCALCRY_SIZEOF_SHE_M4_M5);

      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, outputElement, MCALCRY_SIZEOF_SHE_M4_M5);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateFindProof(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementsIterType, AUTOMATIC, AUTOMATIC) outputElementIndexPtr){
  Std_ReturnType retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  McalCry_KeyElementsIterType outputElement;

  for(outputElement = McalCry_GetKeyElementsStartIdxOfKey(cryptoKeyId);
       outputElement < McalCry_GetKeyElementsEndIdxOfKey(cryptoKeyId);
       outputElement++){
    if((McalCry_GetIdOfKeyElements(outputElement) == CRYPTO_KE_MAC_PROOF)||
        (McalCry_GetIdOfKeyElements(outputElement) == CRYPTO_KE_CIPHER_PROOF)){
      if((McalCry_GetKeyStorageEndIdxOfKeyElements(outputElement) - McalCry_GetKeyStorageStartIdxOfKeyElements(outputElement)) >= (uint16)MCALCRY_SIZEOF_SHE_M4_M5)
      {
        *outputElementIndexPtr = outputElement;
        retVal = E_OK;
      }
      else
      {
        retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
      }
      break;
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateLockKeys(
  uint32 cryptoKeyId
   ,  uint32 authKeyId){
  Std_ReturnType retVal = E_NOT_OK;
  uint32 sheInfoKeyId;

  sheInfoKeyId = McalCry_GetSheInfoKeyRefOfSheKeyUpdate();

  if(McalCry_Local_KeyReadLockGet(sheInfoKeyId) == E_OK){
    if(authKeyId != cryptoKeyId){
      if(McalCry_Local_KeyReadLockGet(authKeyId) == E_OK)
      {
        retVal = E_OK;
      }
      else
      {
        McalCry_Local_KeyReadLockRelease(sheInfoKeyId);
      }
    }
    else{
      retVal = E_OK;
    }
  }
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_SheKeyUpdateUnlockKeys(
  uint32 cryptoKeyId
   ,  uint32 authKeyId){
  uint32 sheInfoKeyId;

  sheInfoKeyId = McalCry_GetSheInfoKeyRefOfSheKeyUpdate();

  McalCry_Local_KeyReadLockRelease(sheInfoKeyId);

  if(authKeyId != cryptoKeyId){
    McalCry_Local_KeyReadLockRelease(authKeyId);
  }
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdateVerifyAndExtract(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  McalCry_SizeOfKeyElementsType outputElement
   ,  Std_ReturnType proofAvailable){
  uint8 KDFbuffer[MCALCRY_SIZEOF_KDF_BUFFER];

  uint8 encBuffer[MCALCRY_SIZEOF_ENC_BUFFER];

  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SheKeyTypeType sheKeyType = McalCry_SheKeyGetKeyType(McalCry_GetSheIdOfSheKeys(indexOfSheKey));

  if(McalCry_SheKeyUpdateVerifyM3(m1m2m3, indexOfAuthSheKey, indexOfSheKey, KDFbuffer, MCALCRY_SIZEOF_KDF_BUFFER, encBuffer) == E_OK){
    if(McalCry_SheKeyUpdateCheckUid(m1m2m3, elementIndex, sheKeyType) == E_OK){
      retVal = McalCry_SheKeyUpdateExtractKey(cryptoKeyId, m1m2m3, elementIndex, KDFbuffer, MCALCRY_SIZEOF_KDF_BUFFER, encBuffer, indexOfSheKey);

      if(retVal == E_OK)
      {
#if(MCALCRY_SHE_ENABLE_COUNTER == STD_ON)

        if(McalCry_IsKeyElementsCounterUsedOfSheKeys(indexOfSheKey))
        {
          McalCry_SheKeyUpdateCopyCounter(cryptoKeyId, McalCry_GetKeyElementsCounterIdxOfSheKeys(indexOfSheKey), encBuffer);
        }
#endif
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)
        McalCry_SheKeyUpdateCopyFid(elementIndex, encBuffer, sheKeyType);
#else
        McalCry_ClearKeyElementExtensionByMask(elementIndex, MCALCRY_KEYELEMENTSEXTENSION_SHE_CLEAR_PLAIN_KEY_MASK);
#endif

        if(proofAvailable == E_OK)
        {
          retVal = McalCry_SheKeyUpdateProofM4M5(cryptoKeyId, m1m2m3, (McalCry_SizeOfKeyElementsType)outputElement, KDFbuffer, encBuffer, indexOfSheKey);
        }
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyUpdate(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3){
  Std_ReturnType retVal = E_NOT_OK;
  Std_ReturnType proofAvailable;
  McalCry_KeyElementsIterType outputElement = 0u;
  McalCry_SizeOfSheKeysType indexOfAuthSheKey = 0u;

  proofAvailable = McalCry_SheKeyUpdateFindProof(cryptoKeyId, &outputElement);

  if((proofAvailable == E_OK) ||
    (proofAvailable == CRYPTO_E_KEY_NOT_AVAILABLE)){
    if(McalCry_SheKeyUpdateCheckM1Ids(m1m2m3, indexOfSheKey, &indexOfAuthSheKey) == E_OK){
      if(McalCry_SheKeyUpdateLockKeys(cryptoKeyId, McalCry_GetKeyIdxOfSheKeys(indexOfAuthSheKey)) == E_OK)
      {
        retVal = McalCry_SheKeyUpdateVerifyAndExtract(cryptoKeyId, elementIndex, m1m2m3, indexOfSheKey, indexOfAuthSheKey, (McalCry_SizeOfKeyElementsType)outputElement, proofAvailable);

        McalCry_SheKeyUpdateUnlockKeys(cryptoKeyId, McalCry_GetKeyIdxOfSheKeys(indexOfAuthSheKey));
      }
      else
      {
        retVal = CRYPTO_E_BUSY;
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSetShe(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength
   ,  Std_ReturnType oldRetVal){
  Std_ReturnType retVal = oldRetVal;
  McalCry_SizeOfSheKeysType indexOfSheKey;

  if(McalCry_IsKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK)){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
  }

  else if((keyLength == MCALCRY_SIZEOF_SHE_M1_M3) &&
    (McalCry_GetKeyElementLength(elementIndex) == MCALCRY_SIZEOF_SHE_KEY)){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
    if(McalCry_SheKeyGetSheIndex(elementIndex, &indexOfSheKey) == E_OK){
      if((MCALCRY_WA_ENCRYPTED == McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))) ||
        ((MCALCRY_WA_ALLOWED == McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))) &&
          (McalCry_GetSheIdOfSheKeys(indexOfSheKey) == MCALCRY_SHE_M1_RAM_KEY_ID)))
      {
        retVal = McalCry_SheKeyUpdate(cryptoKeyId, elementIndex, indexOfSheKey, keyPtr);
      }
    }
  }

  else if((keyLength == MCALCRY_SIZEOF_SHE_KEY)){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
    if(MCALCRY_WA_ALLOWED == McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))){
      if(McalCry_SheKeyGetSheIndex(elementIndex, &indexOfSheKey) == E_OK)
      {
        if(McalCry_GetSheIdOfSheKeys(indexOfSheKey) == MCALCRY_SHE_M1_RAM_KEY_ID)
        {
          retVal = McalCry_Local_KeyElementSetInternal(cryptoKeyId, elementIndex, keyPtr, keyLength, MCALCRY_WA_ENCRYPTED);

          if(retVal == E_OK)
          {
            McalCry_SetKeyElementExtensionByMask(elementIndex, MCALCRY_KEYELEMENTSEXTENSION_SHE_PLAIN_KEY_MASK);
          }
        }
      }
    }
  }
  else{
  }
  return retVal;
}

#if(MCALCRY_RAM_KEY_EXPORT == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetShe(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfSheKeysType indexOfSheKey, indexOfAuthSheKey = 0u;

  if(McalCry_SheKeyGetSheIndex(elementIndex, &indexOfSheKey) == E_OK){
    if(McalCry_GetSheIdOfSheKeys(indexOfSheKey) == MCALCRY_SHE_M1_RAM_KEY_ID){
      if(*resultLengthPtr >= MCALCRY_SIZEOF_SHE_M1_M3)
      {
        (void)McalCry_GetSheKey(MCALCRY_SHE_M1_SECRET_KEY_ID, MCALCRY_SHE_PAGE0, &indexOfAuthSheKey);

        if(McalCry_SheKeyUpdateLockKeys(cryptoKeyId, (uint32)McalCry_GetKeyIdxOfSheKeys(indexOfAuthSheKey)) == E_OK)
        {
          retVal = McalCry_SheKeyExport(indexOfSheKey, indexOfAuthSheKey, resultPtr, resultLengthPtr);

          McalCry_SheKeyUpdateUnlockKeys(cryptoKeyId, McalCry_GetKeyIdxOfSheKeys(indexOfAuthSheKey));
        }
        else
        {
          retVal = CRYPTO_E_BUSY;
        }
      }
      else
      {
        retVal = CRYPTO_E_SMALL_BUFFER;
      }
    }
    else{
      retVal = CRYPTO_E_KEY_READ_FAIL;
    }
  }
  else{
    retVal = CRYPTO_E_KEY_READ_FAIL;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyExport_M1M2M3(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) m1m2m3
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) KDFbufferPtr
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) encBufferPtr
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) ramKey
   ,  McalCry_SizeOfSheKeysType indexOfSheKey){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 key[MCALCRY_SIZEOF_SHE_KEY];
  eslt_WorkSpaceCMACAES workSpaceCmacAes;

  McalCry_CopyData(m1m2m3, uid, MCALCRY_SIZEOF_SHE_M1_UID);
  m1m2m3[MCALCRY_STARTINDEX_SHE_M1_IDS] = McalCry_She_M1_BuildIds(MCALCRY_SHE_M1_RAM_KEY_ID, MCALCRY_SHE_M1_SECRET_KEY_ID);

  McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrEncConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);

  if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, MCALCRY_SIZEOF_SHE_KEY + MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT, key) == E_OK){
    McalCry_ClearData(encBufferPtr, MCALCRY_SIZEOF_SHE_KEY);
    McalCry_CopyData(&encBufferPtr[MCALCRY_SIZEOF_SHE_KEY], ramKey, MCALCRY_SIZEOF_SHE_KEY);

    if(McalCry_SheKeyUpdateEncrypt(encBufferPtr, key, &m1m2m3[MCALCRY_STARTINDEX_SHE_M2], 2u) == E_OK){
      McalCry_CopyData(&KDFbufferPtr[MCALCRY_SIZEOF_SHE_KEY], McalCry_She_GetPtrMacConst(indexOfSheKey), MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT);
      if(McalCry_SheKeyUpdateMiyaguchiPreneel(KDFbufferPtr, MCALCRY_SIZEOF_SHE_KEY + MCALCRY_SIZEOF_SHE_UPDATE_CONSTANT, key) == E_OK)
      {
        if(McalCry_SheKeyUpdateCmac(m1m2m3, MCALCRY_STARTINDEX_SHE_M3, key, &m1m2m3[MCALCRY_STARTINDEX_SHE_M3], &workSpaceCmacAes) == E_OK)
        {
          retVal = E_OK;
        }
      }
    }

  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_SheKeyExport(
  McalCry_SizeOfSheKeysType indexOfSheKey
   ,  McalCry_SizeOfSheKeysType indexOfAuthSheKey
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  uint8 m1m5[MCALCRY_SIZEOF_SHE_M1_M5];
  uint8 kdfBuffer[MCALCRY_SIZEOF_KDF_BUFFER];
  uint8 encBuffer[MCALCRY_SIZEOF_ENC_BUFFER];
  uint32 writtenLength = MCALCRY_SIZEOF_SHE_M1_M3;

  McalCry_SizeOfKeyStorageType uIdStorageIndex, keyStorageIndex, authKeyStorageIndex;
  uint32 length;

  length = MCALCRY_SIZEOF_SHE_M1_UID;
  localRet = McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_UID, &uIdStorageIndex, &length, MCALCRY_LENGTH_CHECK_MIN);

  if(localRet == E_OK){
    length = MCALCRY_SIZEOF_SHE_KEY;
    localRet = McalCry_Local_KeyElementGetStorageIndexBasic( McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfAuthSheKey), &authKeyStorageIndex, &length, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE);
    if(!McalCry_IsKeyElementValid(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfAuthSheKey))){
      localRet = E_NOT_OK;
    }

    if(localRet == E_OK){
      length = MCALCRY_SIZEOF_SHE_KEY;
      localRet = McalCry_Local_KeyElementGetStorageIndexBasic( McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfSheKey), &keyStorageIndex, &length, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE);

      if(localRet == E_OK)
      {
        if(!McalCry_IsKeyElementExtensionByMask(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfSheKey), MCALCRY_KEYELEMENTSEXTENSION_SHE_PLAIN_KEY_MASK))
        {
          retVal = CRYPTO_E_KEY_READ_FAIL;
          localRet = E_NOT_OK;
        }

        if(localRet == E_OK)
        {
          McalCry_CopyData(kdfBuffer, McalCry_GetAddrKeyStorage(authKeyStorageIndex), MCALCRY_SIZEOF_SHE_KEY);
          retVal = McalCry_SheKeyExport_M1M2M3(m1m5, kdfBuffer, encBuffer, McalCry_GetAddrKeyStorage(uIdStorageIndex), McalCry_GetAddrKeyStorage(keyStorageIndex), indexOfSheKey);

          if((retVal == E_OK) &&
              (*resultLengthPtr >= MCALCRY_SIZEOF_SHE_M1_M5))
          {
            McalCry_CopyData(kdfBuffer, McalCry_GetAddrKeyStorage(keyStorageIndex), MCALCRY_SIZEOF_SHE_KEY);
            retVal = McalCry_SheKeyUpdateGenM4M5(m1m5, &m1m5[MCALCRY_STARTINDEX_SHE_M4], McalCry_GetAddrKeyStorage(uIdStorageIndex), kdfBuffer, encBuffer, indexOfSheKey);
            writtenLength = MCALCRY_SIZEOF_SHE_M1_M5;
          }

          if(retVal == E_OK)
          {
            McalCry_CopyData(resultPtr, m1m5, writtenLength);
            *resultLengthPtr = writtenLength;
          }
        }
      }
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_Authorization(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) masterKey
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) uid
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) challenge
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) authorization){
  Std_ReturnType retVal = E_NOT_OK;
  const uint8 debugKeyC[MCALCRY_SIZEOF_SHE_KEY] = { 0x01U, 0x03U, 0x53U, 0x48U, 0x45U, 0x00U, 0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0xB0U };

  uint8 key[MCALCRY_SIZEOF_SHE_KEY];
  uint8 result[MCALCRY_SIZEOF_SHE_KEY];
  uint8 buffer[MCALCRY_SIZEOF_KDF_BUFFER];
  uint8_least i;
  eslt_WorkSpaceCMACAES workSpaceCmacAes;

  McalCry_CopyData(buffer, masterKey, MCALCRY_SIZEOF_SHE_KEY);
  McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_KEY], debugKeyC, MCALCRY_SIZEOF_SHE_KEY);
  if(McalCry_SheKeyUpdateMiyaguchiPreneel(buffer, MCALCRY_SIZEOF_KDF_BUFFER, key) == E_OK){
    McalCry_CopyData(buffer, challenge, MCALCRY_SIZEOF_SHE_KEY);
    McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_KEY], uid, MCALCRY_SIZEOF_SHE_M1_UID);
    if(McalCry_SheKeyUpdateCmac(buffer, MCALCRY_SIZEOF_SHE_KEY + MCALCRY_SIZEOF_SHE_M1_UID, key, result, &workSpaceCmacAes) == E_OK){
      retVal = E_OK;
      for(i = 0u; i < MCALCRY_SIZEOF_SHE_KEY; i++)
      {
        if(authorization[i] != result[i])
        {
          retVal = E_NOT_OK;
        }
      }
    }
  }

  return retVal;
}

#if(MCALCRY_SHE_ENABLE_FID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_She_DebugCmd_IsWriteProtected(void){
  boolean writeProtection = FALSE;
  McalCry_KeyIterType keyIdx;
  McalCry_KeyElementsIterType elementIdx;

  for(keyIdx = 0u; keyIdx < McalCry_GetSizeOfKey(); keyIdx++){
    if(McalCry_IsDebugDeletionOfKey(keyIdx)){
      for(elementIdx = McalCry_GetKeyElementsStartIdxOfKey(keyIdx); elementIdx < McalCry_GetKeyElementsEndIdxOfKey(keyIdx); elementIdx++)
      {
        if(McalCry_IsKeyElementStateByMask(elementIdx, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK))
        {
          writeProtection = TRUE;
          break;
        }
      }
    }
  }

  return writeProtection;
}
#endif

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_She_DebugCmd_DeleteKeys(void){
  McalCry_KeyIterType keyIdx;
  McalCry_SheKeysIterType sheKeyIndex;
  McalCry_KeyElementsIterType elementIdx;

  for(keyIdx = 0u; keyIdx < McalCry_GetSizeOfKey(); keyIdx++){
    if(McalCry_IsDebugDeletionOfKey(keyIdx)){
      for(elementIdx = McalCry_GetKeyElementsStartIdxOfKey(keyIdx); elementIdx < McalCry_GetKeyElementsEndIdxOfKey(keyIdx); elementIdx++)
      {
        McalCry_ClearData(McalCry_GetAddrKeyStorageOfKeyElements(elementIdx), McalCry_GetKeyElementLength(elementIdx));

        McalCry_Init_Key(elementIdx, FALSE);

#if(MCALCRY_KEYVALUECHANGEDCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

        McalCry_GetKeyValueChangedCalloutFctNameOfConfigurableCallouts()(keyIdx, McalCry_GetIdOfKeyElements(elementIdx));
#endif
      }
    }
  }

  for(sheKeyIndex = 0u; sheKeyIndex < McalCry_GetSizeOfSheKeys(); sheKeyIndex++){
    elementIdx = McalCry_GetKeyElementsKeyIdxOfSheKeys(sheKeyIndex);
    McalCry_Init_KeySheAdditional(elementIdx);
  }

#if(MCALCRY_KEYVALIDITYSETCALLOUTFCTNAMEOFCONFIGURABLECALLOUTS == STD_ON)

  {
    boolean isValid;

    for(keyIdx = 0u; keyIdx < McalCry_GetSizeOfKey(); keyIdx++){
      isValid = TRUE;

      if(McalCry_IsDebugDeletionOfKey(keyIdx))
      {
        for(elementIdx = McalCry_GetKeyElementsStartIdxOfKey(keyIdx); elementIdx < McalCry_GetKeyElementsEndIdxOfKey(keyIdx); elementIdx++)
        {
          if(!McalCry_IsKeyElementValid(elementIdx))
          {
            isValid = FALSE;
            break;
          }
        }

        if(isValid == TRUE)
        {
          McalCry_GetKeyValiditySetCalloutFctNameOfConfigurableCallouts()(keyIdx, TRUE);
        }
      }
    }
  }
#endif
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_GetChallenge(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode localRet;

  if(*resultLengthPtr >= MCALCRY_SIZEOF_SHE_KEY){
#if(MCALCRY_SHE_ENABLE_FID == STD_ON)
    if(!McalCry_She_DebugCmd_IsWriteProtected())
#endif
    {
      localRet = esl_getBytesRNG( MCALCRY_SIZEOF_SHE_KEY, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))McalCry_She_Debug_Cmd_Challenge );
      if(localRet == E_OK)
      {
        McalCry_CopyData(resultPtr, McalCry_She_Debug_Cmd_Challenge, MCALCRY_SIZEOF_SHE_KEY);
        *resultLengthPtr = MCALCRY_SIZEOF_SHE_KEY;
        McalCry_She_Debug_Cmd_ChallengeFlag = TRUE;
        retVal = E_OK;
      }
      else
      {
        retVal = E_NOT_OK;
      }
    }
  }
  else{
    retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_SetAuthorization(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  McalCry_SizeOfSheKeysType indexOfSheKey = 0u;
  McalCry_SizeOfKeyStorageType uIdStorageIndex, keyStorageIndex = 0u;
  uint32 length;

  McalCry_She_Debug_Cmd_ChallengeFlag = FALSE;

  localRet = McalCry_GetSheKey(MCALCRY_SHE_M1_ECU_MASTER_KEY_ID, MCALCRY_SHE_PAGE0, &indexOfSheKey);

  length = MCALCRY_SIZEOF_SHE_M1_UID;
  localRet |= McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_UID, &uIdStorageIndex, &length, MCALCRY_LENGTH_CHECK_MIN);

  if(localRet == E_OK){
    length = MCALCRY_SIZEOF_SHE_KEY;
    localRet = McalCry_Local_KeyElementGetStorageIndexBasic(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfSheKey), &keyStorageIndex, &length, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE);

    if(localRet == E_OK){
      retVal = McalCry_She_DebugCmd_Authorization(McalCry_GetAddrKeyStorage(keyStorageIndex), McalCry_GetAddrKeyStorage(uIdStorageIndex), McalCry_She_Debug_Cmd_Challenge, keyPtr);
      if(retVal == E_OK)
      {
        McalCry_She_DebugCmd_DeleteKeys();
      }
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_DebugCmd_SetAuthorizationAndLock(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength){
  McalCry_KeyIterType lockedKeyIdx, releaseKeyIdx;
#if(MCALCRY_NVBLOCK == STD_ON)
  McalCry_KeyElementsIterType elementIdx;
  boolean persist;
#endif
  Std_ReturnType retVal = E_NOT_OK;

  if((keyLength == MCALCRY_SIZEOF_SHE_KEY) &&
      McalCry_She_Debug_Cmd_ChallengeFlag){
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(lockedKeyIdx = 0u; lockedKeyIdx < McalCry_GetSizeOfKey(); lockedKeyIdx++){
      if(McalCry_IsDebugDeletionOfKey(lockedKeyIdx))
      {
        if(McalCry_Local_KeyWriteLockGetNotProtected((uint32)lockedKeyIdx) == E_NOT_OK)
        {
          retVal = CRYPTO_E_BUSY;
        }
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(retVal != CRYPTO_E_BUSY){
      retVal = McalCry_She_DebugCmd_SetAuthorization(keyPtr);
    }

    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(releaseKeyIdx = 0; releaseKeyIdx < lockedKeyIdx; releaseKeyIdx++){
      if(McalCry_IsDebugDeletionOfKey(releaseKeyIdx))
      {
        McalCry_Local_KeyWriteLockReleaseNotProtected((uint32)releaseKeyIdx);
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

#if(MCALCRY_NVBLOCK == STD_ON)
    if(retVal == E_OK){
      for(releaseKeyIdx = 0; releaseKeyIdx < lockedKeyIdx; releaseKeyIdx++)
      {
        persist = FALSE;

        if(McalCry_IsDebugDeletionOfKey(releaseKeyIdx))
        {
          for(elementIdx = McalCry_GetKeyElementsStartIdxOfKey(releaseKeyIdx); elementIdx < McalCry_GetKeyElementsEndIdxOfKey(releaseKeyIdx); elementIdx++)
          {
            if(McalCry_IsKeyElementPersist(elementIdx))
            {
              persist = TRUE;
            }
          }
          if(persist == TRUE)
          {
            McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(releaseKeyIdx));
          }
        }
      }
    }
#endif
  }
  else{
    retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  return retVal;
}
#endif
#endif

#if(MCALCRY_NVBLOCK == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Trigger_Write_Req(
  McalCry_SizeOfNvBlockType blockIdx){
  Std_ReturnType retVal = E_NOT_OK, localRet = E_OK;

#if(MCALCRY_NV_MENABLE_SET_RAM_BLOCK_STATUS == STD_ON)
  localRet = NvM_SetRamBlockStatus((NvM_BlockIdType)McalCry_GetDescriptorOfNvBlock(blockIdx), TRUE);
  if(localRet == E_OK)
#endif
  {
    if((McalCry_GetProcessingOfNvBlock(blockIdx) == MCALCRY_NV_PROCESSING_IMMEDIATE)){
      localRet = McalCry_NvM_WriteBlock((NvM_BlockIdType)McalCry_GetDescriptorOfNvBlock(blockIdx), NULL_PTR);
    }
  }

  if(localRet == E_OK){
    retVal = E_OK;
  }
  else{
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    McalCry_ClearNvBlockStateMask(blockIdx, MCALCRY_NVBLOCK_STATE_MASK_CLEAR_WRITE_REQUESTED);
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  }
  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_MainFunction(void){
  McalCry_NvBlockIterType blockIdx;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  for(blockIdx = 0; blockIdx < McalCry_GetSizeOfNvBlock(); blockIdx++){
    if(McalCry_GetNvBlockState(blockIdx) == MCALCRY_NVBLOCK_STATE_WRITE_REQ_PENDING){
      McalCry_SetNvBlockState(blockIdx, MCALCRY_NVBLOCK_STATE_WRITE_REQ);
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      (void)McalCry_NvBlock_Trigger_Write_Req((McalCry_SizeOfNvBlockType)blockIdx);

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    }
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_Write_Req(
  McalCry_SizeOfNvBlockType blockIdx){
  boolean setBlockStatus = FALSE;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  if(McalCry_IsNvBlockState(blockIdx, MCALCRY_NVBLOCK_STATE_IDLE)){
    McalCry_SetNvBlockState(blockIdx, MCALCRY_NVBLOCK_STATE_WRITE_REQ);
    setBlockStatus = TRUE;
  }

  else{
    McalCry_SetNvBlockStateMask(blockIdx, MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE);
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  if(setBlockStatus){
    (void)McalCry_NvBlock_Trigger_Write_Req(blockIdx);
  }
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_CallbackWrittenToBlock(
  McalCry_SizeOfNvBlockType blockIdx){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  McalCry_ClearNvBlockStateMask(blockIdx, MCALCRY_NVBLOCK_STATE_MASK_CLEAR_WRITE_COPIED);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_WrittenToBlock(
  McalCry_SizeOfNvBlockType blockIdx){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  if(McalCry_IsNvBlockStateMask(blockIdx, MCALCRY_NVBLOCK_STATE_MASK_DATA_CHANGE)){
    McalCry_SetNvBlockState(blockIdx, MCALCRY_NVBLOCK_STATE_COPY_DATA);
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock_Copy(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr){
  McalCry_SizeOfKeyStorageType length, writtenLength = 0u;

  McalCry_NvBlock_State_WrittenToBlock(blockIdx);

  if(McalCry_GetConsistencyLevelOfNvBlock(blockIdx) == MCALCRY_NV_CONSISTENCY_LEVEL_DETECT){
    McalCry_NvBlock_WriteToBlock_HeaderCrc(blockIdx, NvMBufferPtr, &writtenLength);
  }
  else{
  }

  length = (McalCry_SizeOfKeyStorageType)(McalCry_GetKeyStorageEndIdxOfNvBlock(blockIdx) - McalCry_GetKeyStorageStartIdxOfNvBlock(blockIdx));

  McalCry_CopyData(&NvMBufferPtr[writtenLength], McalCry_GetAddrKeyStorage(McalCry_GetKeyStorageStartIdxOfNvBlock(blockIdx)), length);
  writtenLength = (McalCry_SizeOfKeyStorageType)(writtenLength + length);

  McalCry_ClearData(&NvMBufferPtr[writtenLength], (McalCry_SizeOfKeyStorageType)(McalCry_GetLengthOfNvBlock(blockIdx) - (writtenLength)));
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_Copy(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_DATA) NvMBufferPtr){
  boolean validHeader = TRUE;
  McalCry_SizeOfKeyStorageType length, dataStartPos = 0u;

  McalCry_NvBlock_State_Init(blockIdx);

  if((McalCry_GetConsistencyLevelOfNvBlock(blockIdx) == MCALCRY_NV_CONSISTENCY_LEVEL_DETECT)){
    validHeader = McalCry_NvBlock_ReadFromBlock_HeaderCrc(blockIdx, NvMBufferPtr);
    dataStartPos = (McalCry_SizeOfKeyStorageType)MCALCRY_SIZEOF_NVBLOCK_HEADER_CRC;
  }

  if(validHeader){
    length = (McalCry_SizeOfKeyStorageType)(McalCry_GetKeyStorageEndIdxOfNvBlock(blockIdx) - McalCry_GetKeyStorageStartIdxOfNvBlock(blockIdx));
    McalCry_CopyData(McalCry_GetAddrKeyStorage(McalCry_GetKeyStorageStartIdxOfNvBlock(blockIdx)), &NvMBufferPtr[dataStartPos], length);
  }

  else{
    McalCry_NvBlock_ReadFromBlock_Restore(blockIdx);
  }

  return E_OK;
}

MCALCRY_LOCAL_INLINE FUNC(boolean, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_HeaderCrc(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_DATA) NvMBufferPtr){
  boolean validHeader = TRUE;
  uint32 crc;

  if(NvMBufferPtr[MCALCRY_POS_NVBLOCK_VERSION] != MCALCRY_NVBLOCK_VERSION_0){
    validHeader = FALSE;
  }

  if(NvMBufferPtr[MCALCRY_POS_NVBLOCK_FLAGS] != MCALCRY_NVBLOCK_FLAGS_0){
    validHeader = FALSE;
  }

  McalCry_Local_Uint8ArrayToUint32BigEndian(&crc, &NvMBufferPtr[MCALCRY_POS_NVBLOCK_CRC]);
  if(crc != McalCry_GetCrcOfNvBlock(blockIdx)){
    validHeader = FALSE;
  }

  return validHeader;
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock_HeaderCrc(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) writtenLengthPtr){
  NvMBufferPtr[MCALCRY_POS_NVBLOCK_VERSION] = MCALCRY_NVBLOCK_VERSION_0;

  NvMBufferPtr[MCALCRY_POS_NVBLOCK_FLAGS] = MCALCRY_NVBLOCK_FLAGS_0;

  McalCry_Local_Uint32ToUint8ArrayBigEndian(&NvMBufferPtr[MCALCRY_POS_NVBLOCK_CRC], McalCry_GetCrcOfNvBlock(blockIdx));
  *writtenLengthPtr = (McalCry_SizeOfKeyStorageType)(*writtenLengthPtr + MCALCRY_SIZEOF_NVBLOCK_HEADER_CRC);
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock_Restore(
  McalCry_SizeOfNvBlockType blockIdx){
  (void)McalCry_NvBlock_Init(blockIdx);
}
#endif

#if(MCALCRY_SHECMDGETID == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_She_Cmd_Get_Status(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) statusPtr){
  Std_ReturnType retVal;
  McalCry_SizeOfKeyStorageType bootProtectionElementIndexPtr = 0u;
  McalCry_SizeOfKeyStorageType debuggerProtectionElementIndexPtr = 0u;
  uint32 elementLength = 1u;

  *statusPtr = MCALCRY_SHE_CLEARED_STATUS;

  retVal = McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_BOOT_PROTECTION, &bootProtectionElementIndexPtr, &elementLength, MCALCRY_LENGTH_CHECK_EQUAL);
  retVal |= McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_DEBUGGER_PROTECTION, &debuggerProtectionElementIndexPtr, &elementLength, MCALCRY_LENGTH_CHECK_EQUAL);

  if(retVal == E_OK){
    if((*(McalCry_GetAddrKeyStorage(bootProtectionElementIndexPtr)) == 1u)){
      *statusPtr |= MCALCRY_SHE_STATUS_BOOT_FINISHED;
      *statusPtr |= MCALCRY_SHE_STATUS_BOOT_OK;
    }

    if((*(McalCry_GetAddrKeyStorage(debuggerProtectionElementIndexPtr)) == 0u)){
      *statusPtr |= MCALCRY_SHE_STATUS_EXT_DEBUGGER;
    }
  }
  else{
    retVal = E_NOT_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_USE_VSTD_LIB == STD_OFF)

FUNC(void, MCALCRY_CODE) McalCry_Local_CopyData_Implementation(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) sourceData
   ,  uint32 dataLength){
  uint32_least byteIdx;

  for(byteIdx = 0u; byteIdx < dataLength; byteIdx++){
    targetData[byteIdx] = sourceData[byteIdx];
  }
}

FUNC(void, MCALCRY_CODE) McalCry_Local_SetData_Implementation(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) dataBuf
   ,  uint8 pattern
   ,  uint32 dataLength){
  uint32_least byteIdx;

  for(byteIdx = 0u; byteIdx < dataLength; byteIdx++){
    dataBuf[byteIdx] = pattern;
  }
}

FUNC(void, MCALCRY_CODE) McalCry_Local_ClearData_Implementation(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) dataBuf
   ,  uint32 dataLength){
  McalCry_Local_SetData_Implementation(dataBuf, 0x00u, dataLength);
}
#endif

#if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_CompareData_IsSmaller(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) referenceData
   ,  uint32 dataLength){
  uint32_least byteIdx;
  Std_ReturnType retVal = E_NOT_OK;

  for(byteIdx = 0u; byteIdx < dataLength; byteIdx++){
    if(targetData[byteIdx] < referenceData[byteIdx]){
      retVal = E_OK;
      break;
    }
  }
  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyReadLockGetNotProtected(
  uint32 cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK;

  if((McalCry_GetKeyLock(cryptoKeyId) >= MCALCRY_KEY_LOCK_FREE) && (McalCry_GetKeyLock(cryptoKeyId) < MCALCRY_KEY_LOCK_READ_MAX)){
    McalCry_IncKeyLock(cryptoKeyId);
    retVal = E_OK;
  }

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyReadLockReleaseNotProtected(
  uint32 cryptoKeyId){
  if(McalCry_GetKeyLock(cryptoKeyId) > MCALCRY_KEY_LOCK_FREE){
    McalCry_DecKeyLock(cryptoKeyId);
  }
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyWriteLockGetNotProtected(
  uint32 cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK;

  if(McalCry_GetKeyLock(cryptoKeyId) == MCALCRY_KEY_LOCK_FREE){
    McalCry_SetKeyLock(cryptoKeyId, MCALCRY_KEY_LOCK_WRITE);
    retVal = E_OK;
  }

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyWriteLockReleaseNotProtected(
  uint32 cryptoKeyId){
  if(McalCry_GetKeyLock(cryptoKeyId) == MCALCRY_KEY_LOCK_WRITE){
    McalCry_SetKeyLock(cryptoKeyId, MCALCRY_KEY_LOCK_FREE);
  }

}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyReadLockGet(
  uint32 cryptoKeyId){
  Std_ReturnType retVal;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  retVal = McalCry_Local_KeyReadLockGetNotProtected(cryptoKeyId);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyReadLockRelease(
  uint32 cryptoKeyId){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  McalCry_Local_KeyReadLockReleaseNotProtected(cryptoKeyId);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyWriteLockGet(
  uint32 cryptoKeyId){
  Std_ReturnType retVal;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  retVal = McalCry_Local_KeyWriteLockGetNotProtected(cryptoKeyId);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyWriteLockRelease(
  uint32 cryptoKeyId){
  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  McalCry_Local_KeyWriteLockReleaseNotProtected(cryptoKeyId);
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSearch(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndex){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_KeyElementsIterType elementIdx;

  for(elementIdx = McalCry_GetKeyElementsStartIdxOfKey(cryptoKeyId); elementIdx < McalCry_GetKeyElementsEndIdxOfKey(cryptoKeyId); elementIdx++){
    if(keyElementId == McalCry_GetIdOfKeyElements(elementIdx)){
      retVal = E_OK;
      *elementIndex = (McalCry_SizeOfKeyElementsType)elementIdx;
      break;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_BinarySearchCryptoKeyId(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK;

  if(elementIndex < McalCry_GetSizeOfKeyElements()){
    McalCry_SizeOfKeyType minKey = 0u;
    McalCry_SizeOfKeyType maxKey = (McalCry_SizeOfKeyType)(McalCry_GetSizeOfKey() - 1u);
    McalCry_SizeOfKeyType middleKey = 0u;
    boolean keyFound = FALSE;

    while(!keyFound){
      middleKey = (McalCry_SizeOfKeyType)McalCry_Math_CalcMiddle(minKey, maxKey);

      if(elementIndex < McalCry_GetKeyElementsStartIdxOfKey(middleKey))
      {
        maxKey = (McalCry_SizeOfKeyType)(middleKey - 1u);
      }
      else if(elementIndex >= McalCry_GetKeyElementsEndIdxOfKey(middleKey))
      {
        minKey = (McalCry_SizeOfKeyType)(middleKey + 1u);
      }
      else
      {
        *cryptoKeyId = middleKey;
        retVal = E_OK;
        keyFound = TRUE;
      }
    }
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementIdsGet(
  uint32 cryptoKeyId
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) keyElementIdsPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) keyElementIdsLengthPtr){
  Std_ReturnType retVal;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(keyElementIdsPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(keyElementIdsLengthPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
    McalCry_KeyElementsIterType elementIndex = McalCry_GetKeyElementsStartIdxOfKey(cryptoKeyId);
    uint8 idx = 0u;
    retVal = E_OK;

    while(elementIndex < McalCry_GetKeyElementsEndIdxOfKey(cryptoKeyId)){
      if(idx < *(keyElementIdsLengthPtr))
      {
        keyElementIdsPtr[idx] = McalCry_GetIdOfKeyElements(elementIndex);
      }
      else
      {
        retVal = CRYPTO_E_SMALL_BUFFER;

        errorId = CRYPTO_E_SMALL_BUFFER;
        break;
      }

      idx++;
      elementIndex++;
    }

    *keyElementIdsLengthPtr = idx;
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_ELEMENT_IDS_GET
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyCopy(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal, retValBuf;
  McalCry_KeyElementsIterType elementIndexSrc;
  McalCry_SizeOfKeyElementsType elementIndexDst = 0u;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(targetCryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif

  {
    if(McalCry_Local_KeyWriteLockGet(targetCryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      if(McalCry_Local_KeyReadLockGet(cryptoKeyId) != E_OK)
      {
        retVal = CRYPTO_E_BUSY;
      }
      else
      {
        retVal = CRYPTO_E_KEY_NOT_AVAILABLE;

        for(elementIndexSrc = McalCry_GetKeyElementsStartIdxOfKey(cryptoKeyId); elementIndexSrc < McalCry_GetKeyElementsEndIdxOfKey(cryptoKeyId); elementIndexSrc++)
        {
          if(McalCry_Local_KeyElementSearch(targetCryptoKeyId, McalCry_GetIdOfKeyElements(elementIndexSrc), &elementIndexDst) == E_OK)
          {
            retValBuf = McalCry_Local_KeyElementCopy((McalCry_SizeOfKeyElementsType)elementIndexSrc, elementIndexDst, targetCryptoKeyId);
            if(retVal != E_OK)
            {
              retVal = retValBuf;
            }
          }
        }
        McalCry_Local_KeyReadLockRelease(cryptoKeyId);
      }
      McalCry_Local_KeyWriteLockRelease(targetCryptoKeyId);
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_COPY
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementCopy(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 targetCryptoKeyId
   ,  uint32 targetKeyElementId){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType elementIndexSrc = 0u;
  McalCry_SizeOfKeyElementsType elementIndexDst = 0u;
  uint8 errorId = CRYPTO_E_PARAM_HANDLE;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(targetCryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
    if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndexSrc) != E_OK){
      retVal = E_NOT_OK;
    }
    else{
      if(McalCry_Local_KeyElementSearch(targetCryptoKeyId, targetKeyElementId, &elementIndexDst) == E_OK)
      {
        errorId = CRYPTO_E_NO_ERROR;

        if(McalCry_Local_KeyWriteLockGet(targetCryptoKeyId) != E_OK)
        {
          retVal = CRYPTO_E_BUSY;
        }
        else
        {
          if(cryptoKeyId == targetCryptoKeyId)
          {
            retVal = McalCry_Local_KeyElementCopy(elementIndexSrc, elementIndexDst, targetCryptoKeyId);
          }
          else if(McalCry_Local_KeyReadLockGet(cryptoKeyId) != E_OK)
          {
            retVal = CRYPTO_E_BUSY;
          }
          else
          {
            retVal = McalCry_Local_KeyElementCopy(elementIndexSrc, elementIndexDst, targetCryptoKeyId);
            McalCry_Local_KeyReadLockRelease(cryptoKeyId);
          }
          McalCry_Local_KeyWriteLockRelease(targetCryptoKeyId);
        }
      }
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_ELEMENT_COPY
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif
  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementCopyPartial(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 keyElementSourceOffset
   ,  uint32 keyElementTargetOffset
   ,  uint32 keyElementCopyLength
   ,  uint32 targetCryptoKeyId
   ,  uint32 targetKeyElementId){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyElementsType elementIndexSrc = 0u;
  McalCry_SizeOfKeyElementsType elementIndexDst = 0u;
  uint8 errorId = CRYPTO_E_PARAM_HANDLE;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(targetCryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
    if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndexSrc) != E_OK){
    }
    else{
      if(McalCry_Local_KeyElementSearch(targetCryptoKeyId, targetKeyElementId, &elementIndexDst) == E_OK)
      {
        errorId = CRYPTO_E_NO_ERROR;

        if(McalCry_Local_KeyWriteLockGet(targetCryptoKeyId) != E_OK)
        {
          retVal = CRYPTO_E_BUSY;
        }
        else
        {
          if(cryptoKeyId == targetCryptoKeyId)
          {
            retVal = McalCry_Local_KeyElementCopyPartial(elementIndexSrc, elementIndexDst, targetCryptoKeyId, keyElementSourceOffset, keyElementTargetOffset, keyElementCopyLength);
          }
          else if(McalCry_Local_KeyReadLockGet(cryptoKeyId) != E_OK)
          {
            retVal = CRYPTO_E_BUSY;
          }
          else
          {
            retVal = McalCry_Local_KeyElementCopyPartial(elementIndexSrc, elementIndexDst, targetCryptoKeyId, keyElementSourceOffset, keyElementTargetOffset, keyElementCopyLength);
            McalCry_Local_KeyReadLockRelease(cryptoKeyId);
          }
          McalCry_Local_KeyWriteLockRelease(targetCryptoKeyId);
        }
      }
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_ELEMENT_COPY_PARTIAL
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif
  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_KeyElementSetInternalStandard(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength){
  McalCry_KeyStorageIterType keyStorageIndex;
  uint32 maxLength = McalCry_GetKeyElementLength(elementIndex);

  keyStorageIndex = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndex);

  McalCry_CopyData(McalCry_GetAddrKeyStorage(keyStorageIndex), keyPtr, keyLength);

  if(maxLength > keyLength){
    McalCry_ClearData(McalCry_GetAddrKeyStorage(keyStorageIndex + keyLength), (uint32)(maxLength - keyLength));
  }

  McalCry_SetKeyElementWrittenLengthWithCryptoKeyIdSearch(elementIndex, keyLength);
}

FUNC(void, MCALCRY_CODE) McalCry_KeyElementSetInternalStandardWithCryptoKeyId(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength){
  McalCry_KeyStorageIterType keyStorageIndex;
  uint32 maxLength = McalCry_GetKeyElementLength(elementIndex);

  keyStorageIndex = McalCry_GetKeyStorageStartIdxOfKeyElements(elementIndex);

  McalCry_CopyData(McalCry_GetAddrKeyStorage(keyStorageIndex), keyPtr, keyLength);

  if(maxLength > keyLength){
    McalCry_ClearData(McalCry_GetAddrKeyStorage(keyStorageIndex + keyLength), (uint32)(maxLength - keyLength));
  }

  McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(cryptoKeyId, elementIndex, keyLength);
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSetInternal(
  uint32 cryptoKeyId
   ,  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength
   ,  McalCry_WriteOfKeyElementInfoType writeAccess){
  Std_ReturnType retVal = E_NOT_OK;

#if(MCALCRY_SHEKEYS == STD_ON)
  if((writeAccess != MCALCRY_WA_ENCRYPTED) &&
      McalCry_IsSheKey(elementIndex)){
    retVal = CRYPTO_E_KEY_WRITE_FAIL;
  }
  else
#endif
  {
    {
      if(McalCry_IsKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK))
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }

      else if((keyLength == McalCry_GetKeyElementLength(elementIndex)) ||
        ((McalCry_IsKeyElementPartial(elementIndex) == TRUE) &&
               (keyLength <= McalCry_GetKeyElementLength(elementIndex))))
      {
        if(writeAccess >= (McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))))
        {
          McalCry_KeyElementSetInternalStandardWithCryptoKeyId(cryptoKeyId, elementIndex, keyPtr, keyLength);
          retVal = E_OK;
        }
        else
        {
          retVal = CRYPTO_E_KEY_WRITE_FAIL;
        }
      }
      else
      {
        retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
      }
    }
  }
  return retVal;
}

#if((MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON) || (MCALCRY_KEY_GENERATE_ALGORITHM == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength){
  Std_ReturnType retVal;
  McalCry_SizeOfKeyElementsType elementIndex = 0u;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex) != E_OK){
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }
  else{
    retVal = McalCry_Local_KeyElementSetInternal(cryptoKeyId, elementIndex, keyPtr, keyLength, MCALCRY_WA_INTERNAL_COPY);

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(elementIndex);
    }
  }

  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementSet(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength){
  Std_ReturnType retVal;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(keyPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
#if(MCALCRY_KEY_ELEMENT_DELETE == STD_OFF)
  else if(keyLength == 0u){
    errorId = CRYPTO_E_PARAM_VALUE;
  }
#endif
  else
#endif
  {
    McalCry_SizeOfKeyElementsType elementIndex = 0u;

    if(McalCry_Local_KeyWriteLockGet(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

      if(McalCry_She_IsDebugCmd(cryptoKeyId, keyElementId))
      {
        retVal = McalCry_She_DebugCmd_SetAuthorizationAndLock(keyPtr, keyLength);
      }
      else
#endif

        if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex) != E_OK)
        {
          errorId = CRYPTO_E_PARAM_HANDLE;
          retVal = E_NOT_OK;
        }
        else
        {
          retVal = McalCry_Local_KeyElementSetInternal(cryptoKeyId, elementIndex, keyPtr, keyLength, MCALCRY_WA_ALLOWED);
#if(MCALCRY_SHEKEYS == STD_ON)
          if((retVal == CRYPTO_E_KEY_SIZE_MISMATCH) ||
              (retVal == CRYPTO_E_KEY_WRITE_FAIL))
          {
            retVal = McalCry_Local_KeyElementSetShe(cryptoKeyId, elementIndex, keyPtr, keyLength, retVal);
          }
#endif

          if(retVal == E_OK)
          {
            McalCry_ClearKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_CLEAR_NORMAL_MASK | MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK);
            if(McalCry_IsKeyElementWriteOnce(elementIndex))
            {
              McalCry_SetKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK);
            }
          }
        }
      McalCry_Local_KeyWriteLockRelease(cryptoKeyId);
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_ELEMENT_SET
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyValidSet(
  uint32 cryptoKeyId){
  uint8 errorId = CRYPTO_E_NO_ERROR;
  Std_ReturnType retVal;
  boolean writeBlock;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
    if(McalCry_Local_KeyWriteLockGet(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      writeBlock = McalCry_SetKeyState(cryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);

#if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)
      McalCry_ClearObjectWorkspaceForChangedKey(cryptoKeyId);
#endif
      McalCry_Local_KeyWriteLockRelease(cryptoKeyId);

#if(MCALCRY_NVBLOCK == STD_ON)
      if(writeBlock)
      {
        McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(cryptoKeyId));
      }
#else
      MCALCRY_DUMMY_STATEMENT(writeBlock);
#endif
      retVal = E_OK;
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_VALID_SET
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexBasic(
  McalCry_SizeOfKeyElementsType elementIndex
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck
   ,  McalCry_ServiceType serviceType){
  Std_ReturnType retVal = E_NOT_OK;

#if((MCALCRY_SHEKEYS == STD_ON) && (MCALCRY_SHE_ENABLE_FID == STD_ON))
  boolean access = FALSE;
  if(!McalCry_IsSheKey(elementIndex)){
    access = TRUE;
  }
  else{
    if(serviceType != MCALCRY_SHE_SERVICE_OTHER){
      access = McalCry_Local_KeyElementGetSheCheckFid(elementIndex, serviceType);
    }
  }

  if(access == FALSE){
    retVal = CRYPTO_E_KEY_READ_FAIL;
  }
  else
#else
  MCALCRY_DUMMY_STATEMENT(serviceType);
#endif
  {
    {
      retVal = McalCry_Local_KeyElementGet_Standard(resultIndexPtr, (P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR))resultLengthPtr, elementIndex, lengthCheck);
    }
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexExtended(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck
   ,  McalCry_ServiceType serviceType){
  Std_ReturnType retVal;
  McalCry_SizeOfKeyElementsType elementIndex = 0u;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex) != E_OK){
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }

  else if(FALSE == McalCry_IsKeyElementValid(elementIndex)){
    retVal = CRYPTO_E_KEY_NOT_VALID;
  }
  else{
    retVal = McalCry_Local_KeyElementGetStorageIndexBasic(elementIndex, resultIndexPtr, resultLengthPtr, lengthCheck, serviceType);
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndex(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementGetStorageIndexExtended(cryptoKeyId, keyElementId, resultIndexPtr, resultLengthPtr, lengthCheck, MCALCRY_SHE_SERVICE_OTHER);

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexJob(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementGetStorageIndexExtended(cryptoKeyId, keyElementId, resultIndexPtr, resultLengthPtr, lengthCheck, MCALCRY_SHE_SERVICE_OTHER);

  if(retVal == E_OK){
  }
  else if(retVal == CRYPTO_E_KEY_NOT_VALID){
  }
  else  if(retVal == CRYPTO_E_SMALL_BUFFER){
    retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
  }
  else{
    retVal = E_NOT_OK;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexJobOptional(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementGetStorageIndexExtended(cryptoKeyId, keyElementId, resultIndexPtr, resultLengthPtr, lengthCheck, MCALCRY_SHE_SERVICE_OTHER);

  if(retVal == E_OK){
  }
  else if(retVal == CRYPTO_E_KEY_NOT_VALID){
  }
  else if(retVal == CRYPTO_E_KEY_NOT_AVAILABLE){
  }
  else{
    retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_GetElementsIndexJob(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  McalCry_KeyElementGetSizeType numberOfElements
   ,  McalCry_LengthCheckType lengthCheck
  ){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_KeyElementGetSizeType i;
  for(i = 0; i < numberOfElements; i++){
    retVal = McalCry_Local_KeyElementGetStorageIndexJob(cryptoKeyId, keyElements[i].keyElementId, &keyElements[i].keyElementIndex, &keyElements[i].keyElementLength, lengthCheck);
    if(retVal != E_OK){
      break;
    }
  }
  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_ElementGetterSetId(
  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  McalCry_KeyElementGetSizeType elementNumber
   ,  uint32 keyElementId){
  keyElements[elementNumber].keyElementId = keyElementId;
}

FUNC(void, MCALCRY_CODE) McalCry_Local_ElementGetterSetIdAndLength(
  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements
   ,  McalCry_KeyElementGetSizeType elementNumber
   ,  uint32 keyElementId
   ,  uint32 keyLength){
  keyElements[elementNumber].keyElementId = keyElementId;
  keyElements[elementNumber].keyElementLength = keyLength;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementGet(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr){
  uint8 errorId = CRYPTO_E_NO_ERROR;
  Std_ReturnType retVal;
  McalCry_SizeOfKeyElementsType elementIndex = 0u;
  McalCry_SizeOfKeyStorageType resultIndex;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(resultPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(resultLengthPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(*resultLengthPtr == 0u){
    errorId = CRYPTO_E_PARAM_VALUE;
  }
  else
#endif
  {
    if(McalCry_Local_KeyReadLockGet(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
#if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

      if(McalCry_She_IsDebugCmd(cryptoKeyId, keyElementId))
      {
        retVal = McalCry_She_DebugCmd_GetChallenge(resultPtr, resultLengthPtr);
      }
      else
#endif

        if(McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex) != E_OK)
        {
          errorId = CRYPTO_E_PARAM_HANDLE;

          retVal = E_NOT_OK;
        }
        else
        {
          if(FALSE == McalCry_IsKeyElementValid(elementIndex))
          {
            retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
          }
          else
          {
            if(MCALCRY_RA_ALLOWED == (McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))))
            {
              retVal = McalCry_Local_KeyElementGetStorageIndexBasic( elementIndex, &resultIndex, resultLengthPtr, MCALCRY_LENGTH_CHECK_MAX, MCALCRY_SHE_SERVICE_KEY_SERVICE);

              if(retVal == E_OK)
              {
                McalCry_CopyData(resultPtr, McalCry_GetAddrKeyStorage(resultIndex), *resultLengthPtr);
              }
            }
#if(MCALCRY_RAM_KEY_EXPORT == STD_ON)

            else if(MCALCRY_RA_ENCRYPTED == (McalCry_GetReadOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex))))
            {
              retVal = McalCry_Local_KeyElementGetShe(cryptoKeyId, elementIndex, resultPtr, resultLengthPtr);
            }
#endif
            else
            {
              retVal = CRYPTO_E_KEY_READ_FAIL;
            }
          }
        }
      McalCry_Local_KeyReadLockRelease(cryptoKeyId);
    }
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_ELEMENT_GET
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RandomSeed(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength){
  uint8 errorId = CRYPTO_E_NO_ERROR;
  Std_ReturnType retVal;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(entropyPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(entropyLength == 0u){
    errorId = CRYPTO_E_PARAM_VALUE;
  }
  else
#endif
  {
#if((MCALCRY_FIPS186 == STD_ON) || (MCALCRY_DRBGAES == STD_ON) || (MCALCRY_DRBGHASHSHA512 == STD_ON))
    retVal = McalCry_Local_RandomSeed(cryptoKeyId, entropyPtr, entropyLength);
#else
    retVal = E_NOT_OK;
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(entropyPtr);
    MCALCRY_DUMMY_STATEMENT(entropyLength);
#endif
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_RANDOM_SEED
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyGenerate(
  uint32 cryptoKeyId){
  uint8 errorId = CRYPTO_E_NO_ERROR;
  Std_ReturnType retVal;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
#if(MCALCRY_KEY_GENERATE_ALGORITHM == STD_ON)
    retVal = McalCry_Local_KeyGenerate(cryptoKeyId);
#else
    retVal = E_NOT_OK;
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
#endif
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_GENERATE
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyDerive(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(targetCryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
#if(MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON)
    boolean writeBlock = FALSE;

    if(McalCry_Local_KeyWriteLockGet(targetCryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      if(cryptoKeyId == targetCryptoKeyId)
      {
        retVal = McalCry_Local_KeyDerive(cryptoKeyId, targetCryptoKeyId, &writeBlock);
      }
      else if(McalCry_Local_KeyReadLockGet(cryptoKeyId) != E_OK)
      {
        retVal = CRYPTO_E_BUSY;
      }
      else
      {
        retVal = McalCry_Local_KeyDerive(cryptoKeyId, targetCryptoKeyId, &writeBlock);
        McalCry_Local_KeyReadLockRelease(cryptoKeyId);
      }

      McalCry_Local_KeyWriteLockRelease(targetCryptoKeyId);

#if(MCALCRY_NVBLOCK == STD_ON)
      if(writeBlock)
      {
        McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(targetCryptoKeyId));
      }
#endif
    }
#else
    retVal = E_NOT_OK;
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(targetCryptoKeyId);
#endif
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID, MCALCRY_INSTANCE_ID, MCALCRY_SID_KEY_DERIVE, errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyExchangeCalcPubVal(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  uint8 errorId = CRYPTO_E_NO_ERROR;
  Std_ReturnType retVal;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(publicValuePtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(publicValueLengthPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(*publicValueLengthPtr == 0u){
    errorId = CRYPTO_E_PARAM_VALUE;
  }

  else
#endif
  {
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)

    retVal = McalCry_Local_KeyExchangeCalcPubVal(cryptoKeyId, publicValuePtr, publicValueLengthPtr);

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
    if(retVal == CRYPTO_E_SMALL_BUFFER){
      errorId = CRYPTO_E_PARAM_VALUE;
    }
#endif
#else
    retVal = E_NOT_OK;
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(publicValuePtr);
    MCALCRY_DUMMY_STATEMENT(publicValueLengthPtr);
#endif
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_EXCHANGE_CALC_PUB_VAL
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyExchangeCalcSecret(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength){
  Std_ReturnType retVal;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)
  retVal = E_NOT_OK;

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(partnerPublicValuePtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else if(partnerPublicValueLength == 0u){
    errorId = CRYPTO_E_PARAM_VALUE;
  }
  else
#endif
  {
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)

    retVal = McalCry_Local_KeyExchangeCalcSecret(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
#else
    retVal = E_NOT_OK;
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(partnerPublicValuePtr);
    MCALCRY_DUMMY_STATEMENT(partnerPublicValueLength);
#endif
  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_KEY_EXCHANGE_CALC_SECRET
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CertificateParse(
  uint32 cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else
#endif
  {
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);

  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_CERTIFICATE_PARSE
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CertificateVerify(
  uint32 cryptoKeyId
   ,  uint32 verifyCryptoKeyId
   ,  P2VAR(Crypto_VerifyResultType, AUTOMATIC, MCALCRY_APPL_VAR) verifyPtr){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }

  else if(cryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(verifyCryptoKeyId >= McalCry_GetSizeOfKey()){
    errorId = CRYPTO_E_PARAM_HANDLE;
  }
  else if(verifyPtr == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else
#endif
  {
    MCALCRY_DUMMY_STATEMENT(cryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(verifyCryptoKeyId);
    MCALCRY_DUMMY_STATEMENT(verifyPtr);

  }

#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_CERTIFICATE_VERIFY
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

#if(MCALCRY_NVBLOCK == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_Init(
  McalCry_SizeOfNvBlockType blockIdx){
  McalCry_SetNvBlockState(blockIdx, MCALCRY_NVBLOCK_STATE_IDLE);
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2CONST(void, AUTOMATIC, MCALCRY_APPL_DATA) NvMBuffer){
  Std_ReturnType retVal = E_NOT_OK;
  boolean locked = FALSE;
  McalCry_KeyIterType lockedKeyIdx, releaseKeyIdx;
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr = (P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR))NvMBuffer;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }
  else if(NvMBuffer == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else
#endif
  {
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(lockedKeyIdx = 0u; lockedKeyIdx < McalCry_GetSizeOfKey(); lockedKeyIdx++){
      if(McalCry_GetNvBlockIdxOfKey(lockedKeyIdx) == blockIdx)
      {
        locked = TRUE;
        if(McalCry_Local_KeyWriteLockGetNotProtected((uint32)lockedKeyIdx) == E_NOT_OK)
        {
          locked = FALSE;
          break;
        }
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(locked == TRUE){
      retVal = McalCry_NvBlock_ReadFromBlock_Copy(blockIdx, NvMBufferPtr);
    }

    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(releaseKeyIdx = 0; releaseKeyIdx < lockedKeyIdx; releaseKeyIdx++){
      if(McalCry_GetNvBlockIdxOfKey(releaseKeyIdx) == blockIdx)
      {
        McalCry_Local_KeyWriteLockReleaseNotProtected((uint32)releaseKeyIdx);
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  }
#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_NVBLOCK_READFROMBLOCK
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock(
  McalCry_SizeOfNvBlockType blockIdx
   ,  P2VAR(void, AUTOMATIC, MCALCRY_APPL_VAR) NvMBuffer){
  Std_ReturnType retVal = E_NOT_OK;
  boolean locked = FALSE;
  McalCry_KeyIterType lockedKeyIdx, releaseKeyIdx;
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) NvMBufferPtr = (P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))NvMBuffer;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }
  else if(NvMBuffer == NULL_PTR){
    errorId = CRYPTO_E_PARAM_POINTER;
  }
  else
#endif
  {
    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(lockedKeyIdx = 0u; lockedKeyIdx < McalCry_GetSizeOfKey(); lockedKeyIdx++){
      if(McalCry_GetNvBlockIdxOfKey(lockedKeyIdx) == blockIdx)
      {
        locked = TRUE;
        if(McalCry_Local_KeyReadLockGetNotProtected((uint32)lockedKeyIdx) == E_NOT_OK)
        {
          locked = FALSE;
          break;
        }
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

    if(locked == TRUE){
      McalCry_NvBlock_WriteToBlock_Copy(blockIdx, NvMBufferPtr);
      retVal = E_OK;
    }

    SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
    for(releaseKeyIdx = 0; releaseKeyIdx < lockedKeyIdx; releaseKeyIdx++){
      if(McalCry_GetNvBlockIdxOfKey(releaseKeyIdx) == blockIdx)
      {
        McalCry_Local_KeyReadLockReleaseNotProtected((uint32)releaseKeyIdx);
      }
    }
    SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
  }
#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_NVBLOCK_WRITETOBLOCK
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Init(
  McalCry_SizeOfNvBlockType blockIdx){
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyIterType keyIdx;
  McalCry_KeyElementsIterType elementIndex;
#if(MCALCRY_SHEKEYS == STD_ON)
  McalCry_SheKeysIterType sheKeyIndex;
#endif
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }
  else
#endif
  {
    retVal = E_OK;
    McalCry_NvBlock_State_Init(blockIdx);

    for(keyIdx = 0u; keyIdx < McalCry_GetSizeOfKey(); keyIdx++){
      if(McalCry_GetNvBlockIdxOfKey(keyIdx) == blockIdx)
      {
        for(elementIndex = McalCry_GetKeyElementsStartIdxOfKey(keyIdx); elementIndex < McalCry_GetKeyElementsEndIdxOfKey(keyIdx); elementIndex++)
        {
          if(McalCry_IsKeyElementPersist(elementIndex))
          {
            McalCry_Init_Key(elementIndex, TRUE);
          }
        }
      }
    }

#if(MCALCRY_SHEKEYS == STD_ON)
    for(sheKeyIndex = 0u; sheKeyIndex < McalCry_GetSizeOfSheKeys(); sheKeyIndex++){
      keyIdx = McalCry_GetKeyIdxOfSheKeys(sheKeyIndex);
      if(McalCry_GetNvBlockIdxOfKey(keyIdx) == blockIdx)
      {
        elementIndex = McalCry_GetKeyElementsKeyIdxOfSheKeys(sheKeyIndex);
        if(McalCry_IsKeyElementPersist(elementIndex))
        {
          McalCry_Init_KeySheAdditional(elementIndex);
        }
      }
    }
#endif
  }
#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_NVBLOCK_INIT
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Callback(
  McalCry_SizeOfNvBlockType blockIdx
   ,  uint8 ServiceId
   ,  NvM_RequestResultType JobResult){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 errorId = CRYPTO_E_NO_ERROR;

#if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

  if(McalCry_IsModuleNotInitialized()){
    errorId = CRYPTO_E_UNINIT;
  }
  else
#endif
  {
    retVal = E_OK;
    switch(ServiceId){
      case MCALCRY_NVM_WRITE_BLOCK:
      case MCALCRY_NVM_WRITE_ALL:
      {
        McalCry_NvBlock_State_CallbackWrittenToBlock(blockIdx);
        break;
      }

      default:

      break;
    }

  }
#if(MCALCRY_DEV_ERROR_REPORT == STD_ON)

  if(errorId != CRYPTO_E_NO_ERROR){
    (void)Det_ReportError((uint16)MCALCRY_MODULE_ID
   ,                         MCALCRY_INSTANCE_ID
   ,                         MCALCRY_SID_NVBLOCK_CALLBACK
   ,                         errorId);
  }
#else
  MCALCRY_DUMMY_STATEMENT(errorId);
#endif

  MCALCRY_DUMMY_STATEMENT(JobResult);

  return retVal;
}
#endif

#if(MCALCRY_KEYSETVALID == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySetValid(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    McalCry_ProcessJob_Trigger_Write[objectId] = McalCry_SetKeyState(job->cryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);

  }
  return E_OK;
}
#endif

#if(MCALCRY_SHECMDGETID == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SheCmdGetId(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  McalCry_SizeOfSheKeysType indexOfSheMasterKey = 0u;
  McalCry_SizeOfKeyStorageType uIdStorageIndex, masterKeyStorageIndex;
  uint32 length;
  uint8 result[MCALCRY_SIZEOF_CMAC];
  uint8 buffer[MCALCRY_SIZEOF_SHE_CMD_GET_ID_OUTPUT];
  uint8 status;

  if(McalCry_IsJobMode(job, CRYPTO_OPERATIONMODE_SINGLECALL)){
    if(mode == CRYPTO_OPERATIONMODE_FINISH){
      P2VAR(eslt_WorkSpaceCMACAES, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfSheCmdGetId(McalCry_GetSheCmdGetIdIdxOfObjectInfo(objectId));

      (void)McalCry_GetSheKey(MCALCRY_SHE_M1_ECU_MASTER_KEY_ID, MCALCRY_SHE_PAGE0, &indexOfSheMasterKey);

      if((job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength == MCALCRY_SIZEOF_SHE_CHALLENGE) &&
        (McalCry_GetKeyIdxOfSheKeys(indexOfSheMasterKey) == job->cryptoKeyId) &&
        (McalCry_IsKeyElementValid(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfSheMasterKey))))
      {
        if(McalCry_Local_KeyReadLockGet(McalCry_GetSheInfoKeyRefOfSheKeyUpdate()) == E_OK)
        {
          localRet = McalCry_She_Cmd_Get_Status(&status);

          length = MCALCRY_SIZEOF_SHE_M1_UID;
          localRet |= McalCry_Local_KeyElementGetStorageIndex(McalCry_GetSheInfoKeyRefOfSheKeyUpdate(), CRYPTO_KE_CUSTOM_SHE_UID, &uIdStorageIndex, &length, MCALCRY_LENGTH_CHECK_MIN);

          length = MCALCRY_SIZEOF_SHE_KEY;
          localRet |= McalCry_Local_KeyElementGetStorageIndexBasic(McalCry_GetKeyElementsKeyIdxOfSheKeys(indexOfSheMasterKey), &masterKeyStorageIndex, &length, MCALCRY_LENGTH_CHECK_EQUAL, MCALCRY_SHE_SERVICE_KEY_SERVICE);

          if(localRet == E_OK)
          {
            McalCry_CopyData(buffer, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, MCALCRY_SIZEOF_SHE_CHALLENGE);
            McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_CHALLENGE], McalCry_GetAddrKeyStorage(uIdStorageIndex), MCALCRY_SIZEOF_SHE_M1_UID);
            McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_CHALLENGE + MCALCRY_SIZEOF_SHE_M1_UID], &status, MCALCRY_SIZEOF_SHE_STATUS);

            if(McalCry_SheKeyUpdateCmac(buffer, MCALCRY_SIZEOF_ENC_BUFFER, McalCry_GetAddrKeyStorage(masterKeyStorageIndex), result, workspace) == E_OK)
            {
              McalCry_CopyData(buffer, McalCry_GetAddrKeyStorage(uIdStorageIndex), MCALCRY_SIZEOF_SHE_M1_UID);
              McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_M1_UID], &status, MCALCRY_SIZEOF_SHE_STATUS);
              McalCry_CopyData(&buffer[MCALCRY_SIZEOF_SHE_M1_UID + MCALCRY_SIZEOF_SHE_STATUS], result, MCALCRY_SIZEOF_CMAC);

              if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > MCALCRY_SIZEOF_ENC_BUFFER)
              {
                *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = MCALCRY_SIZEOF_ENC_BUFFER;
              }

              McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, buffer, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

              retVal = E_OK;
            }
          }

          McalCry_Local_KeyReadLockRelease(McalCry_GetSheInfoKeyRefOfSheKeyUpdate());
        }
      }
    }
    else{
      retVal = E_OK;
    }
  }

  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_GetKeyFlags(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_KeyFlagType, AUTOMATIC, MCALCRY_APPL_VAR) keyFlagsPtr){
  Std_ReturnType retVal;
  McalCry_SizeOfKeyElementsType elementIndex = 0u;

  retVal = McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, &elementIndex);

  if(retVal == E_OK){
    if(McalCry_IsKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_VALID_MASK)){
      keyFlagsPtr->isKeyValid = TRUE;
    }
    else{
      keyFlagsPtr->isKeyValid = FALSE;
    }

    if(McalCry_IsKeyElementStateByMask(elementIndex, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK)){
      keyFlagsPtr->write_protection = TRUE;
    }
    else{
      keyFlagsPtr->write_protection = FALSE;
    }
    {
#if((MCALCRY_SHEKEYS == STD_ON) && (MCALCRY_SHE_ENABLE_FID == STD_ON))
      uint8 sheExtensions;
      sheExtensions = McalCry_GetKeyElementExtension(elementIndex);

      if(McalCry_IsSheKey(elementIndex))
      {
        keyFlagsPtr->isSheKey = TRUE;

#if(MCALCRY_KEYELEMENTSBOOTPROTECTIONIDXOFSHEPAGE == STD_ON)

        if(McalCry_Uint8CheckMask(sheExtensions, MCALCRY_SHE_FID_MASK_BOOT_PROTECTION))
        {
          keyFlagsPtr->boot_protection = TRUE;
        }
        else
#endif
        {
          keyFlagsPtr->boot_protection = FALSE;
        }

#if(MCALCRY_KEYELEMENTSDEBUGGERPROTECTIONIDXOFSHEPAGE == STD_ON)

        if(McalCry_Uint8CheckMask(sheExtensions, MCALCRY_SHE_FID_MASK_DEBUGGER_PROTECTION))
        {
          keyFlagsPtr->debugger_protection = TRUE;
        }
        else
#endif
        {
          keyFlagsPtr->debugger_protection = FALSE;
        }

        if(McalCry_Uint8CheckMask(sheExtensions, MCALCRY_SHE_FID_MASK_KEY_USAGE))
        {
          keyFlagsPtr->key_usage = TRUE;
        }
        else
        {
          keyFlagsPtr->key_usage = FALSE;
        }

        if(McalCry_Uint8CheckMask(sheExtensions, MCALCRY_SHE_FID_MASK_WILDCARD))
        {
          keyFlagsPtr->disable_wildcard = TRUE;
        }
        else
        {
          keyFlagsPtr->disable_wildcard = FALSE;
        }

        if(McalCry_Uint8CheckMask(sheExtensions, MCALCRY_SHE_FID_MASK_CMAC_USAGE))
        {
          keyFlagsPtr->cmac_usage = TRUE;
        }
        else
        {
          keyFlagsPtr->cmac_usage = FALSE;
        }
      }
      else
#endif
      {
        keyFlagsPtr->isSheKey = FALSE;
        keyFlagsPtr->boot_protection = FALSE;
        keyFlagsPtr->debugger_protection = FALSE;
        keyFlagsPtr->key_usage = FALSE;
        keyFlagsPtr->disable_wildcard = FALSE;
        keyFlagsPtr->cmac_usage = FALSE;
      }
    }
  }
  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_KeyElementGetStorageIndex(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) resultIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr
   ,  McalCry_LengthCheckType lengthCheck
   ,  McalCry_ServiceType serviceType){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementGetStorageIndexExtended(
    cryptoKeyId
   ,   keyElementId
   ,   resultIndexPtr
   ,   resultLengthPtr
   ,   lengthCheck
   ,   serviceType);

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_KeyReadLockGetNotProtected(
  uint32 cryptoKeyId){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyReadLockGetNotProtected(cryptoKeyId);

  return retVal;
}

FUNC(void, MCALCRY_CODE) McalCry_Api_KeyReadLockReleaseNotProtected(
  uint32 cryptoKeyId){
  McalCry_Local_KeyReadLockReleaseNotProtected(cryptoKeyId);
}

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

