#if !defined (MCALCRY_SERVICE_H)
# define MCALCRY_SERVICE_H
#ifdef __cplusplus
extern "C"
{
#endif

# include "Csm_Types.hpp"
# include "CfgMcalCry.hpp"
# include "ESLib_version.hpp"

# if !defined (MCALCRY_LOCAL)
#  define MCALCRY_LOCAL                                       static
# endif

# if !defined (MCALCRY_LOCAL_INLINE)
#  define MCALCRY_LOCAL_INLINE                                LOCAL_INLINE
# endif

# if(MCALCRY_DEV_ERROR_REPORT == STD_ON)
#  include "SwcServiceDet.hpp"
# endif

# if !defined (MCALCRY_BYTES_PER_DIGIT)
#  define MCALCRY_BYTES_PER_DIGIT                             actBN_BYTES_PER_DIGIT
# endif

# define MCALCRY_KEYELEMENTSTATE_CLEAR_NORMAL_MASK            MCALCRY_KEYELEMENTSTATE_CLEAR_ALL_MASK
# define MCALCRY_KEYELEMENTSTATE_CLEAR_ALL_MASK               (0x00u)
# define MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK            (0x80u)
# define MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_INV_MASK        (0x7Fu)
# define MCALCRY_KEYELEMENTSTATE_SEED_INIT_MASK               (0x08u)
# define MCALCRY_KEYELEMENTSTATE_SEED_INIT_INV_MASK           (0xF7u)
# define MCALCRY_KEYELEMENTSTATE_VALUE_USED_MASK              (0x04u)
# define MCALCRY_KEYELEMENTSTATE_VALUE_USED_INV_MASK          (0xFBu)
# define MCALCRY_KEYELEMENTSTATE_VALID_MASK                   (0x01u)
# define MCALCRY_KEYELEMENTSTATE_VALID_INV_MASK               (0xFEu)

# define MCALCRY_KEYELEMENTSEXTENSION_CLEAR_ALL_MASK          (0x00u)
# define MCALCRY_KEYELEMENTSEXTENSION_SHE_KEY_MASK            (0x01u)
# define MCALCRY_KEYELEMENTSEXTENSION_SHE_PLAIN_KEY_MASK      (0x03u)
# define MCALCRY_KEYELEMENTSEXTENSION_SHE_CLEAR_PLAIN_KEY_MASK (0xFDu)

# if(MCALCRY_RSAPKCS1GENERATE == STD_ON) || (MCALCRY_RSAPSSGENERATE == STD_ON)
#  define MCALCRY_RSAGENERATE                                 STD_ON
# else
#  define MCALCRY_RSAGENERATE                                 STD_OFF
# endif

# if(MCALCRY_RSAPKCS1VERIFY == STD_ON) || (MCALCRY_RSAPSSVERIFY == STD_ON)
#  define MCALCRY_RSAVERIFY                                   STD_ON
# else
#  define MCALCRY_RSAVERIFY                                   STD_OFF
# endif

# define MCALCRY_KE_TARGET_KEY                                (1u)

# define MCALCRY_CMACAES_MAX_KEY_SIZE                         (16u)
# define MCALCRY_CMACAES_MAC_SIZE                             (16u)
# define MCALCRY_AES_BLOCK_SIZE                               (16u)
# define MCALCRY_AESCCM_SUM_OF_NONCE_LENGTH_AND_L             (15u)

# define MCALCRY_KEY_LOCK_READ_MAX                            (0xFFu)
# define MCALCRY_KEY_LOCK_READ_ONE                            (3u)
# define MCALCRY_KEY_LOCK_FREE                                (2u)
# define MCALCRY_KEY_LOCK_WRITE                               (1u)

# define MCALCRY_LONG_TERM_WS_LOCK_FREE                       (MCALCRY_MAX_LONGTERMWSLOCK)

# define MCALCRY_SIZEOF_UINT32                                (4u)

# define MCALCRY_UINT32_MAX                                   (0xFFFFFFFFuL)
# define MCALCRY_UINT24_MAX                                   (0xFFFFFFuL)
# define MCALCRY_UINT16_MAX                                   (0xFFFFu)

# define MCALCRY_LENGTH_CHECK_NONE                            (0u)
# define MCALCRY_LENGTH_CHECK_MAX                             (1u)
# define MCALCRY_LENGTH_CHECK_EQUAL                           (2u)
# define MCALCRY_LENGTH_CHECK_MIN                             (3u)

# define MCALCRY_SHE_SERVICE_ENCRYPT_DECRYPT                  (0u)
# define MCALCRY_SHE_SERVICE_MAC_GENERATE                     (1u)
# define MCALCRY_SHE_SERVICE_MAC_VERIFY                       (2u)
# define MCALCRY_SHE_SERVICE_KEY_SERVICE                      (3u)
# define MCALCRY_SHE_SERVICE_OTHER                            (4u)
# define MCALCRY_SHE_NUM_SERVICES                             (4u)

# define MCALCRY_BOOT_PROTECTED                               (0x01u)
# define MCALCRY_DEBUGGER_PROTECTED                           (0x01u)

# define MCALCRY_SIZEOF_ECC_160_P                             (20u)
# define MCALCRY_SIZEOF_ECC_160_N                             (21u)
# define MCALCRY_SIZEOF_ECC_224_P                             (28u)
# define MCALCRY_SIZEOF_ECC_224_N                             (28u)
# define MCALCRY_SIZEOF_ECC_256_P                             (32u)
# define MCALCRY_SIZEOF_ECC_256_N                             (32u)
# define MCALCRY_SIZEOF_ECC_384_P                             (48u)
# define MCALCRY_SIZEOF_ECC_384_N                             (48u)

# define MCALCRY_SIZEOF_ECC_160_SIGNATURE                     (MCALCRY_SIZEOF_ECC_160_N)
# define MCALCRY_SIZEOF_ECC_224_SIGNATURE                     (MCALCRY_SIZEOF_ECC_224_N)
# define MCALCRY_SIZEOF_ECC_256_SIGNATURE                     (MCALCRY_SIZEOF_ECC_256_N)
# define MCALCRY_SIZEOF_ECC_384_SIGNATURE                     (MCALCRY_SIZEOF_ECC_384_N)

# define MCALCRY_SIZEOF_ECC_160_KEY_PRIVATE                   (MCALCRY_SIZEOF_ECC_160_N)
# define MCALCRY_SIZEOF_ECC_224_KEY_PRIVATE                   (MCALCRY_SIZEOF_ECC_224_N)
# define MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE                   (MCALCRY_SIZEOF_ECC_256_N)
# define MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE                   (MCALCRY_SIZEOF_ECC_384_N)

# define MCALCRY_SIZEOF_ECC_160_KEY_PUBLIC                    (MCALCRY_SIZEOF_ECC_160_P)
# define MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC                    (MCALCRY_SIZEOF_ECC_224_P)
# define MCALCRY_SIZEOF_ECC_256_KEY_PUBLIC                    (MCALCRY_SIZEOF_ECC_256_P)
# define MCALCRY_SIZEOF_ECC_384_KEY_PUBLIC                    (MCALCRY_SIZEOF_ECC_384_P)

# define MCALCRY_SIZEOF_ECC_160_KEY_PUBLIC_XY                 (2u * (MCALCRY_SIZEOF_ECC_160_P))
# define MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY                 (2u * (MCALCRY_SIZEOF_ECC_224_P))
# define MCALCRY_SIZEOF_ECC_256_KEY_PUBLIC_XY                 (2u * (MCALCRY_SIZEOF_ECC_256_P))
# define MCALCRY_SIZEOF_ECC_384_KEY_PUBLIC_XY                 (2u * (MCALCRY_SIZEOF_ECC_384_P))

# if(MCALCRY_ECP384GENERATE == STD_ON)
#  define MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY       (MCALCRY_SIZEOF_ECC_384_SIGNATURE)
# else
#  if(MCALCRY_ECP256GENERATE == STD_ON)
#   define MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY      (MCALCRY_SIZEOF_ECC_256_SIGNATURE)
#  else

#   define MCALCRY_MAX_SIZEOF_SIGNATURE_GENERATE_ECC_KEY      (MCALCRY_SIZEOF_ECC_160_SIGNATURE)
#  endif
# endif

# define McalCry_NvM_Persist(idx)                             McalCry_NvBlock_Write_Req(McalCry_GetNvBlockIdxOfKey(idx))

# define McalCry_IsLongTermWsLock(id, value)                  (McalCry_GetLongTermWsLock((id)) == (value))

# define McalCry_Uint8CheckMask(value, mask)                  (((value) & (mask)) == (mask))
# define McalCry_Uint8SetMask(value, mask)                    ((value) = (uint8)((value) | (mask)))
# define McalCry_Uint8ClearMask(value, mask)                  ((value) = (uint8)((value) & (mask)))

# define McalCry_IsKeyElementPartial(Index)                   (McalCry_IsPartialOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))))
# define McalCry_IsKeyElementPersist(Index)                   (McalCry_IsPersistOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))))
# define McalCry_IsKeyElementWriteOnce(Index)                 (McalCry_IsOnceOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))))
# define McalCry_GetKeyElementLength(Index)                   (McalCry_GetLengthOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))))
# define McalCry_HasKeyElementInitValue(Index)                (McalCry_IsInitValueUsedOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))))
# define McalCry_GetKeyElementInitValueLength(Index)          ((uint16)McalCry_GetInitValueEndIdxOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements((Index))) - (uint16)McalCry_GetInitValueStartIdxOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(Index)))
# define McalCry_IsKeyElementValid(Index)                     ((McalCry_GetKeyStorage(McalCry_GetKeyStorageValidIdxOfKeyElements((Index))) & MCALCRY_KEYELEMENTSTATE_VALID_MASK) ==  MCALCRY_KEYELEMENTSTATE_VALID_MASK)
# define McalCry_SetKeyElementState(Index, Value)             (McalCry_SetKeyStorage(McalCry_GetKeyStorageValidIdxOfKeyElements((Index)), (Value)))
# define McalCry_GetKeyElementState(Index)                    (McalCry_GetKeyStorage(McalCry_GetKeyStorageValidIdxOfKeyElements((Index))))
# define McalCry_ClearKeyElementStateByMask(Index, Mask)      (McalCry_SetKeyElementState((Index), (uint8)(McalCry_GetKeyElementState((Index)) & (Mask))))
# define McalCry_SetKeyElementStateByMask(Index, Mask)        (McalCry_SetKeyElementState((Index), (uint8)(McalCry_GetKeyElementState((Index)) | (Mask))))
# define McalCry_IsKeyElementStateByMask(Index, Mask)         ((McalCry_GetKeyElementState((Index)) & (uint8)(Mask)) == (Mask))

# define McalCry_GetAddrKeyStorageOfKeyElements(Index)        (McalCry_GetAddrKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(Index)))

# define McalCry_SetKeyElementExtension(Index, Value)         (McalCry_SetKeyStorage(McalCry_GetKeyStorageExtensionIdxOfKeyElements((Index)), (Value)))
# define McalCry_GetKeyElementExtension(Index)                (McalCry_GetKeyStorage(McalCry_GetKeyStorageExtensionIdxOfKeyElements((Index))))
# define McalCry_ClearKeyElementExtensionByMask(Index, Mask)  (McalCry_SetKeyElementExtension((Index), (uint8)(McalCry_GetKeyElementExtension((Index)) & (Mask))))
# define McalCry_SetKeyElementExtensionByMask(Index, Mask)    (McalCry_SetKeyElementExtension((Index), (uint8)(McalCry_GetKeyElementExtension((Index)) | (Mask))))
# define McalCry_IsKeyElementExtensionByMask(Index, Mask)     ((McalCry_GetKeyElementExtension((Index)) & (uint8)(Mask)) == (Mask))

# define McalCry_IsSheKey(Index)                              (McalCry_IsKeyElementExtensionByMask((Index), MCALCRY_KEYELEMENTSEXTENSION_SHE_KEY_MASK)? TRUE : FALSE)

# define McalCry_IsJobMode(Job, Mask)                         ((((Job)->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.mode) & (Mask)) == (Mask))

# if((MCALCRY_ECP256GENERATE == STD_ON) || (MCALCRY_ECP384GENERATE == STD_ON) || (MCALCRY_ECP160GENERATE == STD_ON))
#  define MCALCRY_ECPGENERATE                                 STD_ON
# else
#  define MCALCRY_ECPGENERATE                                 STD_OFF
# endif

# if((MCALCRY_ECP256VERIFY == STD_ON) || (MCALCRY_ECP384VERIFY == STD_ON) || (MCALCRY_ECP160VERIFY == STD_ON))
#  define MCALCRY_ECPVERIFY                                   STD_ON
# else
#  define MCALCRY_ECPVERIFY                                   STD_OFF
# endif

# if((MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON)\
     || (MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON))
#  define MCALCRY_KEY_EXCHANGE_P256R1_DOMAIN                  STD_ON
# else
#  define MCALCRY_KEY_EXCHANGE_P256R1_DOMAIN                  STD_OFF
# endif

# if((MCALCRY_ECP160GENERATE == STD_ON)\
     || (MCALCRY_ECP160VERIFY == STD_ON))
#  define MCALCRY_CUSTOM_P160R1_DOMAIN                        STD_ON
# else
#  define MCALCRY_CUSTOM_P160R1_DOMAIN                        STD_OFF
# endif

# if((MCALCRY_ECP160GENERATE == STD_ON))
#  define MCALCRY_CUSTOM_P160R1_SPEEDUP                       STD_ON
# else
#  define MCALCRY_CUSTOM_P160R1_SPEEDUP                       STD_OFF
# endif

# if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)
#  define MCALCRY_CUSTOM_P224R1_DOMAIN                        STD_ON
# else
#  define MCALCRY_CUSTOM_P224R1_DOMAIN                        STD_OFF
# endif

# if((MCALCRY_ECP256GENERATE == STD_ON)\
     || (MCALCRY_ECP256VERIFY == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_P256R1_DOMAIN == STD_ON)\
     || (MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON))
#  define MCALCRY_CUSTOM_P256R1_DOMAIN                        STD_ON
# else
#  define MCALCRY_CUSTOM_P256R1_DOMAIN                        STD_OFF
# endif

# if((MCALCRY_ECP256GENERATE == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON))
#  define MCALCRY_CUSTOM_P256R1_SPEEDUP                       STD_ON
# else
#  define MCALCRY_CUSTOM_P256R1_SPEEDUP                       STD_OFF
# endif

# if((MCALCRY_ECP384GENERATE == STD_ON)\
     || (MCALCRY_ECP384VERIFY == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))
#  define MCALCRY_CUSTOM_P384R1_DOMAIN                        STD_ON
# else
#  define MCALCRY_CUSTOM_P384R1_DOMAIN                        STD_OFF
# endif

# if((MCALCRY_ECP384GENERATE == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))
#  define MCALCRY_CUSTOM_P384R1_SPEEDUP                       STD_ON
# else
#  define MCALCRY_CUSTOM_P384R1_SPEEDUP                       STD_OFF
# endif

# if((MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON) || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))
#  define MCALCRY_ECC_KEY_MAXSIZE                             (MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE)
# else
#  define MCALCRY_ECC_KEY_MAXSIZE                             (MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE)
# endif

# define McalCry_Math_Mul2(Value)                             ((Value) << 1u)
# define McalCry_Math_Div2(Value)                             ((Value) >> 1u)
# define McalCry_Math_IsEven(Value)                           (((Value) & (1u)) == 0u)
# define McalCry_Math_CalcMiddle(Value1, Value2)              (((Value1) + (Value2)) / (uint8)2u)

# define McalCry_Byte2Bit(Byte)                               ((Byte) << 3u)
# define McalCry_Bit2Byte(Bit)                                ((Bit) >> 3u)

# define McalCry_IsModuleInitialized()                        ((McalCry_ModuleInitialized & MCALCRY_INITIALIZED) == MCALCRY_INITIALIZED)
# define McalCry_IsModuleNotInitialized()                     ((McalCry_ModuleInitialized & MCALCRY_INITIALIZED) != MCALCRY_INITIALIZED)
# define McalCry_IsModuleBootProtected(value)                 (((value) & MCALCRY_BOOT_PROTECTED) == MCALCRY_BOOT_PROTECTED)
# define McalCry_IsModuleDebuggerProtected(value)             (((value) & MCALCRY_DEBUGGER_PROTECTED) == MCALCRY_DEBUGGER_PROTECTED)

# define McalCry_IsUint32Overflow(Value1, Value2)             (((Value2) > (uint32)(MCALCRY_UINT32_MAX - Value1)) ? TRUE:FALSE )

# define MCALCRY_NUM_OF_REDIRECTION_KEYS                      (5u)

# if(MCALCRY_REDIRECTION == STD_ON)

#  define MCALCRY_MAX_NUM_OF_USED_KEYS                        (MCALCRY_NUM_OF_REDIRECTION_KEYS + 2u)
# else

#  define MCALCRY_MAX_NUM_OF_USED_KEYS                        (3u)
# endif

# define MCALCRY_KEY_ACCESS_WRITE                             (1u)
# define MCALCRY_KEY_ACCESS_READ                              (0u)

typedef McalCry_SizeOfKeyStorageType McalCry_KeyStorageIndexType;

typedef struct{
  uint32 keyElementId;
  uint32 keyElementLength;
  McalCry_SizeOfKeyStorageType keyElementIndex;
}McalCry_KeyElementGetType;

typedef uint8 McalCry_KeyElementGetSizeType;

typedef uint8 McalCry_LengthCheckType;

typedef uint8 McalCry_ServiceType;

typedef struct{
  uint32 firstOutputLength;
  uint32 firstOutputLengthWritten;
  uint32 secondaryOutputLength;
  uint32 secondaryOutputLengthWritten;
  Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput_Restore;
}McalCry_Redirect_Type;

typedef struct{
  uint32 keyId;
  uint8 keyAccess;
}McalCry_KeyLockKeyType;

typedef struct{
  McalCry_KeyLockKeyType keyLockList[MCALCRY_MAX_NUM_OF_USED_KEYS];
  uint8 numKeys;
}McalCry_KeyLockListType;

# define MCALCRY_START_SEC_VAR_ZERO_INIT_8BIT
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

extern VAR(uint8, MCALCRY_VAR_ZERO_INIT) McalCry_ModuleInitialized;
# endif

# define MCALCRY_STOP_SEC_VAR_ZERO_INIT_8BIT
# include "CompilerCfg_McalCry.hpp"

# define MCALCRY_START_SEC_VAR_NOINIT_8BIT
# include "CompilerCfg_McalCry.hpp"

extern VAR(boolean, MCALCRY_VAR_NOINIT) McalCry_ProcessJob_Trigger_Write[McalCry_GetSizeOfDriverObjectState()];

# if(MCALCRY_SHEKEYS == STD_ON)
#  if(MCALCRY_SHE_DEBUG_CMD == STD_ON)

extern VAR(boolean, MCALCRY_VAR_NOINIT) McalCry_She_Debug_Cmd_ChallengeFlag;
#  endif
# endif

# define MCALCRY_STOP_SEC_VAR_NOINIT_8BIT
# include "CompilerCfg_McalCry.hpp"

# define MCALCRY_START_SEC_VAR_NOINIT_16BIT
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)

extern VAR(uint16, MCALCRY_VAR_NOINIT) McalCry_RandomSourceGenerateCount;
# endif

# define MCALCRY_STOP_SEC_VAR_NOINIT_16BIT
# include "CompilerCfg_McalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

FUNC(void, MCALCRY_CODE) McalCry_Init_Key(
  McalCry_KeyElementsIterType elementIndex,
  boolean initAllBytes);

FUNC(void, MCALCRY_CODE) McalCry_Init_KeySimple(
  McalCry_KeyElementsIterType elementIndex);

# if(MCALCRY_SHEKEYS == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_Init_KeySheAdditional(
  McalCry_KeyElementsIterType elementIndex);
# endif

# if(MCALCRY_NVBLOCK == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_State_Init(
  McalCry_SizeOfNvBlockType blockIdx);

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_MainFunction(void);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_ReadFromBlock(
  McalCry_SizeOfNvBlockType blockIdx,
  P2CONST(void, AUTOMATIC, MCALCRY_APPL_DATA) NvMBuffer);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_WriteToBlock(
  McalCry_SizeOfNvBlockType blockIdx,
  P2VAR(void, AUTOMATIC, MCALCRY_APPL_VAR) NvMBuffer);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Init(
  McalCry_SizeOfNvBlockType blockIdx);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_NvBlock_Callback(
  McalCry_SizeOfNvBlockType blockIdx,
  uint8 ServiceId,
  NvM_RequestResultType JobResult);
# endif

# if(MCALCRY_USE_VSTD_LIB == STD_OFF)

FUNC(void, MCALCRY_CODE) McalCry_Local_CopyData_Implementation(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) sourceData,
  uint32 dataLength);

FUNC(void, MCALCRY_CODE) McalCry_Local_SetData_Implementation(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataBuf,
  uint8 pattern,
  uint32 dataLength);

FUNC(void, MCALCRY_CODE) McalCry_Local_ClearData_Implementation(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) dataBuf,
  uint32 dataLength);
# endif

# if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_CompareData_IsSmaller(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) referenceData,
  uint32 dataLength);
# endif

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Uint32ToUint8ArrayBigEndian(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  uint32 sourceData);

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Uint8ArrayToUint32BigEndian(
  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) sourceData);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyListAddKey(
  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList,
  uint32 cryptoKeyId,
  uint8 keyAccess);

FUNC(void, MCALCRY_CODE) McalCry_Local_GetKeyList(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);

# if(MCALCRY_DEV_ERROR_DETECT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_GetKeyListAndDet(
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  P2VAR(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);
# endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyListPreLockKeys(
  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyListPostFreeKeys(
  P2CONST(McalCry_KeyLockListType, AUTOMATIC, AUTOMATIC) keyList);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSearch(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndex);

# if((MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON) || (MCALCRY_KEY_GENERATE_ALGORITHM == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr,
  uint32 keyLength);
# endif

# if(MCALCRY_NVBLOCK == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_NvBlock_Write_Req(
  McalCry_SizeOfNvBlockType blockIdx);
# endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndex(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_GetElementsIndexJob(
  uint32 cryptoKeyId,
  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements,
  McalCry_KeyElementGetSizeType numberOfElements,
  McalCry_LengthCheckType lengthCheck);

FUNC(void, MCALCRY_CODE) McalCry_Local_ElementGetterSetId(
  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements,
  McalCry_KeyElementGetSizeType elementNumber,
  uint32 keyElementId);

FUNC(void, MCALCRY_CODE) McalCry_Local_ElementGetterSetIdAndLength(
  P2VAR(McalCry_KeyElementGetType, AUTOMATIC, AUTOMATIC) keyElements,
  McalCry_KeyElementGetSizeType elementNumber,
  uint32 keyElementId,
  uint32 keyLength);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexJobOptional(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexJob(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexExtended(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck,
  McalCry_ServiceType serviceType);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementGetStorageIndexBasic(
  McalCry_SizeOfKeyElementsType elementIndex,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck,
  McalCry_ServiceType serviceType);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSetInternal(
  uint32 cryptoKeyId,
  McalCry_SizeOfKeyElementsType elementIndex,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr,
  uint32 keyLength,
  McalCry_WriteOfKeyElementInfoType writeAccess);

FUNC(void, MCALCRY_CODE) McalCry_KeyElementSetInternalStandard(
  McalCry_SizeOfKeyElementsType elementIndex,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr,
  uint32 keyLength);

FUNC(void, MCALCRY_CODE) McalCry_KeyElementSetInternalStandardWithCryptoKeyId(
  uint32 cryptoKeyId,
  McalCry_SizeOfKeyElementsType elementIndex,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr,
  uint32 keyLength);

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLength(
  McalCry_SizeOfKeyElementsType keyElementIndex,
  uint32 keyElementLength);

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLengthWithCryptoKeyIdSearch(
  McalCry_SizeOfKeyElementsType keyElementIndex,
  uint32 keyElementLength);

FUNC(void, MCALCRY_CODE) McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(
  uint32 cryptoKeyId,
  McalCry_SizeOfKeyElementsType keyElementIndex,
  uint32 keyElementLength);

FUNC(void, MCALCRY_CODE) McalCry_Local_SetKeyElementStateWritten(
  McalCry_SizeOfKeyElementsType elementIndex);

FUNC(boolean, MCALCRY_CODE) McalCry_SetKeyState(
  uint32 cryptoKeyId,
  uint8 mask);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyReadLockGet(
  uint32 cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyReadLockRelease(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyReadLockGetNotProtected(
  uint32 cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyReadLockReleaseNotProtected(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyWriteLockGet(
  uint32 cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyWriteLockRelease(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyWriteLockGetNotProtected(
  uint32 cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_Local_KeyWriteLockReleaseNotProtected(
  uint32 cryptoKeyId);

# if(MCALCRY_LONGTERMWS == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsLockGet(
  uint32 cryptoKeyId,
  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_LongWsIsLock(
  uint32 cryptoKeyId,
  P2VAR(McalCry_SizeOfLongTermWsLockType, AUTOMATIC, AUTOMATIC) longWsIdxPtr);

FUNC(void, MCALCRY_CODE) McalCry_Local_LongWsLockRelease(
  uint32 cryptoKeyId,
  McalCry_SizeOfLongTermWsLockType longWsIdx);
# endif

# if(MCALCRY_CMAC_AES_ROUNDKEY_REUSE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_IsObjectWorkspaceUnchanged(
  uint32 objectId,
  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

FUNC(void, MCALCRY_CODE) McalCry_ClearObjectWorkspaceForChangedKey(
  uint32 cryptoKeyId);
# endif

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Uint32ToUint8ArrayBigEndian(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  uint32 sourceData){
  targetData[0] = (uint8)(((sourceData)& 0xff000000u) >> 24);
  targetData[1] = (uint8)(((sourceData)& 0x00ff0000u) >> 16);
  targetData[2] = (uint8)(((sourceData)& 0x0000ff00u) >> 8);
  targetData[3] = (uint8)(((sourceData)& 0x000000ffu));
}

MCALCRY_LOCAL_INLINE FUNC(void, MCALCRY_CODE) McalCry_Local_Uint8ArrayToUint32BigEndian(
  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) targetData,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) sourceData){
  *targetData = ((((uint32)sourceData[0]) & 0x000000FFu) << 24) | ((((uint32)sourceData[1]) & 0x000000FFu) << 16) | ((((uint32)sourceData[2]) & 0x000000FFu) << 8) | (((uint32)sourceData[3]) & 0x000000FFu);
}

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#ifdef __cplusplus
}
#endif
#endif

