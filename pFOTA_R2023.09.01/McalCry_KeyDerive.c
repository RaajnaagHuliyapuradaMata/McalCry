

#define MCALCRY_KEYDERIVE_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_KeyDerive.hpp"
#include "McalCry_KeyExchange.hpp"

#include "McalCry_Custom.hpp"
#include "McalCry_Curve.hpp"

#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
#include "actBigNum.hpp"
#endif

#define MCALCRY_KEY_DERIVE_SIZEOF_ALGORITHM                   (1u)

#define MCALCRY_ISO15118_SIZEOF_IV                            (16u)
#define MCALCRY_ISO15118_PRIV_KEY_START                       (MCALCRY_ISO15118_SIZEOF_IV)
#define MCALCRY_ISO15118_SIZEOF_IV_AND_PRIV_KEY               (48u)
#define MCALCRY_ISO15118_SIZEOF_OTHER_INFO                    (3u)

#define MCALCRY_NIST80056A_COUNTER_SIZE                       (4u)
#define MCALCRY_NIST80056A_OTHER_INFO_MAXSIZE                 (5u)

#define MCALCRY_SIZEOF_KDF_PRF_INPUT_BUFFER                   (256u + 12u)
#define MCALCRY_SIZEOF_KDF_MAX_PARENT_KEY                     (256u)
#define MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY                     (256u)
#define MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY_PLUS_8              (256u + 8u)
#define MCALCRY_SIZEOF_KDF_SALT_SYMMETRIC                     (6u)
#define MCALCRY_SIZEOF_KDF_SALT_ASYMMETRIC                    (38u)
#define MCALCRY_SIZEOF_KDF_PRIME                              (32u)
#define MCALCRY_SIZEOF_KDF_CONTEXT                            (4u)
#define MCALCRY_SIZEOF_KDF_TARGET_KEY_LENGTH                  (2u)
#define MCALCRY_SIZEOF_KDF_LABEL_LENGTH                       (4u)
#define MCALCRY_SIZEOF_KDF_ALGORITHM_LENGTH                   (1u)
#define MCALCRY_SIZEOF_KDF_PRIME_ASYM_EXTEND                  (8u)

#define MCALCRY_SIZEOF_KDF_ITERATIONSLENGTH                   (MCALCRY_SIZEOF_UINT32)
#define MCALCRY_SIZEOF_HKDF_ITERATIONSLENGTH                  (1u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if((MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) parentKeyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams_Salt(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams_Salt_TargetKeyLength(
  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_CallPRF(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  uint32 prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) targetKey
   ,  uint32 targetKeyLength, uint32 parentKeyLength);
#endif

#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_AsymDivideByPrimeMinusOne(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) targetKey
   ,  uint32 targetKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) primeMinus1Ptr
   ,  uint32 primeMinus1Length);
#endif

#if(MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_With_Ws_AndLoadKey(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_AndLoadKey(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);
#endif

#if((MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON) \
    || (MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_SingleStepKdfHash(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) sharedSecretPtr
   ,  uint32 sharedSecretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) otherInfoPtr
   ,  uint32 otherInfoLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) derivedKeyPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) derivedKeyLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) privateKeyPtr
   ,  uint32 privateKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) partnerPubKeyPtr
   ,  uint32 partnerPubKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) otherInfoPtr
   ,  uint32 otherInfoPtrLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) derivedKeyPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) derivedKeyLengthPtr);
#endif

#if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_CheckKey(
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) privateKeyPtr
   ,  uint32 privateKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) pubKeyPtr
   ,  uint32 pubKeyLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_Aes128Decrypt(
  P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) ivPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) encryptedMessagePtr
   ,  uint32 encryptedMessageLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) plainMessagePtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) plainMessageLengthPtr);
#endif

#if(MCALCRY_SERVICE_KEY_DERIVE == STD_ON)

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_Derive_UpdateKeyState(
  uint32 objectId
   ,  uint32 targetCryptoKeyId
   ,  Std_ReturnType retVal);
#endif

#if(MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet_Check(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) keyLengthPtr
   ,  McalCry_WriteOfKeyElementInfoType writeAccess);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet_CheckAndLength(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndexPtr
   ,  uint32 requestedKeyLength
   ,  McalCry_WriteOfKeyElementInfoType writeAccess);
#endif

#if((MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist800108NistFips1864_WS(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist800108NistFips1864(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm);
#endif

#if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_WS(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);
#endif

#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA1(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA1(
  P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint32 iterations);
#endif

#if((MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(
  P2VAR(eslt_WorkSpaceKDF2, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 algorithm);
#endif

#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA256(
  P2VAR(eslt_WorkSpaceKDF2HMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint32 iterations);
#endif

#if(MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_HMAC_SHA256_WS(
  P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_HMAC_SHA256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_HKDF_HMAC_SHA256(
  P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 saltLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) saltPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint8 iterations);
#endif

#if(MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_Hash_Option_1_WS(
  P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  eslt_HashAlgorithm hashId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_Hash_Option_1(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  eslt_HashAlgorithm hashId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_HKDF_Hash_Option_1(
  P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  eslt_HashAlgorithm hashId);
#endif

#if(MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Spake2Plus_WS(
  P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Spake2Plus(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_Spake2Plus(
  P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 secretLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) w1Ptr
   ,  uint32 w1Length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) lPtr
   ,  uint32 lLength);
#endif

#if(MCALCRY_KDF_ALGO_X963_SHA256_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256_Calc(
  P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256_WS(
  P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);
#endif

#if(MCALCRY_KDF_ALGO_X963_SHA512_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512_Calc(
  P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512_WS(
  P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);
#endif

#if((MCALCRY_KDF_ALGO_X963_SHA256_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_X963_SHA512_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_Get_Secret_And_Salt(
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) secretLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) secretIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) saltLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) saltIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) keyLength
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) keyElementIndex
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);
#endif

#if((MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams_Salt_TargetKeyLength(
  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength){
  Std_ReturnType retVal = E_OK;

  uint32 configuredTargetKeyLength = 0u;

  McalCry_SizeOfKeyElementsType elementIndex;
  if(McalCry_Local_KeyElementSearch(targetCryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &elementIndex) == E_OK){
    configuredTargetKeyLength = McalCry_GetKeyElementLength(elementIndex);
  }
  else{
    retVal = E_NOT_OK;
  }

  (*targetKeyLength) = (((((uint32)(saltBuffer[4])) << 8) | ((uint32)(saltBuffer[5]))));

  if((*targetKeyLength > MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY) ||
    ((*targetKeyLength) > configuredTargetKeyLength)){
    retVal = E_NOT_OK;
  }

#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
#if(MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON)

  if(deriveAlgorithm == MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB)
#else
  MCALCRY_DUMMY_STATEMENT(deriveAlgorithm);
#endif
  {
    if((*targetKeyLength) != MCALCRY_SIZEOF_KDF_PRIME){
      retVal = E_NOT_OK;
    }

    (*targetKeyLength) += MCALCRY_SIZEOF_KDF_PRIME_ASYM_EXTEND;
  }
#else
  MCALCRY_DUMMY_STATEMENT(deriveAlgorithm);
#endif

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams_Salt(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength){
  Std_ReturnType retVal;

  McalCry_SizeOfKeyStorageType saltIndex;
  uint32 saltLength;

  retVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, &saltIndex, &saltLength, MCALCRY_LENGTH_CHECK_NONE);

  if(retVal == E_OK){
#if(MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON)
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
    if(deriveAlgorithm == MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256)
#endif
    {
      if(saltLength != MCALCRY_SIZEOF_KDF_SALT_SYMMETRIC)
      {
        retVal = E_NOT_OK;
      }
    }
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
    else
#endif
#endif
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON){
      if(saltLength != MCALCRY_SIZEOF_KDF_SALT_ASYMMETRIC)
      {
        retVal = E_NOT_OK;
      }
    }
#endif
  }

  if(retVal == E_OK){
    McalCry_CopyData(saltBuffer, McalCry_GetAddrKeyStorage(saltIndex), saltLength);
    McalCry_CopyData(&(prfInputBuffer[*prfInputBufferLength]), saltBuffer, MCALCRY_SIZEOF_KDF_CONTEXT);
    (*prfInputBufferLength) += MCALCRY_SIZEOF_KDF_CONTEXT;

    retVal = McalCry_Local_Kdf_HandleInputParams_Salt_TargetKeyLength(targetCryptoKeyId, deriveAlgorithm, saltBuffer, targetKeyLength);
  }
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_HandleInputParams(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltBuffer
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) targetKeyLength
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) parentKeyLength){
  Std_ReturnType retVal;
  McalCry_SizeOfKeyStorageType passwordIndex = 0u;
  McalCry_SizeOfKeyStorageType labelIndex = 0u;
  uint32 labelLength = MCALCRY_SIZEOF_KDF_LABEL_LENGTH;

  (*parentKeyLength) = MCALCRY_SIZEOF_KDF_MAX_PARENT_KEY;

  retVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &passwordIndex, parentKeyLength, MCALCRY_LENGTH_CHECK_MAX);

  if(retVal == E_OK){
    McalCry_CopyData(prfInputBuffer, McalCry_GetAddrKeyStorage(passwordIndex), *parentKeyLength);
    (*prfInputBufferLength) += *parentKeyLength;

    (*prfInputBufferLength)++;

    retVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYDERIVATION_LABEL, &labelIndex, &labelLength, MCALCRY_LENGTH_CHECK_MAX);
  }

  if(retVal == E_OK){
    McalCry_CopyData(&(prfInputBuffer[*prfInputBufferLength]), McalCry_GetAddrKeyStorage(labelIndex), labelLength);
    (*prfInputBufferLength) += labelLength;

    prfInputBuffer[*prfInputBufferLength] = 0x00u;
    (*prfInputBufferLength)++;

    retVal = McalCry_Local_Kdf_HandleInputParams_Salt(cryptoKeyId, targetCryptoKeyId, deriveAlgorithm, prfInputBuffer, prfInputBufferLength, saltBuffer, targetKeyLength);
  }

  if(retVal == E_OK){
    prfInputBuffer[*prfInputBufferLength] = (uint8)((uint16)((*targetKeyLength << 3u)) & 0x00FFu);
    prfInputBuffer[*prfInputBufferLength + 1u] = (uint8)((uint16)((*targetKeyLength) >> 5u) & 0x00FFu);
    (*prfInputBufferLength) += MCALCRY_SIZEOF_KDF_TARGET_KEY_LENGTH;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_CallPRF(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) prfInputBuffer
   ,  uint32 prfInputBufferLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) targetKey
   ,  uint32 targetKeyLength
   ,  uint32 parentKeyLength){
  Std_ReturnType retVal = E_OK;
  uint32_least derivedLength;
  uint8 i = 1u;

  for(derivedLength = 0u; derivedLength < targetKeyLength; derivedLength += ESL_SIZEOF_SHA256_DIGEST){
    uint8 tempHashBuf[ESL_SIZEOF_SHA256_DIGEST] = { 0u };

    prfInputBuffer[parentKeyLength] = i;
    i++;

    retVal = E_NOT_OK;

    if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_SHA256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
      if(esl_initSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace) == ESL_ERC_NO_ERROR)
      {
        if(esl_updateSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (eslt_Length)prfInputBufferLength, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))prfInputBuffer) == ESL_ERC_NO_ERROR)
        {
          if(esl_finalizeSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf) == ESL_ERC_NO_ERROR)
          {
            retVal = E_OK;
          }
        }
      }
    }

    if(retVal == E_OK){
      if((derivedLength + ESL_SIZEOF_SHA256_DIGEST) <= targetKeyLength)
      {
        McalCry_CopyData(&(targetKey[derivedLength]), tempHashBuf, ESL_SIZEOF_SHA256_DIGEST);
      }
      else
      {
        McalCry_CopyData(&(targetKey[derivedLength]), tempHashBuf, (uint16)(targetKeyLength - derivedLength));
      }
    }
    else{
      break;
    }

  }
  return retVal;
}

#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Kdf_AsymDivideByPrimeMinusOne(
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) targetKey
   ,  uint32 targetKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) primeMinus1Ptr
   ,  uint32 primeMinus1Length){
  Std_ReturnType retVal = E_OK;

#if(MCALCRY_BYTES_PER_DIGIT == 4)
  actBNDIGIT a[264u >> 2];
  actBNLENGTH a_length = (actBNLENGTH)(targetKeyLength >> 2);
  actBNDIGIT b[256u >> 2];
  actBNLENGTH b_length = (actBNLENGTH)(primeMinus1Length >> 2);
  actBNDIGIT r[264u >> 2];
#else
#   error "Value of MCALCRY_BYTES_PER_DIGIT is not supported"
#endif

  uint8 one = 1u;
  uint32 res;

  actBNSetOctetString(a, a_length, targetKey, (uint32)targetKeyLength);

  actBNSetOctetString(b, b_length, primeMinus1Ptr, (uint32)primeMinus1Length);

  res = actBNReduce(a, a_length, b, b_length, r, MCALCRY_WATCHDOG_PTR);
  if(res == (uint32)0){
    actBNSetOctetString(a, a_length, &one, (uint32)1);
    (void)actBNAdd(r, a, r, a_length);
    actBNOctetString(targetKey, (uint32)targetKeyLength, r, a_length);
  }
  else{
    retVal = E_NOT_OK;
  }
  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist800108NistFips1864_WS(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm){
  Std_ReturnType retVal;
  uint32 targetKeyLength;

  uint32 parentKeyLength;
  uint32 prfInputBufferLength = 0u;
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
  uint16 primeMinus1Length;
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) primeMinus1Ptr;
#endif

  uint8 prfInputBuffer[MCALCRY_SIZEOF_KDF_PRF_INPUT_BUFFER];
  uint8 saltBuffer[MCALCRY_SIZEOF_KDF_SALT_ASYMMETRIC];
  uint8 targetKey[MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY_PLUS_8];

  McalCry_ClearData(targetKey, MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY_PLUS_8);

  retVal = McalCry_Local_Kdf_HandleInputParams(cryptoKeyId, targetCryptoKeyId, deriveAlgorithm, prfInputBuffer, &prfInputBufferLength, saltBuffer, &targetKeyLength, &parentKeyLength);

  if(retVal == E_OK){
    retVal = McalCry_Local_Kdf_CallPRF(workspace, prfInputBuffer, prfInputBufferLength, targetKey, targetKeyLength, parentKeyLength);
  }

  if(retVal == E_OK){
#if(MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON)
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
    if(deriveAlgorithm == MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256)
#endif
    {
      retVal = McalCry_Local_KeyElementSet(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, targetKey, targetKeyLength);
    }
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
    else
#endif
#endif
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON){
      primeMinus1Ptr = &(saltBuffer[MCALCRY_SIZEOF_KDF_SALT_SYMMETRIC]);
      primeMinus1Length = MCALCRY_SIZEOF_KDF_PRIME;

      retVal = McalCry_Local_Kdf_AsymDivideByPrimeMinusOne(targetKey, targetKeyLength, primeMinus1Ptr, primeMinus1Length);

      if(retVal == E_OK)
      {
        retVal = McalCry_Local_KeyElementSet(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, &(targetKey[8]), targetKeyLength - 8u);
      }
    }
#endif
  }
  McalCry_ClearData(targetKey, MCALCRY_SIZEOF_KDF_MAX_TARGET_KEY_PLUS_8);

  if(retVal != E_OK){
    retVal = E_NOT_OK;
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist800108NistFips1864(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 deriveAlgorithm){
  Std_ReturnType retVal;
  eslt_WorkSpaceSHA256 workspace;

  retVal = McalCry_Local_KeyDerive_Nist800108NistFips1864_WS(&workspace, cryptoKeyId, targetCryptoKeyId, deriveAlgorithm);
  return retVal;
}
#endif

#if((MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON) \
    || (MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_SingleStepKdfHash(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) sharedSecretPtr
   ,  uint32 sharedSecretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) otherInfoPtr
   ,  uint32 otherInfoLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) derivedKeyPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) derivedKeyLengthPtr){
  uint32 derivedLength = 0u;
  uint8 concatenateBuf[MCALCRY_NIST80056A_COUNTER_SIZE + MCALCRY_ECC_KEY_MAXSIZE + MCALCRY_NIST80056A_OTHER_INFO_MAXSIZE];
  Std_ReturnType retVal = E_NOT_OK;

  if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_SHA256, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    {
      McalCry_CopyData(&concatenateBuf[MCALCRY_NIST80056A_COUNTER_SIZE], sharedSecretPtr, sharedSecretLength);

      McalCry_CopyData(&concatenateBuf[MCALCRY_NIST80056A_COUNTER_SIZE + sharedSecretLength], otherInfoPtr, otherInfoLength);

      {
        McalCry_Local_Uint32ToUint8ArrayBigEndian(concatenateBuf, (uint32)1u);

        if(esl_initSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace) == ESL_ERC_NO_ERROR)
        {
          if(esl_updateSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (eslt_Length)(MCALCRY_NIST80056A_COUNTER_SIZE + sharedSecretLength + otherInfoLength), (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))concatenateBuf) == ESL_ERC_NO_ERROR)
          {
            if(esl_finalizeSHA256((P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&derivedKeyPtr[derivedLength]) == ESL_ERC_NO_ERROR)
            {
              derivedLength += ESL_SIZEOF_SHA256_DIGEST;
              retVal = E_OK;
            }
          }
        }

      }
    }
  }

  if(retVal == E_OK){
    *derivedKeyLengthPtr = derivedLength;
  }

  McalCry_ClearData(concatenateBuf, MCALCRY_NIST80056A_COUNTER_SIZE + MCALCRY_ECC_KEY_MAXSIZE + MCALCRY_NIST80056A_OTHER_INFO_MAXSIZE);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) privateKeyPtr
   ,  uint32 privateKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) partnerPubKeyPtr
   ,  uint32 partnerPubKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) otherInfoPtr
   ,  uint32 otherInfoPtrLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) derivedKeyPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) derivedKeyLengthPtr){
  uint8 sharedSecret[MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE * 2u];
  Std_ReturnType retVal = E_NOT_OK;

  if(McalCry_Local_EcP_CalculateSharedSecret_With_Ws(
    privateKeyPtr, privateKeyLength
   ,   partnerPubKeyPtr, partnerPubKeyLength
   ,   sharedSecret, MCALCRY_ECDHE_256_ID
   ,   &workspace->wsEcP) == E_OK){
    retVal = McalCry_Local_KeyDerive_Nist80056A_SingleStepKdfHash(
      &workspace->wsSHA256
   ,     sharedSecret, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE
   ,     otherInfoPtr, otherInfoPtrLength
   ,     derivedKeyPtr, derivedKeyLengthPtr);
  }

  McalCry_ClearData(sharedSecret, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE * 2u);

  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_With_Ws_AndLoadKey(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  uint32 partnerPubKeyLength = MCALCRY_ECC_KEY_MAXSIZE * 2u;
  uint32 privKeyLength = MCALCRY_ECC_KEY_MAXSIZE;
  uint32 otherInfoLength = MCALCRY_NIST80056A_OTHER_INFO_MAXSIZE;
  uint32 derivedKeyBufLength = MCALCRY_ECC_KEY_MAXSIZE;

  McalCry_SizeOfKeyStorageType partnerPubKeyIndex;
  McalCry_SizeOfKeyStorageType privKeyIndex;
  McalCry_SizeOfKeyStorageType otherInfoIndex;
  uint8 derivedKeyBuf[MCALCRY_ECC_KEY_MAXSIZE];
  Std_ReturnType retVal = E_NOT_OK;
  Std_ReturnType localRet;

  McalCry_ClearData(derivedKeyBuf, MCALCRY_ECC_KEY_MAXSIZE);

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYDERIVATION_ADDITIONAL_INFO, &otherInfoIndex, &otherInfoLength, MCALCRY_LENGTH_CHECK_MAX);
  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY, &partnerPubKeyIndex, &partnerPubKeyLength, MCALCRY_LENGTH_CHECK_MAX);
  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &privKeyIndex, &privKeyLength, MCALCRY_LENGTH_CHECK_MAX);

  if(localRet == E_OK){
    if(McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S(workspace
   ,                                                                McalCry_GetAddrKeyStorage(privKeyIndex), privKeyLength
   ,                                                                McalCry_GetAddrKeyStorage(partnerPubKeyIndex), partnerPubKeyLength
   ,                                                                McalCry_GetAddrKeyStorage(otherInfoIndex), otherInfoLength
   ,                                                                derivedKeyBuf, &derivedKeyBufLength) == E_OK){
      if(McalCry_Local_KeyElementSet(targetCryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, derivedKeyBuf, derivedKeyBufLength) == E_OK)
      {
        retVal = E_OK;
      }
    }
  }

  McalCry_ClearData(derivedKeyBuf, derivedKeyBufLength);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_AndLoadKey(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retval;
  McalCry_WorkSpaceISO15118 workspace;

  retval = McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_With_Ws_AndLoadKey(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retval;
}
#endif

#if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_CheckKey(
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) privateKeyPtr
   ,  uint32 privateKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) pubKeyPtr
   ,  uint32 pubKeyLength){
  uint8 sharedSecret[MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE * 2u];
  Std_ReturnType retVal = E_NOT_OK;

  P2CONST(uint8, AUTOMATIC, MCALCRY_CONST) basePointOrder = &McalCry_EccCurveNistAnsiSecP256R1Domain[192];

  if(McalCry_Local_CompareData_IsSmaller(privateKeyPtr, basePointOrder, privateKeyLength) == E_OK){
    if(McalCry_Local_EcP_CalculateSharedSecret_With_Ws(privateKeyPtr, privateKeyLength, pubKeyPtr, pubKeyLength, sharedSecret, MCALCRY_ECDHE_256_ID, workspace) == E_OK){
      retVal = E_OK;
    }
  }

  McalCry_ClearData(sharedSecret, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE * 2u);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_Aes128Decrypt(
  P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) ivPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) encryptedMessagePtr
   ,  uint32 encryptedMessageLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) plainMessagePtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) plainMessageLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslt_Length outputDataLen;
  uint32 totalOutputDataLen = 0u;

  if(esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_AES128, MCALCRY_WATCHDOG_PTR) == ESL_ERC_NO_ERROR){
    eslRet = esl_initDecryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr
   ,                                  ESL_BM_CBC, ESL_PM_OFF, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))ivPtr);

    if(eslRet == ESL_ERC_NO_ERROR){
      outputDataLen = (eslt_Length)*plainMessageLengthPtr;

      eslRet = esl_decryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,       (eslt_Length)encryptedMessageLength, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))encryptedMessagePtr
   ,                                (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputDataLen, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))plainMessagePtr);

      if(eslRet == ESL_ERC_NO_ERROR)
      {
        totalOutputDataLen = outputDataLen;

        outputDataLen = (eslt_Length)(*plainMessageLengthPtr - totalOutputDataLen);

        eslRet = esl_decryptAES128((P2VAR(eslt_WorkSpaceAES128, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,         (eslt_Length)1u, (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))encryptedMessagePtr
   ,                                  (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&outputDataLen, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&plainMessagePtr[totalOutputDataLen]);

        if(eslRet == ESL_ERC_NO_ERROR)
        {
          totalOutputDataLen += outputDataLen;
        }
      }
    }
    if(eslRet == ESL_ERC_NO_ERROR){
      *plainMessageLengthPtr = totalOutputDataLen;
      retVal = E_OK;
    }
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118_WS(
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  uint32 encryptedIvAndPrivKeyLength = MCALCRY_ISO15118_SIZEOF_IV_AND_PRIV_KEY;

  uint32 privKeyLength = MCALCRY_ECC_KEY_MAXSIZE;
  uint32 partnerPubKeyLength = MCALCRY_ECC_KEY_MAXSIZE * 2u;

  uint32 derivedKeyLength = MCALCRY_ECC_KEY_MAXSIZE;

  uint32 newPrivateKeyLength = MCALCRY_ECC_KEY_MAXSIZE;
  uint32 newPubKeyLength = MCALCRY_ECC_KEY_MAXSIZE * 2u;

  McalCry_SizeOfKeyStorageType encryptedIvAndPrivKeyIndex;

  McalCry_SizeOfKeyStorageType privKeyIndex;
  McalCry_SizeOfKeyStorageType partnerPubKeyIndex;

  McalCry_SizeOfKeyStorageType newPubKeyIndex;

  uint8 otherInfo[MCALCRY_ISO15118_SIZEOF_OTHER_INFO];
  uint8 derivedKey[MCALCRY_ECC_KEY_MAXSIZE];

  uint8 newPrivateKey[MCALCRY_ECC_KEY_MAXSIZE];

  Std_ReturnType retVal = E_NOT_OK;
  Std_ReturnType localRet;

  McalCry_ClearData(derivedKey, MCALCRY_ECC_KEY_MAXSIZE);

  localRet = McalCry_Local_KeyElementGetStorageIndex(targetCryptoKeyId, CRYPTO_KE_CUSTOM_SCC_CONTRACT_PUBLIC_KEY, &newPubKeyIndex, &newPubKeyLength, MCALCRY_LENGTH_CHECK_MAX);
  localRet |= McalCry_Local_KeyElementGetStorageIndex(targetCryptoKeyId, CRYPTO_KE_CUSTOM_SCC_IV_AND_ENCRYPTED_PRIVATE_KEY, &encryptedIvAndPrivKeyIndex, &encryptedIvAndPrivKeyLength, MCALCRY_LENGTH_CHECK_MAX);
  localRet |= McalCry_Local_KeyElementGetStorageIndex(targetCryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY, &partnerPubKeyIndex, &partnerPubKeyLength, MCALCRY_LENGTH_CHECK_MAX);

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &privKeyIndex, &privKeyLength, MCALCRY_LENGTH_CHECK_MAX);

  if((localRet == E_OK) &&
    (encryptedIvAndPrivKeyLength == MCALCRY_ISO15118_SIZEOF_IV_AND_PRIV_KEY)){
    otherInfo[0] = 0x01u;
    otherInfo[1] = 0x55u;
    otherInfo[2] = 0x56u;

    localRet = McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S(workspace
   ,                                                                       McalCry_GetAddrKeyStorage(privKeyIndex), privKeyLength
   ,                                                                       McalCry_GetAddrKeyStorage(partnerPubKeyIndex), partnerPubKeyLength
   ,                                                                       otherInfo, MCALCRY_ISO15118_SIZEOF_OTHER_INFO
   ,                                                                       derivedKey, &derivedKeyLength);
    if(localRet == E_OK){
      localRet = McalCry_Local_KeyDerive_ISO15118_Aes128Decrypt(&workspace->wsAes
   ,                                                                       McalCry_GetAddrKeyStorage(encryptedIvAndPrivKeyIndex)
   ,                                                                       derivedKey
   ,                                                                       McalCry_GetAddrKeyStorage(encryptedIvAndPrivKeyIndex + MCALCRY_ISO15118_PRIV_KEY_START)
   ,                                                                       encryptedIvAndPrivKeyLength - MCALCRY_ISO15118_PRIV_KEY_START
   ,                                                                       newPrivateKey, &newPrivateKeyLength);
      if(localRet == E_OK)
      {
        if(McalCry_Local_KeyDerive_ISO15118_CheckKey(&workspace->wsEcP
   ,           newPrivateKey, newPrivateKeyLength
   ,           McalCry_GetAddrKeyStorage(newPubKeyIndex), newPubKeyLength)
            == E_OK)
        {
          if(McalCry_Local_KeyElementSet(targetCryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &newPrivateKey[0], newPrivateKeyLength) == E_OK)
          {
            retVal = E_OK;
          }
        }
      }
    }
  }

  McalCry_ClearData(derivedKey, derivedKeyLength);
  McalCry_ClearData(newPrivateKey, newPrivateKeyLength);

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_ISO15118(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  McalCry_WorkSpaceISO15118 workspace;

  retVal = McalCry_Local_KeyDerive_ISO15118_WS(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_X963_SHA256_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256_Calc(
  P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_KDFX963SHA256, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initKDFX963SHA256((P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyKDFX963SHA256((P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                       (eslt_Length)secretLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                       (eslt_Length)infoLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                       (eslt_Length)keyLength
   ,                                       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceKDFX963SHA256 workspace;

  retVal= McalCry_Local_KeyDerive_KDF_963_256_WS(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_256_WS(
  P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK, localRet;

  uint32 secretLength, saltLength, keyLength;
  McalCry_SizeOfKeyStorageType secretIndex, saltIndex;
  McalCry_SizeOfKeyElementsType keyElementIndex;
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltPtr = NULL_PTR;

  localRet = McalCry_Local_KeyDerive_KDF_963_Get_Secret_And_Salt(
    &secretLength
   ,   &secretIndex
   ,   &saltLength
   ,   &saltIndex
   ,   &keyLength
   ,   &keyElementIndex
   ,   cryptoKeyId
   ,   targetCryptoKeyId);

  if(localRet == E_OK){
    if(saltLength > 0u){
      saltPtr = McalCry_GetAddrKeyStorage(saltIndex);
    }

    retVal = McalCry_Local_KeyDerive_KDF_963_256_Calc(
      workspace
   ,     secretLength
   ,     McalCry_GetAddrKeyStorage(secretIndex)
   ,     saltLength
   ,     saltPtr
   ,     keyLength
   ,     McalCry_GetAddrKeyStorageOfKeyElements(keyElementIndex));

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(keyElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, keyElementIndex, keyLength);
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_X963_SHA512_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512_Calc(
  P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_KDFX963SHA512, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initKDFX963SHA512((P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyKDFX963SHA512((P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                       (eslt_Length)secretLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                       (eslt_Length)infoLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                       (eslt_Length)keyLength
   ,                                       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceKDFX963SHA512 workspace;

  retVal= McalCry_Local_KeyDerive_KDF_963_512_WS(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_512_WS(
  P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK, localRet;

  uint32 secretLength, saltLength, keyLength;
  McalCry_SizeOfKeyStorageType secretIndex, saltIndex;
  McalCry_SizeOfKeyElementsType keyElementIndex;
  P2VAR(uint8, AUTOMATIC, AUTOMATIC) saltPtr = NULL_PTR;

  localRet = McalCry_Local_KeyDerive_KDF_963_Get_Secret_And_Salt(
    &secretLength
   ,   &secretIndex
   ,   &saltLength
   ,   &saltIndex
   ,   &keyLength
   ,   &keyElementIndex
   ,   cryptoKeyId
   ,   targetCryptoKeyId);

  if(localRet == E_OK){
    if(saltLength > 0u){
      saltPtr = McalCry_GetAddrKeyStorage(saltIndex);
    }

    retVal = McalCry_Local_KeyDerive_KDF_963_512_Calc(
      workspace
   ,     secretLength
   ,     McalCry_GetAddrKeyStorage(secretIndex)
   ,     saltLength
   ,     saltPtr
   ,     keyLength
   ,     McalCry_GetAddrKeyStorageOfKeyElements(keyElementIndex));

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(keyElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, keyElementIndex, keyLength);
    }
  }

  return retVal;
}
#endif

#if((MCALCRY_KDF_ALGO_X963_SHA256_ENABLED == STD_ON) || (MCALCRY_KDF_ALGO_X963_SHA512_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_KDF_963_Get_Secret_And_Salt(
  P2VAR(uint32, AUTOMATIC, AUTOMATIC) secretLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) secretIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) saltLength
   ,  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, AUTOMATIC) saltIndex
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) keyLength
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) keyElementIndex
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType localRet;

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, secretIndex, secretLength, MCALCRY_LENGTH_CHECK_NONE);

  if(localRet == E_OK){
    localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, saltIndex, saltLength, MCALCRY_LENGTH_CHECK_NONE);

    if(localRet == CRYPTO_E_KEY_NOT_AVAILABLE){
      *saltLength = 0u;

      localRet = E_OK;
    }
    else{
    }

    if(localRet == E_OK){
      localRet = McalCry_Local_KeyElementSet_Check(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, keyElementIndex, keyLength, MCALCRY_WA_INTERNAL_COPY);
    }
  }
  return localRet;
}
#endif

#if(MCALCRY_SERVICE_KEY_DERIVE == STD_ON)

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_Derive_UpdateKeyState(
  uint32 objectId
   ,  uint32 targetCryptoKeyId
   ,  Std_ReturnType retVal){
  if(retVal == E_OK){
    McalCry_ProcessJob_Trigger_Write[objectId] = McalCry_SetKeyState(targetCryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);
  }
}
#endif

#if(MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet_Check(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndexPtr
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) keyLengthPtr
   ,  McalCry_WriteOfKeyElementInfoType writeAccess){
  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementSearch(cryptoKeyId, keyElementId, elementIndexPtr);

  if(retVal != E_OK){
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }
  else
#if(MCALCRY_SHEKEYS == STD_ON)
    if(McalCry_IsSheKey(*elementIndexPtr)){
      retVal = CRYPTO_E_KEY_WRITE_FAIL;
    }
    else
#endif

      if(McalCry_IsKeyElementStateByMask(*elementIndexPtr, MCALCRY_KEYELEMENTSTATE_WRITTEN_ONCE_MASK))
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }
      else if(writeAccess >= (McalCry_GetWriteOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(*elementIndexPtr))))
      {
        *keyLengthPtr = McalCry_GetKeyElementLength(*elementIndexPtr);
        retVal = E_OK;
      }
      else
      {
        retVal = CRYPTO_E_KEY_WRITE_FAIL;
      }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyElementSet_CheckAndLength(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(McalCry_SizeOfKeyElementsType, AUTOMATIC, AUTOMATIC) elementIndexPtr
   ,  uint32 requestedKeyLength
   ,  McalCry_WriteOfKeyElementInfoType writeAccess){
  Std_ReturnType retVal;
  uint32 keyLength;

  retVal = McalCry_Local_KeyElementSet_Check(cryptoKeyId
   ,                                                    keyElementId
   ,                                                    elementIndexPtr
   ,                                                    &keyLength
   ,                                                    writeAccess);

  if(retVal == E_OK){
    if(keyLength < requestedKeyLength){
      retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
    }
    else if((keyLength > requestedKeyLength) && (McalCry_IsKeyElementPartial(*elementIndexPtr) == FALSE)){
      retVal = CRYPTO_E_KEY_SIZE_MISMATCH;
    }
    else{
    }
  }

  return retVal;
}

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock){
  uint32 deriveAlgorithmLength = MCALCRY_KEY_DERIVE_SIZEOF_ALGORITHM;
  McalCry_SizeOfKeyStorageType deriveAlgorithmIndex;

  Std_ReturnType retVal;

  retVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_ALGORITHM, &deriveAlgorithmIndex, &deriveAlgorithmLength, MCALCRY_LENGTH_CHECK_EQUAL);

  if(retVal == E_OK){
    switch(McalCry_GetKeyStorage(deriveAlgorithmIndex)){
#if(MCALCRY_KDF_ALGO_SYM_NIST_800_108_CNT_MODE_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256:
        retVal = McalCry_Local_KeyDerive_Nist800108NistFips1864(cryptoKeyId, targetCryptoKeyId, MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256);
        break;
#endif
#if(MCALCRY_KDF_ALGO_ASYM_NIST_FIPS_186_4_ERB_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB:
        retVal = McalCry_Local_KeyDerive_Nist800108NistFips1864(cryptoKeyId, targetCryptoKeyId, MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB);
        break;
#endif
#if(MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256:
        retVal = McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_AndLoadKey(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_ISO_15118_CERTIFICATE_HANDLING:
        retVal = McalCry_Local_KeyDerive_ISO15118(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_X963_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_X963_SHA256:
        retVal = McalCry_Local_KeyDerive_KDF_963_256(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_X963_SHA512_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_KDF_X963_SHA512:
        retVal = McalCry_Local_KeyDerive_KDF_963_512(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1:
        retVal = McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA1(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256:
        retVal = McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA256(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256:
        retVal = McalCry_Local_KeyDerive_HKDF_HMAC_SHA256(cryptoKeyId, targetCryptoKeyId);
        break;
#endif
#if(MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256:
        retVal = McalCry_Local_KeyDerive_HKDF_Hash_Option_1(cryptoKeyId, targetCryptoKeyId, ESL_HA_SHA2_256);
        break;
#endif
#if(MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1_ENABLED == STD_ON)
      case MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1:
        retVal = McalCry_Local_KeyDerive_Spake2Plus(cryptoKeyId, targetCryptoKeyId);
        break;
#endif

      default:
        retVal = E_NOT_OK;
        break;
    }
  }
  else{
    retVal = E_NOT_OK;
  }

  if(retVal == E_OK){
    *writeBlock = McalCry_SetKeyState(targetCryptoKeyId, MCALCRY_KEYELEMENTSTATE_VALID_MASK);
  }
  else{
    retVal = E_NOT_OK;
    *writeBlock = FALSE;
  }

  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA1(
  P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint32 iterations){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_KDF2HMACSHA1, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initKDF2HMACSHA1((P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (eslt_Length)iterations);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyKDF2HMACSHA1((P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                       (eslt_Length)secretLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                       (eslt_Length)infoLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                       (eslt_Length)keyLength
   ,                                       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA1(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceKDF2HMACSHA1 workspace;

  retVal= McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(&workspace, cryptoKeyId, targetCryptoKeyId, MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1);
  return retVal;
}
#endif

#if((MCALCRY_KEYDERIVEKDF2HMACSHA1 == STD_ON) || (MCALCRY_KEYDERIVEKDF2HMACSHA256 == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(
  P2VAR(eslt_WorkSpaceKDF2, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  uint8 algorithm){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  uint32 iterationLength = MCALCRY_SIZEOF_KDF_ITERATIONSLENGTH;
  uint32 secretLength, saltLength, keyLength;
  McalCry_SizeOfKeyStorageType secretIndex, saltIndex, iterationIndex;
  McalCry_SizeOfKeyElementsType keyElementIndex;
  uint32 iterations;

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &secretIndex, &secretLength, MCALCRY_LENGTH_CHECK_NONE);

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, &saltIndex, &saltLength, MCALCRY_LENGTH_CHECK_NONE);

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_ITERATIONS, &iterationIndex, &iterationLength, MCALCRY_LENGTH_CHECK_EQUAL);

  localRet |= McalCry_Local_KeyElementSet_Check(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, &keyElementIndex, &keyLength, MCALCRY_WA_INTERNAL_COPY);

  if(localRet == E_OK){
    McalCry_Local_Uint8ArrayToUint32BigEndian(&iterations, McalCry_GetAddrKeyStorage(iterationIndex));

    switch(algorithm){
#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1_ENABLED == STD_ON)
    case MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1:

      retVal = McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA1(workspace
   ,       secretLength, McalCry_GetAddrKeyStorage(secretIndex)
   ,       saltLength, McalCry_GetAddrKeyStorage(saltIndex)
   ,       keyLength, McalCry_GetAddrKeyStorageOfKeyElements(keyElementIndex)
   ,       iterations);
      break;
#endif
#if(MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256_ENABLED == STD_ON)
    case MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256:

      retVal = McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA256(workspace
   ,       secretLength, McalCry_GetAddrKeyStorage(secretIndex)
   ,       saltLength, McalCry_GetAddrKeyStorage(saltIndex)
   ,       keyLength, McalCry_GetAddrKeyStorageOfKeyElements(keyElementIndex)
   ,       iterations);
      break;
#endif

    default:

      retVal = E_NOT_OK;
      break;
    }

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(keyElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, keyElementIndex, keyLength);
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEKDF2HMACSHA256 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceKDF2HMACSHA256 workspace;

  retVal= McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(&workspace, cryptoKeyId, targetCryptoKeyId, MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256);
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_PBKDF2_HMAC_SHA256(
  P2VAR(eslt_WorkSpaceKDF2HMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint32 iterations){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_KDF2HMACSHA256, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initKDF2HMACSHA256((P2VAR(eslt_WorkSpaceKDF2HMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, (eslt_Length)iterations);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyKDF2HMACSHA256((P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                       (eslt_Length)secretLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                       (eslt_Length)infoLength
   ,                                       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                       (eslt_Length)keyLength
   ,                                       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_HMAC_SHA256_WS(
  P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK, localRet, localRet_2;
  uint32 iterationLength = MCALCRY_SIZEOF_HKDF_ITERATIONSLENGTH;
  uint32 secretLength, saltLength, infoLength, keyLength;
  McalCry_SizeOfKeyStorageType secretIndex, saltIndex = 0u, infoIndex = 0u, iterationIndex;
  McalCry_SizeOfKeyElementsType keyElementIndex;
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) saltPtr;
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr;

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, &saltIndex, &saltLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRet == CRYPTO_E_KEY_NOT_AVAILABLE){
    localRet = E_OK;
    saltPtr = NULL_PTR;
    saltLength = 0u;
  }
  else{
    saltPtr = McalCry_GetAddrKeyStorage(saltIndex);
  }

  localRet_2 = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYDERIVATION_ADDITIONAL_INFO, &infoIndex, &infoLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRet_2 == CRYPTO_E_KEY_NOT_AVAILABLE){
    infoPtr = NULL_PTR;
    infoLength = 0u;
  }
  else{
    localRet |= localRet_2;
    infoPtr = McalCry_GetAddrKeyStorage(infoIndex);
  }

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &secretIndex, &secretLength, MCALCRY_LENGTH_CHECK_NONE);

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_ITERATIONS, &iterationIndex, &iterationLength, MCALCRY_LENGTH_CHECK_EQUAL);

  localRet |= McalCry_Local_KeyElementSet_Check(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, &keyElementIndex, &keyLength, MCALCRY_WA_INTERNAL_COPY);

  if(localRet == E_OK){
    retVal = McalCry_Local_KeyDerive_Calc_HKDF_HMAC_SHA256(workspace
   ,                                                                  secretLength, McalCry_GetAddrKeyStorage(secretIndex)
   ,                                                                  saltLength, saltPtr
   ,                                                                  infoLength, infoPtr
   ,                                                                  keyLength, McalCry_GetAddrKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(keyElementIndex))
   ,                                                                  *McalCry_GetAddrKeyStorage(iterationIndex));

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(keyElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, keyElementIndex, keyLength);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_HMAC_SHA256(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceHKDFHMAC workspace;

  retVal = McalCry_Local_KeyDerive_HKDF_HMAC_SHA256_WS(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_HKDF_HMAC_SHA256(
  P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 saltLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) saltPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  uint8 iterations){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_HKDF_HMAC, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initHKDF_HMAC_SHA256((P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, iterations);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyHKDF_HMAC_SHA256((P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                          (eslt_Length)secretLength
   ,                                          (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                          (eslt_Length)saltLength
   ,                                          (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))saltPtr
   ,                                          (eslt_Length)infoLength
   ,                                          (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                          (eslt_Length)keyLength
   ,                                          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_Hash_Option_1_WS(
  P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  eslt_HashAlgorithm hashId){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  uint32 secretLength, infoLength, keyLength = 0u;
  McalCry_SizeOfKeyStorageType secretIndex = 0u, infoIndex = 0u;
  McalCry_SizeOfKeyElementsType keyElementIndex;
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr;

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYDERIVATION_ADDITIONAL_INFO, &infoIndex, &infoLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRet == CRYPTO_E_KEY_NOT_AVAILABLE){
    infoPtr = NULL_PTR;
    infoLength = 0u;
    localRet = E_OK;
  }
  else{
    infoPtr = McalCry_GetAddrKeyStorage(infoIndex);
  }

  localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &secretIndex, &secretLength, MCALCRY_LENGTH_CHECK_NONE);

  localRet |= McalCry_Local_KeyElementSet_Check(targetCryptoKeyId, MCALCRY_KE_TARGET_KEY, &keyElementIndex, &keyLength, MCALCRY_WA_INTERNAL_COPY);

  if(localRet == E_OK){
    retVal = McalCry_Local_KeyDerive_Calc_HKDF_Hash_Option_1(workspace
   ,                                                                    secretLength, McalCry_GetAddrKeyStorage(secretIndex)
   ,                                                                    infoLength, infoPtr
   ,                                                                    keyLength, McalCry_GetAddrKeyStorage(McalCry_GetKeyStorageStartIdxOfKeyElements(keyElementIndex))
   ,                                                                    hashId);

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(keyElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, keyElementIndex, keyLength);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_HKDF_Hash_Option_1(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  eslt_HashAlgorithm hashId){
  Std_ReturnType retVal;
  eslt_WorkSpaceHKDFHASH workspace;

  retVal = McalCry_Local_KeyDerive_HKDF_Hash_Option_1_WS(&workspace, cryptoKeyId, targetCryptoKeyId, hashId);
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_HKDF_Hash_Option_1(
  P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 secretLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 infoLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) infoPtr
   ,  uint32 keyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) keyPtr
   ,  eslt_HashAlgorithm hashId){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_HKDF_HASH, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initHKDF_Hash_OneStep((P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, hashId);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_deriveKeyHKDF_Hash_OneStep((P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                          (eslt_Length)secretLength
   ,                                          (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                          (eslt_Length)infoLength
   ,                                          (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))infoPtr
   ,                                          (eslt_Length)keyLength
   ,                                          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))keyPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

#endif

#if(MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1_ENABLED == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Spake2Plus_WS(
  P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK, localRet;
  uint32 secretLength, w0Length, w1Length, lLength;
  McalCry_SizeOfKeyStorageType secretIndex;
  McalCry_SizeOfKeyElementsType w0ElementIndex, w1ElementIndex, lElementIndex;

  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr;
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr;

  domainPtr = (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain;
  domainExtPtr = (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt;
  w0Length = MCALCRY_SIZEOF_ECC_256_N;
  w1Length = MCALCRY_SIZEOF_ECC_256_N;
  lLength = 1u + (2u * MCALCRY_SIZEOF_ECC_256_P);

  localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_PASSWORD, &secretIndex, &secretLength, MCALCRY_LENGTH_CHECK_NONE);

  localRet |= McalCry_Local_KeyElementSet_CheckAndLength(targetCryptoKeyId, CRYPTO_KE_CUSTOM_W0, &w0ElementIndex, w0Length, MCALCRY_WA_INTERNAL_COPY);

  localRet |= McalCry_Local_KeyElementSet_CheckAndLength(targetCryptoKeyId, CRYPTO_KE_CUSTOM_W1, &w1ElementIndex, w1Length, MCALCRY_WA_INTERNAL_COPY);

  localRet |= McalCry_Local_KeyElementSet_CheckAndLength(targetCryptoKeyId, CRYPTO_KE_CUSTOM_L, &lElementIndex, lLength, MCALCRY_WA_INTERNAL_COPY);

  if(localRet == E_OK){
    retVal = McalCry_Local_KeyDerive_Calc_Spake2Plus(workspace
   ,                                                            domainPtr
   ,                                                            domainExtPtr
   ,                                                            McalCry_GetAddrKeyStorage(secretIndex), secretLength
   ,                                                            McalCry_GetAddrKeyStorageOfKeyElements(w0ElementIndex), w0Length
   ,                                                            McalCry_GetAddrKeyStorageOfKeyElements(w1ElementIndex), w1Length
   ,                                                            McalCry_GetAddrKeyStorageOfKeyElements(lElementIndex), lLength);

    if(retVal == E_OK){
      McalCry_Local_SetKeyElementStateWritten(w0ElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, w0ElementIndex, w0Length);

      McalCry_Local_SetKeyElementStateWritten(w1ElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, w1ElementIndex, w1Length);

      McalCry_Local_SetKeyElementStateWritten(lElementIndex);
      McalCry_SetKeyElementWrittenLengthWithCryptoKeyId(targetCryptoKeyId, lElementIndex, lLength);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Spake2Plus(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId){
  Std_ReturnType retVal;
  eslt_WorkSpaceSPAKE2PPreamble workspace;

  retVal = McalCry_Local_KeyDerive_Spake2Plus_WS(&workspace, cryptoKeyId, targetCryptoKeyId);
  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive_Calc_Spake2Plus(
  P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) secretPtr
   ,  uint32 secretLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) w1Ptr
   ,  uint32 w1Length
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) lPtr
   ,  uint32 lLength){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  eslt_Length lLengthPtr, w0LengthPtr, w1LengthPtr;

  lLengthPtr = (eslt_Length)lLength;
  w0LengthPtr = (eslt_Length)w0Length;
  w1LengthPtr = (eslt_Length)w1Length;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_SIZEOF_WS_SPAKE2PPRE, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initSPAKE2PPreamble((P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                    domainPtr
   ,                                    domainExtPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_calcSPAKE2PPreamble((P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,                                    (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))secretPtr
   ,                                    (eslt_Length)secretLength
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))w0Ptr
   ,                                    (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&w0LengthPtr
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))w1Ptr
   ,                                    (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&w1LengthPtr
   ,                                    (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))lPtr
   ,                                    (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&lLengthPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
      retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVENISTFIPS186ERB == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNistFips186Erb(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveNistFips186Erb(McalCry_GetKeyDeriveNistFips186ErbIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyDerive_Nist800108NistFips1864_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId, MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEISO15118 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveISO15118(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveISO15118(McalCry_GetKeyDeriveISO15118IdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyDerive_ISO15118_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEX963SHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveX963SHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceKDFX963SHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveX963SHA256(McalCry_GetKeyDeriveX963SHA256IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_KDF_963_256_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEX963SHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveX963SHA512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceKDFX963SHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveX963SHA512(McalCry_GetKeyDeriveX963SHA512IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_KDF_963_512_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVENIST80056AONEPASS == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNist80056AOnePass(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(McalCry_WorkSpaceISO15118, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveNist80056AOnePass(McalCry_GetKeyDeriveNist80056AOnePassIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyDerive_Nist80056A_OnePass_C1E1S_With_Ws_AndLoadKey(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVENIST800108CNT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNist800108Cnt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveNist800108Cnt(McalCry_GetKeyDeriveNist800108CntIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyDerive_Nist800108NistFips1864_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId, MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEKDF2HMACSHA1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveKDF2HMACSHA1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceKDF2HMACSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveKDF2HMACSHA1(McalCry_GetKeyDeriveKDF2HMACSHA1IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId, MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEKDF2HMACSHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveKDF2HMACSHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceKDF2HMACSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveKDF2HMACSHA256(McalCry_GetKeyDeriveKDF2HMACSHA256IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_PBKDF2_HMAC_SHA_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId, MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEHKDFHMACSHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveHKDFHMACSHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceHKDFHMAC, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveHKDFHMACSHA256(McalCry_GetKeyDeriveHKDFHMACSHA256IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_HKDF_HMAC_SHA256_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVESPAKE2P == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveSpake2P(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceSPAKE2PPreamble, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveSpake2P(McalCry_GetKeyDeriveSpake2PIdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_Spake2Plus_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYDERIVEHKDFHASHOPTION1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveHKDFHashOption1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceHKDFHASH, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyDeriveHKDFHashOption1(McalCry_GetKeyDeriveHKDFHashOption1IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyDerive_HKDF_Hash_Option_1_WS(workspace, job->cryptoKeyId, job->targetCryptoKeyId, ESL_HA_SHA2_256);

    McalCry_Local_Derive_UpdateKeyState(objectId, job->targetCryptoKeyId, retVal);

  }
  return retVal;
}
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

