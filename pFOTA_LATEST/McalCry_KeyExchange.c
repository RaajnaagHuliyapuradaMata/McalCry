

#define MCALCRY_KEYEXCHANGE_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_KeyExchange.hpp"
#include "McalCry_KeyGenerate.hpp"
#include "McalCry_Custom.hpp"
#include "McalCry_Curve.hpp"

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)
#include "actIX25519.hpp"
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)
#include "ESLib_SPAKE2PConstants.hpp"
#endif

#define MCALCRY_ECDHE_256_ID                                  (1u)
#define MCALCRY_ECDHE_384_ID                                  (2u)

#define MCALCRY_SPAKE2P_MODE_NORMAL                           (0u)
#define MCALCRY_SPAKE2P_MODE_CHANGED_VERIFICATION             (1u)

#define MCALCRY_SPAKE2P_STATE_UNINIT                          (0u)
#define MCALCRY_SPAKE2P_STATE_CALC_PUBVAL                     (1u)
#define MCALCRY_SPAKE2P_STATE_CALC_SECRET                     (2u)
#define MCALCRY_SPAKE2P_STATE_VERIFICATION                    (3u)

#define MCALCRY_SIZEOF_ECDHE_BD_NUM_ECU_LENGTH                (1u)
#define MCALCRY_SIZEOF_ECDHE_BD_ECU_ID_LENGTH                 (1u)
#define MCALCRY_ECDHE_BD_MIN_NUM_ECU                          (3u)

#define MCALCRY_ECBD_STATE_UNINIT                             (0u)
#define MCALCRY_ECBD_STATE_CALC_PUBVAL                        (1u)
#define MCALCRY_ECBD_STATE_CALC_INTERMEDIATE                  (2u)
#define MCALCRY_ECBD_STATE_REC_INTERMEDIATE                   (3u)
#define MCALCRY_ECBD_STATE_CALC_SECRET                        (4u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_A_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w1Ptr
   ,  uint32 w1Length);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_B_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2_Public(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_Calc(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  uint8 mode);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  uint8 mode);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Spake2P_AdditionalInfoRead(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) infoPtr
   ,  uint32 infoLength
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) readPos
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) dataPos
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) dataLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_AdditionalInfo(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) infoPtr
   ,  uint32 infoLength
   ,  Std_ReturnType infoElementRetVal);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_Secret(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_Verification(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerConfirmationValuePtr
   ,  uint32 partnerConfirmationValueLength);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength);
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_X25519(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);
#endif

#if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON) \
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Generic(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr
   ,  uint32 keySize);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Generic_With_Ws(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength
   ,  uint32 keySize
   ,  uint8 keaId
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Generic_With_Ws(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr
   ,  uint32 keySize
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerIntermediateValuePtr
   ,  uint32 partnerIntermediateValueLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_First(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Update(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerIntermediateValuePtr
   ,  uint32 partnerIntermediateValueLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Finish(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId);
#endif

#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_X25519(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_X25519_With_Ws(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsX25519);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_X25519_With_Ws(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsX25519);
#endif

#if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON) \
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Generic(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength
   ,  uint32 keySize
   ,  uint8 keaId);
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GetPartnerPub(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyStorageIndexType, AUTOMATIC, AUTOMATIC) leftStorageIndexPtr
   ,  P2VAR(McalCry_KeyStorageIndexType, AUTOMATIC, AUTOMATIC) rightStorageIndexPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair_Init(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_CalcIntermediate(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_KeyExchange_BD_Prime_DeleteWorkspace(
  McalCry_SizeOfLongTermWsLockType longWsIdx);

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_KeyExchange_BD_Prime_DeleteKeys(
  uint32 cryptoKeyId);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

#endif

#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_A_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w1Ptr
   ,  uint32 w1Length){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_setPreambleDataPartyASPAKE2P(ws
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))w0Ptr, (eslt_Length)w0Length
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))w1Ptr, (eslt_Length)w1Length);

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_B_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) w0Ptr
   ,  uint32 w0Length){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode eslRet;
  McalCry_SizeOfKeyStorageType  lElementIndex;
  uint32  lElementLength;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_L, &lElementIndex, &lElementLength, MCALCRY_LENGTH_CHECK_NONE);
  if(localRetVal == E_OK){
    eslRet = esl_setPreambleDataPartyBSPAKE2P(ws
   ,     (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))w0Ptr, (eslt_Length)w0Length
   ,                                             (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(lElementIndex), (eslt_Length)lElementLength);

    if(eslRet == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2_Pre(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  McalCry_SizeOfKeyStorageType w0ElementIndex, w1ElementIndex;
  uint32 w0ElementLength, w1ElementLength;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_W0, &w0ElementIndex, &w0ElementLength, MCALCRY_LENGTH_CHECK_NONE);

  if(localRetVal == E_OK){
    localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_W1, &w1ElementIndex, &w1ElementLength, MCALCRY_LENGTH_CHECK_NONE);

    if(localRetVal != CRYPTO_E_KEY_NOT_AVAILABLE){
      if(localRetVal == E_OK)
      {
        retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P_A_Pre(ws
   ,                                                                          McalCry_GetAddrKeyStorage(w0ElementIndex), w0ElementLength
   ,                                                                          McalCry_GetAddrKeyStorage(w1ElementIndex), w1ElementLength);
      }
    }
    else{
      retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P_B_Pre(ws, cryptoKeyId
   ,                                                                        McalCry_GetAddrKeyStorage(w0ElementIndex), w0ElementLength);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2_Public(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  eslt_Length reqLength;

  reqLength = MCALCRY_SIZEOF_ECC_256_KEY_PUBLIC;

  if((McalCry_Math_Mul2((uint32)reqLength)) > *publicValueLengthPtr){
    retVal = CRYPTO_E_SMALL_BUFFER;
  }
  else{
    eslRet = esl_calcPubValSPAKE2P(ws
   ,                                 (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))publicValuePtr
   ,                                 (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&publicValuePtr[reqLength]
   ,                                 (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&reqLength);

    if(eslRet == ESL_ERC_NO_ERROR){
      *publicValueLengthPtr = McalCry_Math_Mul2((uint32)reqLength);
      retVal = E_OK;
    }
    else{
      McalCry_ClearData(publicValuePtr, *publicValueLengthPtr);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P_Calc(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  uint8 mode){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  eslt_SPAKE2PMode spakeMode;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_APPL_VAR))&ws->header, ESL_SIZEOF_WS_SPAKE2P, MCALCRY_WATCHDOG_PTR);

  if(mode == MCALCRY_SPAKE2P_MODE_NORMAL){
    spakeMode = ESL_SPAKE2P_MODE_CIPHERSUITE_8_1;
  }
  else{
    spakeMode = ESL_SPAKE2P_MODE_CIPHERSUITE_8_2;
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initSPAKE2P(ws
   ,                            domainPtr
   ,                            domainExtPtr
   ,                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))esl_SPAKE2P_pointM_P256
   ,                            (eslt_Length)sizeof(esl_SPAKE2P_pointM_P256)
   ,                            (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))esl_SPAKE2P_pointN_P256
   ,                            (eslt_Length)sizeof(esl_SPAKE2P_pointN_P256)
   ,                            spakeMode);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2_Pre(ws, cryptoKeyId);

    if(retVal == E_OK){
      retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2_Public(ws, publicValuePtr, publicValueLengthPtr);
    }
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Spake2P(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  uint8 mode){
  Std_ReturnType retVal;
  P2VAR(McalCry_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws;
  McalCry_SizeOfLongTermWsLockType longWsIdx;

  if(McalCry_Local_LongWsLockGet(cryptoKeyId, &longWsIdx) == E_OK){
    ws = (P2VAR(McalCry_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&McalCry_GetLongTermWs(longWsIdx).wsSPAKE2P;
    ws->state = MCALCRY_SPAKE2P_STATE_CALC_PUBVAL;

    retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P_Calc(cryptoKeyId
   ,                                                                    publicValuePtr, publicValueLengthPtr
   ,                                                                    &ws->wsSpake
   ,                                                                    domainPtr
   ,                                                                    domainExtPtr
   ,                                                                    mode);
    if(retVal != E_OK){
      McalCry_Local_LongWsLockRelease(cryptoKeyId, longWsIdx);
    }
  }
  else{
    retVal = CRYPTO_E_BUSY;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Spake2P_AdditionalInfoRead(
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) infoPtr
   ,  uint32 infoLength
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) readPos
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) dataPos
   ,  P2VAR(uint32, AUTOMATIC, AUTOMATIC) dataLength){
  Std_ReturnType retVal = E_NOT_OK;
  uint32 length;

  *dataLength = 0u;

  if((infoLength >= (*readPos + MCALCRY_SIZEOF_UINT32)) && !McalCry_IsUint32Overflow(*readPos, MCALCRY_SIZEOF_UINT32)){
    McalCry_Local_Uint8ArrayToUint32BigEndian(&length, &infoPtr[*readPos]);
    *readPos += MCALCRY_SIZEOF_UINT32;

    if((infoLength >= (*readPos + length)) && !McalCry_IsUint32Overflow(*readPos, length)){
      *dataLength = length;
      *dataPos = *readPos;
      *readPos += length;
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_AdditionalInfo(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) infoPtr
   ,  uint32 infoLength
   ,  Std_ReturnType infoElementRetVal){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode eslRet;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) aPtr = NULL_PTR;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) bPtr = NULL_PTR;
  P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) aadPtr = NULL_PTR;
  uint32 aLength, bLength, aadLength, readPos, dataPos;

  readPos = 0u;
  dataPos = 0u;
  if(infoElementRetVal == E_OK){
    localRetVal = McalCry_Local_Spake2P_AdditionalInfoRead(infoPtr, infoLength, &readPos, &dataPos, &aLength);
    if(aLength != 0u){
      aPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&infoPtr[dataPos];
    }

    localRetVal |= McalCry_Local_Spake2P_AdditionalInfoRead(infoPtr, infoLength, &readPos, &dataPos, &bLength);
    if(bLength != 0u){
      bPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&infoPtr[dataPos];
    }

    localRetVal |= McalCry_Local_Spake2P_AdditionalInfoRead(infoPtr, infoLength, &readPos, &dataPos, &aadLength);
    if(aadLength != 0u){
      aadPtr = (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&infoPtr[dataPos];
    }

    if(localRetVal == E_OK){
      eslRet = esl_setAdditionalInformationSPAKE2P(ws
   ,                                                  aPtr, (eslt_Length)aLength
   ,                                                  bPtr, (eslt_Length)bLength
   ,                                                  aadPtr, (eslt_Length)aadLength);
      if(eslRet == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }

  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_Secret(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength){
  Std_ReturnType retVal = E_NOT_OK, localRetVal;
  eslt_ErrorCode eslRet;
  eslt_Length halfLength, secretLength, verificationLength;
  McalCry_SizeOfKeyStorageType elementIndex;
  uint32 elementLength;
  uint8 secret[ESL_SIZEOF_SHA256_DIGEST /2u];
  uint8 verification[MCALCRY_CMACAES_MAC_SIZE];

  secretLength = ESL_SIZEOF_SHA256_DIGEST /2u;
  verificationLength = MCALCRY_CMACAES_MAC_SIZE;

  localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_ADDITIONAL_INFO, &elementIndex, &elementLength, MCALCRY_LENGTH_CHECK_NONE);

  if(localRetVal != CRYPTO_E_KEY_NOT_AVAILABLE){
    localRetVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P_AdditionalInfo(ws, McalCry_GetAddrKeyStorage(elementIndex), elementLength, localRetVal);
  }
  else{
    localRetVal = E_OK;
  }

  if(((McalCry_Math_Mul2((uint32)MCALCRY_SIZEOF_ECC_256_KEY_PUBLIC)) == partnerPublicValueLength) && (localRetVal == E_OK)){
    halfLength = (eslt_Length)McalCry_Math_Div2(partnerPublicValueLength);
    {
      eslRet = esl_calcSharedSecretSPAKE2P(ws
   ,                                          partnerPublicValuePtr, &partnerPublicValuePtr[halfLength], halfLength
   ,                                          secret, &secretLength
   ,                                          verification, &verificationLength);

      if(eslRet == ESL_ERC_NO_ERROR)
      {
        localRetVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, secret, (uint32)secretLength);
        localRetVal |= McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_VERIFICATION, verification, (uint32)verificationLength);
        if(localRetVal == E_OK)
        {
          retVal = E_OK;
        }
        else
        {
          retVal = E_NOT_OK;
        }
      }

      McalCry_ClearData(secret, ESL_SIZEOF_SHA256_DIGEST /2u);
      McalCry_ClearData(verification, MCALCRY_CMACAES_MAC_SIZE);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P_Verification(
  P2VAR(eslt_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws
   ,  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerConfirmationValuePtr
   ,  uint32 partnerConfirmationValueLength){
  Std_ReturnType retVal = E_NOT_OK, localRetVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  uint8 verification;

  verification = CRYPTO_E_VER_NOT_OK;

  eslRet = esl_confirmKeySPAKE2P(ws, partnerConfirmationValuePtr, (eslt_Length)partnerConfirmationValueLength);

  if(eslRet == ESL_ERC_INCORRECT_MAC){
    localRetVal = E_OK;
  }
  else if(eslRet == ESL_ERC_NO_ERROR){
    localRetVal = E_OK;
    verification = CRYPTO_E_VER_OK;
  }
  else{
  }

  if(McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_VERIFICATION_RESULT, &verification, 1u) == E_OK){
    retVal = localRetVal;
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Spake2P(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength){
  Std_ReturnType retVal = E_NOT_OK;
  P2VAR(McalCry_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) ws;
  McalCry_SizeOfLongTermWsLockType longWsIdx;

  if(McalCry_Local_LongWsIsLock(cryptoKeyId, &longWsIdx) == E_OK){
    ws = (P2VAR(McalCry_WorkSpaceSPAKE2P, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&McalCry_GetLongTermWs(longWsIdx).wsSPAKE2P;
    if(ws->state == MCALCRY_SPAKE2P_STATE_CALC_PUBVAL){
      ws->state = MCALCRY_SPAKE2P_STATE_CALC_SECRET;
      retVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P_Secret(&ws->wsSpake, cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
    }
    else{
      ws->state = MCALCRY_SPAKE2P_STATE_VERIFICATION;
      retVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P_Verification(&ws->wsSpake, cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
    }

    if(retVal != E_OK){
      McalCry_ClearData(ws, sizeof(McalCry_WorkSpaceSPAKE2P));
      McalCry_Local_LongWsLockRelease(cryptoKeyId, longWsIdx);
    }
    else if(ws->state == MCALCRY_SPAKE2P_STATE_VERIFICATION){
      McalCry_Local_LongWsLockRelease(cryptoKeyId, longWsIdx);
    }
    else{
    }

  }
  return retVal;
}

#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_X25519(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  eslt_WorkSpaceX25519 localWsX25519;

  return McalCry_Local_KeyExchangeCalcPubVal_X25519_With_Ws(cryptoKeyId, publicValuePtr, publicValueLengthPtr, &localWsX25519);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_X25519_With_Ws(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsX25519){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 publicKeyBuf[ESL_SIZEOF_X25519_PUBLIC_KEY];
  eslt_Length publicKeyLength = ESL_SIZEOF_X25519_PUBLIC_KEY;
  eslt_ErrorCode eslRet;
  Std_ReturnType retValKeyElementSetPrivateKey = E_NOT_OK;
  Std_ReturnType retValKeyElementSetPublicKey = E_NOT_OK;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_APPL_VAR))&wsX25519->header, ESL_SIZEOF_WS_X25519, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initECDH(wsX25519, ESL_Curve25519);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    if(esl_generateEphemeralKeyPairECDH(wsX25519, publicKeyBuf, &publicKeyLength) == ESL_ERC_NO_ERROR){
      retValKeyElementSetPrivateKey = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, (P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(((actX25519Struct*)wsX25519->wsX25519)->privateKey), ESL_SIZEOF_X25519_PRIVATE_KEY);
      retValKeyElementSetPublicKey = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY, (P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))publicKeyBuf, ESL_SIZEOF_X25519_PUBLIC_KEY);
    }

    if((retValKeyElementSetPrivateKey == E_OK) &&
      (retValKeyElementSetPublicKey == E_OK)){
      if(*publicValueLengthPtr >= ESL_SIZEOF_X25519_PUBLIC_KEY)
      {
        McalCry_CopyData(publicValuePtr, publicKeyBuf, ESL_SIZEOF_X25519_PUBLIC_KEY);
        McalCry_ClearData(publicKeyBuf, ESL_SIZEOF_X25519_PUBLIC_KEY);
        *publicValueLengthPtr = ESL_SIZEOF_X25519_PUBLIC_KEY;
        retVal = E_OK;
      }
      else

      {
        retVal = CRYPTO_E_SMALL_BUFFER;
      }
    }
  }
  return retVal;
}
#endif

#if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON) \
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Generic(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr
   ,  uint32 keySize){
  eslt_WorkSpaceEcP workspace;

  return McalCry_Local_KeyExchangeCalcPubVal_Generic_With_Ws(cryptoKeyId
   ,                                                                    publicValuePtr
   ,                                                                    publicValueLengthPtr
   ,                                                                    domainPtr
   ,                                                                    domainExtPtr
   ,                                                                    speedUpExtPtr
   ,                                                                    keySize
   ,                                                                    &workspace);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_Generic_With_Ws(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr
   ,  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr
   ,  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr
   ,  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr
   ,  uint32 keySize
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 privKey[MCALCRY_ECC_KEY_MAXSIZE];
  uint8 pubKey[McalCry_Math_Mul2(MCALCRY_ECC_KEY_MAXSIZE)];
  uint32 doubleKeySize;
  Std_ReturnType retValKeyElementSetPrivateKey = E_NOT_OK;
  Std_ReturnType retValKeyElementSetPublicKey = E_NOT_OK;

  if(McalCry_Local_Ecc_Calculate_With_Ws(pubKey, privKey, domainPtr, domainExtPtr, speedUpExtPtr, keySize, workspace) == E_OK){
    doubleKeySize = McalCry_Math_Mul2(keySize);

    retValKeyElementSetPublicKey = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY, pubKey, doubleKeySize);
    retValKeyElementSetPrivateKey = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, privKey, keySize);

    if((retValKeyElementSetPrivateKey == E_OK) &&
      (retValKeyElementSetPublicKey == E_OK)){
      if(*publicValueLengthPtr >= doubleKeySize)
      {
        McalCry_CopyData(publicValuePtr, pubKey, doubleKeySize);

        McalCry_ClearData(privKey, keySize);
        McalCry_ClearData(pubKey, doubleKeySize);

        *publicValueLengthPtr = doubleKeySize;
        retVal = E_OK;
      }
      else

      {
        retVal = CRYPTO_E_SMALL_BUFFER;
      }
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GetPartnerPub(
  uint32 cryptoKeyId
   ,  P2VAR(McalCry_KeyStorageIndexType, AUTOMATIC, AUTOMATIC) leftStorageIndexPtr
   ,  P2VAR(McalCry_KeyStorageIndexType, AUTOMATIC, AUTOMATIC) rightStorageIndexPtr){
  uint32 keyLengthLeft = MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY;
  uint32 keyLengthRight = MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY;

  Std_ReturnType retVal = E_NOT_OK;

  if(McalCry_Local_KeyElementGetStorageIndex(
    cryptoKeyId
   ,   CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY
   ,   leftStorageIndexPtr
   ,   (P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR))&keyLengthLeft
   ,   MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
    if(McalCry_Local_KeyElementGetStorageIndex(
      cryptoKeyId
   ,     CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2
   ,     rightStorageIndexPtr
   ,     (P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR))&keyLengthRight
   ,     MCALCRY_LENGTH_CHECK_EQUAL) == E_OK){
        retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair_Init(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId){
  uint32 numberDevicesLength = MCALCRY_SIZEOF_ECDHE_BD_NUM_ECU_LENGTH;
  uint32 deviceIdLength = MCALCRY_SIZEOF_ECDHE_BD_ECU_ID_LENGTH;
  McalCry_KeyStorageIndexType numberDevicesIndex;
  McalCry_KeyStorageIndexType deviceIdIndex;
  Std_ReturnType retVal = E_NOT_OK, localRet;
  uint8 numEcu, ecuId;

  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainPtr = McalCry_EccCurveNistSecP224R1Domain;
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainExtPtr = McalCry_EccCurveNistSecP224R1DomainExt;
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcSpeedUpExtPtr = McalCry_EccCurveNistSecP224R1SpeedUpExt;

  if(esl_getLengthOfEcPprivateKey(EcDomainPtr) == MCALCRY_SIZEOF_ECC_224_KEY_PRIVATE){
    if(esl_getLengthOfEcPpublicKey_comp(EcDomainPtr) == MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC){
      localRet = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_NUM_ECU
   ,                                                                &numberDevicesIndex
   ,                                                                &numberDevicesLength
   ,                                                                MCALCRY_LENGTH_CHECK_EQUAL);
      localRet |= McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_ECU_ID
   ,                                                                 &deviceIdIndex
   ,                                                                 &deviceIdLength
   ,                                                                 MCALCRY_LENGTH_CHECK_EQUAL);
      if(localRet == E_OK)
      {
        numEcu = McalCry_GetKeyStorage(numberDevicesIndex);
        ecuId = McalCry_GetKeyStorage(deviceIdIndex);
        if((ecuId <= numEcu) && (numEcu >= MCALCRY_ECDHE_BD_MIN_NUM_ECU))
        {
          wsPtr->ecuNum = numEcu;

          if(ESL_ERC_NO_ERROR == esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(wsPtr->wsBD.header), ESL_MAXSIZEOF_WS_ECBD, MCALCRY_WATCHDOG_PTR))
          {
            if(ESL_ERC_NO_ERROR == esl_initECBD(&wsPtr->wsBD, (eslt_Size32)numEcu, (eslt_Size32)ecuId, EcDomainPtr, EcDomainExtPtr, EcSpeedUpExtPtr))
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

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr)

{
  Std_ReturnType retVal = E_NOT_OK;
  Std_ReturnType localRet = E_NOT_OK;
  uint8 privKey[MCALCRY_SIZEOF_ECC_224_KEY_PRIVATE];
  uint8 publicKey[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY];

  if(McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair_Init(wsPtr, cryptoKeyId) == E_OK){
    if(esl_generateEphemeralKeyPairECBD(
      &wsPtr->wsBD
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))privKey
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))publicKey
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(publicKey[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC]))
      == ESL_ERC_NO_ERROR){
      localRet = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY
   ,                                                    publicKey
   ,                                                    MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
      localRet |= McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY
   ,                                                     privKey
   ,                                                     MCALCRY_SIZEOF_ECC_224_KEY_PRIVATE);
    }

    if(localRet == E_OK){
      if(*publicValueLengthPtr >= MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY)
      {
        McalCry_CopyData(publicValuePtr, publicKey, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
        *publicValueLengthPtr = MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY;

        retVal = E_OK;
      }
      else
      {
        retVal = CRYPTO_E_SMALL_BUFFER;
      }

      McalCry_ClearData(privKey, MCALCRY_SIZEOF_ECC_224_KEY_PRIVATE);
      McalCry_ClearData(publicKey, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_CalcIntermediate(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;

  McalCry_KeyStorageIndexType leftPublicStorageIndex;
  McalCry_KeyStorageIndexType rightPublicStorageIndex;

  uint8 intermediateKey[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY];

  if(McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GetPartnerPub(cryptoKeyId, &leftPublicStorageIndex, &rightPublicStorageIndex) == E_OK){
    if(esl_calculateIntermediateECBD(wsPtr
   ,     (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(leftPublicStorageIndex)
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&((McalCry_GetAddrKeyStorage(leftPublicStorageIndex))[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC])
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))McalCry_GetAddrKeyStorage(rightPublicStorageIndex)
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&((McalCry_GetAddrKeyStorage(rightPublicStorageIndex))[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC])
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))intermediateKey
   ,       (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(intermediateKey[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC])) == ESL_ERC_NO_ERROR){
      if(McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_INTERMEDIATE, intermediateKey, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY) == E_OK)
      {
        if(*publicValueLengthPtr >= MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY)
        {
          McalCry_CopyData(publicValuePtr, intermediateKey, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
          *publicValueLengthPtr = MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY;

          McalCry_ClearData(intermediateKey, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
          retVal = E_OK;
        }
        else
        {
          retVal = CRYPTO_E_SMALL_BUFFER;
        }
      }
    }

  }

  return retVal;
}

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_KeyExchange_BD_Prime_DeleteWorkspace(
  McalCry_SizeOfLongTermWsLockType longWsIdx){
  McalCry_ClearData(&McalCry_GetLongTermWs(longWsIdx).wsECBD, sizeof(McalCry_WorkSpaceECBD));
}

MCALCRY_LOCAL FUNC(void, MCALCRY_CODE) McalCry_Local_KeyExchange_BD_Prime_DeleteKeys(
  uint32 cryptoKeyId){
  uint8 keyBuf = 0;

  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, &keyBuf, 0u);
  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY, &keyBuf, 0u);
  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY, &keyBuf, 0u);
  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2, &keyBuf, 0u);
  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_CUSTOM_KEYEXCHANGE_INTERMEDIATE, &keyBuf, 0u);
  (void)McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, &keyBuf, 0u);
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal_BD_Prime(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) localWsEcBPPtr = NULL_PTR;
  McalCry_SizeOfLongTermWsLockType longWsIdx;

  if(McalCry_Local_LongWsIsLock(cryptoKeyId, &longWsIdx) == E_OK){
    localWsEcBPPtr = (P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&McalCry_GetLongTermWs(longWsIdx).wsECBD;
  }
  else if(McalCry_Local_LongWsLockGet(cryptoKeyId, &longWsIdx) == E_OK){
    localWsEcBPPtr = (P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&McalCry_GetLongTermWs(longWsIdx).wsECBD;
    localWsEcBPPtr->state = MCALCRY_ECBD_STATE_CALC_PUBVAL;
  }
  else{
    retVal = CRYPTO_E_BUSY;
  }

  if(localWsEcBPPtr != NULL_PTR){
    switch(localWsEcBPPtr->state){
      default:
      {
        localWsEcBPPtr->ecuCount = 0u;
        localWsEcBPPtr->ecuNum = 0u;

        retVal = McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_GenKeyPair(localWsEcBPPtr, cryptoKeyId, publicValuePtr, publicValueLengthPtr);
        localWsEcBPPtr->state = MCALCRY_ECBD_STATE_CALC_INTERMEDIATE;
        break;
      }

      case MCALCRY_ECBD_STATE_CALC_INTERMEDIATE:
      {
        retVal = McalCry_Local_KeyExchangeCalcPubVal_BD_Prime_CalcIntermediate(&localWsEcBPPtr->wsBD, cryptoKeyId, publicValuePtr, publicValueLengthPtr);
        localWsEcBPPtr->ecuCount = 1u;
        localWsEcBPPtr->state = MCALCRY_ECBD_STATE_REC_INTERMEDIATE;
        break;
      }

    }

    if(retVal != E_OK){
      McalCry_Local_KeyExchange_BD_Prime_DeleteWorkspace(longWsIdx);
      McalCry_Local_KeyExchange_BD_Prime_DeleteKeys(cryptoKeyId);
      McalCry_Local_LongWsLockRelease(cryptoKeyId, longWsIdx);
    }
  }

  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyStorageType keaIndex;
  uint32 keaLength = MCALCRY_KEY_EXCHANGE_SIZEOF_ALGORITHM;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)

  if(McalCry_Local_KeyReadLockGetNotProtected(McalCry_GetDefaultRandomKey()) != E_OK){
    retVal = CRYPTO_E_BUSY;
  }
  else
#endif
  {
    if(McalCry_Local_KeyWriteLockGetNotProtected(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_ALGORITHM, &keaIndex, &keaLength, MCALCRY_LENGTH_CHECK_EQUAL) != E_OK)
      {
      }
      else
      {
        switch(McalCry_GetKeyStorage(keaIndex))
        {
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)
          case MCALCRY_KEY_EXCHANGE_X25519:

            retVal = McalCry_Local_KeyExchangeCalcPubVal_X25519(cryptoKeyId, publicValuePtr, publicValueLengthPtr);
            break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON)
          case MCALCRY_KEY_EXCHANGE_SECP256R1:

            retVal = McalCry_Local_KeyExchangeCalcPubVal_Generic(cryptoKeyId, publicValuePtr, publicValueLengthPtr
   ,             (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                        (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt
   ,                                                                        MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE);
            break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)
          case MCALCRY_KEY_EXCHANGE_ANSIP256R1:

            retVal = McalCry_Local_KeyExchangeCalcPubVal_Generic(cryptoKeyId, publicValuePtr, publicValueLengthPtr
   ,             (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                        (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt
   ,                                                                        MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE);
            break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)
          case MCALCRY_KEY_EXCHANGE_SECP384R1:

            retVal = McalCry_Local_KeyExchangeCalcPubVal_Generic(cryptoKeyId, publicValuePtr, publicValueLengthPtr
   ,             (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1DomainExt
   ,                                                                        (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1SpeedUpExt
   ,                                                                        MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE);
            break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)

          case MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8:
            retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P(cryptoKeyId, publicValuePtr, publicValueLengthPtr
   ,             (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                        MCALCRY_SPAKE2P_MODE_NORMAL);
            break;
          case MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8_1:
            retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P(cryptoKeyId, publicValuePtr, publicValueLengthPtr
   ,             (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                        MCALCRY_SPAKE2P_MODE_CHANGED_VERIFICATION);
            break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)
            case MCALCRY_KEY_EXCHANGE_NISTP224R1_BD:

              retVal = McalCry_Local_KeyExchangeCalcPubVal_BD_Prime(cryptoKeyId, publicValuePtr, publicValueLengthPtr);
            break;
#endif
          default:

            break;
        }
      }

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
      McalCry_Local_KeyWriteLockReleaseNotProtected(cryptoKeyId);
    }
#if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
    McalCry_Local_KeyReadLockReleaseNotProtected(McalCry_GetDefaultRandomKey());
#endif
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_X25519(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr){
  eslt_WorkSpaceX25519 localWsX25519;

  return McalCry_Local_KeyExchangeCalcSecret_X25519_With_Ws(cryptoKeyId, partnerPublicValuePtr, &localWsX25519);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_X25519_With_Ws(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsX25519){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  McalCry_SizeOfKeyStorageType keyExchangePrivateKeyIndex;
  uint32 keyExchangePrivateKeyLength = ESL_SIZEOF_X25519_PRIVATE_KEY;
  eslt_Length sharedSecretLength_eslt = ESL_SIZEOF_X25519_SHARED_SECRET;
  uint8 sharedSecret[ESL_SIZEOF_X25519_SHARED_SECRET];

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&wsX25519->header, ESL_SIZEOF_WS_X25519, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initECDH(wsX25519, ESL_Curve25519);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    Std_ReturnType localRetVal;

    localRetVal = McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY, &keyExchangePrivateKeyIndex, &keyExchangePrivateKeyLength, MCALCRY_LENGTH_CHECK_EQUAL);

    if(localRetVal == E_OK){
      if(esl_importStaticPrivateKeyECDH(wsX25519, McalCry_GetAddrKeyStorage(keyExchangePrivateKeyIndex)) == ESL_ERC_NO_ERROR)
      {
        eslRet = esl_generateSharedSecretECDH(wsX25519, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))partnerPublicValuePtr, sharedSecret, &sharedSecretLength_eslt);

        if(eslRet == ESL_ERC_NO_ERROR)
        {
          if(McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, sharedSecret, (uint32)sharedSecretLength_eslt) == E_OK)
          {
            retVal = E_OK;
          }
        }

        McalCry_ClearData(sharedSecret, ESL_SIZEOF_X25519_KEY);
      }
    }
  }
  return retVal;
}
#endif

#if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON) || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON) \
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Generic(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength
   ,  uint32 keySize
   ,  uint8 keaId){
  eslt_WorkSpaceEcP workspace;

  return  McalCry_Local_KeyExchangeCalcSecret_Generic_With_Ws(cryptoKeyId
   ,                                                                     partnerPublicValuePtr
   ,                                                                     partnerPublicValueLength
   ,                                                                     keySize
   ,                                                                     keaId
   ,                                                                     &workspace);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_Generic_With_Ws(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength
   ,  uint32 keySize
   ,  uint8 keaId
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyStorageType keyExchangePrivateKeyIndex;
  uint32 keyExchangePrivateKeyLength;
  uint8 sharedSecret[McalCry_Math_Mul2(MCALCRY_ECC_KEY_MAXSIZE)];

  McalCry_ClearData(sharedSecret, McalCry_Math_Mul2((uint32)MCALCRY_ECC_KEY_MAXSIZE));

  if(McalCry_Local_KeyElementGetStorageIndex(
    cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_PRIVKEY
   ,   &keyExchangePrivateKeyIndex, &keyExchangePrivateKeyLength
   ,   MCALCRY_LENGTH_CHECK_NONE) != E_OK){
  }
  else{
    if(McalCry_Local_EcP_CalculateSharedSecret_With_Ws(
      McalCry_GetAddrKeyStorage(keyExchangePrivateKeyIndex), keyExchangePrivateKeyLength
   ,       partnerPublicValuePtr, partnerPublicValueLength
   ,     sharedSecret
   ,     keaId, workspace) == E_OK){
      if(McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, sharedSecret, McalCry_Math_Mul2(keySize)) == E_OK)
      {
        retVal = E_OK;
      }
    }

    McalCry_ClearData(sharedSecret, (uint32)McalCry_Math_Mul2(keySize));
  }

  return retVal;
}
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_First(
  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr){
  Std_ReturnType retVal = E_NOT_OK;

  if(esl_initSharedSecretECBD(&wsPtr->wsBD) == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Update(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerIntermediateValuePtr
   ,  uint32 partnerIntermediateValueLength){
  Std_ReturnType retVal = E_NOT_OK;

  if(partnerIntermediateValueLength == (MCALCRY_SIZEOF_ECDHE_BD_ECU_ID_LENGTH + MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY)){
    if(esl_updateSharedSecretECBD(wsPtr
   ,     (eslt_Size32)partnerIntermediateValuePtr[0]
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&partnerIntermediateValuePtr[MCALCRY_SIZEOF_ECDHE_BD_ECU_ID_LENGTH]
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&partnerIntermediateValuePtr[MCALCRY_SIZEOF_ECDHE_BD_ECU_ID_LENGTH + MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC])
        == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Finish(
  P2VAR(eslt_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) wsPtr
   ,  uint32 cryptoKeyId){
  uint8 sharedSecret[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY];
  Std_ReturnType retVal = E_NOT_OK, localRet;

  if(esl_retrieveSharedSecretECBD(wsPtr
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))sharedSecret
   ,          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&sharedSecret[MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC])
           == ESL_ERC_NO_ERROR){
    localRet = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE
   ,                                                  sharedSecret, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
    if(localRet == E_OK){
      retVal = E_OK;
    }

    McalCry_ClearData(sharedSecret, MCALCRY_SIZEOF_ECC_224_KEY_PUBLIC_XY);
  }
  else{
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret_BD_Prime(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerIntermediateValuePtr
   ,  uint32 partnerIntermediateValueLength){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) localWsEcBPPtr;
  McalCry_SizeOfLongTermWsLockType longWsIdx;
  boolean release = FALSE;

  if(McalCry_Local_LongWsIsLock(cryptoKeyId, &longWsIdx) == E_OK){
    localWsEcBPPtr = (P2VAR(McalCry_WorkSpaceECBD, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&McalCry_GetLongTermWs(longWsIdx).wsECBD;

    if(localWsEcBPPtr->state == MCALCRY_ECBD_STATE_REC_INTERMEDIATE){
      if(localWsEcBPPtr->ecuCount == 1u)
      {
        retVal = McalCry_Local_KeyExchangeCalcSecret_BD_Prime_First(localWsEcBPPtr);
      }
      else
      {
        retVal = E_OK;
      }

      if(retVal == E_OK)
      {
        retVal = McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Update(&localWsEcBPPtr->wsBD, partnerIntermediateValuePtr, partnerIntermediateValueLength);
      }

      if((retVal == E_OK) && (localWsEcBPPtr->ecuCount == (localWsEcBPPtr->ecuNum - 1u)))
      {
        retVal = McalCry_Local_KeyExchangeCalcSecret_BD_Prime_Finish(&localWsEcBPPtr->wsBD, cryptoKeyId);
        McalCry_Local_KeyExchange_BD_Prime_DeleteWorkspace(longWsIdx);
        release = TRUE;
      }
    }

    if(retVal != E_OK){
      McalCry_Local_KeyExchange_BD_Prime_DeleteWorkspace(longWsIdx);
      McalCry_Local_KeyExchange_BD_Prime_DeleteKeys(cryptoKeyId);
      release = TRUE;
    }
    else{
      localWsEcBPPtr->ecuCount = (uint8)(localWsEcBPPtr->ecuCount + 1u);
    }

    if(release){
      McalCry_Local_LongWsLockRelease(cryptoKeyId, longWsIdx);
    }
  }

  return retVal;
}
#endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyStorageType keaIndex;
  uint32 keaLength = MCALCRY_KEY_EXCHANGE_SIZEOF_ALGORITHM;

  if(McalCry_Local_KeyWriteLockGet(cryptoKeyId) != E_OK){
    retVal = CRYPTO_E_BUSY;
  }
  else{
    if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_ALGORITHM, &keaIndex, &keaLength, MCALCRY_LENGTH_CHECK_EQUAL) != E_OK){
    }
    else{
      switch(McalCry_GetKeyStorage(keaIndex))
      {
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_X25519_ENABLED == STD_ON)
        case MCALCRY_KEY_EXCHANGE_X25519:

          if(partnerPublicValueLength == ESL_SIZEOF_X25519_PUBLIC_KEY)
          {
            retVal = McalCry_Local_KeyExchangeCalcSecret_X25519(cryptoKeyId, partnerPublicValuePtr);
          }
          break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)
        case MCALCRY_KEY_EXCHANGE_ANSIP256R1:

          retVal = McalCry_Local_KeyExchangeCalcSecret_Generic(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE, MCALCRY_ECDHE_256_ID);
          break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON)
        case MCALCRY_KEY_EXCHANGE_SECP256R1:

          retVal = McalCry_Local_KeyExchangeCalcSecret_Generic(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE, MCALCRY_ECDHE_256_ID);
          break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)
        case MCALCRY_KEY_EXCHANGE_SECP384R1:

          retVal = McalCry_Local_KeyExchangeCalcSecret_Generic(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength, MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE, MCALCRY_ECDHE_384_ID);
          break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SPAKE2_PLUS_CIPHERSUITE_8_ENABLED == STD_ON)

        case MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8:
          retVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
          break;
        case MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8_1:
          retVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
          break;
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_NISTP224R1_BD_ENABLED == STD_ON)
        case MCALCRY_KEY_EXCHANGE_NISTP224R1_BD:

            retVal = McalCry_Local_KeyExchangeCalcSecret_BD_Prime(cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
          break;
#endif
        default:

          break;
      }
    }

    McalCry_Local_KeyWriteLockRelease(cryptoKeyId);
  }

  return retVal;
}
#endif

#if((MCALCRY_KDF_ALGO_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256_ENABLED == STD_ON)\
    || (MCALCRY_KDF_ALGO_ISO_15118_CERTIFICATE_HANDLING_ENABLED == STD_ON)\
    || (MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)\
    || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON)\
    || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_EcP_CalculateSharedSecret_With_Ws(
  P2CONST(uint8, AUTOMATIC, AUTOMATIC) privateKeyPtr
   ,  uint32 privateKeyLength
   ,  P2CONST(uint8, AUTOMATIC, AUTOMATIC) partnerPubKeyPtr
   ,  uint32 partnerPubKeyLength
   ,  P2VAR(uint8, AUTOMATIC, AUTOMATIC) sharedSecretPtr
   ,  uint8 keaId
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainPtr;
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) EcDomainExtPtr;

#if(MCALCRY_KEY_EXCHANGE_P256R1_DOMAIN == STD_ON)
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)
  if(keaId == MCALCRY_ECDHE_256_ID)
#else
  MCALCRY_DUMMY_STATEMENT(keaId);
#endif
  {
    EcDomainPtr = McalCry_EccCurveNistAnsiSecP256R1Domain;
    EcDomainExtPtr = McalCry_EccCurveNistAnsiSecP256R1DomainExt;
  }
#else
  MCALCRY_DUMMY_STATEMENT(keaId);
#endif
#if(MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)
#if(MCALCRY_KEY_EXCHANGE_P256R1_DOMAIN == STD_ON)
  else
#endif
  {
  EcDomainPtr = McalCry_EccCurveNistSecP384R1Domain;
  EcDomainExtPtr = McalCry_EccCurveNistSecP384R1DomainExt;
  }
#endif

  if(privateKeyLength != esl_getLengthOfEcPprivateKey(EcDomainPtr)){
  }
  else if(partnerPubKeyLength != (uint32)McalCry_Math_Mul2((uint32)esl_getLengthOfEcPpublicKey_comp(EcDomainPtr))){
  }
  else{
    eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_ECP, MCALCRY_WATCHDOG_PTR);

    if(eslRet == ESL_ERC_NO_ERROR){
      eslRet = esl_initGenerateSharedSecretDHEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, EcDomainPtr, EcDomainExtPtr);
    }

    if(eslRet == ESL_ERC_NO_ERROR){
      eslRet = esl_generateSharedSecretDHEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace
   ,       (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))privateKeyPtr
   ,                                                 (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&partnerPubKeyPtr[0], (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&partnerPubKeyPtr[esl_getLengthOfEcPprivateKey(EcDomainPtr)]
   ,                                                 (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&sharedSecretPtr[0], (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&sharedSecretPtr[esl_getLengthOfEcPsecret_comp(EcDomainPtr)]);
      if(eslRet == ESL_ERC_NO_ERROR)
      {
        retVal = E_OK;
      }
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_KEYX25519SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyX25519Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyX25519Secret(McalCry_GetKeyX25519SecretIdxOfObjectInfo(objectId));

  if(mode ==CRYPTO_OPERATIONMODE_FINISH){
    if(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength == ESL_SIZEOF_X25519_PUBLIC_KEY){
      retVal = McalCry_Local_KeyExchangeCalcSecret_X25519_With_Ws(job->cryptoKeyId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, workspace);
    }
    else{
      retVal = E_NOT_OK;
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP256R1SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP256R1Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyP256R1Secret(McalCry_GetKeyP256R1SecretIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcSecret_Generic_With_Ws(job->cryptoKeyId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE, MCALCRY_ECDHE_256_ID, workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP384R1SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP384R1Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyP384R1Secret(McalCry_GetKeyP384R1SecretIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcSecret_Generic_With_Ws(job->cryptoKeyId, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr, job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength, MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE, MCALCRY_ECDHE_384_ID, workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYSPAKE2PSECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySpake2PSecret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  MCALCRY_DUMMY_STATEMENT_CONST(objectId);

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcSecret_Spake2P(job->cryptoKeyId
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP224R1BDSECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP224R1BDSecret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  MCALCRY_DUMMY_STATEMENT_CONST(objectId);

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcSecret_BD_Prime(job->cryptoKeyId
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYX25519PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyX25519PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceX25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyX25519PubVal(McalCry_GetKeyX25519PubValIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcPubVal_X25519_With_Ws( job->cryptoKeyId
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,                                                                        workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP256R1PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP256R1PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyP256R1PubVal(McalCry_GetKeyP256R1PubValIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcPubVal_Generic_With_Ws(job->cryptoKeyId
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,                                                                        (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                        (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt
   ,                                                                        MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE
   ,                                                                        workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP384R1PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP384R1PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyP384R1PubVal(McalCry_GetKeyP384R1PubValIdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcPubVal_Generic_With_Ws(job->cryptoKeyId
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                                        job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,                                                                        (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1Domain
   ,                                                                        (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1DomainExt
   ,                                                                        (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1SpeedUpExt
   ,                                                                        MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE
   ,                                                                        workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYP224R1BDPUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP224R1BDPubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  MCALCRY_DUMMY_STATEMENT_CONST(objectId);

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyExchangeCalcPubVal_BD_Prime(job->cryptoKeyId
   ,                                                                 job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                                 job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYSPAKE2PPUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySpake2PPubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  uint8 spakeMode;

  MCALCRY_DUMMY_STATEMENT_CONST(objectId);

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    if(job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == CRYPTO_ALGOMODE_NOT_SET){
      spakeMode = MCALCRY_SPAKE2P_MODE_NORMAL;
    }
    else{
      spakeMode = MCALCRY_SPAKE2P_MODE_CHANGED_VERIFICATION;
    }

    retVal = McalCry_Local_KeyExchangeCalcPubVal_Spake2P(job->cryptoKeyId
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,                                                                job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr
   ,                                                                (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain
   ,                                                                (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt
   ,                                                                spakeMode);
  }
  return retVal;
}
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

