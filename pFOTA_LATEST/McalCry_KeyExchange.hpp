

#ifndef MCALCRY_KEYEXCHANGE_H
#define MCALCRY_KEYEXCHANGE_H

#include "CfgMcalCry.hpp"

#define MCALCRY_KEY_EXCHANGE_SIZEOF_ALGORITHM                (1u)

#define MCALCRY_ECDHE_256_ID                                 (1u)
#define MCALCRY_ECDHE_384_ID                                 (2u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_KEYX25519SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyX25519Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP256R1SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP256R1Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP384R1SECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP384R1Secret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYSPAKE2PSECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySpake2PSecret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP224R1BDSECRET == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP224R1BDSecret(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYX25519PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyX25519PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP256R1PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP256R1PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP384R1PUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP384R1PubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYP224R1BDPUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyP224R1BDPubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYSPAKE2PPUBVAL == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySpake2PPubVal(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEY_EXCHANGE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcPubVal(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyExchangeCalcSecret(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength);

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
   ,  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

