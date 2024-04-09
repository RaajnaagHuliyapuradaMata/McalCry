

#ifndef MCALCRY_KEYMANAGEMENT_H
#define MCALCRY_KEYMANAGEMENT_H
#include "Types_SwcServiceCsm.hpp"
#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyCopy(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementCopy(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 targetCryptoKeyId
   ,  uint32 targetKeyElementId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementCopyPartial(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  uint32 keyElementSourceOffset
   ,  uint32 keyElementTargetOffset
   ,  uint32 keyElementCopyLength
   ,  uint32 targetCryptoKeyId
   ,  uint32 targetKeyElementId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementIdsGet(
  uint32 cryptoKeyId
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) keyElementIdsPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) keyElementIdsLengthPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementSet(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) keyPtr
   ,  uint32 keyLength);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyValidSet(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyElementGet(
  uint32 cryptoKeyId
   ,  uint32 keyElementId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) resultPtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_RandomSeed(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr
   ,  uint32 entropyLength);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyGenerate(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyDerive(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyExchangeCalcPubVal(
  uint32 cryptoKeyId
   ,  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr
   ,  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_KeyExchangeCalcSecret(
  uint32 cryptoKeyId
   ,  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) partnerPublicValuePtr
   ,  uint32 partnerPublicValueLength);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CertificateParse(
  uint32 cryptoKeyId);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CertificateVerify(
  uint32 cryptoKeyId
   ,  uint32 verifyCryptoKeyId
   ,  P2VAR(Crypto_VerifyResultType, AUTOMATIC, MCALCRY_APPL_VAR) verifyPtr);

#if(MCALCRY_SHECMDGETID == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SheCmdGetId(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

