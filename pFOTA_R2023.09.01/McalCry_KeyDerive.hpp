

#ifndef MCALCRY_KEYDRIVE_H
#define MCALCRY_KEYDRIVE_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_KEY_DERIVE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyDerive(
  uint32 cryptoKeyId
   ,  uint32 targetCryptoKeyId
   ,  P2VAR(boolean, AUTOMATIC, AUTOMATIC) writeBlock);
#endif

#if(MCALCRY_KEYDERIVENISTFIPS186ERB == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNistFips186Erb(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEISO15118 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveISO15118(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVENIST80056AONEPASS == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNist80056AOnePass(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVENIST800108CNT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveNist800108Cnt(
   uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEX963SHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveX963SHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEX963SHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveX963SHA512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEKDF2HMACSHA1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveKDF2HMACSHA1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEKDF2HMACSHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveKDF2HMACSHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEHKDFHMACSHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveHKDFHMACSHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVEHKDFHASHOPTION1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveHKDFHashOption1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_KEYDERIVESPAKE2P == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyDeriveSpake2P(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

