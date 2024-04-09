

#if !defined (MCALCRY_MACVERIFY_H)
#define MCALCRY_MACVERIFY_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_CMACAESVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_CmacAesVerify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_SIPHASHVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SipHashVerify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_HMACSHA1VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha1Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_HMACSHA256VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha256Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_HMACSHA384VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha384Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_GMACAESVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_GmacAesVerify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_HMACRIPEMD160VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacRipeMd160Verify(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

