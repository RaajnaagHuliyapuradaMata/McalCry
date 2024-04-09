

#if !defined (MCALCRY_HASH_H)
#define MCALCRY_HASH_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_SHA1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_SHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_SHA384 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA384(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_SHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_RIPEMD160 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RipeMd160(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_SHA3_256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA3_256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_MD5 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_MD5(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

