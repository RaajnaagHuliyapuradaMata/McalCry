

#if !defined (MCALCRY_RANDOMGENERATE_H)
#define MCALCRY_RANDOMGENERATE_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_FIPS186 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Fips186(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_DRBGAES == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_DRBGAES(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_DRBGHASHSHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_DRBGHashSha512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

