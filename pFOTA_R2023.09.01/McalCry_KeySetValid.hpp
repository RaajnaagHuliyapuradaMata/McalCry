

#ifndef MCALCRY_KEYSETVALID_H
#define MCALCRY_KEYSETVALID_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_KEYSETVALID == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySetValid(uint32 objectId, P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job, Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

