

#if !defined (MCALCRY_MACGENERATE_H)
# define MCALCRY_MACGENERATE_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_CMACAESGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_CmacAesGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_SIPHASHGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SipHashGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_HMACSHA1GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha1Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_HMACSHA256GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha256Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_HMACSHA384GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacSha384Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_GMACAESGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_GmacAesGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_HMACRIPEMD160GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_HmacRipeMd160Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

