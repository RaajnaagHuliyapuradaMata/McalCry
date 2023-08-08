

#if !defined (MCALCRY_SIGNATUREGENERATE_H)
# define MCALCRY_SIGNATUREGENERATE_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_ED25519GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Ed25519Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_RSAPKCS1GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_RSAPSSGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPssGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_RSAPKCS1CRTGENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1CrtGenerate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP256GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP256Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP384GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP384Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP160GENERATE == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP160Generate(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

