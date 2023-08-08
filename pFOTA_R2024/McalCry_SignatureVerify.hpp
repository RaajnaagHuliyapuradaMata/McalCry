

#if !defined (MCALCRY_SIGNATUREVERIFY_H)
# define MCALCRY_SIGNATUREVERIFY_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_ED25519VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_Ed25519Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_RSAPKCS1VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_RSAPSSVERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPssVerify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP256VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP256Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP384VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP384Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_ECP160VERIFY == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_EcP160Verify(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

