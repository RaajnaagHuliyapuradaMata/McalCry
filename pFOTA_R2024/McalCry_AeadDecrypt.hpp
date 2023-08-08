

#if !defined (MCALCRY_AEADDECRYPT_H)
# define MCALCRY_AEADDECRYPT_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_AESGCMDECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesGcmDecrypt(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_AESCCMDECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesCcmDecrypt(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_AEADCHACHAPOLY1305DECRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AEADChaChaPoly1305Decrypt(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

