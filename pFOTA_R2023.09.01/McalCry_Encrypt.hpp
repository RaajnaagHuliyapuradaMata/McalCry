

#if !defined (MCALCRY_ENCRYPT_H)
#define MCALCRY_ENCRYPT_H

#include "CfgMcalCry.hpp"

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_AESENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_AesEncrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_RSAPKCS1ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaPkcs1Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_RSAOAEPSHA1ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha1Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#if(MCALCRY_RSAOAEPSHA256ENCRYPT == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RsaOaepSha256Encrypt(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode);
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#endif

