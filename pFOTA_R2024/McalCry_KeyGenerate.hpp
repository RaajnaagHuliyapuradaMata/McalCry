

#ifndef MCALCRY_KEYGENERATE_H
# define MCALCRY_KEYGENERATE_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_KEY_GENERATE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate(uint32 cryptoKeyId);
# endif

# if(MCALCRY_KEYGENSYMGENERIC == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenSymGeneric(uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_KEYGENP256R1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenP256R1(uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_KEYGENP384R1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenP384R1(uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_KEYGENED25519 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenEd25519(uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_EXCHANGE_ALGORITHM_SECP384R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON)\
     || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE)  McalCry_Local_Ecc_Calculate_With_Ws(
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) privateValuePtr,
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr,
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr,
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr,
  uint32 keySize,
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

