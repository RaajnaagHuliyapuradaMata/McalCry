

#ifndef MCALCRY_RANDOMSEED_H
# define MCALCRY_RANDOMSEED_H

# include "CfgMcalCry.hpp"

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

# if((MCALCRY_FIPS186 == STD_ON) || (MCALCRY_DRBGAES == STD_ON) || (MCALCRY_DRBGHASHSHA512 == STD_ON))

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_RandomSeed(
  uint32 cryptoKeyId,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) entropyPtr,
  uint32 entropyLength);
# endif

# if(MCALCRY_KEYSEEDDRBGAES == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedDRBGAES(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_KEYSEEDFIPS186 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedFips186(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# if(MCALCRY_KEYSEEDDRBGHASHSHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeySeedDRBGHashSha512(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
  Crypto_OperationModeType mode);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

