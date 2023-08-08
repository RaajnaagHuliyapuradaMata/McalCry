

#if !defined (MCALCRY_INTERNALAPI_H)
# define MCALCRY_INTERNALAPI_H

# include "McalCry_Services.hpp"

typedef struct{
  boolean isKeyValid;
  boolean isSheKey;
  boolean write_protection;

  boolean boot_protection;
  boolean debugger_protection;
  boolean key_usage;
  boolean disable_wildcard;
  boolean cmac_usage;
}McalCry_KeyFlagType;

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_KeyElementGetStorageIndex(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_SizeOfKeyStorageType, AUTOMATIC, MCALCRY_APPL_VAR) resultIndexPtr,
  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) resultLengthPtr,
  McalCry_LengthCheckType lengthCheck,
  McalCry_ServiceType serviceType);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_GetKeyFlags(
  uint32 cryptoKeyId,
  uint32 keyElementId,
  P2VAR(McalCry_KeyFlagType, AUTOMATIC, MCALCRY_APPL_VAR) keyFlagsPtr);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Api_KeyReadLockGetNotProtected(
  uint32 cryptoKeyId);

FUNC(void, MCALCRY_CODE) McalCry_Api_KeyReadLockReleaseNotProtected(
  uint32 cryptoKeyId);

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#endif

