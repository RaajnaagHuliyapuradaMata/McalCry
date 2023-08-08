

#define MCALCRY_KEYGENERATE_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_KeyGenerate.hpp"
#include "McalCry_Curve.hpp"

#define MCALCRY_KEY_GENERATE_SIZEOF_ALGORITHM                 (1u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_KEY_GENERATE_ALGORITHM_SYMMETRIC_GENERIC_ENABLED == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Symmetric(uint32 cryptoKeyId);
#endif

#if((MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON) || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_ECC_Generic(
  uint32 cryptoKeyId,
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr,
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr,
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr,
  uint32 keySize);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_ECC_Generic_With_Ws(
  uint32 cryptoKeyId,
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr,
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr,
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr,
  uint32 keySize,
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);
#endif

#if(MCALCRY_KEY_GENERATE_ALGORITHM_ED25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Ed25519(
  uint32 cryptoKeyId);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Ed25519_With_Ws(
  uint32 cryptoKeyId,
  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace);

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Ed25519_Calculate_With_Ws(
  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) privateValuePtr,
  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) privateValueLengthPtr,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr,
  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr);
#endif

#if(MCALCRY_KEY_GENERATE_ALGORITHM_SYMMETRIC_GENERIC_ENABLED == STD_ON)

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Symmetric(uint32 cryptoKeyId){
  eslt_ErrorCode getBytesRetVal = E_NOT_OK;
  Std_ReturnType retVal = E_NOT_OK;
  uint32 kgkLength;
  uint8 keyBuffer[MCALCRY_KEY_GENERATE_MAX_LENGTH];
  McalCry_SizeOfKeyElementsType elementIndex;

  if(McalCry_Local_KeyElementSearch(cryptoKeyId, CRYPTO_KE_KEYGENERATE_KEY, &elementIndex) == E_OK){
    kgkLength = McalCry_GetLengthOfKeyElementInfo(McalCry_GetKeyElementInfoIdxOfKeyElements(elementIndex));

    if(kgkLength <= MCALCRY_KEY_GENERATE_MAX_LENGTH){
      getBytesRetVal = esl_getBytesRNG((eslt_Length)kgkLength, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_APPL_VAR))keyBuffer);

      if(getBytesRetVal == E_OK)
      {
        retVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYGENERATE_KEY, (P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR))keyBuffer, kgkLength);
      }

      McalCry_ClearData(keyBuffer, kgkLength);
    }
  }
  else{
    retVal = CRYPTO_E_KEY_NOT_AVAILABLE;
  }
  return retVal;
}
#endif

#if((MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON) || (MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON))

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_ECC_Generic(
  uint32 cryptoKeyId,
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr,
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr,
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr,
  uint32 keySize){
  eslt_WorkSpaceEcP workspace;

  return McalCry_Local_KeyGenerate_ECC_Generic_With_Ws(
    cryptoKeyId,
    domainPtr,
    domainExtPtr,
    speedUpExtPtr,
    keySize,
    &workspace);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_ECC_Generic_With_Ws(
  uint32 cryptoKeyId,
  P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainPtr,
  P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) domainExtPtr,
  P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) speedUpExtPtr,
  uint32 keySize,
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;
  uint8 privKey[MCALCRY_ECC_KEY_MAXSIZE];
  uint8 pubKey[McalCry_Math_Mul2(MCALCRY_ECC_KEY_MAXSIZE)];
  uint32 doubleKeySize;

  if(McalCry_Local_Ecc_Calculate_With_Ws(pubKey, privKey, domainPtr, domainExtPtr, speedUpExtPtr, keySize, workspace) == E_OK){
    doubleKeySize = McalCry_Math_Mul2(keySize);

    retVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY, pubKey, doubleKeySize);

    if(retVal == E_OK){
      retVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYGENERATE_KEY, privKey, keySize);
    }

    McalCry_ClearData(privKey, keySize);
    McalCry_ClearData(pubKey, doubleKeySize);
  }

  return retVal;
}
#endif

#if(MCALCRY_KEY_GENERATE_ALGORITHM_ED25519_ENABLED == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Ed25519(
  uint32 cryptoKeyId){
  eslt_WorkSpaceEd25519 workspace;

  return McalCry_Local_KeyGenerate_Ed25519_With_Ws(
    cryptoKeyId,
    &workspace);
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate_Ed25519_With_Ws(
  uint32 cryptoKeyId,
  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  uint8 privKey[ESL_SIZEOF_Ed25519_SECRET_KEY];
  uint8 pubKey[ESL_SIZEOF_Ed25519_PUBLIC_KEY];
  eslt_Length privKeyLength = ESL_SIZEOF_Ed25519_SECRET_KEY;
  eslt_Length pubKeyLength = ESL_SIZEOF_Ed25519_PUBLIC_KEY;
  Std_ReturnType retVal = E_NOT_OK;

  if(McalCry_Local_Ed25519_Calculate_With_Ws(workspace,
    privKey,
    &privKeyLength,
    pubKey,
    &pubKeyLength) == E_OK){
    retVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY, pubKey, pubKeyLength);

    if(retVal == E_OK){
      retVal = McalCry_Local_KeyElementSet(cryptoKeyId, CRYPTO_KE_KEYGENERATE_KEY, privKey, privKeyLength);
    }

    McalCry_ClearData(privKey, privKeyLength);
    McalCry_ClearData(pubKey, pubKeyLength);
  }

  return retVal;
}

MCALCRY_LOCAL FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_Ed25519_Calculate_With_Ws(
  P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) privateValuePtr,
  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) privateValueLengthPtr,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) publicValuePtr,
  P2VAR(eslt_Length, AUTOMATIC, MCALCRY_APPL_VAR) publicValueLengthPtr){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_SIZEOF_WS_Ed25519, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initGenerateKeyPairEdDSA(workspace, ESL_Curve25519);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    if(esl_generateKeyPairEdDSA(workspace,
      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))privateValuePtr,
      privateValueLengthPtr,
      (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))publicValuePtr,
      publicValueLengthPtr) == ESL_ERC_NO_ERROR){
      retVal = E_OK;
    }
  }
  return retVal;
}

#endif

#if(MCALCRY_KEY_GENERATE_ALGORITHM == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Local_KeyGenerate(uint32 cryptoKeyId){
  Std_ReturnType retVal = E_NOT_OK;
  McalCry_SizeOfKeyStorageType kgaIndex;
  uint32 kgaLength = MCALCRY_KEY_GENERATE_SIZEOF_ALGORITHM;

  SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
# if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)

  if(McalCry_Local_KeyReadLockGetNotProtected(McalCry_GetDefaultRandomKey()) != E_OK){
    retVal = CRYPTO_E_BUSY;
  }
  else
# endif
  {
    if(McalCry_Local_KeyWriteLockGetNotProtected(cryptoKeyId) != E_OK){
      retVal = CRYPTO_E_BUSY;
    }
    else{
      SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

      if(McalCry_Local_KeyElementGetStorageIndex(cryptoKeyId, CRYPTO_KE_KEYGENERATE_ALGORITHM, &kgaIndex, &kgaLength, MCALCRY_LENGTH_CHECK_EQUAL) != E_OK)
      {
      }
      else
      {
# if(MCALCRY_KEY_GENERATE_ALGORITHM_SYMMETRIC_GENERIC_ENABLED == STD_ON)
        if(McalCry_GetKeyStorage(kgaIndex) == MCALCRY_KEY_GENERATE_SYMMETRIC)
        {
          retVal = McalCry_Local_KeyGenerate_Symmetric(cryptoKeyId);
        }
        else
# endif
# if(MCALCRY_KEY_GENERATE_ALGORITHM_ANSI_NIST_SEC_P256R1_ENABLED == STD_ON)
          if(McalCry_GetKeyStorage(kgaIndex) == MCALCRY_KEY_GENERATE_P256R1)
          {
            retVal = McalCry_Local_KeyGenerate_ECC_Generic(cryptoKeyId,
              (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain,
              (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt,
              (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt,
              MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE);
          }
          else
# endif
# if(MCALCRY_KEY_GENERATE_ALGORITHM_NIST_SEC_P384R1_ENABLED == STD_ON)
            if(McalCry_GetKeyStorage(kgaIndex) == MCALCRY_KEY_GENERATE_P384R1)
            {
              retVal = McalCry_Local_KeyGenerate_ECC_Generic(cryptoKeyId,
                (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1Domain,
                (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1DomainExt,
                (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1SpeedUpExt,
                MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE);
            }
            else
# endif
# if(MCALCRY_KEY_GENERATE_ALGORITHM_ED25519_ENABLED == STD_ON)
              if(McalCry_GetKeyStorage(kgaIndex) == MCALCRY_KEY_GENERATE_ALGORITHM_ED25519)
              {
                retVal = McalCry_Local_KeyGenerate_Ed25519(cryptoKeyId);
              }
              else
# endif
              {
              }

        if(retVal != E_OK)
        {
          retVal = E_NOT_OK;
        }
      }

      SchM_Enter_McalCry_MCALCRY_EXCLUSIVE_AREA_0();
      McalCry_Local_KeyWriteLockReleaseNotProtected(cryptoKeyId);
    }
# if(MCALCRY_DEFAULT_RANDOM_SOURCE == STD_ON)
    McalCry_Local_KeyReadLockReleaseNotProtected(McalCry_GetDefaultRandomKey());
# endif
  }
  SchM_Exit_McalCry_MCALCRY_EXCLUSIVE_AREA_0();

  return retVal;
}
#endif

#if((MCALCRY_KEY_EXCHANGE_ALGORITHM_ANSIP256R1_ENABLED == STD_ON)\
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
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace){
  Std_ReturnType retVal = E_NOT_OK;
  eslt_ErrorCode eslRet;

  eslRet = esl_initWorkSpaceHeader((P2VAR(eslt_WorkSpaceHeader, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&workspace->header, ESL_MAXSIZEOF_WS_ECP, MCALCRY_WATCHDOG_PTR);

  if(eslRet == ESL_ERC_NO_ERROR){
    eslRet = esl_initGenerateKeyEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace, domainPtr, domainExtPtr, speedUpExtPtr);
  }

  if(eslRet == ESL_ERC_NO_ERROR){
    if(esl_getLengthOfEcPprivateKey(domainPtr) == keySize){
      if(esl_getLengthOfEcPpublicKey_comp(domainPtr) == keySize)
      {
        if(esl_generateKeyEcP_prim((P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))workspace,
          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))privateValuePtr, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))publicValuePtr,
          (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&(publicValuePtr[keySize])) == ESL_ERC_NO_ERROR)
        {
          retVal = E_OK;
        }
      }
    }
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYGENSYMGENERIC == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenSymGeneric( uint32 objectId,
      P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
      Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyGenerate_Symmetric(job->cryptoKeyId);
  }

  MCALCRY_DUMMY_STATEMENT(objectId);

  return retVal;
}
#endif

#if(MCALCRY_KEYGENP256R1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenP256R1( uint32 objectId,
                                                                                  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
                                                                                  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyGenP256R1(McalCry_GetKeyGenP256R1IdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyGenerate_ECC_Generic_With_Ws(job->cryptoKeyId,
      (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1Domain,
      (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1DomainExt,
      (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt,
      MCALCRY_SIZEOF_ECC_256_KEY_PRIVATE,
      workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYGENP384R1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenP384R1( uint32 objectId,
                                                                                  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
                                                                                  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;
  P2VAR(eslt_WorkSpaceEcP, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyGenP384R1(McalCry_GetKeyGenP384R1IdxOfObjectInfo(objectId));

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    retVal = McalCry_Local_KeyGenerate_ECC_Generic_With_Ws(job->cryptoKeyId,
      (P2CONST(eslt_EccDomain, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1Domain,
      (P2CONST(eslt_EccDomainExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1DomainExt,
      (P2CONST(eslt_EccSpeedUpExt, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR)) McalCry_EccCurveNistSecP384R1SpeedUpExt,
      MCALCRY_SIZEOF_ECC_384_KEY_PRIVATE,
      workspace);
  }
  return retVal;
}
#endif

#if(MCALCRY_KEYGENED25519 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_KeyGenEd25519( uint32 objectId,
                                                                                   P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job,
                                                                                   Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_OK;

  if(mode == CRYPTO_OPERATIONMODE_FINISH){
    P2VAR(eslt_WorkSpaceEd25519, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workspace = McalCry_GetWorkspaceOfKeyGenEd25519(McalCry_GetKeyGenEd25519IdxOfObjectInfo(objectId));

    retVal = McalCry_Local_KeyGenerate_Ed25519_With_Ws(job->cryptoKeyId, workspace);
  }
  return retVal;
}
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

