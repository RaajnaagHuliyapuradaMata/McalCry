

#define MCALCRY_HASH_SOURCE

#include "McalCry.hpp"
#include "McalCry_Services.hpp"
#include "McalCry_Hash.hpp"

#define MCALCRY_HASH_SHA3_224_BITLENGTH                       (224u)
#define MCALCRY_HASH_SHA3_256_BITLENGTH                       (256u)
#define MCALCRY_HASH_SHA3_384_BITLENGTH                       (384u)
#define MCALCRY_HASH_SHA3_512_BITLENGTH                       (512u)

#define MCALCRY_START_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

#if(MCALCRY_SHA1 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeStart(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeFinish(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SHA256 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeStart(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeFinish(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SHA384 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeStart(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeFinish(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SHA512 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeStart(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeFinish(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SHA3_256 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeStart(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  eslt_Length bitLength);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeFinish(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_RIPEMD160 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeStart(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeUpdate(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeFinish(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_MD5 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeStart(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeUpdate(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeFinish(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);
#endif

#if(MCALCRY_SHA1 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeStart(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_SHA1, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initSHA1(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateSHA1(workSpace
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha1ModeFinish(
  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_SHA1_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeSHA1(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA1_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA1_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA256 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeStart(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_SHA256, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initSHA256(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateSHA256(workSpace
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha256ModeFinish(
  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_SHA256_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeSHA256(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA256_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA256_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA384 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeStart(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_SHA384, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initSHA384(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateSHA384(workSpace
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha384ModeFinish(
  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_SHA384_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeSHA384(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA384_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA384_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA512 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeStart(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_SHA512, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initSHA512(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateSHA512(workSpace
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashSha512ModeFinish(
  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_SHA512_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeSHA512(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_SHA512_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_SHA512_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA3_256 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeStart(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  eslt_Length bitLength){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_SHA3, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initSHA3(workSpace, bitLength);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeUpdate(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateSHA3(workSpace
   ,   (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchSha3ModeFinish(
  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;
  eslt_Length tempHashLength = (eslt_Length)*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr;

  retValCv = esl_finalizeSHA3(workSpace
   ,   (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr
   ,   (P2VAR(eslt_Length, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))&tempHashLength);

  *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = tempHashLength;

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_RIPEMD160 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeStart(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_RIPEMD160, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initRIPEMD160(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeUpdate(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateRIPEMD160(workSpace
   ,                           (eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,                           (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchRipeMd160ModeFinish(
  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_RIPEMD160_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeRIPEMD160(workSpace, tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_RIPEMD160_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_RIPEMD160_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_MD5 == STD_ON)

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeStart(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_initWorkSpaceHeader(&(workSpace->header), ESL_MAXSIZEOF_WS_MD5, MCALCRY_WATCHDOG_PTR);

  if(retValCv == ESL_ERC_NO_ERROR){
    retValCv = esl_initMD5(workSpace);
  }

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeUpdate(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2CONST(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_updateMD5(workSpace
   ,   (const eslt_Length)job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputLength
   ,   (P2CONST(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.inputPtr);

  if(retValCv == ESL_ERC_NO_ERROR){
    retVal = E_OK;
  }

  return retVal;
}

MCALCRY_LOCAL_INLINE FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_DispatchHashMD5ModeFinish(
  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpace
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job){
  eslt_ErrorCode retValCv;
  uint8 tempHashBuf[ESL_SIZEOF_MD5_DIGEST];
  Std_ReturnType retVal = E_NOT_OK;

  retValCv = esl_finalizeMD5(workSpace, (P2VAR(eslt_Byte, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR))tempHashBuf);

  if(retValCv == ESL_ERC_NO_ERROR){
    if(*job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr > ESL_SIZEOF_MD5_DIGEST){
      *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr = ESL_SIZEOF_MD5_DIGEST;
    }

    McalCry_CopyData(job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputPtr, tempHashBuf, *job->MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER.outputLengthPtr);

    retVal = E_OK;
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA1 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA1(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceSHA1, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceSha1 = McalCry_GetWorkspaceOfSHA1(McalCry_GetSHA1IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSHA1));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHashSha1ModeStart(workSpaceSha1);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchHashSha1ModeUpdate(workSpaceSha1, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchHashSha1ModeFinish(workSpaceSha1, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceSHA256, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceSha256 = McalCry_GetWorkspaceOfSHA256(McalCry_GetSHA256IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSHA256));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHashSha256ModeStart(workSpaceSha256);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchHashSha256ModeUpdate(workSpaceSha256, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchHashSha256ModeFinish(workSpaceSha256, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA384 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA384(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceSHA384, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceSha384 = McalCry_GetWorkspaceOfSHA384(McalCry_GetSHA384IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSHA384));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHashSha384ModeStart(workSpaceSha384);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchHashSha384ModeUpdate(workSpaceSha384, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchHashSha384ModeFinish(workSpaceSha384, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA512 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA512(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceSHA512, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceSha512 = McalCry_GetWorkspaceOfSHA512(McalCry_GetSHA512IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSHA512));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHashSha512ModeStart(workSpaceSha512);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchHashSha512ModeUpdate(workSpaceSha512, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchHashSha512ModeFinish(workSpaceSha512, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_SHA3_256 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_SHA3_256(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceSHA3, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceSha3 = McalCry_GetWorkspaceOfSHA3_256(McalCry_GetSHA3_256IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceSHA3));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchSha3ModeStart(workSpaceSha3, MCALCRY_HASH_SHA3_256_BITLENGTH);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchSha3ModeUpdate(workSpaceSha3, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchSha3ModeFinish(workSpaceSha3, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_RIPEMD160 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_RipeMd160(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceRIPEMD160, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceRipeMd160 = McalCry_GetWorkspaceOfRipeMd160(McalCry_GetRipeMd160IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceRIPEMD160));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchRipeMd160ModeStart(workSpaceRipeMd160);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchRipeMd160ModeUpdate(workSpaceRipeMd160, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchRipeMd160ModeFinish(workSpaceRipeMd160, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#if(MCALCRY_MD5 == STD_ON)

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_Dispatch_MD5(
  uint32 objectId
   ,  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job
   ,  Crypto_OperationModeType mode){
  Std_ReturnType retVal = E_NOT_OK;

  P2VAR(eslt_WorkSpaceMD5, AUTOMATIC, MCALCRY_CRYPTOCV_APPL_VAR) workSpaceMd5 = McalCry_GetWorkspaceOfMD5(McalCry_GetMD5IdxOfObjectInfo(objectId));
  McalCry_SetLengthOfSaveAndRestoreWorkspace(objectId, sizeof(eslt_WorkSpaceMD5));

  switch(mode){
    case CRYPTO_OPERATIONMODE_START:
    {
      retVal = McalCry_DispatchHashMD5ModeStart(workSpaceMd5);
      break;
    }

    case CRYPTO_OPERATIONMODE_UPDATE:
    {
      retVal = McalCry_DispatchHashMD5ModeUpdate(workSpaceMd5, job);
      break;
    }

    case CRYPTO_OPERATIONMODE_FINISH:
    {
      retVal = McalCry_DispatchHashMD5ModeFinish(workSpaceMd5, job);
      break;
    }
    default:
    {
      break;
    }
  }

  return retVal;
}
#endif

#define MCALCRY_STOP_SEC_CODE
#include "CompilerCfg_McalCry.hpp"

