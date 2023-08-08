#if !defined (MCALCRY_H)
# define MCALCRY_H
#ifdef __cplusplus
extern "C"
{
#endif

# include "Csm_Types.hpp"
# include "CfgMcalCry.hpp"
# include "McalCry_KeyManagement.hpp"
# include "SchM_McalCry.hpp"

# include "McalCry_Custom.hpp"

# if(MCALCRY_USE_VSTD_LIB == STD_ON)
#  include "vstdlib.hpp"
# endif

# define MCALCRY_VENDOR_ID                                    (30u)
# define MCALCRY_MODULE_ID                                    (114u)
# define MCALCRY_INSTANCE_ID                                  (0u)

# define MCALCRY_AR_RELEASE_MAJOR_VERSION                     (0x04u)
# define MCALCRY_AR_RELEASE_MINOR_VERSION                     (0x03u)
# define MCALCRY_AR_RELEASE_REVISION_VERSION                  (0x00u)

# define MCALCRY_MAJOR_VERSION                                (11u)
# define MCALCRY_MINOR_VERSION                                (1u)
# define MCALCRY_PATCH_VERSION                                (0u)

# define MCALCRY_SID_INIT                                     (0x00u)
# define MCALCRY_SID_GET_VERSION_INFO                         (0x01u)
# define MCALCRY_SID_PROCESS_JOB                              (0x03u)
# define MCALCRY_SID_CANCEL_JOB                               (0x0Eu)
# define MCALCRY_SID_KEY_ELEMENT_SET                          (0x04u)
# define MCALCRY_SID_KEY_VALID_SET                            (0x05u)
# define MCALCRY_SID_KEY_ELEMENT_GET                          (0x06u)
# define MCALCRY_SID_KEY_ELEMENT_COPY                         (0x0Fu)
# define MCALCRY_SID_KEY_ELEMENT_COPY_PARTIAL                 (0x13u)
# define MCALCRY_SID_KEY_COPY                                 (0x10u)
# define MCALCRY_SID_KEY_ELEMENT_IDS_GET                      (0x11u)
# define MCALCRY_SID_RANDOM_SEED                              (0x0Du)
# define MCALCRY_SID_KEY_GENERATE                             (0x07u)
# define MCALCRY_SID_KEY_DERIVE                               (0x08u)
# define MCALCRY_SID_KEY_EXCHANGE_CALC_PUB_VAL                (0x09u)
# define MCALCRY_SID_KEY_EXCHANGE_CALC_SECRET                 (0x0Au)
# define MCALCRY_SID_CERTIFICATE_PARSE                        (0x0Bu)
# define MCALCRY_SID_CERTIFICATE_VERIFY                       (0x12u)
# define MCALCRY_SID_MAIN_FUNCTION                            (0x0Cu)
# define MCALCRY_SID_NVBLOCK_READFROMBLOCK                    (0x80u)
# define MCALCRY_SID_NVBLOCK_WRITETOBLOCK                     (0x81u)
# define MCALCRY_SID_NVBLOCK_INIT                             (0x82u)
# define MCALCRY_SID_NVBLOCK_CALLBACK                         (0x83u)
# define MCALCRY_SID_ESL_GETBYTESRNG                          (0x84u)

# define MCALCRY_UNINIT                                       (0x00u)

# define MCALCRY_INITIALIZED                                  (0x01u)

# ifndef CRYPTO_E_NO_ERROR
#  define CRYPTO_E_NO_ERROR                                           (255u)
# endif
# ifndef CRYPTO_E_UNINIT
#  define CRYPTO_E_UNINIT                                             (0u)
# endif
# ifndef CRYPTO_E_INIT_FAILED
#  define CRYPTO_E_INIT_FAILED                                        (1u)
# endif
# ifndef CRYPTO_E_PARAM_POINTER
#  define CRYPTO_E_PARAM_POINTER                                      (2u)
# endif
# ifndef CRYPTO_E_PARAM_HANDLE
#  define CRYPTO_E_PARAM_HANDLE                                       (4u)
# endif
# ifndef CRYPTO_E_PARAM_VALUE
#  define CRYPTO_E_PARAM_VALUE                                        (5u)
# endif

# ifndef CRYPTO_E_KEY_EMPTY
#  define CRYPTO_E_KEY_EMPTY                                          (13u)
# endif

# ifndef CRYPTO_E_RE_ENTROPY_EXHAUSTED
#  define CRYPTO_E_RE_ENTROPY_EXHAUSTED                               (3u)
# endif
# ifndef CRYPTO_E_RE_GET_BYTES_RNG_ERROR
#  define CRYPTO_E_RE_GET_BYTES_RNG_ERROR                             (30u)
# endif

# if(MCALCRY_USE_VSTD_LIB == STD_ON)

#  define McalCry_CopyData(destinationPtr, sourcePtr, length) (VStdLib_MemCpy((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(destinationPtr), (P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(sourcePtr), (VStdLib_CntType)(length)))
#  define McalCry_ClearData(dataPtr, length)                  (VStdLib_MemClr((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(dataPtr), (VStdLib_CntType)(length)))
#  define McalCry_SetData(dataPtr, pattern, length)           (VStdLib_MemSet((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(dataPtr), (pattern), (VStdLib_CntType)(length)))
# else

#  define McalCry_CopyData(destinationPtr, sourcePtr, length) (McalCry_Local_CopyData_Implementation((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(destinationPtr), (P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(sourcePtr), (length)))
#  define McalCry_ClearData(dataPtr, length)                  (McalCry_Local_ClearData_Implementation((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(dataPtr), (length)))
#  define McalCry_SetData(dataPtr, pattern, length)           (McalCry_Local_SetData_Implementation((P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR))(dataPtr), (pattern), (length)))
# endif

# if(MCALCRY_WATCHDOGTRIGGERFUNCTIONOFGENERAL == STD_ON)
#  define MCALCRY_WATCHDOG_PTR                                McalCry_GetWatchdogTriggerFunctionOfGeneral()
# else
#  define MCALCRY_WATCHDOG_PTR                                (NULL_PTR)
# endif

# ifndef MCALCRY_JOB_STATE_MEMBER
#  define MCALCRY_JOB_STATE_MEMBER                            jobState
# endif

# ifndef MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER
#  define MCALCRY_JOB_PRIMITIVE_INPUT_OUTPUT_MEMBER           jobPrimitiveInputOutput
# endif

# define MCALCRY_START_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

FUNC(void, MCALCRY_CODE) McalCry_Init(void);

FUNC(void, MCALCRY_CODE) McalCry_InitMemory(void);

# if(MCALCRY_VERSION_INFO_API == STD_ON)

FUNC(void, MCALCRY_CODE) McalCry_GetVersionInfo(
  P2VAR(Std_VersionInfoType, AUTOMATIC, MCALCRY_APPL_VAR) versioninfo);
# endif

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_ProcessJob(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

FUNC(Std_ReturnType, MCALCRY_CODE) McalCry_CancelJob(
  uint32 objectId,
  P2VAR(Crypto_JobType, AUTOMATIC, MCALCRY_APPL_VAR) job);

# if(MCALCRY_SAVEANDRESTOREWORKSPACE == STD_ON)

extern FUNC(Std_ReturnType, MCALCRY_APPL_CODE) Appl_McalCry_SaveContextCallout(
  uint32 objectId,
  uint32 jobId,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) context,
  uint32 contextLength,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) outputPtr,
  P2VAR(uint32, AUTOMATIC, MCALCRY_APPL_VAR) outputLengthPtr);

extern FUNC(Std_ReturnType, MCALCRY_APPL_CODE) Appl_McalCry_RestoreContextCallout(
  uint32 objectId,
  uint32 jobId,
  P2VAR(uint8, AUTOMATIC, MCALCRY_APPL_VAR) context,
  uint32 contextLength,
  P2CONST(uint8, AUTOMATIC, MCALCRY_APPL_VAR) inputPtr,
  uint32 inputLength);
# endif

# define MCALCRY_STOP_SEC_CODE
# include "CompilerCfg_McalCry.hpp"

#ifdef __cplusplus
}
#endif
#endif

