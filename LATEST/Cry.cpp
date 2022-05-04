/******************************************************************************/
/* File   : Cry.cpp                                                           */
/* Author : NAGARAJA HM (c) since 1982. All rights reserved.                  */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "Module.hpp"
#include "CfgCry.hpp"
#include "Cry_core.hpp"
#include "infCry.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define CRY_AR_RELEASE_VERSION_MAJOR                                           4
#define CRY_AR_RELEASE_VERSION_MINOR                                           3

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/
#if(CRY_AR_RELEASE_VERSION_MAJOR != STD_AR_RELEASE_VERSION_MAJOR)
   #error "Incompatible CRY_AR_RELEASE_VERSION_MAJOR!"
#endif

#if(CRY_AR_RELEASE_VERSION_MINOR != STD_AR_RELEASE_VERSION_MINOR)
   #error "Incompatible CRY_AR_RELEASE_VERSION_MINOR!"
#endif

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/
class module_Cry:
      public abstract_module
   ,  public class_Cry_Functionality
{
   public:
      module_Cry(Std_TypeVersionInfo lVersionInfo) : abstract_module(lVersionInfo){
      }
      FUNC(void, CRY_CODE) InitFunction(
         CONSTP2CONST(CfgModule_TypeAbstract, CRY_CONFIG_DATA, CRY_APPL_CONST) lptrCfgModule
      );
      FUNC(void, CRY_CODE) DeInitFunction (void);
      FUNC(void, CRY_CODE) MainFunction   (void);
      CRY_CORE_FUNCTIONALITIES
};

extern VAR(module_Cry, CRY_VAR) Cry;

/******************************************************************************/
/* CONSTS                                                                     */
/******************************************************************************/
CONSTP2VAR(infEcuMClient, CRY_VAR, CRY_CONST) gptrinfEcuMClient_Cry = &Cry;
CONSTP2VAR(infDcmClient,  CRY_VAR, CRY_CONST) gptrinfDcmClient_Cry  = &Cry;
CONSTP2VAR(infSchMClient, CRY_VAR, CRY_CONST) gptrinfSchMClient_Cry = &Cry;

/******************************************************************************/
/* PARAMS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/
VAR(module_Cry, CRY_VAR) Cry(
   {
         CRY_AR_RELEASE_VERSION_MAJOR
      ,  CRY_AR_RELEASE_VERSION_MINOR
      ,  0x00
      ,  0xFF
      ,  0x01
      ,  '0'
      ,  '1'
      ,  '0'
   }
);

/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/
FUNC(void, CRY_CODE) module_Cry::InitFunction(
   CONSTP2CONST(CfgModule_TypeAbstract, CRY_CONFIG_DATA, CRY_APPL_CONST) lptrCfgModule
){
#if(STD_ON == Cry_InitCheck)
   if(E_OK != IsInitDone){
#endif
      if(NULL_PTR != lptrCfgModule){
         if(STD_LOW){
            // check lptrCfgModule for memory faults
            lptrCfg = lptrCfgModule;
         }
         else{
            // use PBcfgCanIf as back-up configuration
            lptrCfg = &PBcfgCry;
         }
      }
      else{
#if(STD_ON == Cry_DevErrorDetect)
         Det_ReportError(
               0 //TBD: IdModule
            ,  0 //TBD: IdInstance
            ,  0 //TBD: IdApi
            ,  0 //TBD: IdError
         );
#endif
      }
#if(STD_ON == Cry_InitCheck)
      IsInitDone = E_OK;
   }
   else{
#if(STD_ON == Cry_DevErrorDetect)
      Det_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_Cry::DeInitFunction(void){
#if(STD_ON == Cry_InitCheck)
   if(E_OK == IsInitDone){
#endif
#if(STD_ON == Cry_InitCheck)
      IsInitDone = E_NOT_OK;
   }
   else{
#if(STD_ON == Cry_DevErrorDetect)
      Det_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_Cry::MainFunction(void){
#if(STD_ON == Cry_InitCheck)
   if(E_OK == IsInitDone){
#endif
#if(STD_ON == Cry_InitCheck)
   }
   else{
#if(STD_ON == Cry_DevErrorDetect)
      Det_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_Cry::ProcessJob(void){
}

FUNC(void, CRY_CODE) module_Cry::CancelJob(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyElementSet(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyValidSet(void){
}

FUNC(void, CRY_CODE) module_Cry::KeySetValid(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyElementGet(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyElementCopy(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyCopy(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyElementIdsGet(void){
}

FUNC(void, CRY_CODE) module_Cry::RandomSeed(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyGenerate(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyDerive(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyExchangeCalcPubVal(void){
}

FUNC(void, CRY_CODE) module_Cry::KeyExchangeCalcSecret(void){
}

FUNC(void, CRY_CODE) module_Cry::CertificateParse(void){
}

FUNC(void, CRY_CODE) module_Cry::CertificateVerify(void){
}

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

