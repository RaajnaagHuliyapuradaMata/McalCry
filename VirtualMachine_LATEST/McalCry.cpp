/******************************************************************************/
/* File   : McalCry.cpp                                                       */
/* Author : NAGARAJA HM (c) since 1982. All rights reserved.                  */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "Module.hpp"
#include "McalCry.hpp"
#include "infMcalCry_Imp.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define MCALCRY_AR_RELEASE_VERSION_MAJOR                                       4
#define MCALCRY_AR_RELEASE_VERSION_MINOR                                       3

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/
#if(MCALCRY_AR_RELEASE_VERSION_MAJOR != STD_AR_RELEASE_VERSION_MAJOR)
   #error "Incompatible MCALCRY_AR_RELEASE_VERSION_MAJOR!"
#endif

#if(MCALCRY_AR_RELEASE_VERSION_MINOR != STD_AR_RELEASE_VERSION_MINOR)
   #error "Incompatible MCALCRY_AR_RELEASE_VERSION_MINOR!"
#endif

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/

/******************************************************************************/
/* CONSTS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* PARAMS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/
VAR(module_McalCry, MCALCRY_VAR) McalCry;

/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/
FUNC(void, MCALCRY_CODE) module_McalCry::InitFunction(
      CONSTP2CONST(ConstModule_TypeAbstract, MCALCRY_CONST,       MCALCRY_APPL_CONST) lptrConstModule
   ,  CONSTP2CONST(CfgModule_TypeAbstract,   MCALCRY_CONFIG_DATA, MCALCRY_APPL_CONST) lptrCfgModule
){
#if(STD_ON == McalCry_InitCheck)
   if(
         E_OK
      != IsInitDone
   ){
#endif
      if(
            (NULL_PTR != lptrConstModule)
         && (NULL_PTR != lptrCfgModule)
      ){
         lptrConst = (const ConstMcalCry_Type*)lptrConstModule;
         lptrCfg   = lptrCfgModule;
      }
      else{
#if(STD_ON == McalCry_DevErrorDetect)
         ServiceDet_ReportError(
               0 //TBD: IdModule
            ,  0 //TBD: IdInstance
            ,  0 //TBD: IdApi
            ,  0 //TBD: IdError
         );
#endif
      }
#if(STD_ON == McalCry_InitCheck)
      IsInitDone = E_OK;
   }
   else{
#if(STD_ON == McalCry_DevErrorDetect)
      ServiceDet_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  MCALCRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, MCALCRY_CODE) module_McalCry::DeInitFunction(
   void
){
#if(STD_ON == McalCry_InitCheck)
   if(
         E_OK
      == IsInitDone
   ){
#endif
#if(STD_ON == McalCry_InitCheck)
      IsInitDone = E_NOT_OK;
   }
   else{
#if(STD_ON == McalCry_DevErrorDetect)
      ServiceDet_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  MCALCRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, MCALCRY_CODE) module_McalCry::MainFunction(
   void
){
#if(STD_ON == McalCry_InitCheck)
   if(
         E_OK
      == IsInitDone
   ){
#endif
#if(STD_ON == McalCry_InitCheck)
   }
   else{
#if(STD_ON == McalCry_DevErrorDetect)
      ServiceDet_ReportError(
            0 //TBD: IdModule
         ,  0 //TBD: IdInstance
         ,  0 //TBD: IdApi
         ,  MCALCRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, MCALCRY_CODE) module_McalCry::ProcessJob(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::McalCancelJob(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyElementSet(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyValidSet(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeySetValid(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyElementGet(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyElementCopy(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyCopy(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyElementIdsGet(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::RandomSeed(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyGenerate(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyDerive(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyExchangeCalcPubVal(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::KeyExchangeCalcSecret(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::CertificateParse(
   void
){
}

FUNC(void, MCALCRY_CODE) module_McalCry::CertificateVerify(
   void
){
}

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

