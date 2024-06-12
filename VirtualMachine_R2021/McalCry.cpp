/******************************************************************************/
/* File   : McalCry.cpp                                                           */
/* Author : Nagaraja HULIYAPURADA-MATA                                        */
/* Date   : 01.02.1982                                                        */
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

/******************************************************************************/
/* CONSTS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* PARAMS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/
VAR(module_McalCry, CRY_VAR) McalCry;

/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/
FUNC(void, CRY_CODE) module_McalCry::InitFunction(
      CONSTP2CONST(ConstModule_TypeAbstract, CRY_CONST,       CRY_APPL_CONST) lptrConstModule
   ,  CONSTP2CONST(CfgModule_TypeAbstract,   CRY_CONFIG_DATA, CRY_APPL_CONST) lptrCfgModule
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
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_McalCry::DeInitFunction(
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
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_McalCry::MainFunction(
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
         ,  CRY_E_UNINIT
      );
#endif
   }
#endif
}

FUNC(void, CRY_CODE) module_McalCry::ProcessJob(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::McalCancelJob(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyElementSet(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyValidSet(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeySetValid(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyElementGet(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyElementCopy(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyCopy(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyElementIdsGet(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::RandomSeed(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyGenerate(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyDerive(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyExchangeCalcPubVal(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::KeyExchangeCalcSecret(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::CertificateParse(
   void
){
}

FUNC(void, CRY_CODE) module_McalCry::CertificateVerify(
   void
){
}

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

