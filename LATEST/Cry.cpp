/******************************************************************************/
/* File   : Cry.cpp                                                           */
/* Author : NAGARAJA HM (c) since 1982. All rights reserved.                  */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "module.hpp"
#include "infCry_EcuM.hpp"
#include "infCry_Dcm.hpp"
#include "infCry_SchM.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define CRY_AR_RELEASE_MAJOR_VERSION                                           4
#define CRY_AR_RELEASE_MINOR_VERSION                                           3

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/
#if(CRY_AR_RELEASE_MAJOR_VERSION != STD_AR_RELEASE_MAJOR_VERSION)
   #error "Incompatible CRY_AR_RELEASE_MAJOR_VERSION!"
#endif

#if(CRY_AR_RELEASE_MINOR_VERSION != STD_AR_RELEASE_MINOR_VERSION)
   #error "Incompatible CRY_AR_RELEASE_MINOR_VERSION!"
#endif

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/
class module_Cry:
      public abstract_module
{
   public:
      module_Cry(Std_TypeVersionInfo lVersionInfo) : abstract_module(lVersionInfo){
      }
      FUNC(void, CRY_CODE) InitFunction   (void);
      FUNC(void, CRY_CODE) DeInitFunction (void);
      FUNC(void, CRY_CODE) MainFunction   (void);
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
#include "CfgCry.hpp"

/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/
VAR(module_Cry, CRY_VAR) Cry(
   {
         0x0000
      ,  0xFFFF
      ,  0x01
      ,  '0'
      ,  '1'
      ,  '0'
   }
);

/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/
FUNC(void, CRY_CODE) module_Cry::InitFunction(void){
   Cry.IsInitDone = E_OK;
}

FUNC(void, CRY_CODE) module_Cry::DeInitFunction(void){
   Cry.IsInitDone = E_NOT_OK;
}

FUNC(void, CRY_CODE) module_Cry::MainFunction(void){
}

class class_Cry_Unused{
   public:
      FUNC(void, CRY_CODE) ProcessJob            (void);
      FUNC(void, CRY_CODE) CancelJob             (void);
      FUNC(void, CRY_CODE) KeyElementSet         (void);
      FUNC(void, CRY_CODE) KeyValidSet           (void);
      FUNC(void, CRY_CODE) KeySetValid           (void);
      FUNC(void, CRY_CODE) KeyElementGet         (void);
      FUNC(void, CRY_CODE) KeyElementCopy        (void);
      FUNC(void, CRY_CODE) KeyCopy               (void);
      FUNC(void, CRY_CODE) KeyElementIdsGet      (void);
      FUNC(void, CRY_CODE) RandomSeed            (void);
      FUNC(void, CRY_CODE) KeyGenerate           (void);
      FUNC(void, CRY_CODE) KeyDerive             (void);
      FUNC(void, CRY_CODE) KeyExchangeCalcPubVal (void);
      FUNC(void, CRY_CODE) KeyExchangeCalcSecret (void);
      FUNC(void, CRY_CODE) CertificateParse      (void);
      FUNC(void, CRY_CODE) CertificateVerify     (void);
};

FUNC(void, CRY_CODE) class_Cry_Unused::ProcessJob(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::CancelJob(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyElementSet(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyValidSet(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeySetValid(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyElementGet(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyElementCopy(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyCopy(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyElementIdsGet(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::RandomSeed(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyGenerate(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyDerive(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyExchangeCalcPubVal(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::KeyExchangeCalcSecret(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::CertificateParse(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::CertificateVerify(void){
}

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

