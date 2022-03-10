/*****************************************************/
/* File   : Cry.cpp                                  */
/* Author : Naagraaj HM                              */
/*****************************************************/

/*****************************************************/
/* #INCLUDES                                         */
/*****************************************************/
#include "module.h"
#include "infCry_EcuM.h"
#include "infCry_SchM.h"
#include "Cry_Unused.h"

/*****************************************************/
/* #DEFINES                                          */
/*****************************************************/

/*****************************************************/
/* MACROS                                            */
/*****************************************************/

/*****************************************************/
/* TYPEDEFS                                          */
/*****************************************************/
class module_Cry:
      public abstract_module
{
   public:
      FUNC(void, CRY_CODE) InitFunction   (void);
      FUNC(void, CRY_CODE) DeInitFunction (void);
      FUNC(void, CRY_CODE) GetVersionInfo (void);
      FUNC(void, CRY_CODE) MainFunction   (void);
};

/*****************************************************/
/* CONSTS                                            */
/*****************************************************/

/*****************************************************/
/* PARAMS                                            */
/*****************************************************/

/*****************************************************/
/* OBJECTS                                           */
/*****************************************************/
module_Cry     Cry;
infEcuMClient* gptrinfEcuMClient_Cry = &Cry;
infDcmClient*  gptrinfDcmClient_Cry  = &Cry;
infSchMClient* gptrinfSchMClient_Cry = &Cry;

/*****************************************************/
/* FUNCTIONS                                         */
/*****************************************************/
FUNC(void, CRY_CODE) module_Cry::InitFunction(void){
}

FUNC(void, CRY_CODE) module_Cry::DeInitFunction(void){
}

FUNC(void, CRY_CODE) module_Cry::GetVersionInfo(void){
}

FUNC(void, CRY_CODE) module_Cry::MainFunction(void){
}

FUNC(void, CRY_CODE) class_Cry_Unused::GetVersionInfo(void){
}

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

/*****************************************************/
/* EOF                                               */
/*****************************************************/

