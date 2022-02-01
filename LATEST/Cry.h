#pragma once
/*****************************************************/
/* File   : Cry.h                                    */
/* Author : Naagraaj HM                              */
/*****************************************************/

/*****************************************************/
/* #INCLUDES                                         */
/*****************************************************/
#include "Std_Types.h"
#include "Compiler_Cfg_Cry.h"

/*****************************************************/
/* #DEFINES                                          */
/*****************************************************/

/*****************************************************/
/* MACROS                                            */
/*****************************************************/

/*****************************************************/
/* TYPEDEFS                                          */
/*****************************************************/
class class_Cry{
   public:
/*****************************************************/
/* FUNCTIONS                                         */
/*****************************************************/
      FUNC(void, CRY_CODE) InitFunction          (void);
      FUNC(void, CRY_CODE) GetVersionInfo        (void);
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
      FUNC(void, CRY_CODE) MainFunction          (void);
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
extern class_Cry Cry;

/*****************************************************/
/* EOF                                               */
/*****************************************************/

