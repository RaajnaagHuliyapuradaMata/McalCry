#pragma once
/******************************************************************************/
/* File   : Cry_core.hpp                                                      */
/* Author : NAGARAJA HM (c) since 1982. All rights reserved.                  */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "CompilerCfg_Cry.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define CRY_CORE_FUNCTIONALITIES                                               \
              FUNC(void, CRY_CODE) ProcessJob            (void);               \
              FUNC(void, CRY_CODE) CancelJob             (void);               \
              FUNC(void, CRY_CODE) KeyElementSet         (void);               \
              FUNC(void, CRY_CODE) KeyValidSet           (void);               \
              FUNC(void, CRY_CODE) KeySetValid           (void);               \
              FUNC(void, CRY_CODE) KeyElementGet         (void);               \
              FUNC(void, CRY_CODE) KeyElementCopy        (void);               \
              FUNC(void, CRY_CODE) KeyCopy               (void);               \
              FUNC(void, CRY_CODE) KeyElementIdsGet      (void);               \
              FUNC(void, CRY_CODE) RandomSeed            (void);               \
              FUNC(void, CRY_CODE) KeyGenerate           (void);               \
              FUNC(void, CRY_CODE) KeyDerive             (void);               \
              FUNC(void, CRY_CODE) KeyExchangeCalcPubVal (void);               \
              FUNC(void, CRY_CODE) KeyExchangeCalcSecret (void);               \
              FUNC(void, CRY_CODE) CertificateParse      (void);               \
              FUNC(void, CRY_CODE) CertificateVerify     (void);               \

#define CRY_CORE_FUNCTIONALITIES_VIRTUAL                                       \
      virtual FUNC(void, CRY_CODE) ProcessJob            (void) = 0;           \
      virtual FUNC(void, CRY_CODE) CancelJob             (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyElementSet         (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyValidSet           (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeySetValid           (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyElementGet         (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyElementCopy        (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyCopy               (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyElementIdsGet      (void) = 0;           \
      virtual FUNC(void, CRY_CODE) RandomSeed            (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyGenerate           (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyDerive             (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyExchangeCalcPubVal (void) = 0;           \
      virtual FUNC(void, CRY_CODE) KeyExchangeCalcSecret (void) = 0;           \
      virtual FUNC(void, CRY_CODE) CertificateParse      (void) = 0;           \
      virtual FUNC(void, CRY_CODE) CertificateVerify     (void) = 0;           \

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/
class class_Cry_Functionality{
   public:
      CRY_CORE_FUNCTIONALITIES_VIRTUAL
};

/******************************************************************************/
/* CONSTS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* PARAMS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/

/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

