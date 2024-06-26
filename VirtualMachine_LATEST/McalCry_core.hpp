#pragma once
/******************************************************************************/
/* File   : McalCry_core.hpp                                                      */
/* Author : Nagaraja HULIYAPURADA-MATA                                        */
/* Date   : 01.02.1982                                                        */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "CompilerCfg_McalCry.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define MCALCRY_CORE_FUNCTIONALITIES                                               \
              FUNC(void, MCALCRY_CODE) ProcessJob            (void);               \
              FUNC(void, MCALCRY_CODE) McalCancelJob             (void);               \
              FUNC(void, MCALCRY_CODE) KeyElementSet         (void);               \
              FUNC(void, MCALCRY_CODE) KeyValidSet           (void);               \
              FUNC(void, MCALCRY_CODE) KeySetValid           (void);               \
              FUNC(void, MCALCRY_CODE) KeyElementGet         (void);               \
              FUNC(void, MCALCRY_CODE) KeyElementCopy        (void);               \
              FUNC(void, MCALCRY_CODE) KeyCopy               (void);               \
              FUNC(void, MCALCRY_CODE) KeyElementIdsGet      (void);               \
              FUNC(void, MCALCRY_CODE) RandomSeed            (void);               \
              FUNC(void, MCALCRY_CODE) KeyGenerate           (void);               \
              FUNC(void, MCALCRY_CODE) KeyDerive             (void);               \
              FUNC(void, MCALCRY_CODE) KeyExchangeCalcPubVal (void);               \
              FUNC(void, MCALCRY_CODE) KeyExchangeCalcSecret (void);               \
              FUNC(void, MCALCRY_CODE) CertificateParse      (void);               \
              FUNC(void, MCALCRY_CODE) CertificateVerify     (void);               \

#define MCALCRY_CORE_FUNCTIONALITIES_VIRTUAL                                       \
      virtual FUNC(void, MCALCRY_CODE) ProcessJob            (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) McalCancelJob             (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyElementSet         (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyValidSet           (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeySetValid           (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyElementGet         (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyElementCopy        (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyCopy               (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyElementIdsGet      (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) RandomSeed            (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyGenerate           (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyDerive             (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyExchangeCalcPubVal (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) KeyExchangeCalcSecret (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) CertificateParse      (void) = 0;           \
      virtual FUNC(void, MCALCRY_CODE) CertificateVerify     (void) = 0;           \

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/
class class_McalCry_Functionality{
   public:
      MCALCRY_CORE_FUNCTIONALITIES_VIRTUAL
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

