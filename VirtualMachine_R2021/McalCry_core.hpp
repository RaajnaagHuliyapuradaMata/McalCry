#pragma once
/******************************************************************************/
/* File   : McalCry_core.hpp                                                      */
/*                                                                            */
/* Author : Nagaraja HULIYAPURADA MATA                                        */
/*                                                                            */
/* License / Warranty / Terms and Conditions                                  */
/*                                                                            */
/* Everyone is permitted to copy and distribute verbatim copies of this lice- */
/* nse document, but changing it is not allowed. This is a free, copyright l- */
/* icense for software and other kinds of works. By contrast, this license is */
/* intended to guarantee your freedom to share and change all versions of a   */
/* program, to make sure it remains free software for all its users. You have */
/* certain responsibilities, if you distribute copies of the software, or if  */
/* you modify it: responsibilities to respect the freedom of others.          */
/*                                                                            */
/* All rights reserved. Copyright © 1982 Nagaraja HULIYAPURADA MATA           */
/*                                                                            */
/* Always refer latest software version from:                                 */
/* https://github.com/NagarajaHuliyapuradaMata?tab=repositories               */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "CompilerCfg_McalCry.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/
#define CRY_CORE_FUNCTIONALITIES                                               \
              FUNC(void, CRY_CODE) ProcessJob            (void);               \
              FUNC(void, CRY_CODE) McalCancelJob             (void);               \
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
      virtual FUNC(void, CRY_CODE) McalCancelJob             (void) = 0;           \
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
class class_McalCry_Functionality{
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

