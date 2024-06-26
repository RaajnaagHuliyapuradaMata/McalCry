#pragma once
/******************************************************************************/
/* File   : McalCry.hpp                                                           */
/* Author : Nagaraja HULIYAPURADA-MATA                                        */
/* Date   : 01.02.1982                                                        */
/******************************************************************************/

/******************************************************************************/
/* #INCLUDES                                                                  */
/******************************************************************************/
#include "ConstMcalCry.hpp"
#include "CfgMcalCry.hpp"
#include "McalCry_core.hpp"
#include "infMcalCry_Exp.hpp"

/******************************************************************************/
/* #DEFINES                                                                   */
/******************************************************************************/

/******************************************************************************/
/* MACROS                                                                     */
/******************************************************************************/

/******************************************************************************/
/* TYPEDEFS                                                                   */
/******************************************************************************/
class module_McalCry:
      INTERFACES_EXPORTED_CRY
      public abstract_module
   ,  public class_McalCry_Functionality
{
   private:
/******************************************************************************/
/* OBJECTS                                                                    */
/******************************************************************************/
      const ConstMcalCry_Type* lptrConst = (ConstMcalCry_Type*)NULL_PTR;

   public:
/******************************************************************************/
/* FUNCTIONS                                                                  */
/******************************************************************************/
      FUNC(void, CRY_CODE) InitFunction(
            CONSTP2CONST(ConstModule_TypeAbstract, CRY_CONST,       CRY_APPL_CONST) lptrConstModule
         ,  CONSTP2CONST(CfgModule_TypeAbstract,   CRY_CONFIG_DATA, CRY_APPL_CONST) lptrCfgModule
      );
      FUNC(void, CRY_CODE) DeInitFunction (void);
      FUNC(void, CRY_CODE) MainFunction   (void);
      CRY_CORE_FUNCTIONALITIES
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
extern VAR(module_McalCry, CRY_VAR) McalCry;

/******************************************************************************/
/* EOF                                                                        */
/******************************************************************************/

