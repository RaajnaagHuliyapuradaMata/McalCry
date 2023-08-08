

#if !defined (MCALCRY_CURVE_H)
# define MCALCRY_CURVE_H

# include "McalCry_Services.hpp"

# define MCALCRY_START_SEC_CONST_8BIT
# include "CompilerCfg_McalCry.hpp"

# if(MCALCRY_CUSTOM_P160R1_DOMAIN == STD_ON)

extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveSecP160R1Domain[155];
#  if(MCALCRY_BYTES_PER_DIGIT == 1)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveSecP160R1DomainExt[147];
#  elif(MCALCRY_BYTES_PER_DIGIT == 2)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveSecP160R1DomainExt[149];
#  elif(MCALCRY_BYTES_PER_DIGIT == 4)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveSecP160R1DomainExt[153];
#  endif
#  if(MCALCRY_CUSTOM_P160R1_SPEEDUP == STD_ON)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveSecP160R1SpeedUpExt[355];
#  endif

# endif

# if(MCALCRY_CUSTOM_P224R1_DOMAIN == STD_ON)

extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP224R1Domain[203];
#  if(actBN_BYTES_PER_DIGIT == 1)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP224R1DomainExt[195];
#  elif(actBN_BYTES_PER_DIGIT == 2)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP224R1DomainExt[197];
#  elif(actBN_BYTES_PER_DIGIT == 4)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP224R1DomainExt[201];
#  endif
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP224R1SpeedUpExt[483];

# endif

# if(MCALCRY_CUSTOM_P256R1_DOMAIN == STD_ON)

extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistAnsiSecP256R1Domain[227];
#  if(MCALCRY_BYTES_PER_DIGIT == 1)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistAnsiSecP256R1DomainExt[219];
#  elif(MCALCRY_BYTES_PER_DIGIT == 2)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistAnsiSecP256R1DomainExt[221];
#  elif(MCALCRY_BYTES_PER_DIGIT == 4)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistAnsiSecP256R1DomainExt[225];
#  endif
#  if(MCALCRY_CUSTOM_P256R1_SPEEDUP == STD_ON)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistAnsiSecP256R1SpeedUpExt[547];
#  endif

# endif

# if(MCALCRY_CUSTOM_P384R1_DOMAIN == STD_ON)

extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP384R1Domain[324];
#  if(MCALCRY_BYTES_PER_DIGIT == 1)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP384R1DomainExt[316];
#  elif(MCALCRY_BYTES_PER_DIGIT == 2)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP384R1DomainExt[318];
#  elif(MCALCRY_BYTES_PER_DIGIT == 4)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP384R1DomainExt[323];
#  endif
#  if(MCALCRY_CUSTOM_P384R1_SPEEDUP == STD_ON)
extern CONST(uint8, MCALCRY_CONST) McalCry_EccCurveNistSecP384R1SpeedUpExt[803];
#  endif

# endif

# define MCALCRY_STOP_SEC_CONST_8BIT
# include "CompilerCfg_McalCry.hpp"

#endif

