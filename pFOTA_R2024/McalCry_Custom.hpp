

#ifndef MCALCRY_CUSTOM_H
# define MCALCRY_CUSTOM_H

# include "CfgApplCry.hpp"

# ifndef CRYPTO_KE_CUSTOM_MAC_AES_ROUNDKEY
#  define CRYPTO_KE_CUSTOM_MAC_AES_ROUNDKEY                           (129u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYDERIVATION_LABEL
#  define CRYPTO_KE_CUSTOM_KEYDERIVATION_LABEL                        (130u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYDERIVATION_ADDITIONAL_INFO
#  define CRYPTO_KE_CUSTOM_KEYDERIVATION_ADDITIONAL_INFO              (131u)
# endif

# ifndef CRYPTO_KE_CUSTOM_ADDITIONAL_INFO
#  define CRYPTO_KE_CUSTOM_ADDITIONAL_INFO                            (131u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_MODULUS
#  define CRYPTO_KE_CUSTOM_RSA_MODULUS                                (160u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT
#  define CRYPTO_KE_CUSTOM_RSA_PUBLIC_EXPONENT                        (161u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT
#  define CRYPTO_KE_CUSTOM_RSA_PRIVATE_EXPONENT                       (162u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_SALT
#  define CRYPTO_KE_CUSTOM_RSA_SALT                                   (163u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_SALT_LENGTH
#  define CRYPTO_KE_CUSTOM_RSA_SALT_LENGTH                            (164u)
# endif

# ifndef CRYPTO_KE_CUSTOM_TLS_CLIENT_HELLO_RANDOM
#  define CRYPTO_KE_CUSTOM_TLS_CLIENT_HELLO_RANDOM                    (3000u)
# endif

# ifndef CRYPTO_KE_CUSTOM_TLS_SERVER_HELLO_RANDOM
#  define CRYPTO_KE_CUSTOM_TLS_SERVER_HELLO_RANDOM                    (3001u)
# endif

# ifndef CRYPTO_KE_CUSTOM_TLS_HMAC_KEY_SIZE
#  define CRYPTO_KE_CUSTOM_TLS_HMAC_KEY_SIZE                          (3002u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY
#  define CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY                (3003u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2
#  define CRYPTO_KE_CUSTOM_KEYEXCHANGE_PARTNER_PUB_KEY_2              (3004u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYEXCHANGE_INTERMEDIATE
#  define CRYPTO_KE_CUSTOM_KEYEXCHANGE_INTERMEDIATE                   (3005u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYEXCHANGE_NUM_ECU
#  define CRYPTO_KE_CUSTOM_KEYEXCHANGE_NUM_ECU                        (3006u)
# endif

# ifndef CRYPTO_KE_CUSTOM_KEYEXCHANGE_ECU_ID
#  define CRYPTO_KE_CUSTOM_KEYEXCHANGE_ECU_ID                         (3007u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SCC_CONTRACT_PUBLIC_KEY
#  define CRYPTO_KE_CUSTOM_SCC_CONTRACT_PUBLIC_KEY                    (3013u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SCC_IV_AND_ENCRYPTED_PRIVATE_KEY
#  define CRYPTO_KE_CUSTOM_SCC_IV_AND_ENCRYPTED_PRIVATE_KEY           (3014u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RANDOM_PERSONALIZATION_STRING
#  define CRYPTO_KE_CUSTOM_RANDOM_PERSONALIZATION_STRING              (3015u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT
#  define CRYPTO_KE_CUSTOM_RANDOM_ADDITIONAL_INPUT                    (3016u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RANDOM_NONCE
#  define CRYPTO_KE_CUSTOM_RANDOM_NONCE                               (3017u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER
#  define CRYPTO_KE_CUSTOM_RANDOM_RESEED_COUNTER                      (3018u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SHE_COUNTER
#  define CRYPTO_KE_CUSTOM_SHE_COUNTER                                (3019u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SHE_UID
#  define CRYPTO_KE_CUSTOM_SHE_UID                                    (3021u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SHE_BOOT_PROTECTION
#  define CRYPTO_KE_CUSTOM_SHE_BOOT_PROTECTION                        (3056u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SHE_DEBUGGER_PROTECTION
#  define CRYPTO_KE_CUSTOM_SHE_DEBUGGER_PROTECTION                    (3057u)
# endif

# ifndef CRYPTO_KE_CUSTOM_SHE_DEBUG_CMD
#  define CRYPTO_KE_CUSTOM_SHE_DEBUG_CMD                              (3059u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_PRIME_P
#  define CRYPTO_KE_CUSTOM_RSA_PRIME_P                                (3051u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_PRIME_Q
#  define CRYPTO_KE_CUSTOM_RSA_PRIME_Q                                (3052u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_EXPONENT_DP
#  define CRYPTO_KE_CUSTOM_RSA_EXPONENT_DP                            (3053u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_EXPONENT_DQ
#  define CRYPTO_KE_CUSTOM_RSA_EXPONENT_DQ                            (3054u)
# endif

# ifndef CRYPTO_KE_CUSTOM_RSA_INVERSE_QI
#  define CRYPTO_KE_CUSTOM_RSA_INVERSE_QI                             (3055u)
# endif

# ifndef CRYPTO_KE_CUSTOM_LABEL
#  define CRYPTO_KE_CUSTOM_LABEL                                      (3058u)
# endif

# ifndef CRYPTO_KE_CUSTOM_W0
#  define CRYPTO_KE_CUSTOM_W0                                         (3084u)
# endif

# ifndef CRYPTO_KE_CUSTOM_W1
#  define CRYPTO_KE_CUSTOM_W1                                         (3085u)
# endif

# ifndef CRYPTO_KE_CUSTOM_L
#  define CRYPTO_KE_CUSTOM_L                                          (3086u)
# endif

# ifndef CRYPTO_KE_CUSTOM_VERIFICATION
#  define CRYPTO_KE_CUSTOM_VERIFICATION                               (3087u)
# endif

# ifndef CRYPTO_KE_CUSTOM_VERIFICATION_RESULT
#  define CRYPTO_KE_CUSTOM_VERIFICATION_RESULT                        (3088u)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_P224R1
#  define CRYPTO_ALGOMODE_CUSTOM_P224R1                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_P224r1)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_P256R1
#  define CRYPTO_ALGOMODE_CUSTOM_P256R1                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_P256r1)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_RSASSA_PKCS1_v1_5_CRT
#  define CRYPTO_ALGOMODE_CUSTOM_RSASSA_PKCS1_v1_5_CRT                (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_RSASSA_PKCS1_v1_5_CRT)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_RSAES_OAEP_CRT
#  define CRYPTO_ALGOMODE_CUSTOM_RSAES_OAEP_CRT                       (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_RSAES_OAEP_CRT)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_USE_DF
#  define CRYPTO_ALGOMODE_CUSTOM_USE_DF                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_UseDF)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_P384R1
#  define CRYPTO_ALGOMODE_CUSTOM_P384R1                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_P384r1)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_P160R1
#  define CRYPTO_ALGOMODE_CUSTOM_P160R1                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_P160r1)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_CCM
#  define CRYPTO_ALGOMODE_CUSTOM_CCM                                  (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_CCM)
# endif

# ifndef CRYPTO_ALGOMODE_CUSTOM_MODE_1
#  define CRYPTO_ALGOMODE_CUSTOM_MODE_1                               (CryptoConf_CryptoPrimitiveAlgorithmModeCustom_McalCry_Mode1)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_ECCANSI
#  define CRYPTO_ALGOFAM_CUSTOM_ECCANSI                               (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_ECCANSI)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_ECCSEC
#  define CRYPTO_ALGOFAM_CUSTOM_ECCSEC                                (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_ECCSEC)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_DRBG
#  define CRYPTO_ALGOFAM_CUSTOM_DRBG                                  (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_DRBG)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_FIPS186
#  define CRYPTO_ALGOFAM_CUSTOM_FIPS186                               (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_FIPS186)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_PADDING_PKCS7
#  define CRYPTO_ALGOFAM_CUSTOM_PADDING_PKCS7                         (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_PaddingPKCS7)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_X25519
#  define CRYPTO_ALGOFAM_CUSTOM_X25519                                (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_X25519)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_ISO15118
#  define CRYPTO_ALGOFAM_CUSTOM_ISO15118                              (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_ISO15118)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_POLY_1305
#  define CRYPTO_ALGOFAM_CUSTOM_POLY_1305                             (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_POLY1305)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_SPAKE2_PLUS
#  define CRYPTO_ALGOFAM_CUSTOM_SPAKE2_PLUS                           (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_SPAKE2PLUS)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_HKDF
#  define CRYPTO_ALGOFAM_CUSTOM_HKDF                                  (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_HKDF)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_CMD_GET_ID
#  define CRYPTO_ALGOFAM_CUSTOM_CMD_GET_ID                            (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_CmdGetId)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_CIPHER_SUITE_8
#  define CRYPTO_ALGOFAM_CUSTOM_CIPHER_SUITE_8                        (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_CipherSuite8)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_MD5
#  define CRYPTO_ALGOFAM_CUSTOM_MD5                                   (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_MD5)
# endif

# ifndef CRYPTO_ALGOFAM_CUSTOM_BD
#  define CRYPTO_ALGOFAM_CUSTOM_BD                                    (CryptoConf_CryptoPrimitiveAlgorithmFamilyCustom_McalCry_BD)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_X25519
#  define MCALCRY_KEY_EXCHANGE_X25519                         (0u)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_ANSIP256R1
#  define MCALCRY_KEY_EXCHANGE_ANSIP256R1                     (1u)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_SECP256R1
#  define MCALCRY_KEY_EXCHANGE_SECP256R1                      (2u)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_NISTP224R1_BD
#  define MCALCRY_KEY_EXCHANGE_NISTP224R1_BD                  (3u)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_SECP384R1
#  define MCALCRY_KEY_EXCHANGE_SECP384R1                      (4u)
# endif

# ifndef MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8
#  define MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8      (5u)
# endif
# ifndef MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8_1
#  define MCALCRY_KEY_EXCHANGE_SPAKE2_PLUS_CIPHERSUITE_8_1    (6u)
# endif

# ifndef MCALCRY_KEY_GENERATE_SYMMETRIC
#  define MCALCRY_KEY_GENERATE_SYMMETRIC                      (0u)
# endif

# ifndef MCALCRY_KEY_GENERATE_P256R1
#  define MCALCRY_KEY_GENERATE_P256R1                         (1u)
# endif

# ifndef MCALCRY_KEY_GENERATE_P384R1
#  define MCALCRY_KEY_GENERATE_P384R1                         (2u)
# endif
# ifndef MCALCRY_KEY_GENERATE_ALGORITHM_ED25519
#  define MCALCRY_KEY_GENERATE_ALGORITHM_ED25519              (3u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256
#  define MCALCRY_KDF_ALGO_KDF_SYM_NIST_800_108_CNT_MODE_SHA256 (1u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB
#  define MCALCRY_KDF_ALGO_KDF_ASYM_NIST_FIPS_186_4_ERB       (2u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256
#  define MCALCRY_KDF_ALGO_KDF_NIST_800_56_A_ONE_PASS_C1E1S_SINGLE_STEP_KDF_SHA256 (3u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_ISO_15118_CERTIFICATE_HANDLING
#  define MCALCRY_KDF_ALGO_KDF_ISO_15118_CERTIFICATE_HANDLING (4u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_X963_SHA1
#  define MCALCRY_KDF_ALGO_KDF_X963_SHA1                      (5u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_X963_SHA256
#  define MCALCRY_KDF_ALGO_KDF_X963_SHA256                    (6u)
# endif

# ifndef MCALCRY_KDF_ALGO_KDF_X963_SHA512
#  define MCALCRY_KDF_ALGO_KDF_X963_SHA512                    (7u)
# endif

# ifndef MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1
#  define MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA1                   (9u)
# endif

# ifndef MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256
#  define MCALCRY_KDF_ALGO_PBKDF2_HMAC_SHA256                 (10u)
# endif

# ifndef MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256
#  define MCALCRY_KDF_ALGO_HKDF_HMAC_SHA256                   (11u)
# endif

# ifndef MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1
#  define MCALCRY_KDF_ALGO_SPAKE2_PLUS_P256R1                 (12u)
# endif

# ifndef MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256
#  define MCALCRY_KDF_ALGO_HKDF_OPTION1_SHA256                (13u)
# endif

# ifndef MCALCRY_RNG_FIPS_186_2_SHA1
#  define MCALCRY_RNG_FIPS_186_2_SHA1                         (0u)
# endif

# ifndef MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128
#  define MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128            (1u)
# endif

# ifndef MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128_DF
#  define MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES128_DF         (2u)
# endif

# ifndef MCALCRY_RNG_NIST_800_90A_HASH_DRBG_SHA_512
#  define MCALCRY_RNG_NIST_800_90A_HASH_DRBG_SHA_512          (3u)
# endif

# ifndef MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256
#  define MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256            (4u)
# endif

# ifndef MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256_DF
#  define MCALCRY_RNG_NIST_800_90A_CTR_DRBG_AES256_DF         (5u)
# endif

#endif

