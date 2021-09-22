//
// Created by Chiang, Samuel on 9/20/21.
//

#ifndef AWSLC_HEADER_SERVICE_INDICATOR_INTERNAL_H
#define AWSLC_HEADER_SERVICE_INDICATOR_INTERNAL_H

#include <openssl/service_indicator.h>

// hwaes_capable when on in x86 uses 9, 11, 13 for key rounds.
// hwaes_capable when on in ARM uses 10, 12, 14 for key rounds.
// When compiling with different ARM specific platforms, 9, 11, 13 are used for
// key rounds.
// TODO: narrow down when and which assembly/x86 ARM CPUs use [9,11,13] and [10,12,14]
#define AES_verify_service_indicator(key_rounds, mode)                      \
do {                                                                        \
  switch (key_rounds) {                                                     \
    case 9:                                                                 \
    case 10:                                                                \
      awslc_fips_service_indicator_update_state(                            \
          FIPS_APPROVED_EVP_AES_128_##mode);                                \
      break;                                                                \
    case 11:                                                                \
    case 12:                                                                \
      awslc_fips_service_indicator_update_state(                            \
          FIPS_APPROVED_EVP_AES_192_##mode);                                \
      break;                                                                \
    case 13:                                                                \
    case 14:                                                                \
      awslc_fips_service_indicator_update_state(                            \
          FIPS_APPROVED_EVP_AES_256_##mode);                                \
      break;                                                                \
    default:                                                                \
      break;                                                                \
  }                                                                         \
}                                                                           \
while(0)                                                                    \

// AEAD APIs work with different parameters.
#define AEAD_verify_service_indicator(key_length, mode)                     \
do {                                                                        \
  switch (key_length) {                                                     \
    case 16:                                                                \
      awslc_fips_service_indicator_update_state(                            \
          FIPS_APPROVED_EVP_AES_128_##mode);                                \
      break;                                                                \
    case 32:                                                                \
      awslc_fips_service_indicator_update_state(                            \
          FIPS_APPROVED_EVP_AES_256_##mode);                                \
      break;                                                                \
    default:                                                                \
      break;                                                                \
  }                                                                         \
}                                                                           \
while(0)                                                                    \

#endif  // AWSLC_HEADER_SERVICE_INDICATOR_INTERNAL_H
