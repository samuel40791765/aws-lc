// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/crypto.h>
#include <openssl/service_indicator.h>

#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "../../test/abi_test.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"

static const uint8_t kAESKey[16] = {
    'B','o','r','i','n','g','C','r','y','p','t','o',' ','K', 'e','y'};
static const uint8_t kPlaintext[64] = {
    'B','o','r','i','n','g','C','r','y','p','t','o','M','o','d','u','l','e',
    ' ','F','I','P','S',' ','K','A','T',' ','E','n','c','r','y','p','t','i',
    'o','n',' ','a','n','d',' ','D','e','c','r','y','p','t','i','o','n',' ',
    'P','l','a','i','n','t','e','x','t','!'};

#if defined(AWSLC_FIPS)
static const uint8_t kAESIV[16] = {0};

static void hex_dump(const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(stderr, "%02x", in[i]);
  }
}

static int check_test(const uint8_t *expected, const uint8_t *actual,
                      size_t expected_len, const char *name) {
  if (OPENSSL_memcmp(actual, expected, expected_len) != 0) {
    fprintf(stderr, "%s failed.\nExpected: ", name);
    hex_dump(expected, expected_len);
    fprintf(stderr, "\nCalculated: ");
    hex_dump(actual, expected_len);
    fprintf(stderr, "\n");
    fflush(stderr);
    return 0;
  }
  return 1;
}

static const uint8_t kAESECBCiphertext[64] = {
    0x87, 0x2d, 0x98, 0xc2, 0xcc, 0x31, 0x5b, 0x41, 0xe0, 0xfa, 0x7b,
    0x0a, 0x71, 0xc0, 0x42, 0xbf, 0xf8, 0xe7, 0xf0, 0x72, 0x37, 0x7a,
    0xb6, 0x7a, 0x4e, 0x83, 0x30, 0xb4, 0x63, 0x83, 0x95, 0xce, 0xbc,
    0x8c, 0xfb, 0x9f, 0xd9, 0x6d, 0x0e, 0xa0, 0x7a, 0x64, 0x09, 0x17,
    0x0d, 0xa4, 0x78, 0x24, 0x35, 0x7b, 0xe6, 0x40, 0x2e, 0x2c, 0x1a,
    0x68, 0x39, 0x5b, 0x28, 0xb9, 0x4b, 0x5e, 0x67, 0x34
};

static const uint8_t kAESCTRCiphertext[64] = {
    0xe0, 0xd1, 0xe9, 0xf5, 0x9a, 0x7c, 0x2d, 0x6f, 0xa2, 0x3d, 0x11,
    0x48, 0xc0, 0x32, 0xb6, 0xf9, 0x4c, 0xd4, 0x1b, 0xdd, 0x20, 0x06,
    0x59, 0x6d, 0x7d, 0x0c, 0x77, 0xf6, 0x05, 0xf3, 0x15, 0x18, 0x71,
    0xc7, 0xe1, 0x7d, 0x79, 0xde, 0x1e, 0x4d, 0xa5, 0x05, 0xe2, 0xe2,
    0x8c, 0xb0, 0xa4, 0xa2, 0xa2, 0x82, 0x98, 0x9e, 0xd9, 0x15, 0xc2,
    0xce, 0x00, 0x9e, 0x4b, 0x0b, 0x3a, 0x6a, 0xf7, 0x48
};

static const uint8_t kAESCBCCiphertext[64] = {
    0x87, 0x2d, 0x98, 0xc2, 0xcc, 0x31, 0x5b, 0x41, 0xe0, 0xfa, 0x7b,
    0x0a, 0x71, 0xc0, 0x42, 0xbf, 0x4f, 0x61, 0xd0, 0x0d, 0x58, 0x8c,
    0xf7, 0x05, 0xfb, 0x94, 0x89, 0xd3, 0xbc, 0xaa, 0x1a, 0x50, 0x45,
    0x1f, 0xc3, 0x8c, 0xb8, 0x98, 0x86, 0xa3, 0xe3, 0x6c, 0xfc, 0xad,
    0x3a, 0xb5, 0x59, 0x27, 0x7d, 0x21, 0x07, 0xca, 0x4c, 0x1d, 0x55,
    0x34, 0xdd, 0x5a, 0x2d, 0xc4, 0xb4, 0xf5, 0xa8,
#if !defined(BORINGSSL_FIPS_BREAK_AES_CBC)
    0x35
#else
    0x00
#endif
};

TEST(ServiceIndicatorTest, BasicTest) {
  int approved = 0;
  uint32_t serviceID = 0;

  // Call an approved service.
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t output[256];
  size_t out_len;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  IS_FIPS_APPROVED_CALL_SERVICE(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_GCM);
}

TEST(ServiceIndicatorTest, AESECB) {
  int approved = 0;
  uint32_t serviceID = 0;

  AES_KEY aes_key;
  uint8_t output[256];

  // AES-CBC Encryption KAT
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  // AES_ecb_encrypt encrypts (or decrypts) a single, 16 byte block from in to out.
  for (uint32_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    IS_FIPS_APPROVED_CALL_SERVICE(approved,
      AES_ecb_encrypt(&kPlaintext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_ENCRYPT));
    ASSERT_TRUE(approved);
  }
  ASSERT_TRUE(check_test(kAESECBCiphertext, output, sizeof(kAESECBCiphertext), "AES-ECB Encryption KAT"));
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_ECB);

  // AES-ECB Decryption KAT
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  for (uint32_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    IS_FIPS_APPROVED_CALL_SERVICE(approved,
      AES_ecb_encrypt(&kAESECBCiphertext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_DECRYPT));
    ASSERT_TRUE(approved);
  }
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext), "AES-ECB Decryption KAT"));
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_ECB);
}

TEST(ServiceIndicatorTest, AESCBC) {
  int approved = 0;
  uint32_t serviceID = 0;

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];

  // AES-CBC Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  IS_FIPS_APPROVED_CALL_SERVICE(approved,AES_cbc_encrypt(kPlaintext, output,
                              sizeof(kPlaintext), &aes_key, aes_iv, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext), "AES-CBC Encryption KAT"));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_CBC);

  // AES-CBC Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  IS_FIPS_APPROVED_CALL_SERVICE(approved,AES_cbc_encrypt(kAESCBCCiphertext, output,
                        sizeof(kAESCBCCiphertext), &aes_key, aes_iv, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext), "AES-CBC Decryption KAT"));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_CBC);
}

TEST(ServiceIndicatorTest, AESCTR) {
  int approved = 0;
  uint32_t serviceID = 0;

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];
  unsigned num = 0;
  uint8_t ecount_buf[AES_BLOCK_SIZE];

  // AES-CBC Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  IS_FIPS_APPROVED_CALL_SERVICE(approved,AES_ctr128_encrypt(kPlaintext, output,
                             sizeof(kPlaintext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kAESCTRCiphertext, output, sizeof(kAESCTRCiphertext), "AES-CTR Encryption KAT"));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_CTR);

  // AES-CTR Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  IS_FIPS_APPROVED_CALL_SERVICE(approved,AES_ctr128_encrypt(kAESCTRCiphertext, output,
                         sizeof(kAESCTRCiphertext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext), "AES-CTR Decryption KAT"));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_CTR);
}

TEST(ServiceIndicatorTest, AESGCM) {
  int approved = 0;
  uint32_t serviceID = 0;

  bssl::ScopedEVP_AEAD_CTX aead_ctx;

  uint8_t encrypt_output[256];
  uint8_t decrypt_output[256];
  size_t out_len;
  size_t out2_len;

  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));

  // AES-GCM Encryption
  IS_FIPS_APPROVED_CALL_SERVICE(approved,EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_GCM);
  
  // AES-GCM Decryption
  IS_FIPS_APPROVED_CALL_SERVICE(approved,EVP_AEAD_CTX_open(aead_ctx.get(),
      decrypt_output, &out2_len, sizeof(decrypt_output), nullptr, 0, encrypt_output, out_len, nullptr, 0));
  ASSERT_TRUE(check_test(kPlaintext, decrypt_output, sizeof(kPlaintext),
                  "AES-GCM Decryption for Internal IVs"));
  ASSERT_TRUE(approved);
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(serviceID, FIPS_APPROVED_EVP_AES_128_GCM);
}

#else
// Service indicator should not be used without FIPS turned on.
TEST(ServiceIndicatorTest, BasicTest) {
   // Reset and check the initial state and counter.
  ASSERT_FALSE(awslc_fips_service_indicator_reset_state());
  int approved = 0;
  uint64_t counter = awslc_fips_service_indicator_get_counter();
  uint32_t serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(counter, (uint64_t)0);
  ASSERT_EQ(serviceID, (uint32_t)0);

  // Call an approved service.
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t encrypt_output[256];
  size_t out_len;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  IS_FIPS_APPROVED_CALL_SERVICE(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
         encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_FALSE(approved);

  // Check state and counter after using an approved service.
  counter = awslc_fips_service_indicator_get_counter();
  serviceID = awslc_fips_service_indicator_get_serviceID();
  ASSERT_EQ(counter,(uint64_t)0);
  ASSERT_EQ(serviceID, (uint32_t)0);
}
#endif // AWSLC_FIPS


