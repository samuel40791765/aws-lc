// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <limits.h>


#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/service_indicator.h>
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

static bool DoCipher(EVP_CIPHER_CTX *ctx, std::vector<uint8_t> *out,
                     bssl::Span<const uint8_t> in) {
  int approved = 0;
  size_t max_out = in.size();
  if ((EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_NO_PADDING) == 0 &&
      EVP_CIPHER_CTX_encrypting(ctx)) {
    unsigned block_size = EVP_CIPHER_CTX_block_size(ctx);
    max_out += block_size - (max_out % block_size);
  }
  out->resize(max_out);

  size_t total = 0;
  int len;
  while (!in.empty()) {
    // Check if EVP_Cipher service is approved.
    CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_CipherUpdate(ctx,
                       out->data() + total, &len, in.data(), in.size()));
    EXPECT_TRUE(approved);

    EXPECT_GE(len, 0);
    total += static_cast<size_t>(len);
    in = in.subspan(in.size());
  }
  if (!EVP_CipherFinal_ex(ctx, out->data() + total, &len)) {
    return false;
  }
  EXPECT_GE(len, 0);
  total += static_cast<size_t>(len);
  out->resize(total);
  return true;
}

static void TestOperation(const EVP_CIPHER *cipher, bool encrypt,
                          const std::vector<uint8_t> &key,
                          const std::vector<uint8_t> &iv,
                          const std::vector<uint8_t> &plaintext,
                          const std::vector<uint8_t> &ciphertext) {
  const std::vector<uint8_t> *in, *out;
  if (encrypt) {
    in = &plaintext;
    out = &ciphertext;
  } else {
    in = &ciphertext;
    out = &plaintext;
  }

  bssl::ScopedEVP_CIPHER_CTX ctx1;
  ASSERT_TRUE(EVP_CipherInit_ex(ctx1.get(), cipher, nullptr, nullptr, nullptr,
                                encrypt ? 1 : 0));
  if (!iv.empty()) {
    ASSERT_EQ(iv.size(), EVP_CIPHER_CTX_iv_length(ctx1.get()));
  }

  bssl::ScopedEVP_CIPHER_CTX ctx2;
  ASSERT_TRUE(EVP_CIPHER_CTX_copy(ctx2.get(), ctx1.get()));
  EVP_CIPHER_CTX *ctx = ctx2.get();

  // The ciphers are run with no padding. For each of the ciphers we test, the
  // output size matches the input size.
  ASSERT_EQ(in->size(), out->size());
  ASSERT_TRUE(EVP_CIPHER_CTX_set_key_length(ctx, key.size()));
  ASSERT_TRUE(EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(), iv.data(), -1));

  ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 0));
  std::vector<uint8_t> result;
  ASSERT_TRUE(DoCipher(ctx, &result, *in));
  EXPECT_EQ(Bytes(*out), Bytes(result));
}

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

static const uint8_t kAESKWCiphertext[72] ={
    0x10, 0x93, 0xe7, 0xc2, 0x68, 0xf3, 0x23, 0xfb, 0x40, 0xc2, 0xa1,
    0x84, 0x03, 0x3b, 0x2e, 0x01, 0x34, 0x48, 0x70, 0x3c, 0xe7, 0x2f,
    0xc1, 0x6c, 0x57, 0x91, 0x2d, 0x1f, 0xef, 0xea, 0x11, 0xb9, 0x00,
    0x3e, 0x4b, 0x64, 0xbd, 0x29, 0xeb, 0xe6, 0xee, 0xa5, 0x60, 0xf0,
    0x58, 0xca, 0x48, 0x73, 0x52, 0x94, 0xf2, 0x65, 0xb0, 0x7f, 0xe6,
    0x2e, 0x90, 0x72, 0x21, 0x30, 0x90, 0x48, 0xa9, 0x76, 0x16, 0x59,
    0x75, 0x0b, 0xa7, 0xe9, 0xfa, 0x42
};

static const uint8_t kAESKWPCiphertext[72] ={
    0x24, 0xca, 0x22, 0xf4, 0x92, 0xac, 0x88, 0x96, 0x53, 0x17, 0x3f,
    0x83, 0xd9, 0xa7, 0xe2, 0x85, 0x68, 0xac, 0x2d, 0xac, 0x08, 0x84,
    0xe6, 0x41, 0x01, 0x60, 0x3a, 0x49, 0x05, 0x45, 0x3b, 0x0c, 0x4d,
    0x81, 0xb9, 0x7d, 0x1a, 0x97, 0x1b, 0xcd, 0xd8, 0xd5, 0x10, 0x42,
    0x2f, 0x07, 0x9b, 0x16, 0x9d, 0x7c, 0xb0, 0x7f, 0xaf, 0x38, 0x57,
    0x4b, 0xbf, 0xf8, 0x08, 0x1e, 0x33, 0x58, 0x37, 0xd9, 0xfc, 0xc7,
    0xa5, 0x66, 0xe5, 0x62, 0x2a, 0x01
};

struct EVP_TestVector {
  const EVP_CIPHER *cipher;
  const uint8_t *expected_ciphertext;
  int cipher_text_length;
  bool has_iv;
  bool expect_approved;
} nTestVectors[] = {
  {
      EVP_aes_128_ecb(),
      kAESECBCiphertext,
      64,
      false,
      true
  },
  {
      EVP_aes_128_cbc(),
      kAESCBCCiphertext,
      64,
      true,
      true
  },
  {
      EVP_aes_128_ctr(),
      kAESCTRCiphertext,
      64,
      true,
      true
  }
};

class EVP_ServiceIndicatorTest : public testing::TestWithParam<EVP_TestVector> {};

INSTANTIATE_TEST_SUITE_P(All, EVP_ServiceIndicatorTest, testing::ValuesIn(nTestVectors));

TEST_P(EVP_ServiceIndicatorTest, EVP_Ciphers) {
  const EVP_TestVector &t = GetParam();

  const EVP_CIPHER *cipher = t.cipher;
  std::vector<uint8_t> key, iv, plaintext;
  key.insert(key.begin(), std::begin(kAESKey), std::end(kAESKey));
  plaintext.insert(plaintext.begin(), std::begin(kPlaintext), std::end(kPlaintext));
  std::vector<uint8_t> ciphertext(t.expected_ciphertext, t.expected_ciphertext + t.cipher_text_length);
  if(t.has_iv) {
    iv.insert(iv.begin(), std::begin(kAESIV), std::end(kAESIV));
  }
  TestOperation(cipher,true /* encrypt */, key, iv, plaintext, ciphertext);
  TestOperation(cipher,false /* decrypt */, key, iv, plaintext, ciphertext);
}


TEST(ServiceIndicatorTest, BasicTest) {
  int approved = 0;

  // Call an approved service.
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t output[256];
  size_t out_len;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_TRUE(approved);
}

TEST(ServiceIndicatorTest, AESECB) {
  int approved = 0;

  AES_KEY aes_key;
  uint8_t output[256];

  // AES-CBC Encryption KAT
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  // AES_ecb_encrypt encrypts (or decrypts) a single, 16 byte block from in to out.
  for (uint32_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kPlaintext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_ENCRYPT));
    ASSERT_TRUE(approved);
  }
  ASSERT_TRUE(check_test(kAESECBCiphertext, output, sizeof(kAESECBCiphertext),
                         "AES-ECB Encryption KAT"));

  // AES-ECB Decryption KAT
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  for (uint32_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kAESECBCiphertext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_DECRYPT));
    ASSERT_TRUE(approved);
  }
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-ECB Decryption KAT"));
}

TEST(ServiceIndicatorTest, AESCBC) {
  int approved = 0;
  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];

  // AES-CBC Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_cbc_encrypt(kPlaintext, output,
                              sizeof(kPlaintext), &aes_key, aes_iv, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                         "AES-CBC Encryption KAT"));
  ASSERT_TRUE(approved);

  // AES-CBC Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_cbc_encrypt(kAESCBCCiphertext, output,
                        sizeof(kAESCBCCiphertext), &aes_key, aes_iv, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CBC Decryption KAT"));
  ASSERT_TRUE(approved);
}

TEST(ServiceIndicatorTest, AESCTR) {
  int approved = 0;

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];
  unsigned num = 0;
  uint8_t ecount_buf[AES_BLOCK_SIZE];

  // AES-CBC Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_ctr128_encrypt(kPlaintext, output,
                             sizeof(kPlaintext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kAESCTRCiphertext, output, sizeof(kAESCTRCiphertext),
                         "AES-CTR Encryption KAT"));
  ASSERT_TRUE(approved);

  // AES-CTR Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_ctr128_encrypt(kAESCTRCiphertext, output,
                         sizeof(kAESCTRCiphertext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CTR Decryption KAT"));
  ASSERT_TRUE(approved);
}

TEST(ServiceIndicatorTest, AESGCM) {
  int approved = 0;
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t encrypt_output[256];
  uint8_t decrypt_output[256];
  size_t out_len;
  size_t out2_len;

  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));

  // AES-GCM Encryption
  CALL_SERVICE_AND_CHECK_APPROVED(approved,EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_TRUE(approved);
  
  // AES-GCM Decryption
  CALL_SERVICE_AND_CHECK_APPROVED(approved,EVP_AEAD_CTX_open(aead_ctx.get(),
      decrypt_output, &out2_len, sizeof(decrypt_output), nullptr, 0, encrypt_output, out_len, nullptr, 0));
  ASSERT_TRUE(check_test(kPlaintext, decrypt_output, sizeof(kPlaintext),
                  "AES-GCM Decryption for Internal IVs"));
  ASSERT_TRUE(approved);
}

TEST(ServiceIndicatorTest, AESKW) {
  int approved = 0;

  AES_KEY aes_key;
  uint8_t output[256];

  // AES-KW Encryption KAT
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_wrap_key(&aes_key, nullptr,
                                    output, kPlaintext, sizeof(kPlaintext)));
  ASSERT_TRUE(check_test(kAESKWCiphertext, output, sizeof(kAESKWCiphertext),
                         "AES-KW Encryption KAT"));
  ASSERT_TRUE(approved);

  // AES-KW Decryption KAT
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_unwrap_key(&aes_key, nullptr,
                                    output, kAESKWCiphertext, sizeof(kAESKWCiphertext)));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-KW Decryption KAT"));
  ASSERT_TRUE(approved);
}

TEST(ServiceIndicatorTest, AESKWP) {
  int approved = 0;

  AES_KEY aes_key;
  uint8_t output[256];
  size_t outlen;
  // AES-KWP Encryption KAT
  memset(output, 0, 256);
  ASSERT_EQ(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_wrap_key_padded(&aes_key,
              output, &outlen, sizeof(kPlaintext) + 15, kPlaintext, sizeof(kPlaintext)));
  ASSERT_TRUE(check_test(kAESKWPCiphertext, output, sizeof(kAESKWPCiphertext),
                         "AES-KWP Encryption KAT"));
  ASSERT_TRUE(approved);

  // AES-KWP Decryption KAT
  ASSERT_EQ(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key),0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,AES_unwrap_key_padded(&aes_key,
             output, &outlen, sizeof(kPlaintext), kPlaintext, sizeof(kPlaintext)));
  ASSERT_TRUE(check_test(kPlaintext, output, outlen,
                         "AES-KW Decryption KAT"));
  ASSERT_TRUE(approved);
}

#else
// Service indicator should not be used without FIPS turned on.
TEST(ServiceIndicatorTest, BasicTest) {
   // Reset and check the initial state and counter.
  int approved = 0;
  int before = FIPS_service_indicator_before_call();
  ASSERT_EQ(before, 0);

  // Call an approved service.
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t encrypt_output[256];
  size_t out_len;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
         encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  // Macro should return true, to ensure FIPS/Non-FIPS compatibility.
  ASSERT_TRUE(approved);

  // Actual approval check should return false during non-FIPS.
  int after = FIPS_service_indicator_after_call();
  ASSERT_EQ(after, 0);
  ASSERT_FALSE(FIPS_service_indicator_check_approved(before, after));
}
#endif // AWSLC_FIPS


