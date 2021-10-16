// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0


#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/service_indicator.h>
#include <openssl/sha.h>

#include "../../test/abi_test.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "../rand/internal.h"
#include "../tls/internal.h"

static const uint8_t kAESKey[16] = {
    'A','W','S','-','L','C','C','r','y','p','t','o',' ','K', 'e','y'};
static const uint8_t kPlaintext[64] = {
    'A','W','S','-','L','C','C','r','y','p','t','o','M','o','d','u','l','e',
    ' ','F','I','P','S',' ','K','A','T',' ','E','n','c','r','y','p','t','i',
    'o','n',' ','a','n','d',' ','D','e','c','r','y','p','t','i','o','n',' ',
    'P','l','a','i','n','t','e','x','t','!'};

#if defined(AWSLC_FIPS)
static const uint8_t kAESKey_192[24] = {
    'A','W','S','-','L','C','C','r','y','p','t','o',' ','1', '9','2', '-','b',
    'i','t',' ','K','e','y'
};

static const uint8_t kAESKey_256[32] = {
    'A','W','S','-','L','C','C','r','y','p','t','o',' ','2', '5','6', '-','b',
    'i','t',' ','L','o','n','g',' ','K','e','y','!','!','!'
};

static const uint8_t kAESIV[AES_BLOCK_SIZE] = {0};

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

static void DoEncryptFinal(EVP_CIPHER_CTX *ctx, std::vector<uint8_t> *out,
                     bssl::Span<const uint8_t> in, int expect_approved) {
  int approved = AWSLC_NOT_APPROVED;
  size_t max_out = in.size();
  if (EVP_CIPHER_CTX_encrypting(ctx)) {
    unsigned block_size = EVP_CIPHER_CTX_block_size(ctx);
    max_out += block_size - (max_out % block_size);
  }
  out->resize(max_out);

  size_t total = 0;
  int len;
  ASSERT_TRUE(EVP_CipherUpdate(ctx, out->data(), &len, in.data(), in.size()));
  total += static_cast<size_t>(len);
  // Check if the overall service is approved by checking |EVP_EncryptFinal_ex|
  // or |EVP_DecryptFinal_ex|, which should be the last part of the service.
  if (ctx->encrypt) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_EncryptFinal_ex(ctx, out->data() + total, &len)));
  } else {
    CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_DecryptFinal_ex(ctx, out->data() + total, &len)));
  }
  total += static_cast<size_t>(len);
  ASSERT_EQ(approved, expect_approved);
  out->resize(total);
}

static void DoCipherFinal(EVP_CIPHER_CTX *ctx, std::vector<uint8_t> *out,
                     bssl::Span<const uint8_t> in, int expect_approved) {
  int approved = AWSLC_NOT_APPROVED;
  size_t max_out = in.size();
  if (EVP_CIPHER_CTX_encrypting(ctx)) {
    unsigned block_size = EVP_CIPHER_CTX_block_size(ctx);
    max_out += block_size - (max_out % block_size);
  }
  out->resize(max_out);

  size_t total = 0;
  int len = 0;
  ASSERT_TRUE(EVP_CipherUpdate(ctx, out->data(), &len, in.data(), in.size()));
  total += static_cast<size_t>(len);
  // Check if the overall service is approved by checking |EVP_CipherFinal_ex|,
  // which should be the last part of the service.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(
                    EVP_CipherFinal_ex(ctx, out->data() + total, &len)));
  total += static_cast<size_t>(len);
  ASSERT_EQ(approved, expect_approved);
  out->resize(total);
}

static void TestOperation(const EVP_CIPHER *cipher, bool encrypt,
                          const std::vector<uint8_t> &key,
                          const std::vector<uint8_t> &plaintext,
                          const std::vector<uint8_t> &ciphertext,
                          int expect_approved) {
  int approved = AWSLC_NOT_APPROVED;
  const std::vector<uint8_t> *in, *out;
  if (encrypt) {
    in = &plaintext;
    out = &ciphertext;
  } else {
    in = &ciphertext;
    out = &plaintext;
  }

  bssl::ScopedEVP_CIPHER_CTX ctx;
  // Test running the EVP_Cipher interfaces one by one directly, and check
  // |EVP_EncryptFinal_ex| and |EVP_DecryptFinal_ex| for approval at the end.
  ASSERT_TRUE(EVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr,
                                    nullptr, encrypt ? 1 : 0));
  std::vector<uint8_t> iv(kAESIV, kAESIV + EVP_CIPHER_CTX_iv_length(ctx.get()));
  ASSERT_EQ(iv.size(), EVP_CIPHER_CTX_iv_length(ctx.get()));

  ASSERT_TRUE(EVP_CIPHER_CTX_set_key_length(ctx.get(), key.size()));
  ASSERT_TRUE(EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data(), encrypt ? 1 : 0));
  ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx.get(), 0));
  std::vector<uint8_t> encrypt_result;
  DoEncryptFinal(ctx.get(), &encrypt_result, *in, expect_approved);
  ASSERT_EQ(Bytes(*out), Bytes(encrypt_result));

  bssl::ScopedEVP_CIPHER_CTX ctx1;
  // Test running the EVP_Cipher interfaces one by one directly, and check
  // |EVP_CipherFinal_ex| for approval at the end.
  ASSERT_TRUE(EVP_CipherInit_ex(ctx1.get(), cipher, nullptr, nullptr,
                                    nullptr, encrypt ? 1 : 0));
  ASSERT_EQ(iv.size(), EVP_CIPHER_CTX_iv_length(ctx1.get()));

  ASSERT_TRUE(EVP_CIPHER_CTX_set_key_length(ctx1.get(), key.size()));
  ASSERT_TRUE(EVP_CipherInit_ex(ctx1.get(), cipher, nullptr, key.data(), iv.data(), encrypt ? 1 : 0));
  ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx1.get(), 0));
  std::vector<uint8_t> final_result;
  DoCipherFinal(ctx1.get(), &final_result, *in, expect_approved);
  ASSERT_EQ(Bytes(*out), Bytes(final_result));


  // Test using the one-shot |EVP_Cipher| function for approval.
  bssl::ScopedEVP_CIPHER_CTX ctx2;
  uint8_t output[256];
  ASSERT_TRUE(EVP_CipherInit_ex(ctx2.get(), cipher, nullptr, key.data(), iv.data(), encrypt ? 1 : 0));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_Cipher(ctx2.get(), output,
                                               in->data(), in->size()));
  ASSERT_EQ(approved, expect_approved);
  ASSERT_TRUE(check_test(out->data(), output, in->size(), "EVP_Cipher Encryption KAT"));
}

static const uint8_t KTDES_EDE3_CipherText[64] = {
    0x2a, 0x17, 0x79, 0x5a, 0x9b, 0x1d, 0xd8, 0x72, 0x06, 0xc6, 0xe7,
    0x55, 0x14, 0xaa, 0x7b, 0x2a, 0x6e, 0xfc, 0x71, 0x29, 0xff, 0x9b,
    0x67, 0x73, 0x7c, 0x9e, 0x15, 0x74, 0x80, 0xc8, 0x2f, 0xca, 0x93,
    0xaa, 0x8e, 0xba, 0x2c, 0x48, 0x88, 0x51, 0xc7, 0xa4, 0xf4, 0xe3,
    0x2b, 0x33, 0xe5, 0xa1, 0x58, 0x0a, 0x08, 0x3c, 0xb9, 0xf6, 0xf1,
    0x20, 0x67, 0x02, 0x49, 0xa0, 0x92, 0x18, 0xde, 0x2b
};

static const uint8_t KTDES_EDE3_CBCCipherText[64] = {
    0x2a, 0x17, 0x79, 0x5a, 0x9b, 0x1d, 0xd8, 0x72, 0xbf, 0x3f, 0xfd,
    0xe4, 0x0d, 0x66, 0x33, 0x49, 0x3b, 0x8c, 0xa6, 0xd0, 0x0a, 0x66,
    0xae, 0xf1, 0xd9, 0xa7, 0xd6, 0xfb, 0xa2, 0x39, 0x6f, 0xf6, 0x1b,
    0x8f, 0x67, 0xe1, 0x2b, 0x58, 0x1c, 0xb6, 0xa2, 0xec, 0xb3, 0xc2,
    0xe6, 0xd1, 0xcc, 0x11, 0x05, 0xdd, 0xee, 0x9d, 0x87, 0x95, 0xe9,
    0x58, 0xc7, 0xef, 0xa4, 0x6d, 0x5e, 0xd6, 0x57, 0x01
};

// AES-OFB is not an approved service, and is only used to test we are not
// validating un-approved services correctly.
static const uint8_t kAESOFBCiphertext[64] = {
    0x49, 0xf5, 0x6a, 0x7d, 0x3e, 0xd7, 0xb2, 0x47, 0x35, 0xca, 0x54,
    0xf5, 0xf1, 0xb8, 0xd1, 0x48, 0x8e, 0x47, 0x09, 0x95, 0xd5, 0xa0,
    0xc6, 0xa3, 0xe4, 0x94, 0xaf, 0xd4, 0x1b, 0x64, 0x25, 0x65, 0x28,
    0x9e, 0x82, 0xba, 0x92, 0xca, 0x75, 0xb3, 0xf3, 0x78, 0x44, 0x87,
    0xd6, 0x11, 0xf9, 0x22, 0xa3, 0xf3, 0xc6, 0x1d, 0x30, 0x00, 0x5b,
    0x77, 0x18, 0x38, 0x39, 0x08, 0x5e, 0x0a, 0x56, 0x6b
};

static const uint8_t kAESECBCiphertext[64] = {
    0xa4, 0xc1, 0x5c, 0x51, 0x2a, 0x2e, 0x2a, 0xda, 0xd9, 0x02, 0x23,
    0xe7, 0xa9, 0x34, 0x9d, 0xd8, 0x15, 0xc5, 0xf5, 0x55, 0x8e, 0xb0,
    0x29, 0x95, 0x48, 0x6c, 0x7f, 0xa9, 0x47, 0x19, 0x0b, 0x54, 0xe5,
    0x0f, 0x05, 0x76, 0xbb, 0xd0, 0x1a, 0x6c, 0xab, 0xe9, 0xfd, 0x5b,
    0xd8, 0x0b, 0x0a, 0xbd, 0x7f, 0xea, 0xda, 0x52, 0x07, 0x65, 0x13,
    0x6c, 0xbe, 0xfc, 0x36, 0x82, 0x4b, 0x6a, 0xc3, 0xd5
};

static const uint8_t kAESECBCiphertext_192[64] = {
    0x1d, 0xc8, 0xaa, 0xa7, 0x29, 0x01, 0x17, 0x09, 0x72, 0xc6, 0xe9,
    0x63, 0x02, 0x9d, 0xeb, 0x01, 0xeb, 0xc0, 0xda, 0x82, 0x6c, 0x30,
    0x7d, 0x60, 0x1b, 0x3e, 0xc7, 0x7b, 0xe3, 0x18, 0xa2, 0x43, 0x59,
    0x15, 0x4a, 0xe4, 0x8a, 0x84, 0xda, 0x16, 0x90, 0x7b, 0xfa, 0x64,
    0x37, 0x62, 0x19, 0xf1, 0x95, 0x11, 0x61, 0x84, 0xb0, 0x70, 0x49,
    0x72, 0x9f, 0xe7, 0x3a, 0x18, 0x99, 0x01, 0xba, 0xb0
};

static const uint8_t kAESECBCiphertext_256[64] = {
    0x6f, 0x2d, 0x6d, 0x7a, 0xc1, 0x8f, 0x00, 0x9f, 0x2d, 0xcf, 0xba,
    0xe6, 0x4f, 0xdd, 0xe0, 0x09, 0x5b, 0xf3, 0xa4, 0xaf, 0xce, 0x45,
    0x49, 0x6e, 0x28, 0x7b, 0x48, 0x57, 0xb5, 0xf5, 0xd8, 0x05, 0x16,
    0x0f, 0xea, 0x21, 0x0c, 0x39, 0x78, 0xee, 0x9e, 0x57, 0x3c, 0x40,
    0x11, 0x9c, 0xd9, 0x34, 0x97, 0xb9, 0xa6, 0x06, 0x40, 0x60, 0xa2,
    0x0c, 0x01, 0xe3, 0x9c, 0xda, 0x3e, 0xad, 0x99, 0x3d
};

static const uint8_t kAESCBCCiphertext[64] = {
    0xa4, 0xc1, 0x5c, 0x51, 0x2a, 0x2e, 0x2a, 0xda, 0xd9, 0x02, 0x23,
    0xe7, 0xa9, 0x34, 0x9d, 0xd8, 0x5c, 0xb3, 0x65, 0x54, 0x72, 0xc8,
    0x06, 0xf1, 0x36, 0xc3, 0x97, 0x73, 0x87, 0xca, 0x44, 0x99, 0x21,
    0xb8, 0xdb, 0x93, 0x22, 0x00, 0x89, 0x7c, 0x1c, 0xea, 0x36, 0x23,
    0x18, 0xdb, 0xc1, 0x52, 0x8c, 0x23, 0x66, 0x11, 0x0d, 0xa8, 0xe9,
    0xb8, 0x08, 0x8b, 0xaa, 0x81, 0x47, 0x01, 0xa4, 0x4f
};

static const uint8_t kAESCBCCiphertext_192[64] = {
    0x1d, 0xc8, 0xaa, 0xa7, 0x29, 0x01, 0x17, 0x09, 0x72, 0xc6, 0xe9,
    0x63, 0x02, 0x9d, 0xeb, 0x01, 0xb4, 0x48, 0xa8, 0x00, 0x94, 0x46,
    0x7f, 0xe3, 0xc1, 0x24, 0xea, 0x41, 0xa0, 0x2b, 0x47, 0x2f, 0xae,
    0x19, 0xce, 0x0d, 0xfa, 0x90, 0x45, 0x85, 0xce, 0xc4, 0x21, 0x0c,
    0x74, 0x38, 0x13, 0xfd, 0x64, 0xba, 0x58, 0x10, 0x37, 0x53, 0x48,
    0x66, 0x02, 0x76, 0xfb, 0xb1, 0x3a, 0x19, 0xce, 0x61
};

static const uint8_t kAESCBCCiphertext_256[64] = {
    0x6f, 0x2d, 0x6d, 0x7a, 0xc1, 0x8f, 0x00, 0x9f, 0x2d, 0xcf, 0xba,
    0xe6, 0x4f, 0xdd, 0xe0, 0x09, 0x9e, 0xa8, 0x28, 0xdc, 0x27, 0xde,
    0x89, 0x26, 0xc7, 0x94, 0x6a, 0xbf, 0xb6, 0x94, 0x05, 0x08, 0x6c,
    0x39, 0x07, 0x52, 0xfa, 0x7b, 0xca, 0x7d, 0x9b, 0xbf, 0xb2, 0x43,
    0x2b, 0x69, 0xee, 0xc5, 0x68, 0x4c, 0xdd, 0x62, 0xae, 0x8d, 0x7e,
    0x71, 0x0c, 0x8f, 0x11, 0xce, 0x1d, 0x8b, 0xee, 0x94
};

static const uint8_t kAESCTRCiphertext[64] = {
    0x49, 0xf5, 0x6a, 0x7d, 0x3e, 0xd7, 0xb2, 0x47, 0x35, 0xca, 0x54,
    0xf5, 0xf1, 0xb8, 0xd1, 0x48, 0xb0, 0x18, 0xc4, 0x5e, 0xeb, 0x42,
    0xfd, 0x10, 0x49, 0x1f, 0x2b, 0x11, 0xe9, 0xb0, 0x07, 0xa4, 0x00,
    0x56, 0xec, 0x25, 0x53, 0x4d, 0x70, 0x98, 0x38, 0x85, 0x5d, 0x54,
    0xab, 0x2c, 0x19, 0x13, 0x6d, 0xf3, 0x0e, 0x6f, 0x48, 0x2f, 0xab,
    0xe1, 0x82, 0xd4, 0x30, 0xa9, 0x16, 0x73, 0x93, 0xc3
};

static const uint8_t kAESCTRCiphertext_192[64] = {
    0x72, 0x7d, 0xbb, 0xd4, 0x8b, 0x16, 0x8b, 0x19, 0xa4, 0xeb, 0xa6,
    0xfa, 0xa0, 0xd0, 0x2b, 0xbb, 0x9b, 0x1f, 0xbf, 0x4d, 0x67, 0xfb,
    0xea, 0x89, 0x16, 0xd7, 0xa4, 0xb6, 0xbe, 0x1a, 0x78, 0x1c, 0x3d,
    0x44, 0x49, 0xa0, 0xf2, 0xb2, 0xb3, 0x82, 0x0f, 0xdd, 0xac, 0xd6,
    0xea, 0x6e, 0x1f, 0x09, 0x8d, 0xa5, 0xdb, 0x4f, 0x3f, 0x97, 0x90,
    0x26, 0xed, 0xf6, 0xbb, 0x62, 0xb3, 0x6f, 0x52, 0x67
};

static const uint8_t kAESCTRCiphertext_256[64] = {
    0x4a, 0x87, 0x44, 0x09, 0xf4, 0x1d, 0x80, 0x94, 0x51, 0x9a, 0xe4,
    0x89, 0x49, 0xcb, 0x98, 0x0d, 0x27, 0xc5, 0xba, 0x20, 0x00, 0x45,
    0xbb, 0x29, 0x75, 0xc0, 0xb7, 0x23, 0x0d, 0x81, 0x9f, 0x43, 0xaa,
    0x78, 0x89, 0xc0, 0xc4, 0x6d, 0x99, 0x0d, 0xb8, 0x9b, 0xc3, 0x25,
    0xa6, 0xd1, 0x7c, 0x98, 0x3e, 0xff, 0x06, 0x59, 0x41, 0xcf, 0xb2,
    0xd5, 0x2f, 0x95, 0xea, 0x83, 0xb1, 0x42, 0xb8, 0xb2
};

static const uint8_t kAESCFBCiphertext[64] = {
    0x49, 0xf5, 0x6a, 0x7d, 0x3e, 0xd7, 0xb2, 0x47, 0x35, 0xca, 0x54,
    0xf5, 0xf1, 0xb8, 0xd1, 0x48, 0x01, 0xdc, 0xba, 0x43, 0x3a, 0x7b,
    0xbf, 0x84, 0x91, 0x49, 0xc5, 0xc9, 0xd6, 0xcf, 0x6a, 0x2c, 0x3a,
    0x66, 0x99, 0x68, 0xe3, 0xd0, 0x56, 0x05, 0xe7, 0x99, 0x7f, 0xc3,
    0xbc, 0x09, 0x13, 0xa6, 0xf0, 0xde, 0x17, 0xf4, 0x85, 0x9a, 0xee,
    0x29, 0xc3, 0x77, 0xab, 0xc4, 0xf6, 0xdb, 0xae, 0x24
};

static const uint8_t kAESCCMCiphertext[68] = {
    0x7a, 0x02, 0x5d, 0x48, 0x02, 0x44, 0x78, 0x7f, 0xb4, 0x71, 0x74,
    0x7b, 0xec, 0x4d, 0x90, 0x29, 0x7b, 0xa7, 0x65, 0xbb, 0x3e, 0x80,
    0x41, 0x7e, 0xab, 0xb4, 0x58, 0x22, 0x4f, 0x86, 0xcd, 0xcc, 0xc2,
    0x12, 0xeb, 0x36, 0x39, 0x89, 0xe3, 0x66, 0x2a, 0xbf, 0xe3, 0x6c,
    0x95, 0x60, 0x13, 0x9e, 0x93, 0xcc, 0xb4, 0x06, 0xbe, 0xaf, 0x3f,
    0xba, 0x13, 0x73, 0x09, 0x92, 0xd1, 0x80, 0x73, 0xb3, 0xc3, 0xa3,
    0xa4, 0x8b
};

static const uint8_t kAESKWCiphertext[72] = {
    0x44, 0xec, 0x7d, 0x92, 0x2c, 0x9f, 0xf3, 0xe8, 0xac, 0xb1, 0xea,
    0x3d, 0x0a, 0xc7, 0x51, 0x27, 0xe8, 0x03, 0x11, 0x78, 0xe5, 0xaf,
    0x8d, 0xb1, 0x70, 0x96, 0x2e, 0xfa, 0x05, 0x48, 0x48, 0x99, 0x1a,
    0x58, 0xcc, 0xfe, 0x11, 0x36, 0x5d, 0x49, 0x98, 0x1e, 0xbb, 0xd6,
    0x0b, 0xf5, 0xb9, 0x64, 0xa4, 0x30, 0x3e, 0x60, 0xf6, 0xc5, 0xff,
    0x82, 0x30, 0x9a, 0xa7, 0x48, 0x82, 0xe2, 0x00, 0xc1, 0xe9, 0xc2,
    0x73, 0x6f, 0xbc, 0x89, 0x66, 0x9d
};

static const uint8_t kAESKWPCiphertext[72] = {
    0x29, 0x5e, 0xb9, 0xea, 0x96, 0xa7, 0xa5, 0xca, 0xfa, 0xeb, 0xda,
    0x78, 0x13, 0xea, 0x83, 0xca, 0x41, 0xdb, 0x4d, 0x36, 0x7d, 0x39,
    0x8a, 0xd6, 0xef, 0xd3, 0xd2, 0x2d, 0x3a, 0xc8, 0x55, 0xc8, 0x73,
    0xd7, 0x79, 0x55, 0xad, 0xc0, 0xce, 0xad, 0x12, 0x54, 0x51, 0xf0,
    0x70, 0x76, 0xff, 0xe7, 0x0c, 0xb2, 0x8e, 0xdd, 0xb6, 0x9a, 0x27,
    0x74, 0x98, 0x28, 0xe0, 0xfa, 0x11, 0xe6, 0x3f, 0x86, 0x93, 0x23,
    0xf8, 0x0d, 0xcb, 0xaf, 0x2b, 0xb7
};

static const uint8_t kAESCMACOutput[16] = {
    0xe7, 0x32, 0x43, 0xb4, 0xae, 0x79, 0x08, 0x86, 0xe7, 0x9f, 0x0d,
    0x3f, 0x88, 0x3f, 0x1a, 0xfd
};

static const uint8_t kOutput_md5[MD5_DIGEST_LENGTH] = {
    0xc8, 0xbe, 0xdc, 0x96, 0xbe, 0xb0, 0xd6, 0x7b, 0x96, 0x7d, 0x3b,
    0xd4, 0x24, 0x29, 0x30, 0xde
};

static const uint8_t kOutput_sha1[SHA_DIGEST_LENGTH] = {
    0x5b, 0xed, 0x47, 0xcc, 0xc8, 0x8d, 0x6a, 0xf8, 0x91, 0xc1, 0x85,
    0x84, 0xe9, 0xd1, 0x31, 0xe6, 0x3e, 0x62, 0x61, 0xd9
};

static const uint8_t kOutput_sha224[SHA224_DIGEST_LENGTH] = {
    0xef, 0xad, 0x36, 0x20, 0xc6, 0x16, 0x17, 0x24, 0x49, 0x80, 0x53,
    0x7a, 0x46, 0x5b, 0xed, 0xde, 0x59, 0x9d, 0xa9, 0x19, 0xb0, 0xb8,
    0x1f, 0xbe, 0x4b, 0xa7, 0xc0, 0xea
};

static const uint8_t kOutput_sha256[SHA256_DIGEST_LENGTH] = {
    0x03, 0x19, 0x41, 0x4c, 0x62, 0x51, 0x83, 0xe5, 0x2b, 0x73, 0xf0,
    0x55, 0x51, 0x5e, 0x8e, 0x7d, 0x6f, 0x3a, 0x91, 0xf1, 0xac, 0xe0,
    0x7b, 0xb2, 0xac, 0x13, 0x65, 0x18, 0x55, 0x2c, 0x98, 0x0f
};

static const uint8_t kOutput_sha384[SHA384_DIGEST_LENGTH] = {
    0x0b, 0xbf, 0xc2, 0x06, 0x7a, 0x1e, 0xeb, 0x4a, 0x11, 0x57, 0x41,
    0x20, 0x7b, 0xfb, 0xf7, 0x2c, 0x22, 0x6b, 0x96, 0xcb, 0xc6, 0x00,
    0x81, 0xe3, 0x19, 0xf2, 0x0e, 0xcc, 0xb9, 0x5d, 0xee, 0x71, 0xda,
    0x34, 0x10, 0xae, 0x02, 0x64, 0x31, 0x07, 0x13, 0xff, 0x47, 0xf2,
    0xdf, 0xb0, 0x05, 0x03
};

static const uint8_t kOutput_sha512[SHA512_DIGEST_LENGTH] = {
    0x9d, 0xa3, 0xfa, 0xaf, 0xae, 0x0a, 0xf4, 0xe4, 0x2e, 0x68, 0xcb,
    0x7c, 0x65, 0x04, 0x76, 0x26, 0x91, 0x2a, 0x52, 0xb6, 0xb0, 0xa9,
    0x40, 0xa7, 0xf7, 0xcb, 0xc8, 0x8d, 0x4b, 0x55, 0x1b, 0x44, 0xe2,
    0x13, 0xcb, 0x6a, 0x28, 0x89, 0xa3, 0x15, 0x94, 0xc6, 0xbb, 0xcb,
    0x5d, 0xf5, 0xb3, 0x4f, 0x47, 0x8f, 0x1a, 0x44, 0x39, 0x51, 0xd2,
    0x63, 0xb1, 0x0c, 0xe1, 0x2c, 0x8d, 0x07, 0x08, 0x2f
};

static const uint8_t kOutput_sha512_256[SHA512_256_DIGEST_LENGTH] = {
    0x4f, 0x8a, 0x34, 0x49, 0xfd, 0xc8, 0x42, 0xb7, 0xc1, 0x2b, 0x6d,
    0x2a, 0x89, 0xb8, 0x10, 0x73, 0xde, 0x4a, 0x33, 0x7d, 0x3c, 0x8c,
    0xa5, 0xff, 0xee, 0xc9, 0xbb, 0x92, 0x3d, 0x47, 0x60, 0x34
};

static const uint8_t kHMACOutput_sha1[SHA_DIGEST_LENGTH] = {
    0x22, 0xbe, 0xf1, 0x4e, 0x72, 0xec, 0xfd, 0x34, 0xd9, 0x57, 0xec,
    0xf6, 0x08, 0xeb, 0x37, 0xff, 0xf9, 0x3b, 0x9f, 0xf3
};

static const uint8_t kHMACOutput_sha224[SHA224_DIGEST_LENGTH] = {
    0x5f, 0x85, 0xbd, 0xb9, 0xf9, 0x00, 0xdf, 0x81, 0xef, 0x65, 0xd3,
    0x8e, 0x7a, 0xb6, 0xd8, 0x5b, 0xf9, 0xd8, 0x62, 0x1c, 0xc5, 0x11,
    0x68, 0xb4, 0xf4, 0xd8, 0x57, 0x46
};

static const uint8_t kHMACOutput_sha256[SHA256_DIGEST_LENGTH] = {
    0x4b, 0xe9, 0x34, 0xa9, 0x37, 0x53, 0x2a, 0xb1, 0x63, 0x5d, 0x8c,
    0x22, 0x9a, 0x02, 0x37, 0x44, 0x75, 0xe1, 0x21, 0x9e, 0xf1, 0xe3,
    0x2c, 0xd0, 0x7d, 0x79, 0x03, 0x87, 0xd9, 0x69, 0x36, 0xb5
};

static const uint8_t kHMACOutput_sha384[SHA384_DIGEST_LENGTH] = {
    0x26, 0x5f, 0x4e, 0x13, 0x99, 0x04, 0xa1, 0xf4, 0xd2, 0x01, 0xd9,
    0xba, 0xe0, 0xe6, 0xa2, 0xbd, 0x50, 0x76, 0x2b, 0xc3, 0x90, 0x11,
    0x50, 0xe7, 0x26, 0xdf, 0x39, 0xf9, 0xd6, 0x8f, 0x83, 0xa5, 0xe6,
    0x8c, 0x16, 0x77, 0xbf, 0xfc, 0x77, 0x66, 0x9a, 0xe5, 0xa0, 0xb7,
    0xfe, 0xfb, 0x09, 0x5e
};

static const uint8_t kHMACOutput_sha512[SHA512_DIGEST_LENGTH] = {
    0x70, 0xf3, 0xf2, 0x82, 0xba, 0xc8, 0x14, 0xe4, 0x00, 0x9b, 0x72,
    0x8a, 0xe6, 0x07, 0xc8, 0xaf, 0x4f, 0x23, 0x0a, 0x5b, 0x16, 0xa8,
    0x9b, 0x68, 0x4f, 0x75, 0x21, 0xac, 0xb4, 0x20, 0x3d, 0x97, 0x77,
    0x21, 0x00, 0x74, 0xfa, 0xb2, 0x79, 0x28, 0x47, 0x8c, 0xa6, 0x11,
    0x85, 0xa5, 0x1e, 0x2f, 0x4a, 0x25, 0xd4, 0xf8, 0x13, 0x64, 0xd1,
    0x30, 0xd8, 0x45, 0x2c, 0x87, 0x44, 0x62, 0xc5, 0xe3
};

static const uint8_t kHMACOutput_sha512_256[SHA512_256_DIGEST_LENGTH] = {
    0xaa, 0xd0, 0x57, 0x0c, 0x98, 0x45, 0x74, 0x6b, 0x39, 0x1e, 0x07,
    0x55, 0x23, 0x08, 0xab, 0x79, 0xad, 0xe5, 0x8b, 0x48, 0xc2, 0x0c,
    0x1a, 0x37, 0x91, 0xe4, 0x8b, 0xc0, 0x9c, 0xce, 0x2c, 0x24
};

static const uint8_t kDRBGEntropy[48] = {
    'B', 'C', 'M', ' ', 'K', 'n', 'o', 'w', 'n', ' ', 'A', 'n', 's',
    'w', 'e', 'r', ' ', 'T', 'e', 's', 't', ' ', 'D', 'B', 'R', 'G',
    ' ', 'I', 'n', 'i', 't', 'i', 'a', 'l', ' ', 'E', 'n', 't', 'r',
    'o', 'p', 'y', ' ', ' ', ' ', ' ', ' ', ' '
};

static const uint8_t kDRBGPersonalization[18] = {
    'B', 'C', 'M', 'P', 'e', 'r', 's', 'o', 'n', 'a', 'l', 'i', 'z',
    'a', 't', 'i', 'o', 'n'
};

static const uint8_t kDRBGAD[16] = {
    'B', 'C', 'M', ' ', 'D', 'R', 'B', 'G', ' ', 'K', 'A', 'T', ' ',
    'A', 'D', ' '
};

const uint8_t kDRBGOutput[64] = {
    0x1d, 0x63, 0xdf, 0x05, 0x51, 0x49, 0x22, 0x46, 0xcd, 0x9b, 0xc5,
    0xbb, 0xf1, 0x5d, 0x44, 0xae, 0x13, 0x78, 0xb1, 0xe4, 0x7c, 0xf1,
    0x96, 0x33, 0x3d, 0x60, 0xb6, 0x29, 0xd4, 0xbb, 0x6b, 0x44, 0xf9,
    0xef, 0xd9, 0xf4, 0xa2, 0xba, 0x48, 0xea, 0x39, 0x75, 0x59, 0x32,
    0xf7, 0x31, 0x2c, 0x98, 0x14, 0x2b, 0x49, 0xdf, 0x02, 0xb6, 0x5d,
    0x71, 0x09, 0x50, 0xdb, 0x23, 0xdb, 0xe5, 0x22, 0x95
};

static const uint8_t kDRBGEntropy2[48] = {
    'B', 'C', 'M', ' ', 'K', 'n', 'o', 'w', 'n', ' ', 'A', 'n', 's',
    'w', 'e', 'r', ' ', 'T', 'e', 's', 't', ' ', 'D', 'B', 'R', 'G',
    ' ', 'R', 'e', 's', 'e', 'e', 'd', ' ', 'E', 'n', 't', 'r', 'o',
    'p', 'y', ' ', ' ', ' ', ' ', ' ', ' ', ' '
};

static const uint8_t kDRBGReseedOutput[64] = {
    0xa4, 0x77, 0x05, 0xdb, 0x14, 0x11, 0x76, 0x71, 0x42, 0x5b, 0xd8,
    0xd7, 0xa5, 0x4f, 0x8b, 0x39, 0xf2, 0x10, 0x4a, 0x50, 0x5b, 0xa2,
    0xc8, 0xf0, 0xbb, 0x3e, 0xa1, 0xa5, 0x90, 0x7d, 0x54, 0xd9, 0xc6,
    0xb0, 0x96, 0xc0, 0x2b, 0x7e, 0x9b, 0xc9, 0xa1, 0xdd, 0x78, 0x2e,
    0xd5, 0xa8, 0x66, 0x16, 0xbd, 0x18, 0x3c, 0xf2, 0xaa, 0x7a, 0x2b,
    0x37, 0xf9, 0xab, 0x35, 0x64, 0x15, 0x01, 0x3f, 0xc4,
};

static const uint8_t kTLSSecret[32] = {
    0xbf, 0xe4, 0xb7, 0xe0, 0x26, 0x55, 0x5f, 0x6a, 0xdf, 0x5d, 0x27,
    0xd6, 0x89, 0x99, 0x2a, 0xd6, 0xf7, 0x65, 0x66, 0x07, 0x4b, 0x55,
    0x5f, 0x64, 0x55, 0xcd, 0xd5, 0x77, 0xa4, 0xc7, 0x09, 0x61,
};
static const char kTLSLabel[] = "FIPS self test";
static const uint8_t kTLSSeed1[16] = {
    0x8f, 0x0d, 0xe8, 0xb6, 0x90, 0x8f, 0xb1, 0xd2,
    0x6d, 0x51, 0xf4, 0x79, 0x18, 0x63, 0x51, 0x65,
};
static const uint8_t kTLSSeed2[16] = {
    0x7d, 0x24, 0x1a, 0x9d, 0x3c, 0x59, 0xbf, 0x3c,
    0x31, 0x1e, 0x2b, 0x21, 0x41, 0x8d, 0x32, 0x81,
};

static const uint8_t kTLSOutput_mdsha1[32] = {
    0x36, 0xa9, 0x31, 0xb0, 0x43, 0xe3, 0x64, 0x72, 0xb9, 0x47, 0x54,
    0x0d, 0x8a, 0xfc, 0xe3, 0x5c, 0x1c, 0x15, 0x67, 0x7e, 0xa3, 0x5d,
    0xf2, 0x3a, 0x57, 0xfd, 0x50, 0x16, 0xe1, 0xa4, 0xa6, 0x37
};

static const uint8_t kTLSOutput_md[32] = {
    0x79, 0xef, 0x46, 0xc4, 0x35, 0xbc, 0xe5, 0xda, 0xd3, 0x66, 0x91,
    0xdc, 0x86, 0x09, 0x41, 0x66, 0xf2, 0x0c, 0xeb, 0xe6, 0xab, 0x5c,
    0x58, 0xf4, 0x65, 0xce, 0x2f, 0x5f, 0x4b, 0x34, 0x1e, 0xa1
};

static const uint8_t kTLSOutput_sha1[32] = {
    0xbb, 0x0a, 0x73, 0x52, 0xf8, 0x85, 0xd7, 0xbd, 0x12, 0x34, 0x78,
    0x3b, 0x54, 0x4c, 0x75, 0xfe, 0xd7, 0x23, 0x6e, 0x22, 0x3f, 0x42,
    0x34, 0x99, 0x57, 0x6b, 0x14, 0xc4, 0xc8, 0xae, 0x9f, 0x4c
};

static const uint8_t kTLSOutput_sha256[32] = {
    0x67, 0x85, 0xde, 0x60, 0xfc, 0x0a, 0x83, 0xe9, 0xa2, 0x2a, 0xb3,
    0xf0, 0x27, 0x0c, 0xba, 0xf7, 0xfa, 0x82, 0x3d, 0x14, 0x77, 0x1d,
    0x86, 0x29, 0x79, 0x39, 0x77, 0x8a, 0xd5, 0x0e, 0x9d, 0x32
};

static const uint8_t kTLSOutput_sha384[32] = {
    0x75, 0x15, 0x3f, 0x44, 0x7a, 0xfd, 0x34, 0xed, 0x2b, 0x67, 0xbc,
    0xd8, 0x57, 0x96, 0xab, 0xff, 0xf4, 0x0c, 0x05, 0x94, 0x02, 0x23,
    0x81, 0xbf, 0x0e, 0xd2, 0xec, 0x7c, 0xe0, 0xa7, 0xc3, 0x7d
};

static const uint8_t kTLSOutput_sha512[32] = {
    0x68, 0xb9, 0xc8, 0x4c, 0xf5, 0x51, 0xfc, 0x7a, 0x1f, 0x6c, 0xe5,
    0x43, 0x73, 0x80, 0x53, 0x7c, 0xae, 0x76, 0x55, 0x67, 0xe0, 0x79,
    0xbf, 0x3a, 0x53, 0x71, 0xb7, 0x9c, 0xb5, 0x03, 0x15, 0x3f
};

struct CipherTestVector {
  const EVP_CIPHER *cipher;
  const uint8_t *key;
  const int key_length;
  const uint8_t *expected_ciphertext;
  const int cipher_text_length;
  const bool has_iv;
  const int expect_approved;
} nTestVectors[] = {
  { EVP_aes_128_ecb(), kAESKey, 16, kAESECBCiphertext, 64, false, AWSLC_APPROVED },
  { EVP_aes_192_ecb(), kAESKey_192, 24, kAESECBCiphertext_192, 64, false, AWSLC_APPROVED },
  { EVP_aes_256_ecb(), kAESKey_256, 32, kAESECBCiphertext_256, 64, false, AWSLC_APPROVED },
  { EVP_aes_128_cbc(), kAESKey, 16, kAESCBCCiphertext, 64, true, AWSLC_APPROVED },
  { EVP_aes_192_cbc(), kAESKey_192, 24, kAESCBCCiphertext_192, 64, true, AWSLC_APPROVED },
  { EVP_aes_256_cbc(), kAESKey_256, 32, kAESCBCCiphertext_256, 64, true, AWSLC_APPROVED },
  { EVP_aes_128_ctr(), kAESKey, 16, kAESCTRCiphertext, 64, true, AWSLC_APPROVED },
  { EVP_aes_192_ctr(), kAESKey_192, 24, kAESCTRCiphertext_192, 64, true, AWSLC_APPROVED },
  { EVP_aes_256_ctr(), kAESKey_256, 32, kAESCTRCiphertext_256, 64, true, AWSLC_APPROVED },
  { EVP_aes_128_ofb(), kAESKey, 16, kAESOFBCiphertext, 64, true, AWSLC_NOT_APPROVED },
  { EVP_des_ede3(), kAESKey_192, 24, KTDES_EDE3_CipherText, 64, false, AWSLC_NOT_APPROVED },
  { EVP_des_ede3_cbc(), kAESKey_192, 24, KTDES_EDE3_CBCCipherText, 64, false, AWSLC_NOT_APPROVED }
};

class EVP_ServiceIndicatorTest : public testing::TestWithParam<CipherTestVector> {};

INSTANTIATE_TEST_SUITE_P(All, EVP_ServiceIndicatorTest, testing::ValuesIn(nTestVectors));

TEST_P(EVP_ServiceIndicatorTest, EVP_Ciphers) {
  const CipherTestVector &evpTestVector = GetParam();

  const EVP_CIPHER *cipher = evpTestVector.cipher;
  std::vector<uint8_t> key(evpTestVector.key, evpTestVector.key + evpTestVector.key_length);
  std::vector<uint8_t> plaintext(kPlaintext, kPlaintext + sizeof(kPlaintext));
  std::vector<uint8_t> ciphertext(evpTestVector.expected_ciphertext, evpTestVector.expected_ciphertext + evpTestVector.cipher_text_length);

  TestOperation(cipher, true /* encrypt */, key, plaintext, ciphertext, evpTestVector.expect_approved);
  TestOperation(cipher, false /* decrypt */, key, plaintext, ciphertext, evpTestVector.expect_approved);
}

struct MD {
  // name is the name of the digest test.
  const char* name;
  // length of digest.
  const int length;
  // func is the digest to test.
  const EVP_MD *(*func)(void);
  // one_shot_func is the convenience one-shot version of the digest.
  uint8_t *(*one_shot_func)(const uint8_t *, size_t, uint8_t *);
};

static const MD md5 = { "KAT for MD5", MD5_DIGEST_LENGTH, &EVP_md5, &MD5 };
static const MD sha1 = { "KAT for SHA1", SHA_DIGEST_LENGTH, &EVP_sha1, &SHA1 };
static const MD sha224 = { "KAT for SHA224", SHA224_DIGEST_LENGTH, &EVP_sha224, &SHA224 };
static const MD sha256 = { "KAT for SHA256", SHA256_DIGEST_LENGTH, &EVP_sha256, &SHA256 };
static const MD sha384 = { "KAT for SHA384", SHA384_DIGEST_LENGTH, &EVP_sha384, &SHA384 };
static const MD sha512 = { "KAT for SHA512", SHA512_DIGEST_LENGTH, &EVP_sha512, &SHA512 };
static const MD sha512_256 = { "KAT for SHA512-256", SHA512_256_DIGEST_LENGTH, &EVP_sha512_256, &SHA512_256 };

struct DigestTestVector {
  // md is the digest to test.
  const MD &md;
  // input is a NUL-terminated string to hash.
  const uint8_t *input;
  // expected_digest is the expected digest.
  const uint8_t *expected_digest;
  // expected to be approved or not.
  const int expect_approved;
} kDigestTestVectors[] = {
    { md5, kPlaintext, kOutput_md5, AWSLC_NOT_APPROVED },
    { sha1, kPlaintext, kOutput_sha1, AWSLC_APPROVED },
    { sha224, kPlaintext, kOutput_sha224, AWSLC_APPROVED },
    { sha256, kPlaintext, kOutput_sha256, AWSLC_APPROVED },
    { sha384, kPlaintext, kOutput_sha384, AWSLC_APPROVED },
    { sha512, kPlaintext, kOutput_sha512, AWSLC_APPROVED },
    { sha512_256, kPlaintext, kOutput_sha512_256, AWSLC_APPROVED }
};

class EVP_MD_ServiceIndicatorTest : public testing::TestWithParam<DigestTestVector> {};

INSTANTIATE_TEST_SUITE_P(All, EVP_MD_ServiceIndicatorTest, testing::ValuesIn(kDigestTestVectors));

TEST_P(EVP_MD_ServiceIndicatorTest, EVP_Digests) {
  const DigestTestVector &digestTestVector = GetParam();

  int approved = AWSLC_NOT_APPROVED;
  bssl::ScopedEVP_MD_CTX ctx;
  std::vector<uint8_t> digest(digestTestVector.md.length);
  unsigned digest_len;

  // Test running the EVP_Digest interfaces one by one directly, and check
  // |EVP_DigestFinal_ex| for approval at the end. |EVP_DigestInit_ex| and
  // |EVP_DigestUpdate| should not be approved, because the functions do not
  // indicate that a service has been fully completed yet.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), digestTestVector.md.func(), nullptr)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), digestTestVector.input, sizeof(digestTestVector.input))));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len)));
  ASSERT_EQ(approved, digestTestVector.expect_approved);
  ASSERT_TRUE(check_test(digestTestVector.expected_digest, digest.data(), digest_len, digestTestVector.md.name));


  // Test using the one-shot |EVP_Digest| function for approval.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_Digest(digestTestVector.input, sizeof(digestTestVector.input),
                                               digest.data(), &digest_len, digestTestVector.md.func(), nullptr)));
  ASSERT_EQ(approved, digestTestVector.expect_approved);
  ASSERT_TRUE(check_test(digestTestVector.expected_digest, digest.data(), digest_len, digestTestVector.md.name));


  // Test using the one-shot API for approval.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, digestTestVector.md.one_shot_func(digestTestVector.input, sizeof(digestTestVector.input), digest.data()));
  ASSERT_EQ(approved, digestTestVector.expect_approved);
  ASSERT_TRUE(check_test(digestTestVector.expected_digest, digest.data(), digestTestVector.md.length, digestTestVector.md.name));
}

struct HMACTestVector {
  // func is the hash function for HMAC to test.
  const EVP_MD *(*func)(void);
  // input is a NUL-terminated string to hash.
  const uint8_t *input;
  // expected_digest is the expected digest.
  const uint8_t *expected_digest;
  // expected to be approved or not.
  const int expect_approved;
} kHMACTestVectors[] = {
    { EVP_sha1, kPlaintext, kHMACOutput_sha1, AWSLC_APPROVED },
    { EVP_sha224, kPlaintext, kHMACOutput_sha224, AWSLC_APPROVED },
    { EVP_sha256, kPlaintext, kHMACOutput_sha256, AWSLC_APPROVED },
    { EVP_sha384, kPlaintext, kHMACOutput_sha384, AWSLC_APPROVED },
    { EVP_sha512, kPlaintext, kHMACOutput_sha512, AWSLC_APPROVED },
    { EVP_sha512_256, kPlaintext, kHMACOutput_sha512_256, AWSLC_NOT_APPROVED }
};

class HMAC_ServiceIndicatorTest : public testing::TestWithParam<HMACTestVector> {};

INSTANTIATE_TEST_SUITE_P(All, HMAC_ServiceIndicatorTest, testing::ValuesIn(kHMACTestVectors));

TEST_P(HMAC_ServiceIndicatorTest, HMACTest) {
  const HMACTestVector &hmacTestVector = GetParam();

  int approved = AWSLC_NOT_APPROVED;
  const uint8_t kHMACKey[64] = {0};
  const EVP_MD *digest = hmacTestVector.func();
  std::vector<uint8_t> key(kHMACKey, kHMACKey + sizeof(kHMACKey));
  unsigned expected_mac_len = EVP_MD_size(digest);
  std::vector<uint8_t> mac(expected_mac_len);

  // Test running the HMAC interfaces one by one directly, and check
  // |HMAC_Final| for approval at the end. |HMAC_Init_ex| and |HMAC_Update|
  // should not be approved, because the functions do not indicate that a
  // service has been fully completed yet.
  unsigned mac_len;
  bssl::ScopedHMAC_CTX ctx;
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(HMAC_Init_ex(ctx.get(), key.data(), key.size(), digest, nullptr)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(HMAC_Update(ctx.get(), hmacTestVector.input, sizeof(hmacTestVector.input))));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(HMAC_Final(ctx.get(), mac.data(), &mac_len)));
  ASSERT_EQ(approved, hmacTestVector.expect_approved);
  ASSERT_TRUE(check_test(hmacTestVector.expected_digest, mac.data(), mac_len, "HMAC KAT"));


  // Test using the one-shot API for approval.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(HMAC(digest, key.data(),
                     key.size(), hmacTestVector.input, sizeof(hmacTestVector.input), mac.data(), &mac_len)));
  ASSERT_EQ(approved, hmacTestVector.expect_approved);
  ASSERT_TRUE(check_test(hmacTestVector.expected_digest, mac.data(), mac_len, "HMAC KAT"));
}

struct ECDHTestVector {
  // nid is the input curve nid.
  const int nid;
  // md_func is the digest to test.
  const int digest_length;
  // expected to be approved or not.
  const int expect_approved;
};
struct ECDHTestVector kECDHTestVectors[] = {
    // Only the following NIDs for |EC_GROUP| are creatable with
    // |EC_GROUP_new_by_curve_name|.
    // |ECDH_compute_key_fips| fails directly when an invalid hash length is
    // inputted.
    { NID_secp224r1, SHA224_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp224r1, SHA256_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp224r1, SHA384_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp224r1, SHA512_DIGEST_LENGTH, AWSLC_APPROVED },

    { NID_X9_62_prime256v1, SHA224_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_X9_62_prime256v1, SHA256_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_X9_62_prime256v1, SHA384_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_X9_62_prime256v1, SHA512_DIGEST_LENGTH, AWSLC_APPROVED },

    { NID_secp384r1, SHA224_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp384r1, SHA256_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp384r1, SHA384_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp384r1, SHA512_DIGEST_LENGTH, AWSLC_APPROVED },

    { NID_secp521r1, SHA224_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp521r1, SHA256_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp521r1, SHA384_DIGEST_LENGTH, AWSLC_APPROVED },
    { NID_secp521r1, SHA512_DIGEST_LENGTH, AWSLC_APPROVED },
};

class ECDH_ServiceIndicatorTest : public testing::TestWithParam<ECDHTestVector> {};

INSTANTIATE_TEST_SUITE_P(All, ECDH_ServiceIndicatorTest, testing::ValuesIn(kECDHTestVectors));

TEST_P(ECDH_ServiceIndicatorTest, ECDH) {
  const ECDHTestVector &ecdhTestVector = GetParam();

  int approved = AWSLC_NOT_APPROVED;

  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(ecdhTestVector.nid));
  bssl::UniquePtr<EC_KEY> our_key(EC_KEY_new());
  bssl::UniquePtr<EC_KEY> peer_key(EC_KEY_new());
  bssl::ScopedEVP_MD_CTX md_ctx;
  ASSERT_TRUE(our_key);
  ASSERT_TRUE(peer_key);

  // Generate two generic ec key pairs.
  ASSERT_TRUE(EC_KEY_set_group(our_key.get(), group.get()));
  ASSERT_TRUE(EC_KEY_generate_key(our_key.get()));
  ASSERT_TRUE(EC_KEY_check_key(our_key.get()));

  ASSERT_TRUE(EC_KEY_set_group(peer_key.get(), group.get()));
  ASSERT_TRUE(EC_KEY_generate_key(peer_key.get()));
  ASSERT_TRUE(EC_KEY_check_key(peer_key.get()));

  // Test that |ECDH_compute_key_fips| has service indicator approval as
  // expected.
  std::vector<uint8_t> digest(ecdhTestVector.digest_length);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(ECDH_compute_key_fips(digest.data(),
                              digest.size(), EC_KEY_get0_public_key(peer_key.get()), our_key.get())));
  ASSERT_EQ(approved, ecdhTestVector.expect_approved);

  // Test running the EVP_PKEY_derive interfaces one by one directly, and check
  // |EVP_PKEY_derive| for approval at the end. |EVP_PKEY_derive_init|,
  // |EVP_PKEY_derive_set_peer| should not be approved because they do not indicate
  // an entire service has been done.
  std::vector<uint8_t> derive_output;
  size_t out_len = 0;
  bssl::UniquePtr<EVP_PKEY> our_pkey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(our_pkey.get(), our_key.get());
  bssl::UniquePtr<EVP_PKEY_CTX> our_ctx(EVP_PKEY_CTX_new(our_pkey.get(), nullptr));
  bssl::UniquePtr<EVP_PKEY> peer_pkey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(peer_pkey.get(), peer_key.get());

  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_PKEY_derive_init(our_ctx.get())));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_PKEY_derive_set_peer(our_ctx.get(), peer_pkey.get())));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  // Determine the size of the output key. The first call of |EVP_PKEY_derive|
  // should not return an approval check because no crypto is being done when
  // |nullptr| is inputted in the |*key| field
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_PKEY_derive(our_ctx.get(), nullptr, &out_len)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  derive_output.resize(out_len);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_PKEY_derive(our_ctx.get(), derive_output.data(), &out_len)));
  derive_output.resize(out_len);
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

struct KDFTestVector {
  // func is the hash function for KDF to test.
  const EVP_MD *(*func)(void);
  const uint8_t *expected_output;
  const int expect_approved;
} kKDFTestVectors[] = {
    { EVP_md5, kTLSOutput_md, AWSLC_NOT_APPROVED },
    { EVP_sha1, kTLSOutput_sha1, AWSLC_NOT_APPROVED },
    { EVP_md5_sha1, kTLSOutput_mdsha1, AWSLC_APPROVED },
    { EVP_sha256, kTLSOutput_sha256, AWSLC_APPROVED },
    { EVP_sha384, kTLSOutput_sha384, AWSLC_APPROVED },
    { EVP_sha512, kTLSOutput_sha512, AWSLC_APPROVED },
};

class KDF_ServiceIndicatorTest : public testing::TestWithParam<KDFTestVector> {};

INSTANTIATE_TEST_SUITE_P(All, KDF_ServiceIndicatorTest, testing::ValuesIn(kKDFTestVectors));

TEST_P(KDF_ServiceIndicatorTest, KDF) {
  const KDFTestVector &kdfTestVector = GetParam();

  int approved = AWSLC_NOT_APPROVED;

  std::vector<uint8_t> tls_output(32);
  CALL_SERVICE_AND_CHECK_APPROVED(
      approved, ASSERT_TRUE(CRYPTO_tls1_prf(kdfTestVector.func(),
                                tls_output.data(), tls_output.size(),
                                kTLSSecret, sizeof(kTLSSecret), kTLSLabel,
                                sizeof(kTLSLabel), kTLSSeed1, sizeof(kTLSSeed1),
                                kTLSSeed2, sizeof(kTLSSeed2))));
  ASSERT_TRUE(check_test(kdfTestVector.expected_output, tls_output.data(),
                         tls_output.size(), "TLS KDF KAT"));
  ASSERT_EQ(approved, kdfTestVector.expect_approved);
}

TEST(ServiceIndicatorTest, CMAC) {
  int approved = AWSLC_NOT_APPROVED;

  std::vector<uint8_t> mac(16);
  size_t out_len;
  bssl::UniquePtr<CMAC_CTX> ctx(CMAC_CTX_new());
  ASSERT_TRUE(ctx);

  // Test running the CMAC interfaces one by one directly, and check
  // |CMAC_Final| for approval at the end. |CMAC_Init| and |CMAC_Update|
  // should not be approved, because the functions do not indicate that a
  // service has been fully completed yet.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CMAC_Init(ctx.get(), kAESKey, sizeof(kAESKey), EVP_aes_128_cbc(), nullptr)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CMAC_Update(ctx.get(), kPlaintext, sizeof(kPlaintext))));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CMAC_Final(ctx.get(), mac.data(), &out_len)));
  ASSERT_EQ(approved, AWSLC_APPROVED);
  ASSERT_TRUE(check_test(kAESCMACOutput, mac.data(), sizeof(kAESCMACOutput), "AES-CMAC KAT"));

  // Test using the one-shot API for approval.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(AES_CMAC(mac.data(), kAESKey, sizeof(kAESKey),
                                                    kPlaintext, sizeof(kPlaintext))));
  ASSERT_TRUE(check_test(kAESCMACOutput, mac.data(), sizeof(kAESCMACOutput), "AES-CMAC KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, BasicTest) {
  int approved = AWSLC_NOT_APPROVED;

  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  AES_KEY aes_key;
  uint8_t aes_iv[sizeof(kAESIV)];
  uint8_t output[256];
  size_t out_len;
  int num = 0;

  // Call an approved service.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Call an approved service in a macro.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_EQ(EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0), 1));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Call an approved service and compare expected return value.
  int return_val = 0;
  CALL_SERVICE_AND_CHECK_APPROVED(approved, return_val = EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_EQ(return_val, 1);
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Call an approved service wrapped in an if statement.
  return_val = 0;
  CALL_SERVICE_AND_CHECK_APPROVED(approved,
    if(EVP_AEAD_CTX_seal(aead_ctx.get(), output, &out_len, sizeof(output),
         nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0) == 1)
    {
      return_val = 1;
    }
  );
  ASSERT_EQ(return_val, 1);
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Fail an approved service on purpose.
  return_val = 0;
  CALL_SERVICE_AND_CHECK_APPROVED(approved, return_val = EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, 0, nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_EQ(return_val, 0);
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // Fail an approved service on purpose while wrapped in an if statement.
  return_val = 0;
  CALL_SERVICE_AND_CHECK_APPROVED(approved,
    if(EVP_AEAD_CTX_seal(aead_ctx.get(), output, &out_len, 0,
        nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0) == 1)
    {
      return_val = 1;
    }
  );
  ASSERT_EQ(return_val, 0);
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // Call a non-approved service.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ofb128_encrypt(kPlaintext, output,
                                   sizeof(kPlaintext), &aes_key, aes_iv, &num));
  ASSERT_TRUE(check_test(kAESOFBCiphertext, output, sizeof(kAESOFBCiphertext),
                         "AES-OFB Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
}

TEST(ServiceIndicatorTest, AESECB) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t output[256];

  // AES-ECB Encryption KAT for 128 bit key.
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  // AES_ecb_encrypt encrypts (or decrypts) a single, 16 byte block from in to out.
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kPlaintext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_ENCRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kAESECBCiphertext, output, sizeof(kAESECBCiphertext),
                         "AES-ECB Encryption KAT for 128 bit key"));

  // AES-ECB Decryption KAT for 128 bit key.
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kAESECBCiphertext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_DECRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-ECB Decryption KAT for 128 bit key"));

  // AES-ECB Encryption KAT for 192 bit key.
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_192, 8 * sizeof(kAESKey_192), &aes_key) == 0);
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kPlaintext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_ENCRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kAESECBCiphertext_192, output, sizeof(kAESECBCiphertext_192),
                         "AES-ECB Encryption KAT for 192 bit key"));

  // AES-ECB Decryption KAT for 192 bit key.
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey_192, 8 * sizeof(kAESKey_192), &aes_key) == 0);
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kAESECBCiphertext_192[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_DECRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-ECB Decryption KAT for 192 bit key"));

  // AES-ECB Encryption KAT for 256 bit key.
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_256, 8 * sizeof(kAESKey_256), &aes_key) == 0);
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kPlaintext[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_ENCRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kAESECBCiphertext_256, output, sizeof(kAESECBCiphertext_256),
                         "AES-ECB Encryption KAT for 256 bit key"));

  // AES-ECB Decryption KAT for 256 bit key.
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey_256, 8 * sizeof(kAESKey_256), &aes_key) == 0);
  for (size_t j = 0; j < sizeof(kPlaintext) / AES_BLOCK_SIZE; j++) {
    CALL_SERVICE_AND_CHECK_APPROVED(approved,
      AES_ecb_encrypt(&kAESECBCiphertext_256[j * AES_BLOCK_SIZE], &output[j * AES_BLOCK_SIZE], &aes_key, AES_DECRYPT));
    ASSERT_EQ(approved, AWSLC_APPROVED);
  }
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-ECB Decryption KAT for 256 bit key"));
}

TEST(ServiceIndicatorTest, AESCBC) {
  int approved = AWSLC_NOT_APPROVED;
  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];
  // AES-CBC Encryption KAT for 128 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kPlaintext, output,
                              sizeof(kPlaintext), &aes_key, aes_iv, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                         "AES-CBC Encryption KAT for 128 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CBC Decryption KAT for 128 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kAESCBCCiphertext, output,
                        sizeof(kAESCBCCiphertext), &aes_key, aes_iv, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CBC Decryption KAT for 128 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CBC Encryption KAT for 192 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_192, 8 * sizeof(kAESKey_192), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kPlaintext, output,
                              sizeof(kPlaintext), &aes_key, aes_iv, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCBCCiphertext_192, output, sizeof(kAESCBCCiphertext_192),
                         "AES-CBC Encryption KAT for 192 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CBC Decryption KAT for 192 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey_192, 8 * sizeof(kAESKey_192), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kAESCBCCiphertext_192, output,
                        sizeof(kAESCBCCiphertext_192), &aes_key, aes_iv, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CBC Decryption KAT for 192 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CBC Encryption KAT for 256 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_256, 8 * sizeof(kAESKey_256), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kPlaintext, output,
                              sizeof(kPlaintext), &aes_key, aes_iv, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCBCCiphertext_256, output, sizeof(kAESCBCCiphertext_256),
                         "AES-CBC Encryption KAT for 256 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CBC Decryption KAT for 256 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey_256, 8 * sizeof(kAESKey_256), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cbc_encrypt(kAESCBCCiphertext_256, output,
                        sizeof(kAESCBCCiphertext_256), &aes_key, aes_iv, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CBC Decryption KAT for 256 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, AESCTR) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];
  unsigned num = 0;
  uint8_t ecount_buf[AES_BLOCK_SIZE];

  // AES-CTR Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kPlaintext, output,
                             sizeof(kPlaintext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kAESCTRCiphertext, output, sizeof(kAESCTRCiphertext),
                         "AES-CTR Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CTR Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kAESCTRCiphertext, output,
                         sizeof(kAESCTRCiphertext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CTR Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CTR Encryption KAT for 192 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_192, 8 * sizeof(kAESKey_192), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kPlaintext, output,
                             sizeof(kPlaintext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kAESCTRCiphertext_192, output, sizeof(kAESCTRCiphertext_192),
                         "AES-CTR Encryption KAT for 192 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CTR Decryption KAT for 192 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kAESCTRCiphertext_192, output,
                         sizeof(kAESCTRCiphertext_192), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CTR Decryption KAT for 192 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CTR Encryption KAT for 256 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey_256, 8 * sizeof(kAESKey_256), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kPlaintext, output,
                             sizeof(kPlaintext), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kAESCTRCiphertext_256, output, sizeof(kAESCTRCiphertext_256),
                         "AES-CTR Encryption KAT for 256 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CTR Decryption KAT for 256 bit key.
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ctr128_encrypt(kAESCTRCiphertext_256, output,
                         sizeof(kAESCTRCiphertext_256), &aes_key, aes_iv, ecount_buf, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CTR Decryption KAT for 256 bit key"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, AESOFB) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t aes_iv[sizeof(kAESIV)];
  uint8_t output[256];
  int num = 0;

  // AES-OFB Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ofb128_encrypt(kPlaintext, output,
                                   sizeof(kPlaintext), &aes_key, aes_iv, &num));
  ASSERT_TRUE(check_test(kAESOFBCiphertext, output, sizeof(kAESOFBCiphertext),
                         "AES-OFB Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // AES-OFB Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_ofb128_encrypt(kAESOFBCiphertext, output,
                               sizeof(kAESOFBCiphertext), &aes_key, aes_iv, &num));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-OFB Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
}

TEST(ServiceIndicatorTest, AESCFB) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t aes_iv[sizeof(kAESIV)];
  uint8_t output[256];
  int num = 0;

  // AES-CFB Encryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cfb128_encrypt(kPlaintext, output,
                                   sizeof(kPlaintext), &aes_key, aes_iv, &num, AES_ENCRYPT));
  ASSERT_TRUE(check_test(kAESCFBCiphertext, output, sizeof(kAESCFBCiphertext),
                         "AES-CFB Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // AES-CFB Decryption KAT
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, AES_cfb128_encrypt(kAESCFBCiphertext, output,
                                 sizeof(kAESCFBCiphertext), &aes_key, aes_iv, &num, AES_DECRYPT));
  ASSERT_TRUE(check_test(kPlaintext, output, sizeof(kPlaintext),
                         "AES-CFB Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
}

TEST(ServiceIndicatorTest, AESGCM) {
  int approved = AWSLC_NOT_APPROVED;
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH] = {0};
  uint8_t encrypt_output[256];
  uint8_t decrypt_output[256];
  size_t out_len;
  size_t out2_len;

  // Approved usages.

  // Call approved internal IV usage of AES-GCM 128 bit kye size.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));

  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_open(aead_ctx.get(),
      decrypt_output, &out2_len, sizeof(decrypt_output), nullptr, 0, encrypt_output, out_len, nullptr, 0)));
  ASSERT_TRUE(check_test(kPlaintext, decrypt_output, sizeof(kPlaintext),
                  "AES-GCM Decryption for Internal IVs"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Call approved internal IV usage of AES-GCM 256 bit kye size.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_256_gcm_randnonce(),
                                kAESKey_256, sizeof(kAESKey_256), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_open(aead_ctx.get(),
      decrypt_output, &out2_len, sizeof(decrypt_output), nullptr, 0, encrypt_output, out_len, nullptr, 0)));
  ASSERT_TRUE(check_test(kPlaintext, decrypt_output, sizeof(kPlaintext),
                  "AES-GCM Decryption for Internal IVs"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Non-approved usages

  // Call non-approved external IV usage of AES-GCM 128 bit key size.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
          kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // Call non-approved external IV usage of AES-GCM 192 bit key size. (192 is
  // not available for internal IV.)
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_192_gcm(),
                              kAESKey_192, sizeof(kAESKey_192), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_192_gcm()),
          kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);

  // Call non-approved external IV usage of AES-GCM 256 bit key size.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_256_gcm(),
                              kAESKey_256, sizeof(kAESKey_256), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
      encrypt_output, &out_len, sizeof(encrypt_output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_256_gcm()),
          kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
}

TEST(ServiceIndicatorTest, AESCCM) {
  int approved = AWSLC_NOT_APPROVED;

  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  uint8_t output[256];
  size_t out_len;

  OPENSSL_memset(nonce, 0, sizeof(nonce));
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_ccm_bluetooth(),
                                kAESKey, sizeof(kAESKey), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));

  // AES-CCM Encryption
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_seal(aead_ctx.get(),
       output, &out_len, sizeof(output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_128_ccm_bluetooth()),
       kPlaintext, sizeof(kPlaintext), nullptr, 0)));
  ASSERT_TRUE(check_test(kAESCCMCiphertext, output, out_len, "AES-CCM Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-CCM Decryption
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(EVP_AEAD_CTX_open(aead_ctx.get(),
       output, &out_len, sizeof(output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_128_ccm_bluetooth()),
       kAESCCMCiphertext, sizeof(kAESCCMCiphertext), nullptr, 0)));
  ASSERT_TRUE(check_test(kPlaintext, output, out_len, "AES-CCM Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, AESKW) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t output[256];
  size_t outlen;

  // AES-KW Encryption KAT
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, outlen = AES_wrap_key(&aes_key, nullptr,
                                    output, kPlaintext, sizeof(kPlaintext)));
  ASSERT_EQ(outlen, sizeof(kAESKWCiphertext));
  ASSERT_TRUE(check_test(kAESKWCiphertext, output, outlen, "AES-KW Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-KW Decryption KAT
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved,outlen = AES_unwrap_key(&aes_key, nullptr,
                                    output, kAESKWCiphertext, sizeof(kAESKWCiphertext)));
  ASSERT_EQ(outlen, sizeof(kPlaintext));
  ASSERT_TRUE(check_test(kPlaintext, output, outlen, "AES-KW Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, AESKWP) {
  int approved = AWSLC_NOT_APPROVED;

  AES_KEY aes_key;
  uint8_t output[256];
  size_t outlen;
  // AES-KWP Encryption KAT
  memset(output, 0, 256);
  ASSERT_TRUE(AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(AES_wrap_key_padded(&aes_key,
              output, &outlen, sizeof(kPlaintext) + 15, kPlaintext, sizeof(kPlaintext))));
  ASSERT_TRUE(check_test(kAESKWPCiphertext, output, outlen, "AES-KWP Encryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // AES-KWP Decryption KAT
  ASSERT_TRUE(AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) == 0);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(AES_unwrap_key_padded(&aes_key,
             output, &outlen, sizeof(kAESKWPCiphertext), kAESKWPCiphertext, sizeof(kAESKWPCiphertext))));
  ASSERT_TRUE(check_test(kPlaintext, output, outlen, "AES-KWP Decryption KAT"));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}

TEST(ServiceIndicatorTest, DRBG) {
  int approved = AWSLC_NOT_APPROVED;
  CTR_DRBG_STATE drbg;
  uint8_t output[256];

  // Test running the DRBG interfaces and check |CTR_DRBG_generate| for approval
  // at the end since it indicates a service is being done. |CTR_DRBG_init| and
  // |CTR_DRBG_reseed| should not be approved, because the functions do not
  // indicate that a service has been fully completed yet.
  // These DRBG functions are not directly accessible for external consumers
  // however.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CTR_DRBG_init(&drbg,
                        kDRBGEntropy, kDRBGPersonalization, sizeof(kDRBGPersonalization))));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CTR_DRBG_generate(&drbg,
                        output, sizeof(kDRBGOutput), kDRBGAD, sizeof(kDRBGAD))));
  ASSERT_EQ(approved, AWSLC_APPROVED);
  ASSERT_TRUE(check_test(kDRBGOutput, output, sizeof(kDRBGOutput),"DBRG Generate KAT"));

  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CTR_DRBG_reseed(&drbg,
                        kDRBGEntropy2, kDRBGAD, sizeof(kDRBGAD))));
  ASSERT_EQ(approved, AWSLC_NOT_APPROVED);
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(CTR_DRBG_generate(&drbg,
                        output, sizeof(kDRBGReseedOutput), kDRBGAD, sizeof(kDRBGAD))));
  ASSERT_EQ(approved, AWSLC_APPROVED);
  ASSERT_TRUE(check_test(kDRBGReseedOutput, output, sizeof(kDRBGReseedOutput),"DRBG Reseed KAT"));

  // Test approval of |RAND_bytes|, which is the only way for the consumer to
  // indirectly interact with the DRBG functions.
  CALL_SERVICE_AND_CHECK_APPROVED(approved, ASSERT_TRUE(RAND_bytes(output, sizeof(output))));
  ASSERT_EQ(approved, AWSLC_APPROVED);
  CTR_DRBG_clear(&drbg);
}

#else
// Service indicator calls should not be used in non-FIPS builds. However, if
// used, the macro |CALL_SERVICE_AND_CHECK_APPROVED| will return
// |AWSLC_APPROVED|, but the direct calls to |FIPS_service_indicator_xxx|
// will not indicate an approved state.
TEST(ServiceIndicatorTest, BasicTest) {
   // Reset and check the initial state and counter.
  int approved = AWSLC_NOT_APPROVED;
  uint64_t before = FIPS_service_indicator_before_call();
  ASSERT_EQ(before, (uint64_t)0);

  // Call an approved service.
  bssl::ScopedEVP_AEAD_CTX aead_ctx;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH] = {0};
  uint8_t output[256];
  size_t out_len;
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm_randnonce(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nullptr, 0, kPlaintext, sizeof(kPlaintext), nullptr, 0));
  // Macro should return true, to ensure FIPS/Non-FIPS compatibility.
  ASSERT_EQ(approved, AWSLC_APPROVED);

  // Approval check should also return true when not in FIPS mode.
  uint64_t after = FIPS_service_indicator_after_call();
  ASSERT_EQ(after, (uint64_t)0);
  ASSERT_TRUE(FIPS_service_indicator_check_approved(before, after));


  // Call a non-approved service.
  ASSERT_TRUE(EVP_AEAD_CTX_init(aead_ctx.get(), EVP_aead_aes_128_gcm(),
                                kAESKey, sizeof(kAESKey), 0, nullptr));
  CALL_SERVICE_AND_CHECK_APPROVED(approved, EVP_AEAD_CTX_seal(aead_ctx.get(),
          output, &out_len, sizeof(output), nonce, EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
          kPlaintext, sizeof(kPlaintext), nullptr, 0));
  ASSERT_EQ(approved, AWSLC_APPROVED);
}
#endif // AWSLC_FIPS


