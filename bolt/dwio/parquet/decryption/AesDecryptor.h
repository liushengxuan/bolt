/*
 * Copyright (c) 2025 ByteDance Ltd. and/or its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#pragma once

#include <cstring>


#include <parquet/encryption/encryption.h>
#include <parquet/types.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bolt/common/base/Exceptions.h"


namespace bytedance::bolt::parquet::decryption {

constexpr int kGcmMode = 0;
constexpr int kCtrMode = 1;
constexpr int kCtrIvLength = 16;
constexpr int kBufferSizeLength = 4;

constexpr int kGcmTagLength = 16;
constexpr int kNonceLength = 12;

#define DECRYPT_INIT(CTX, ALG)                                        \
if (1 != EVP_DecryptInit_ex(CTX, ALG, nullptr, nullptr, nullptr)) { \
BOLT_FAIL("Couldn't init ALG decryption");                       \
}

// AesDecryptor performs AES decryption operations with GCM or CTR ciphers.
class AesDecryptor {
 public:
  /// \brief Constructor function of AesDecryptor.
  ///
  /// \param encryptionType the encryption algorithm to use.
  /// \param keyLen can only serve one key length. Possible values: 16, 24, 32 bytes.
  /// \param hasMetadataDecryptor if true then this is a metadata decryptor.
  /// \param containsLength If it is true, expect ciphertext length prepended to the ciphertext.
  explicit AesDecryptor(
      ::parquet::ParquetCipher::type alg_id,
      int key_len,
      bool metadata,
      int32_t max_encrypted_size,
      bool contains_length = true);

  /// \brief Factory function to create an AesDecryptor.
  ///
  /// \param encryptionType the encryption algorithm to use.
  /// \param keyLen key length. Possible values: 16, 24, 32 bytes.
  /// \param hasMetadataDecryptor if true then this is a metadata decryptor.
  /// \param allDecryptors A weak reference to all decryptors that need to be
  /// wiped out when decryption is finished \return shared pointer to a new
  /// AesDecryptor.
  static std::shared_ptr<AesDecryptor> Make(
      ::parquet::ParquetCipher::type alg_id,
      int key_len,
      bool metadata,
      int32_t max_encrypted_size,
      std::vector<std::weak_ptr<AesDecryptor>>* all_decryptors);

  ~AesDecryptor();

  void WipeOut() {
    if (nullptr != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  /// \brief Get the size difference between plain text and crytped text.
  int ciphertext_size_delta() {
    return ciphertext_size_delta_;
  }

  /// \brief Decrypts crypted text with the key and aad. Key length is passed only for
  /// validation. If it is different from value from the  constructor, an
  /// exception would trigered.

  int Decrypt(
        const unsigned char* ciphertext,
        int ciphertext_len,
        const unsigned char* key,
        int key_len,
        const unsigned char* aad,
        int aad_len,
        unsigned char* plaintext,
        int plaintext_len);


  int GcmDecrypt(
      const unsigned char* ciphertext,
      int ciphertext_len,
      const unsigned char* key,
      int key_len,
      const unsigned char* aad,
      int aad_len,
      unsigned char* plaintext,
      int plaintext_len);

  int CtrDecrypt(
      const unsigned char* ciphertext,
      int ciphertext_len,
      const unsigned char* key,
      int key_len,
      unsigned char* plaintext,
      int plaintext_len);

 private:
  // PIMPL Idiom
  EVP_CIPHER_CTX* ctx_;
  int aes_mode_;
  int key_length_;
  int ciphertext_size_delta_;
  int length_buffer_length_;
  int32_t max_encrypted_size_;
};

std::string CreateModuleAad(
    const std::string& file_aad,
    int8_t module_type,
    int16_t row_group_ordinal,
    int16_t column_ordinal,
    int32_t page_ordinal);

std::string CreateFooterAad(const std::string& aad_prefix_bytes);

// Update last two bytes of page (or page header) module AAD
void QuickUpdatePageAad(int32_t new_page_ordinal, std::string* AAD);

// Wraps OpenSSL RAND_bytes function
void RandBytes(unsigned char* buf, int num);

} // bytedance::bolt::parquet::decryption