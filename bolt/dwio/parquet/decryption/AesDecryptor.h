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


#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bolt/common/base/Exceptions.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/decryption/Decryptor.h"
#include "bolt/dwio/parquet/arrow/Encryption.h"
#include "bolt/dwio/parquet/arrow/Types.h"

namespace bytedance::bolt::parquet::decryption {

// AesDecryptor performs AES decryption operations with GCM or CTR ciphers.
class AesDecryptor : public Decryptor {
 public:
  /// \brief Constructor function of AesDecryptor.
  ///
  /// \param encryptionType the encryption algorithm to use.
  /// \param keyLen can only serve one key length. Possible values: 16, 24, 32
  /// bytes. \param hasMetadataDecryptor if true then this is a metadata
  /// decryptor. \param containsLength If it is true, expect ciphertext length
  /// prepended to the ciphertext.
  explicit AesDecryptor(
      ParquetCipher::type algId,
      bool metadata,
      int32_t maxEncryptedSize,
      const std::string& key,
      const std::string& fileAad,
      const std::string& aad,
      memory::MemoryPool* pool,
      bool containsLength = true);
  //
  // /// \brief Factory function to create an AesDecryptor.
  // ///
  // /// \param encryptionType the encryption algorithm to use.
  // /// \param keyLen key length. Possible values: 16, 24, 32 bytes.
  // /// \param hasMetadataDecryptor if true then this is a metadata decryptor.
  // /// \param allDecryptors A weak reference to all decryptors that need to be
  // /// wiped out when decryption is finished \return shared pointer to a new
  // /// AesDecryptor.
  // static std::shared_ptr<AesDecryptor> Make(
  //     ::parquet::ParquetCipher::type alg_id,
  //     int key_len,
  //     bool metadata,
  //     int32_t max_encrypted_size,
  //     std::vector<std::weak_ptr<AesDecryptor>>* all_decryptors);

  ~AesDecryptor();

  void WipeOut() {
    if (nullptr != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  /// \brief Get the size difference between plain text and crytped text.
  int ciphertext_size_delta() {
    return ciphertextSizeDelta_;
  }

  /// \brief Decrypts crypted text with the key and aad. Key length is passed
  /// only for validation. If it is different from value from the  constructor,
  /// an exception would trigered.

  int Decrypt(
      const uint8_t* ciphertext,
      int ciphertextLen,
      uint8_t* plaintext,
      int plaintextLen) const override;

  int CiphertextSizeDelta() const override {
    return ciphertextSizeDelta_;
  };

private:
  int GcmDecrypt(
      const unsigned char* ciphertext,
      int ciphertextLen,
      const unsigned char* key,
      int keyLen,
      const unsigned char* aad,
      int aadLen,
      unsigned char* plaintext,
      int plaintextLen) const;

  int CtrDecrypt(
      const unsigned char* ciphertext,
      int ciphertextLen,
      const unsigned char* key,
      int keyLen,
      unsigned char* plaintext,
      int plaintextLen) const;


  // PIMPL Idiom
  EVP_CIPHER_CTX* ctx_;
  int aesMode_;
  int ciphertextSizeDelta_;
  int lengthBufferLength_;
  int32_t maxEncryptedSize_;
};

// std::string CreateModuleAad(
//     const std::string& fileAad,
//     int8_t moduleType,
//     int16_t rowGroupOrdinal,
//     int16_t columnOrdinal,
//     int32_t pageOrdinal);
//
// std::string CreateFooterAad(const std::string& aadPrefixBytes);

// Update last two bytes of page (or page header) module AAD
// void QuickUpdatePageAad(int32_t newPageOrdinal, std::string* aad);

// Wraps OpenSSL RAND_bytes function
// void RandBytes(unsigned char* buf, int num);

} // namespace bytedance::bolt::parquet::decryption