/*
 * Copyright (c) ByteDance Ltd. and/or its affiliates.
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

// Partially inspired and adapted from Apache Arrow.

#pragma once

#include <cstring>

#include <cstdint>
#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bolt/common/base/Exceptions.h"
#include "bolt/dwio/parquet/arrow/Encryption.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/arrow/Types.h"
#include "bolt/dwio/parquet/decryption/Decryptor.h"

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
      const std::string& key,
      const std::string& fileAad,
      const std::string& aad,
      memory::MemoryPool* pool,
      bool containsLength = true);

  void wipeOut() {
    if (nullptr != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  /// \brief Decrypts crypted text with the key and aad. Key length is passed
  /// only for validation. If it is different from value from the constructor,
  /// an exception would trigered.

  int decrypt(
      const uint8_t* ciphertext,
      int ciphertextLen,
      uint8_t* plaintext,
      int plaintextLen) const override;

  int ciphertextSizeDelta() const override {
    return ciphertextSizeDelta_;
  }

  ~AesDecryptor() {
    if (nullptr != ctx_) {
      EVP_CIPHER_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

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
};

} // namespace bytedance::bolt::parquet::decryption
