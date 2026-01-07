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

#include "bolt/common/base/Exceptions.h"
#include "bolt/common/memory/MemoryPool.h"

namespace bytedance::bolt::parquet::decryption {

constexpr int kGcmMode = 0;
constexpr int kCtrMode = 1;
constexpr int kCtrIvLength = 16;
constexpr int kBufferSizeLength = 4;

#define DECRYPT_INIT(CTX, ALG)                                        \
  if (1 != EVP_DecryptInit_ex(CTX, ALG, nullptr, nullptr, nullptr)) { \
    BOLT_FAIL("Couldn't init ALG decryption");                        \
  }

// The Decryptor class is the interface class for different types of dcryptors
class Decryptor {
 public:
  Decryptor(
      const std::string& key,
      const std::string& fileAad,
      const std::string& aad,
      memory::MemoryPool* pool)
      : key_(key), fileAad_(fileAad), aad_(aad), pool_(pool) {}

  const std::string& get_key() const {
    return key_;
  }

  const std::string& file_aad() const {
    return fileAad_;
  }
  void UpdateAad(const std::string& aad) {
    aad_ = aad;
  }
  memory::MemoryPool* pool() {
    return pool_;
  }


  /// Size difference between plaintext and ciphertext, for this cipher.
  virtual int CiphertextSizeDelta() const = 0;

  virtual int Decrypt(
      const uint8_t* ciphertext,
      int ciphertext_len,
      uint8_t* plaintext,
      int plaintext_len) const = 0;

 private:
  std::string key_;
  std::string fileAad_;
  std::string aad_;
  memory::MemoryPool* pool_;
};

} // namespace bytedance::bolt::parquet::decryption