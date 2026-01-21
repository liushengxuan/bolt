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

#include <map>
#include <memory>
#include <string>

#include <parquet/encryption/crypto_factory.h>
#include <parquet/encryption/encryption.h>

#include "bolt/common/memory/MemoryPool.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/arrow/Types.h"
#include "bolt/dwio/parquet/decryption/Decryptor.h"

namespace bytedance::bolt::parquet::decryption {
class ParquetFileDecryptor {
 public:
  explicit ParquetFileDecryptor(
      ::parquet::FileDecryptionProperties* properties,
      const std::string& fileAad,
      arrow::ParquetCipher::type algorithm,
      const std::string& footerKeyMetadata,
      memory::MemoryPool* pool);

  std::string& fileAad() {
    return fileAad_;
  }

  std::string getFooterKey();

  arrow::ParquetCipher::type algorithm() {
    return algorithm_;
  }

  std::string& footerKeyMetadata() {
    return footerKeyMetadata_;
  }

  ::parquet::FileDecryptionProperties* properties() {
    return properties_;
  }

  void wipeOutDecryptionKeys();

  memory::MemoryPool* pool() {
    return pool_;
  }

  std::shared_ptr<Decryptor> getFooterDecryptor();
  std::shared_ptr<Decryptor> getFooterDecryptorForColumnMeta(
      const std::string& aad = "");
  std::shared_ptr<Decryptor> getFooterDecryptorForColumnData(
      const std::string& aad = "");
  std::shared_ptr<Decryptor> getColumnMetaDecryptor(
      const std::string& columnPath,
      const std::string& columnKeyMetadata,
      const std::string& aad = "");
  std::shared_ptr<Decryptor> getColumnDataDecryptor(
      const std::string& columnPath,
      const std::string& columnKeyMetadata,
      const std::string& aad = "");

 private:
  ::parquet::FileDecryptionProperties* properties_;
  // Concatenation of aad_prefix (if exists) and aad_file_unique
  std::string fileAad_;
  std::map<std::string, std::shared_ptr<Decryptor>> columnDataMap_;
  std::map<std::string, std::shared_ptr<Decryptor>> columnMetadataMap_;

  std::shared_ptr<Decryptor> footerMetadataDecryptor_;
  std::shared_ptr<Decryptor> footerDataDecryptor_;
  arrow::ParquetCipher::type algorithm_;
  std::string footerKeyMetadata_;

  memory::MemoryPool* pool_;

  void ensureFooterDecryptors(const std::string& aad);
  std::shared_ptr<Decryptor> getFooterMetadataDecryptor(const std::string& aad);
  std::shared_ptr<Decryptor> getFooterDataDecryptor(const std::string& aad);
  void ensureColumnDecryptors(
      const std::string& columnPath,
      const std::string& columnKeyMetadata,
      const std::string& aad);
};
} // namespace bytedance::bolt::parquet::decryption
