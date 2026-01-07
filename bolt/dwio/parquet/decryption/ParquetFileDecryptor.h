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

#include "bolt/dwio/parquet/arrow/Encryption.h"
#include "bolt/dwio/parquet/arrow/Types.h"
#include "bolt/common/memory/MemoryPool.h"

namespace bytedance::bolt::parquet::decryption {

class InternalFileDecryptor {
 public:
  explicit InternalFileDecryptor(
      arrow::FileDecryptionProperties* properties,
      const std::string& file_aad,
      arrow::ParquetCipher::type algorithm,
      const std::string& footer_key_metadata,
      memory::MemoryPool* pool,
      int32_t max_encrypted_size = 0);

  std::string& file_aad() {
    return file_aad_;
  }

  std::string GetFooterKey();

  arrow::ParquetCipher::type algorithm() {
    return algorithm_;
  }

  std::string& footer_key_metadata() {
    return footer_key_metadata_;
  }

  arrow::FileDecryptionProperties* properties() {
    return properties_;
  }

  void WipeOutDecryptionKeys();

  memory::MemoryPool* pool() {
    return pool_;
  }

  std::shared_ptr<Decryptor> GetFooterDecryptor();
  std::shared_ptr<Decryptor> GetFooterDecryptorForColumnMeta(
      const std::string& aad = "");
  std::shared_ptr<Decryptor> GetFooterDecryptorForColumnData(
      const std::string& aad = "");
  std::shared_ptr<Decryptor> GetColumnMetaDecryptor(
      const std::string& column_path,
      const std::string& column_key_metadata,
      const std::string& aad = "");
  std::shared_ptr<Decryptor> GetColumnDataDecryptor(
      const std::string& column_path,
      const std::string& column_key_metadata,
      const std::string& aad = "");

 private:
  ::parquet::FileDecryptionProperties* properties_;
  // Concatenation of aad_prefix (if exists) and aad_file_unique
  std::string file_aad_;
  std::map<std::string, std::shared_ptr<Decryptor>> column_data_map_;
  std::map<std::string, std::shared_ptr<Decryptor>> column_metadata_map_;

  std::shared_ptr<Decryptor> footer_metadata_decryptor_;
  std::shared_ptr<Decryptor> footer_data_decryptor_;
  bytedance::bolt::parquet::ParquetCipher::type algorithm_;
  std::string footer_key_metadata_;
  // A weak reference to all decryptors that need to be wiped out when
  // decryption is finished
  std::vector<std::weak_ptr<encryption::AesDecryptor>> all_decryptors_;

  memory::MemoryPool* pool_;
  int32_t max_encrypted_size_;

  std::shared_ptr<Decryptor> GetFooterDecryptor(
      const std::string& aad,
      bool metadata);
  std::shared_ptr<Decryptor> GetColumnDecryptor(
      const std::string& column_path,
      const std::string& column_key_metadata,
      const std::string& aad,
      bool metadata = false);
};
} // namespace bytedance::bolt::parquet::decryption