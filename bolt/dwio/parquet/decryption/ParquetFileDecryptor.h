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

// Partially inspired and adapted from Apache Arrow.

#pragma once

#include <map>
#include <memory>
#include <string>

#include "bolt/common/memory/MemoryPool.h"
#include "bolt/dwio/parquet/arrow/Encryption.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/arrow/Types.h"
#include "bolt/dwio/parquet/decryption/Decryptor.h"

namespace bytedance::bolt::parquet::decryption {


//
// class ThriftDeserializer {
// public:
//   ThriftDeserializer() {}
//
//   template <class T>
//   bool DeserializeMessage(
//       const uint8_t* buf,
//       uint32_t* len,
//       T* deserialized_msg,
//       const std::shared_ptr<Decryptor>& decryptor,
//       bool print = false) {
//     BOLT_CHECK_NE(decryptor, nullptr);
//     uint32_t clen;
//     clen = *len;
//     // decrypt
//     int64_t allocateSize = clen - decryptor->ciphertextSizeDelta();
//     uint8_t* decrypted_buffer =
//         reinterpret_cast<uint8_t*>(decryptor->pool()->allocate(allocateSize));
//     auto decryptBufferGuard = folly::makeGuard(
//         [&]() { decryptor->pool()->free(decrypted_buffer, allocateSize); });
//     const uint8_t* cipher_buf = buf;
//     uint32_t decrypted_buffer_len =
//         decryptor->decrypt(cipher_buf, 0, decrypted_buffer, allocateSize);
//     if (decrypted_buffer_len <= 0) {
//       return false;
//     }
//     *len = decrypted_buffer_len + decryptor->ciphertextSizeDelta();
//     DeserializeUnencryptedMessage(
//         decrypted_buffer, &decrypted_buffer_len, deserialized_msg);
//     return true;
//   }
//
//   template <class T>
//   void DeserializeUnencryptedMessage(
//       const uint8_t* buf,
//       uint32_t* len,
//       T* deserialized_msg) {
//     std::shared_ptr<thrift::ThriftTransport> thriftTransport =
//         std::make_shared<thrift::ThriftBufferedTransport>(buf, *len);
//     auto thriftProtocol = std::make_unique<
//         ::apache::thrift::protocol::TCompactProtocolT<thrift::ThriftTransport>>(
//         thriftTransport);
//
//     *len = deserialized_msg->read(thriftProtocol.get());
//   }
// };
//
//

class ParquetFileDcryptor {
 public:
  explicit ParquetFileDcryptor(
      arrow::FileDecryptionProperties* properties,
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

  arrow::FileDecryptionProperties* properties() {
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
  arrow::FileDecryptionProperties* properties_;
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
