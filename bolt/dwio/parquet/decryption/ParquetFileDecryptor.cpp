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

#include "bolt/dwio/parquet/decryption/ParquetFileDecryptor.h"
#include "bolt/dwio/parquet/decryption/AesDecryptor.h"

namespace bytedance::bolt::parquet::decryption {

ParquetFileDecryptor::ParquetFileDecryptor(
    ::parquet::FileDecryptionProperties* properties,
    const std::string& fileAad,
    arrow::ParquetCipher::type algorithm,
    const std::string& footerKeyMetadata,
    memory::MemoryPool* pool)
    : properties_(properties),
      fileAad_(fileAad),
      algorithm_(algorithm),
      footerKeyMetadata_(footerKeyMetadata),
      pool_(pool) {
  if (properties_->is_utilized()) {
    BOLT_FAIL(
        "Re-using decryption properties with explicit keys for another file");
  }
  properties_->set_utilized();
}

std::shared_ptr<Decryptor> ParquetFileDecryptor::getFooterDecryptor() {
  std::string aad = arrow::encryption::CreateFooterAad(fileAad_);
  return getFooterMetadataDecryptor(aad);
}

void ParquetFileDecryptor::ensureFooterDecryptors(const std::string& aad) {
  if (footerMetadataDecryptor_ != nullptr && footerDataDecryptor_ != nullptr) {
    footerMetadataDecryptor_->updateAad(aad);
    footerDataDecryptor_->updateAad(aad);
    return;
  }

  std::string footerKey = properties_->footer_key();
  if (footerKey.empty()) {
    if (footerKeyMetadata_.empty()) {
      BOLT_FAIL("No footer key, and no key metadata.");
    }
    if (properties_->key_retriever() == nullptr) {
      BOLT_FAIL("No footer key, and no key retriever.");
    }
    try {
      footerKey = properties_->key_retriever()->GetKey(footerKeyMetadata_);
    } catch (arrow::KeyAccessDeniedException& e) {
      BOLT_FAIL("Footer key: access denied {}", e.what());
    }
  }
  if (footerKey.empty()) {
    BOLT_FAIL("Invalid footer encryption key. Could not parse footer metadata");
  }

  auto aesMetadataDecryptor = std::make_shared<AesDecryptor>(
      algorithm_, true, footerKey, fileAad_, aad, pool_);

  auto aesDataDecryptor = std::make_shared<AesDecryptor>(
      algorithm_, false, footerKey, fileAad_, aad, pool_);

  footerMetadataDecryptor_ = aesMetadataDecryptor;
  footerDataDecryptor_ = aesDataDecryptor;
}

std::shared_ptr<Decryptor> ParquetFileDecryptor::getFooterMetadataDecryptor(
    const std::string& aad) {
  ensureFooterDecryptors(aad);
  return footerMetadataDecryptor_;
}

std::shared_ptr<Decryptor> ParquetFileDecryptor::getFooterDataDecryptor(
    const std::string& aad) {
  ensureFooterDecryptors(aad);
  return footerDataDecryptor_;
}

std::shared_ptr<Decryptor>
ParquetFileDecryptor::getFooterDecryptorForColumnData(const std::string& aad) {
  return getFooterDataDecryptor(aad);
}

std::shared_ptr<Decryptor>
ParquetFileDecryptor::getFooterDecryptorForColumnMeta(const std::string& aad) {
  return getFooterMetadataDecryptor(aad);
}

std::shared_ptr<Decryptor> ParquetFileDecryptor::getColumnMetaDecryptor(
    const std::string& columnPath,
    const std::string& columnKeyMetadata,
    const std::string& aad) {
  ensureColumnDecryptors(columnPath, columnKeyMetadata, aad);
  return columnMetadataMap_.at(columnPath);
}

std::shared_ptr<Decryptor> ParquetFileDecryptor::getColumnDataDecryptor(
    const std::string& columnPath,
    const std::string& columnKeyMetadata,
    const std::string& aad) {
  ensureColumnDecryptors(columnPath, columnKeyMetadata, aad);
  return columnDataMap_.at(columnPath);
}

void ParquetFileDecryptor::ensureColumnDecryptors(
    const std::string& columnPath,
    const std::string& columnKeyMetadata,
    const std::string& aad) {
  const auto metadataIt = columnMetadataMap_.find(columnPath);
  const auto dataIt = columnDataMap_.find(columnPath);

  if (metadataIt != columnMetadataMap_.end() &&
      dataIt != columnDataMap_.end()) {
    metadataIt->second->updateAad(aad);
    dataIt->second->updateAad(aad);
    return;
  }

  std::string columnKey;
  if (metadataIt != columnMetadataMap_.end()) {
    metadataIt->second->updateAad(aad);
    columnKey = metadataIt->second->key();
  } else if (dataIt != columnDataMap_.end()) {
    dataIt->second->updateAad(aad);
    columnKey = dataIt->second->key();
  } else {
    columnKey = properties_->column_key(columnPath);
    if (columnKey.empty() && !columnKeyMetadata.empty() &&
        properties_->key_retriever() != nullptr) {
      try {
        columnKey = properties_->key_retriever()->GetKey(columnKeyMetadata);
      } catch (arrow::KeyAccessDeniedException& e) {
        BOLT_FAIL("HiddenColumnException, path = {}, {}", columnPath, e.what());
      }
    }
    if (columnKey.empty()) {
      BOLT_FAIL("HiddenColumnException, path = {}", columnPath);
    }
  }

  if (metadataIt == columnMetadataMap_.end()) {
    columnMetadataMap_[columnPath] = std::make_shared<AesDecryptor>(
        algorithm_, true, columnKey, fileAad_, aad, pool_);
  }

  if (dataIt == columnDataMap_.end()) {
    columnDataMap_[columnPath] = std::make_shared<AesDecryptor>(
        algorithm_, false, columnKey, fileAad_, aad, pool_);
  }
}

} // namespace bytedance::bolt::parquet::decryption
