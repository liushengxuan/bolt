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

#include "bolt/dwio/parquet/decryption/ParquetFileDecryptor.h"

namespace bytedance::bolt::parquet::decryption {

InternalFileDecryptor::InternalFileDecryptor(
    arrow::FileDecryptionProperties* properties,
    const std::string& file_aad,
    arrow::ParquetCipher::type algorithm,
    const std::string& footer_key_metadata,
    memory::MemoryPool* pool,
    int32_t max_encrypted_size)
    : properties_(properties),
      file_aad_(file_aad),
      algorithm_(algorithm),
      footer_key_metadata_(footer_key_metadata),
      pool_(pool),
      max_encrypted_size_(max_encrypted_size) {
  if (properties_->is_utilized()) {
    BOLT_FAIL(
        "Re-using decryption properties with explicit keys for another file");
  }
  properties_->set_utilized();
}

std::shared_ptr<Decryptor> InternalFileDecryptor::GetFooterDecryptor() {
  std::string aad = arrow::encryption::CreateFooterAad(file_aad_);
  return GetFooterMetadataDecryptor(aad);
}

void InternalFileDecryptor::EnsureFooterDecryptors(const std::string& aad) {
  if (footer_metadata_decryptor_ != nullptr &&
      footer_data_decryptor_ != nullptr) {
    footer_metadata_decryptor_->UpdateAad(aad);
    footer_data_decryptor_->UpdateAad(aad);
    return;
  }

  std::string footer_key = properties_->footer_key();
  if (footer_key.empty()) {
    if (footer_key_metadata_.empty())
      BOLT_FAIL("No footer key, and no key metadata.");
    if (properties_->key_retriever() == nullptr)
      BOLT_FAIL("No footer key, and no key retriever.");
    try {
      footer_key = properties_->key_retriever()->GetKey(footer_key_metadata_);
    } catch (arrow::KeyAccessDeniedException& e) {
      BOLT_FAIL("Footer key: access denied {}", e.what());
    }
  }
  if (footer_key.empty()) {
    BOLT_FAIL("Invalid footer encryption key. Could not parse footer metadata");
  }

  auto aes_metadata_decryptor = std::make_shared<AesDecryptor>(
      algorithm_, true, max_encrypted_size_, footer_key, file_aad_, aad, pool_);

  auto aes_data_decryptor = std::make_shared<AesDecryptor>(
      algorithm_,
      false,
      max_encrypted_size_,
      footer_key,
      file_aad_,
      aad,
      pool_);

  footer_metadata_decryptor_ = aes_metadata_decryptor;
  footer_data_decryptor_ = aes_data_decryptor;
}

std::shared_ptr<Decryptor> InternalFileDecryptor::GetFooterMetadataDecryptor(
    const std::string& aad) {
  EnsureFooterDecryptors(aad);
  return footer_metadata_decryptor_;
}

std::shared_ptr<Decryptor> InternalFileDecryptor::GetFooterDataDecryptor(
    const std::string& aad) {
  EnsureFooterDecryptors(aad);
  return footer_data_decryptor_;
}

std::shared_ptr<Decryptor>
InternalFileDecryptor::GetFooterDecryptorForColumnData(const std::string& aad) {
  return GetFooterDataDecryptor(aad);
}

std::shared_ptr<Decryptor>
InternalFileDecryptor::GetFooterDecryptorForColumnMeta(const std::string& aad) {
  return GetFooterMetadataDecryptor(aad);
}

std::shared_ptr<Decryptor> InternalFileDecryptor::GetColumnMetaDecryptor(
    const std::string& column_path,
    const std::string& column_key_metadata,
    const std::string& aad) {
  EnsureColumnDecryptors(column_path, column_key_metadata, aad);
  return column_metadata_map_.at(column_path);
}

std::shared_ptr<Decryptor> InternalFileDecryptor::GetColumnDataDecryptor(
    const std::string& column_path,
    const std::string& column_key_metadata,
    const std::string& aad) {
  EnsureColumnDecryptors(column_path, column_key_metadata, aad);
  return column_data_map_.at(column_path);
}

void InternalFileDecryptor::EnsureColumnDecryptors(
    const std::string& column_path,
    const std::string& column_key_metadata,
    const std::string& aad) {
  const auto metadata_it = column_metadata_map_.find(column_path);
  const auto data_it = column_data_map_.find(column_path);

  if (metadata_it != column_metadata_map_.end() &&
      data_it != column_data_map_.end()) {
    metadata_it->second->UpdateAad(aad);
    data_it->second->UpdateAad(aad);
    return;
  }

  std::string column_key;
  if (metadata_it != column_metadata_map_.end()) {
    metadata_it->second->UpdateAad(aad);
    column_key = metadata_it->second->get_key();
  } else if (data_it != column_data_map_.end()) {
    data_it->second->UpdateAad(aad);
    column_key = data_it->second->get_key();
  } else {
    column_key = properties_->column_key(column_path);
    if (column_key.empty() && !column_key_metadata.empty() &&
        properties_->key_retriever() != nullptr) {
      try {
        column_key = properties_->key_retriever()->GetKey(column_key_metadata);
      } catch (arrow::KeyAccessDeniedException& e) {
        BOLT_FAIL(
            "HiddenColumnException, path = {}, {}", column_path, e.what());
      }
    }
    if (column_key.empty()) {
      BOLT_FAIL("HiddenColumnException, path = {}", column_path);
    }
  }

  if (metadata_it == column_metadata_map_.end()) {
    column_metadata_map_[column_path] = std::make_shared<AesDecryptor>(
        algorithm_,
        true,
        max_encrypted_size_,
        column_key,
        file_aad_,
        aad,
        pool_);
  }

  if (data_it == column_data_map_.end()) {
    column_data_map_[column_path] = std::make_shared<AesDecryptor>(
        algorithm_,
        false,
        max_encrypted_size_,
        column_key,
        file_aad_,
        aad,
        pool_);
  }
}

} // namespace bytedance::bolt::parquet::decryption
