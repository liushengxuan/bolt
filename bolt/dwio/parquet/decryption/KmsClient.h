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

#pragma once

#include <parquet/encryption/crypto_factory.h>
#include <parquet/encryption/encryption.h>

#include "bolt/common/encode/Base64.h"

namespace bytedance::bolt::parquet {
class KmsClientBase : public ::parquet::encryption::KmsClient {
 public:
  KmsClientBase() = default;

  virtual std::string WrapKey(
      const std::string& keyBytes,
      const std::string& masterKeyIdentifier) override {
    return encoding::Base64::encode(keyBytes);
  }

  virtual std::string UnwrapKey(
      const std::string& wrappedKey,
      const std::string& masterKeyIdentifier) override {
    return encoding::Base64::decode(wrappedKey);
  }
};

class KmsClientFactory : public ::parquet::encryption::KmsClientFactory {
 public:
  explicit KmsClientFactory() : ::parquet::encryption::KmsClientFactory(true) {}

  virtual std::shared_ptr<::parquet::encryption::KmsClient> CreateKmsClient(
      const ::parquet::encryption::KmsConnectionConfig& kmsConnectionConfig)
      override {
    return std::make_shared<KmsClientBase>();
  }
};
} // namespace bytedance::bolt::parquet
