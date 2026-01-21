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

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "bolt/common/base/Exceptions.h"
#include "bolt/common/memory/Memory.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/decryption/AesDecryptor.h"

using namespace bytedance::bolt;

namespace parquet_arrow_encryption =
    bytedance::bolt::parquet::arrow::encryption;
namespace parquet_decryption = bytedance::bolt::parquet::decryption;

namespace {

const uint8_t* bytesOrNull(const std::string& s) {
  return s.empty() ? nullptr : reinterpret_cast<const uint8_t*>(s.data());
}

std::vector<uint8_t> toBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> encryptWithArrowAesEncryptor(
    ParquetCipher::type algorithm,
    bool metadata,
    bool writeLength,
    const std::vector<uint8_t>& plaintext,
    const std::string& key,
    const std::string& moduleAad) {
  parquet_arrow_encryption::AesEncryptor encryptor(
      algorithm, static_cast<int>(key.size()), metadata, writeLength);

  std::vector<uint8_t> ciphertext(
      plaintext.size() + encryptor.CiphertextSizeDelta());
  int writtenLen = encryptor.Encrypt(
      plaintext.data(),
      static_cast<int>(plaintext.size()),
      bytesOrNull(key),
      static_cast<int>(key.size()),
      bytesOrNull(moduleAad),
      static_cast<int>(moduleAad.size()),
      ciphertext.data());

  ciphertext.resize(writtenLen);
  return ciphertext;
}

} // namespace

TEST(AesDecryptorTest, GcmRoundTripUsesModuleAad) {
  const std::string key(16, 'k');
  const std::string fileAad(8, 'f');
  const std::string moduleAad =
      parquet_arrow_encryption::CreateFooterAad(fileAad);

  const auto plaintext = toBytes(std::string("hello\0world", 11));
  const auto ciphertext = encryptWithArrowAesEncryptor(
      ParquetCipher::AES_GCM_V1, true, true, plaintext, key, moduleAad);

  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  parquet_decryption::AesDecryptor decryptor(
      ParquetCipher::AES_GCM_V1,
      true,
      key,
      fileAad,
      moduleAad,
      pool.get(),
      true);

  std::vector<uint8_t> decrypted(plaintext.size());
  const int decryptedLen = decryptor.decrypt(
      ciphertext.data(),
      static_cast<int>(ciphertext.size()),
      decrypted.data(),
      static_cast<int>(decrypted.size()));

  ASSERT_EQ(decryptedLen, static_cast<int>(plaintext.size()));
  EXPECT_EQ(decrypted, plaintext);

  parquet_decryption::AesDecryptor wrongAadDecryptor(
      ParquetCipher::AES_GCM_V1,
      true,
      key,
      fileAad,
      moduleAad + "x",
      pool.get(),
      true);
  EXPECT_THROW(
      wrongAadDecryptor.decrypt(
          ciphertext.data(),
          static_cast<int>(ciphertext.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      BoltRuntimeError);

  auto tampered = ciphertext;
  tampered.back() ^= 0x01;
  EXPECT_THROW(
      decryptor.decrypt(
          tampered.data(),
          static_cast<int>(tampered.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      BoltRuntimeError);
}

TEST(AesDecryptorTest, UpdateAadAffectsGcmDecryption) {
  const std::string key(16, 'k');
  const std::string fileAad(8, 'f');
  const std::string aad1 = parquet_arrow_encryption::CreateFooterAad(fileAad);
  const std::string aad2 = aad1 + "x";
  const auto plaintext = toBytes("payload");

  const auto ciphertext = encryptWithArrowAesEncryptor(
      ParquetCipher::AES_GCM_V1, true, true, plaintext, key, aad1);

  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  parquet_decryption::AesDecryptor decryptor(
      ParquetCipher::AES_GCM_V1, true, key, fileAad, aad1, pool.get(), true);

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_EQ(
      decryptor.decrypt(
          ciphertext.data(),
          static_cast<int>(ciphertext.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      static_cast<int>(plaintext.size()));
  EXPECT_EQ(decrypted, plaintext);

  decryptor.updateAad(aad2);
  EXPECT_THROW(
      decryptor.decrypt(
          ciphertext.data(),
          static_cast<int>(ciphertext.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      BoltRuntimeError);
}

TEST(AesDecryptorTest, InvalidKeyLengthThrows) {
  const std::string key(15, 'k');
  const std::string fileAad(8, 'f');
  const std::string moduleAad =
      parquet_arrow_encryption::CreateFooterAad(fileAad);

  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  EXPECT_THROW(
      parquet_decryption::AesDecryptor(
          ParquetCipher::AES_GCM_V1, true, key, fileAad, moduleAad, pool.get()),
      BoltRuntimeError);
}
