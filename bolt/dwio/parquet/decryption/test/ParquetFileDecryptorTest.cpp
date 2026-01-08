#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "bolt/common/base/Exceptions.h"
#include "bolt/common/memory/Memory.h"
#include "bolt/dwio/parquet/arrow/Encryption.h"
#include "bolt/dwio/parquet/arrow/EncryptionInternal.h"
#include "bolt/dwio/parquet/decryption/ParquetFileDecryptor.h"

using namespace bytedance::bolt;

namespace parquet_arrow = bytedance::bolt::parquet::arrow;
namespace parquet_arrow_encryption =
    bytedance::bolt::parquet::arrow::encryption;
namespace parquet_decryption = bytedance::bolt::parquet::decryption;

namespace {

const uint8_t* bytesOrNull(const std::string& s) {
  return s.empty() ? nullptr : reinterpret_cast<const uint8_t*>(s.data());
}

std::vector<uint8_t> encryptGcm(
    const std::vector<uint8_t>& plaintext,
    const std::string& key,
    const std::string& moduleAad) {
  parquet_arrow_encryption::AesEncryptor encryptor(
      ParquetCipher::AES_GCM_V1, static_cast<int>(key.size()), true, true);
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

std::vector<uint8_t> toBytes(const std::string& s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

} // namespace

TEST(ParquetFileDecryptorTest, FooterDecryptorDecryptsAndCaches) {
  const std::string footerKey(16, 'k');
  const std::string fileAad(8, 'f');
  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  auto properties = parquet_arrow::FileDecryptionProperties::Builder()
                        .footer_key(footerKey)
                        ->build();

  parquet_decryption::InternalFileDecryptor fileDecryptor(
      properties.get(), fileAad, ParquetCipher::AES_GCM_V1, "", pool.get());

  auto decryptor1 = fileDecryptor.GetFooterDecryptor();
  ASSERT_NE(decryptor1, nullptr);
  auto decryptor2 = fileDecryptor.GetFooterDecryptor();
  ASSERT_NE(decryptor2, nullptr);
  EXPECT_EQ(decryptor1.get(), decryptor2.get());

  const std::string moduleAad =
      parquet_arrow_encryption::CreateFooterAad(fileAad);
  const auto plaintext = toBytes(std::string("footer\0data", 11));
  const auto ciphertext = encryptGcm(plaintext, footerKey, moduleAad);

  std::vector<uint8_t> decrypted(plaintext.size());
  const int decryptedLen = decryptor1->Decrypt(
      ciphertext.data(),
      static_cast<int>(ciphertext.size()),
      decrypted.data(),
      static_cast<int>(decrypted.size()));

  ASSERT_EQ(decryptedLen, static_cast<int>(plaintext.size()));
  EXPECT_EQ(decrypted, plaintext);
}

TEST(ParquetFileDecryptorTest, ColumnMetaDecryptorCachesAndUpdatesAad) {
  const std::string footerKey(16, 'k');
  const std::string columnKey(16, 'c');
  const std::string fileAad(8, 'f');
  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  parquet_arrow::ColumnPathToDecryptionPropertiesMap columnKeys;
  columnKeys["col"] = parquet_arrow::ColumnDecryptionProperties::Builder("col")
                          .key(columnKey)
                          ->build();

  auto properties = parquet_arrow::FileDecryptionProperties::Builder()
                        .footer_key(footerKey)
                        ->column_keys(columnKeys)
                        ->build();

  parquet_decryption::InternalFileDecryptor fileDecryptor(
      properties.get(), fileAad, ParquetCipher::AES_GCM_V1, "", pool.get());

  const std::string aad1 = parquet_arrow_encryption::CreateFooterAad(fileAad);
  const std::string aad2 = aad1 + "x";

  auto decryptor1 = fileDecryptor.GetColumnMetaDecryptor("col", "", aad1);
  ASSERT_NE(decryptor1, nullptr);

  const auto plaintext = toBytes("payload");
  const auto ciphertext = encryptGcm(plaintext, columnKey, aad1);
  std::vector<uint8_t> decrypted(plaintext.size());

  EXPECT_EQ(
      decryptor1->Decrypt(
          ciphertext.data(),
          static_cast<int>(ciphertext.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      static_cast<int>(plaintext.size()));
  EXPECT_EQ(decrypted, plaintext);

  auto decryptor2 = fileDecryptor.GetColumnMetaDecryptor("col", "", aad2);
  ASSERT_NE(decryptor2, nullptr);
  EXPECT_EQ(decryptor1.get(), decryptor2.get());

  EXPECT_THROW(
      decryptor2->Decrypt(
          ciphertext.data(),
          static_cast<int>(ciphertext.size()),
          decrypted.data(),
          static_cast<int>(decrypted.size())),
      BoltRuntimeError);
}

TEST(ParquetFileDecryptorTest, MissingColumnKeyThrows) {
  const std::string footerKey(16, 'k');
  const std::string fileAad(8, 'f');
  auto pool = memory::deprecatedAddDefaultLeafMemoryPool(
      "bolt_dwio_parquet_decryption_test");

  auto properties = parquet_arrow::FileDecryptionProperties::Builder()
                        .footer_key(footerKey)
                        ->build();

  parquet_decryption::InternalFileDecryptor fileDecryptor(
      properties.get(), fileAad, ParquetCipher::AES_GCM_V1, "", pool.get());

  EXPECT_THROW(
      fileDecryptor.GetColumnDataDecryptor("missing", "", "aad"),
      BoltRuntimeError);
}
