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

#include "bolt/dwio/parquet/decryption/AesDecryptor.h"

namespace bytedance::bolt::parquet::decryption {

// static void CheckPageOrdinal(int32_t page_ordinal) {
//   if (page_ordinal > std::numeric_limits<int16_t>::max()) {
//     BOLT_FAIL(
//         "Encrypted Parquet files can't have more than {}  pages per chunk: got {}",
//         std::numeric_limits<int16_t>::max(),
//         page_ordinal);
//   }
// }

// static std::string ShortToBytesLe(int16_t input) {
//   int8_t output[2];
//   memset(output, 0, 2);
//   output[1] = static_cast<int8_t>(0xff & (input >> 8));
//   output[0] = static_cast<int8_t>(0xff & (input));
//
//   return std::string(reinterpret_cast<char const*>(output), 2);
// }

// std::string CreateFooterAad(const std::string& aadPrefixBytes) {
//   return CreateModuleAad(
//       aadPrefixBytes,
//       arrow::encryption::kFooter,
//       static_cast<int16_t>(-1),
//       static_cast<int16_t>(-1),
//       static_cast<int16_t>(-1));
// }

// Update last two bytes with new page ordinal (instead of creating new page AAD
// from scratch)
// void QuickUpdatePageAad(int32_t newPageOrdinal, std::string* aad) {
//   CheckPageOrdinal(newPageOrdinal);
//   const std::string pageOrdinalBytes =
//       ShortToBytesLe(static_cast<int16_t>(newPageOrdinal));
//   std::memcpy(aad->data() + aad->length() - 2, pageOrdinalBytes.data(), 2);
// }
//
// std::string CreateModuleAad(
//     const std::string& fileAad,
//     int8_t moduleType,
//     int16_t rowGroupOrdinal,
//     int16_t columnOrdinal,
//     int32_t pageOrdinal) {
//   CheckPageOrdinal(pageOrdinal);
//   const int16_t pageOrdinalShort = static_cast<int16_t>(pageOrdinal);
//   int8_t typeOrdinalBytes[1];
//   typeOrdinalBytes[0] = moduleType;
//   std::string typeOrdinalBytesStr(
//       reinterpret_cast<char const*>(typeOrdinalBytes), 1);
//   if (arrow::encryption::kFooter == moduleType) {
//     std::string result = fileAad + typeOrdinalBytesStr;
//     return result;
//   }
//   std::string rowGroupOrdinalBytes = ShortToBytesLe(rowGroupOrdinal);
//   std::string columnOrdinalBytes = ShortToBytesLe(columnOrdinal);
//   if (arrow::encryption::kDataPage != moduleType &&
//       arrow::encryption::kDataPageHeader != moduleType) {
//     std::ostringstream out;
//     out << fileAad << typeOrdinalBytesStr << rowGroupOrdinalBytes
//         << columnOrdinalBytes;
//     return out.str();
//   }
//   std::string pageOrdinalBytes = ShortToBytesLe(pageOrdinalShort);
//   std::ostringstream out;
//   out << fileAad << typeOrdinalBytesStr << rowGroupOrdinalBytes
//       << columnOrdinalBytes << pageOrdinalBytes;
//   return out.str();
// }

AesDecryptor::AesDecryptor(
    ParquetCipher::type algId,
    bool metadata,
    int32_t maxEncryptedSize,
    const std::string& key,
    const std::string& fileAad,
    const std::string& aad,
    memory::MemoryPool* pool,
    bool containsLength)
    : Decryptor(key, fileAad, aad, pool) {
  if (ParquetCipher::AES_GCM_V1 != algId &&
      ParquetCipher::AES_GCM_CTR_V1 != algId) {
    BOLT_FAIL("Crypto algorithm {} is not supported", algId);
  }

  int keyLen = static_cast<int>(key.size());
  ctx_ = nullptr;
  lengthBufferLength_ = containsLength ? kBufferSizeLength : 0;
  ciphertextSizeDelta_ =
      lengthBufferLength_ + arrow::encryption::kNonceLength;
  if (metadata || (ParquetCipher::AES_GCM_V1 == algId)) {
    aesMode_ = kGcmMode;
    ciphertextSizeDelta_ += arrow::encryption::kGcmTagLength;
  } else {
    aesMode_ = kCtrMode;
  }

  if (16 != keyLen && 24 != keyLen && 32 != keyLen) {
    BOLT_FAIL("Wrong key length: {}", keyLen);
  }

  maxEncryptedSize_ = maxEncryptedSize;

  ctx_ = EVP_CIPHER_CTX_new();
  if (nullptr == ctx_) {
    BOLT_FAIL("Couldn't init decryption context");
  }

  if (kGcmMode == aesMode_) {
    // Init AES-GCM with specified key length
    if (16 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_128_gcm());
    } else if (24 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_192_gcm());
    } else if (32 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_256_gcm());
    }
  } else {
    // Init AES-CTR with specified key length
    if (16 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_128_ctr());
    } else if (24 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_192_ctr());
    } else if (32 == keyLen) {
      DECRYPT_INIT(ctx_, EVP_aes_256_ctr());
    }
  }
  // EVP_CIPHER_CTX_set_padding(ctx_, 0);
}
//
// std::shared_ptr<AesDecryptor> AesDecryptor::Make(
//     ParquetCipher::type alg_id,
//     int key_len,
//     bool metadata,
//     int32_t max_encrypted_size,
//     std::vector<std::weak_ptr<AesDecryptor>>* all_decryptors) {
//   std::shared_ptr<AesDecryptor> decryptor = std::make_shared<AesDecryptor>(
//       alg_id, key_len, metadata, max_encrypted_size);
//
//   if (all_decryptors != nullptr) {
//     all_decryptors->push_back(decryptor);
//   }
//
//   return decryptor;
// }

int AesDecryptor::Decrypt(
    const uint8_t* ciphertext,
    int ciphertextLen,
    uint8_t* plaintext,
    int plaintextLen) const {
  // return Decrypt(      ciphertext,
  //     ciphertext_len,
  //     reinterpret_cast<const uint8_t*>(key_.c_str()),
  //     static_cast<int>(key_.size()),
  //     reinterpret_cast<const uint8_t*>(aad_.c_str()),
  //     static_cast<int>(aad_.size()),
  //     plaintext,
  //     plaintext_len)

  const std::string key = get_key();
  const std::string aad = file_aad();
  const int keyLen = static_cast<int>(key.size());
  const int aadLen = static_cast<int>(aad.size());
  if (kGcmMode == aesMode_) {
    return GcmDecrypt(
        ciphertext,
        ciphertextLen,
        reinterpret_cast<const uint8_t*>(key.c_str()),
        keyLen,
        reinterpret_cast<const uint8_t*>(aad.c_str()),
        aadLen,
        plaintext,
        plaintextLen);
  }

  return CtrDecrypt(
      ciphertext,
      ciphertextLen,
      reinterpret_cast<const uint8_t*>(key.c_str()),
      keyLen,
      plaintext,
      plaintextLen);
}

int AesDecryptor::GcmDecrypt(
    const unsigned char* ciphertext,
    int ciphertextLen,
    const unsigned char* key,
    int keyLen,
    const unsigned char* aad,
    int aadLen,
    unsigned char* plaintext,
    int plaintextLen) const {
  int len;
  int writePlaintextLen;

  uint8_t tag[arrow::encryption::kGcmTagLength];
  memset(tag, 0, arrow::encryption::kGcmTagLength);
  uint8_t nonce[arrow::encryption::kNonceLength];
  memset(nonce, 0, arrow::encryption::kNonceLength);

  if (lengthBufferLength_ > 0) {
    // Extract ciphertext length
    int writtenCiphertextLen = ((ciphertext[3] & 0xff) << 24) |
        ((ciphertext[2] & 0xff) << 16) | ((ciphertext[1] & 0xff) << 8) |
        ((ciphertext[0] & 0xff));

    if (ciphertextLen > 0 &&
        ciphertextLen != (writtenCiphertextLen + lengthBufferLength_)) {
      BOLT_FAIL("Wrong ciphertext length");
    }
    ciphertextLen = writtenCiphertextLen + lengthBufferLength_;
  } else {
    if (ciphertextLen == 0) {
      BOLT_FAIL("Zero ciphertext length");
    }
  }

  auto decryptLen = ciphertextLen - lengthBufferLength_ -
      arrow::encryption::kNonceLength - arrow::encryption::kGcmTagLength;

  BOLT_CHECK(decryptLen <= plaintextLen, "plain text buffer too short");

  // Extracting IV and tag
  std::copy(
      ciphertext + lengthBufferLength_,
      ciphertext + lengthBufferLength_ + arrow::encryption::kNonceLength,
      nonce);
  std::copy(
      ciphertext + ciphertextLen - arrow::encryption::kGcmTagLength,
      ciphertext + ciphertextLen,
      tag);

  auto printError = [&]() {
    {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < keyLen; idx++) {
        out << "\\x" << (static_cast<short>(key[idx]) & 0xff);
      }
      LOG(ERROR) << "decrypt failed key is : " << out.str();
    }

    if (aad != nullptr) {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < aadLen; idx++) {
        out << "\\x" << (static_cast<short>(aad[idx]) & 0xff);
      }
      LOG(ERROR) << "decrypt failed aad is : " << out.str();
    }

    {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < ciphertextLen; idx++) {
        out << "\\x" << (static_cast<short>(ciphertext[idx]) & 0xff);
      }
      LOG(ERROR) << "decrypt failed text is : " << out.str();
    }
  };

  // Setting key and IV
  if (1 != EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key, nonce)) {
    printError();
    BOLT_FAIL("Couldn't set key and IV");
  }

  // Setting additional authenticated data
  if ((nullptr != aad) &&
      (1 != EVP_DecryptUpdate(ctx_, nullptr, &len, aad, aadLen))) {
    printError();
    BOLT_FAIL("Couldn't set AAD");
  }

  // Decryption
  if (!EVP_DecryptUpdate(
          ctx_,
          plaintext,
          &len,
          ciphertext + lengthBufferLength_ + arrow::encryption::kNonceLength,
          decryptLen)) {
    printError();
    BOLT_FAIL("Failed decryption update");
  }

  writePlaintextLen = len;

  // Checking the tag (authentication)
  if (!EVP_CIPHER_CTX_ctrl(
          ctx_, EVP_CTRL_GCM_SET_TAG, arrow::encryption::kGcmTagLength, tag)) {
    printError();
    BOLT_FAIL("Failed authentication");
  }

  // Finalization
  if (1 != EVP_DecryptFinal_ex(ctx_, plaintext + len, &len)) {
    printError();
    BOLT_FAIL("Failed decryption finalization");
  }

  writePlaintextLen += len;
  return writePlaintextLen;
}

int AesDecryptor::CtrDecrypt(
    const unsigned char* ciphertext,
    int ciphertextLen,
    const unsigned char* key,
    int keyLen,
    unsigned char* plaintext,
    int plaintextLen) const {
  int len;
  int writePlaintextLen;

  uint8_t iv[kCtrIvLength];
  memset(iv, 0, kCtrIvLength);

  if (lengthBufferLength_ > 0) {
    // Extract ciphertext length
    int writtenCiphertextLen = ((ciphertext[3] & 0xff) << 24) |
        ((ciphertext[2] & 0xff) << 16) | ((ciphertext[1] & 0xff) << 8) |
        ((ciphertext[0] & 0xff));

    if (ciphertextLen > 0 &&
        ciphertextLen != (writtenCiphertextLen + lengthBufferLength_)) {
      BOLT_FAIL("Wrong ciphertext length");
    }
    ciphertextLen = writtenCiphertextLen;
  } else {
    if (ciphertextLen == 0) {
      BOLT_FAIL("Zero ciphertext length");
    }
  }

  auto decryptLen = ciphertextLen - arrow::encryption::kNonceLength;
  BOLT_CHECK(decryptLen <= plaintextLen, "plain text buffer too short");
  bool left = false;
  if (maxEncryptedSize_ != 0 && decryptLen >= maxEncryptedSize_) {
    left = true;
    decryptLen = maxEncryptedSize_;
  }

  // Extracting nonce
  std::copy(
      ciphertext + lengthBufferLength_,
      ciphertext + lengthBufferLength_ + arrow::encryption::kNonceLength,
      iv);
  // Parquet CTR IVs are comprised of a 12-byte nonce and a 4-byte initial
  // counter field.
  // The first 31 bits of the initial counter field are set to 0, the last bit
  // is set to 1.
  iv[kCtrIvLength - 1] = 1;

  // Setting key and IV
  if (1 != EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key, iv)) {
    BOLT_FAIL("Couldn't set key and IV");
  }

  // Decryption
  if (!EVP_DecryptUpdate(
          ctx_,
          plaintext,
          &len,
          ciphertext + lengthBufferLength_ + arrow::encryption::kNonceLength,
          decryptLen)) {
    BOLT_FAIL("Failed decryption update");
  }

  writePlaintextLen = len;

  // Finalization
  if (1 != EVP_DecryptFinal_ex(ctx_, plaintext + len, &len)) {
    BOLT_FAIL("Failed decryption finalization");
  }

  writePlaintextLen += len;
  if (left) {
    std::copy(
        ciphertext + lengthBufferLength_ + arrow::encryption::kNonceLength +
            decryptLen,
        ciphertext + ciphertextLen + lengthBufferLength_,
        plaintext + writePlaintextLen);
    writePlaintextLen +=
        ciphertextLen - arrow::encryption::kNonceLength - decryptLen;
  }
  return writePlaintextLen;
}

} // namespace bytedance::bolt::parquet::decryption