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


AesDecryptor::AesDecryptor(
    ::parquet::ParquetCipher::type alg_id,
    int key_len,
    bool metadata,
    int32_t max_encrypted_size,
    bool contains_length) {
  
  if (::parquet::ParquetCipher::AES_GCM_V1 != alg_id &&
    ::parquet::ParquetCipher::AES_GCM_CTR_V1 != alg_id) {
    BOLT_FAIL("Crypto algorithm {} is not supported", alg_id);
    }
  
  ctx_ = nullptr;
  length_buffer_length_ = contains_length ? kBufferSizeLength : 0;
  ciphertext_size_delta_ = length_buffer_length_ + kNonceLength;
  if (metadata || (::parquet::ParquetCipher::AES_GCM_V1 == alg_id)) {
    aes_mode_ = kGcmMode;
    ciphertext_size_delta_ += kGcmTagLength;
  } else {
    aes_mode_ = kCtrMode;
  }

  if (16 != key_len && 24 != key_len && 32 != key_len) {
    BOLT_FAIL("Wrong key length: {}", key_len);
  }

  key_length_ = key_len;
  max_encrypted_size_ = max_encrypted_size;

  ctx_ = EVP_CIPHER_CTX_new();
  if (nullptr == ctx_) {
    BOLT_FAIL("Couldn't init decryption context");
  }

  if (kGcmMode == aes_mode_) {
    // Init AES-GCM with specified key length
    if (16 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_128_gcm());
    } else if (24 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_192_gcm());
    } else if (32 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_256_gcm());
    }
  } else {
    // Init AES-CTR with specified key length
    if (16 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_128_ctr());
    } else if (24 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_192_ctr());
    } else if (32 == key_len) {
      DECRYPT_INIT(ctx_, EVP_aes_256_ctr());
    }
  }
  // EVP_CIPHER_CTX_set_padding(ctx_, 0);
}

std::shared_ptr<AesDecryptor> AesDecryptor::Make(
    ::parquet::ParquetCipher::type alg_id,
    int key_len,
    bool metadata,
    int32_t max_encrypted_size,
    std::vector<std::weak_ptr<AesDecryptor>>* all_decryptors) {

  std::shared_ptr<AesDecryptor> decryptor = std::make_shared<AesDecryptor>(
      alg_id, key_len, metadata, max_encrypted_size);

  if (all_decryptors != nullptr) {
    all_decryptors->push_back(decryptor);
  }
  
  return decryptor;
}

int AesDecryptor::Decrypt(
    const unsigned char* ciphertext,
    int ciphertext_len,
    const unsigned char* key,
    int key_len,
    const unsigned char* aad,
    int aad_len,
    unsigned char* plaintext,
    int plaintext_len) {
  if (key_length_ != key_len) {
    BOLT_FAIL("Wrong key length {}. Should be {}", key_len, key_length_);
  }

  if (kGcmMode == aes_mode_) {
    return GcmDecrypt(
        ciphertext,
        ciphertext_len,
        key,
        key_len,
        aad,
        aad_len,
        plaintext,
        plaintext_len);
  }

  return CtrDecrypt(
      ciphertext, ciphertext_len, key, key_len, plaintext, plaintext_len);
}

int AesDecryptor::GcmDecrypt(
    const unsigned char* ciphertext,
    int ciphertext_len,
    const unsigned char* key,
    int key_len,
    const unsigned char* aad,
    int aad_len,
    unsigned char* plaintext,
    int plaintext_len) {
  int len;
  int write_plaintext_len;

  uint8_t tag[kGcmTagLength];
  memset(tag, 0, kGcmTagLength);
  uint8_t nonce[kNonceLength];
  memset(nonce, 0, kNonceLength);

  if (length_buffer_length_ > 0) {
    // Extract ciphertext length
    int written_ciphertext_len = ((ciphertext[3] & 0xff) << 24) |
        ((ciphertext[2] & 0xff) << 16) | ((ciphertext[1] & 0xff) << 8) |
        ((ciphertext[0] & 0xff));

    if (ciphertext_len > 0 &&
        ciphertext_len != (written_ciphertext_len + length_buffer_length_)) {
      BOLT_FAIL("Wrong ciphertext length");
    }
    ciphertext_len = written_ciphertext_len + length_buffer_length_;
  } else {
    if (ciphertext_len == 0) {
      BOLT_FAIL("Zero ciphertext length");
    }
  }

  auto decrypt_len =
      ciphertext_len - length_buffer_length_ - kNonceLength - kGcmTagLength;

  BOLT_CHECK(decrypt_len <= plaintext_len, "plain text buffer too short");

  // Extracting IV and tag
  std::copy(
      ciphertext + length_buffer_length_,
      ciphertext + length_buffer_length_ + kNonceLength,
      nonce);
  std::copy(
      ciphertext + ciphertext_len - kGcmTagLength,
      ciphertext + ciphertext_len,
      tag);

  auto printError = [&]() {
    {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < key_len; idx++) {
        out << "\\x" << (static_cast<short>(key[idx]) & 0xff);
      }
      LOG(ERROR) << "decrypt failed key is : " << out.str();
    }

    if (aad != nullptr) {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < aad_len; idx++) {
        out << "\\x" << (static_cast<short>(aad[idx]) & 0xff);
      }
      LOG(ERROR) << "decrypt failed aad is : " << out.str();
    }

    {
      std::stringstream out;
      out << std::hex;
      for (auto idx = 0; idx < ciphertext_len; idx++) {
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
      (1 != EVP_DecryptUpdate(ctx_, nullptr, &len, aad, aad_len))) {
    printError();
    BOLT_FAIL("Couldn't set AAD");
  }

  // Decryption
  if (!EVP_DecryptUpdate(
          ctx_,
          plaintext,
          &len,
          ciphertext + length_buffer_length_ + kNonceLength,
          decrypt_len)) {
    printError();
    BOLT_FAIL("Failed decryption update");
  }

  write_plaintext_len = len;

  // Checking the tag (authentication)
  if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kGcmTagLength, tag)) {
    printError();
    BOLT_FAIL("Failed authentication");
  }

  // Finalization
  if (1 != EVP_DecryptFinal_ex(ctx_, plaintext + len, &len)) {
    printError();
    BOLT_FAIL("Failed decryption finalization");
  }

  write_plaintext_len += len;
  return write_plaintext_len;
}

int AesDecryptor::CtrDecrypt(
    const unsigned char* ciphertext,
    int ciphertext_len,
    const unsigned char* key,
    int key_len,
    unsigned char* plaintext,
    int plaintext_len) {
  int len;
  int write_plaintext_len;

  uint8_t iv[kCtrIvLength];
  memset(iv, 0, kCtrIvLength);

  if (length_buffer_length_ > 0) {
    // Extract ciphertext length
    int written_ciphertext_len = ((ciphertext[3] & 0xff) << 24) |
        ((ciphertext[2] & 0xff) << 16) | ((ciphertext[1] & 0xff) << 8) |
        ((ciphertext[0] & 0xff));

    if (ciphertext_len > 0 &&
        ciphertext_len != (written_ciphertext_len + length_buffer_length_)) {
      BOLT_FAIL("Wrong ciphertext length");
    }
    ciphertext_len = written_ciphertext_len;
  } else {
    if (ciphertext_len == 0) {
      BOLT_FAIL("Zero ciphertext length");
    }
  }

  auto decrypt_len = ciphertext_len - kNonceLength;
  BOLT_CHECK(decrypt_len <= plaintext_len, "plain text buffer too short");
  bool left = false;
  if (max_encrypted_size_ != 0 && decrypt_len >= max_encrypted_size_) {
    left = true;
    decrypt_len = max_encrypted_size_;
  }

  // Extracting nonce
  std::copy(
      ciphertext + length_buffer_length_,
      ciphertext + length_buffer_length_ + kNonceLength,
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
          ciphertext + length_buffer_length_ + kNonceLength,
          decrypt_len)) {
    BOLT_FAIL("Failed decryption update");
  }

  write_plaintext_len = len;

  // Finalization
  if (1 != EVP_DecryptFinal_ex(ctx_, plaintext + len, &len)) {
    BOLT_FAIL("Failed decryption finalization");
  }

  write_plaintext_len += len;
  if (left) {
    std::copy(
        ciphertext + length_buffer_length_ + kNonceLength + decrypt_len,
        ciphertext + ciphertext_len + length_buffer_length_,
        plaintext + write_plaintext_len);
    write_plaintext_len += ciphertext_len - kNonceLength - decrypt_len;
  }
  return write_plaintext_len;
}


} //bytedance::bolt::parquet::decryption