/*
 * Copyright (c) Facebook, Inc. and its affiliates.
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

#include <thrift/protocol/TCompactProtocol.h> //@manual
#include "bolt/dwio/parquet/decryption/ParquetFileDecryptor.h"
#include "bolt/dwio/parquet/thrift/ThriftTransport.h"

namespace bytedance::bolt::parquet::thrift {
class ThriftDeserializer {
 public:
  ThriftDeserializer() {}

  template <class T>
  bool DeserializeMessage(
      const uint8_t* buf,
      uint32_t* len,
      T* deserialized_msg,
      const std::shared_ptr<decryption::Decryptor>& decryptor,
      bool print = false) {
    // BOLT_CHECK_NE(decryptor, nullptr);
    uint32_t clen;
    clen = *len;
    // decrypt
    int64_t allocateSize = clen - decryptor->ciphertextSizeDelta();
    uint8_t* decrypted_buffer =
        reinterpret_cast<uint8_t*>(decryptor->pool()->allocate(allocateSize));
    auto decryptBufferGuard = folly::makeGuard(
        [&]() { decryptor->pool()->free(decrypted_buffer, allocateSize); });
    const uint8_t* cipher_buf = buf;
    uint32_t decrypted_buffer_len =
        decryptor->decrypt(cipher_buf, 0, decrypted_buffer, allocateSize);
    if (decrypted_buffer_len <= 0) {
      return false;
    }
    *len = decrypted_buffer_len + decryptor->ciphertextSizeDelta();
    DeserializeUnencryptedMessage(
        decrypted_buffer, &decrypted_buffer_len, deserialized_msg);
    return true;
  }

  template <class T>
  void DeserializeUnencryptedMessage(
      const uint8_t* buf,
      uint32_t* len,
      T* deserialized_msg) {
    std::shared_ptr<thrift::ThriftTransport> thriftTransport =
        std::make_shared<thrift::ThriftBufferedTransport>(buf, *len);
    auto thriftProtocol = std::make_unique<
        apache::thrift::protocol::TCompactProtocolT<thrift::ThriftTransport>>(
        thriftTransport);

    *len = deserialized_msg->read(thriftProtocol.get());
  }
};

} // namespace bytedance::bolt::parquet::thrift
