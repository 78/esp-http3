/**
 * @file quic_types.cc
 * @brief QUIC Types Implementation
 */

#include "quic/quic_types.h"
#include "quic/quic_varint.h"

#include <esp_timer.h>

namespace esp_http3 {
namespace quic {

bool BufferWriter::WriteVarint(uint64_t value) {
    size_t encoded_size = VarintEncodedSize(value);
    if (offset_ + encoded_size > capacity_) {
        return false;
    }
    size_t written = EncodeVarint(value, buffer_ + offset_, capacity_ - offset_);
    if (written == 0) {
        return false;
    }
    offset_ += written;
    return true;
}

bool BufferReader::ReadVarint(uint64_t* out) {
    size_t consumed = DecodeVarint(data_ + offset_, len_ - offset_, out);
    if (consumed == 0) {
        return false;
    }
    offset_ += consumed;
    return true;
}

uint64_t GetCurrentTimeUs() {
    return static_cast<uint64_t>(esp_timer_get_time());
}

} // namespace quic
} // namespace esp_http3

