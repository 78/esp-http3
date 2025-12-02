/**
 * @file quic_frame.cc
 * @brief QUIC Frame Building and Parsing Implementation
 */

#include "quic/quic_frame.h"
#include "quic/quic_varint.h"

#include <cstring>

namespace esp_http3 {
namespace quic {

//=============================================================================
// Frame Building
//=============================================================================

bool BuildPaddingFrame(BufferWriter* writer, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!writer->WriteUint8(frame::kPadding)) {
            return false;
        }
    }
    return true;
}

bool BuildPingFrame(BufferWriter* writer) {
    return writer->WriteUint8(frame::kPing);
}

bool BuildAckFrame(BufferWriter* writer,
                   uint64_t largest_ack,
                   uint64_t ack_delay,
                   uint64_t first_ack_range,
                   const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges) {
    // ACK frame type
    if (!writer->WriteUint8(frame::kAck)) {
        return false;
    }
    
    // Largest Acknowledged
    if (!writer->WriteVarint(largest_ack)) {
        return false;
    }
    
    // ACK Delay (in 2^ack_delay_exponent microseconds, we use exponent=3)
    if (!writer->WriteVarint(ack_delay >> 3)) {
        return false;
    }
    
    // ACK Range Count
    if (!writer->WriteVarint(ack_ranges.size())) {
        return false;
    }
    
    // First ACK Range
    if (!writer->WriteVarint(first_ack_range)) {
        return false;
    }
    
    // Additional ACK Ranges
    for (const auto& range : ack_ranges) {
        // Gap
        if (!writer->WriteVarint(range.first)) {
            return false;
        }
        // ACK Range
        if (!writer->WriteVarint(range.second)) {
            return false;
        }
    }
    
    return true;
}

bool BuildCryptoFrame(BufferWriter* writer,
                      uint64_t offset,
                      const uint8_t* data,
                      size_t len) {
    // CRYPTO frame type
    if (!writer->WriteUint8(frame::kCrypto)) {
        return false;
    }
    
    // Offset
    if (!writer->WriteVarint(offset)) {
        return false;
    }
    
    // Length
    if (!writer->WriteVarint(len)) {
        return false;
    }
    
    // Data
    if (!writer->WriteBytes(data, len)) {
        return false;
    }
    
    return true;
}

bool BuildStreamFrame(BufferWriter* writer,
                      uint64_t stream_id,
                      uint64_t offset,
                      const uint8_t* data,
                      size_t len,
                      bool fin) {
    // STREAM frame type with flags
    // 0x08 = STREAM base
    // 0x01 = FIN
    // 0x02 = LEN (we always include length)
    // 0x04 = OFF (include if offset > 0)
    uint8_t frame_type = 0x08 | 0x02;  // Always include length
    if (fin) {
        frame_type |= 0x01;
    }
    if (offset > 0) {
        frame_type |= 0x04;
    }
    
    if (!writer->WriteUint8(frame_type)) {
        return false;
    }
    
    // Stream ID
    if (!writer->WriteVarint(stream_id)) {
        return false;
    }
    
    // Offset (if present)
    if (offset > 0) {
        if (!writer->WriteVarint(offset)) {
            return false;
        }
    }
    
    // Length
    if (!writer->WriteVarint(len)) {
        return false;
    }
    
    // Data
    if (len > 0 && !writer->WriteBytes(data, len)) {
        return false;
    }
    
    return true;
}

bool BuildResetStreamFrame(BufferWriter* writer,
                           uint64_t stream_id,
                           uint64_t error_code,
                           uint64_t final_size) {
    // RESET_STREAM frame type (0x04)
    if (!writer->WriteUint8(frame::kResetStream)) {
        return false;
    }
    
    // Stream ID
    if (!writer->WriteVarint(stream_id)) {
        return false;
    }
    
    // Application Protocol Error Code
    if (!writer->WriteVarint(error_code)) {
        return false;
    }
    
    // Final Size
    if (!writer->WriteVarint(final_size)) {
        return false;
    }
    
    return true;
}

bool BuildStopSendingFrame(BufferWriter* writer,
                           uint64_t stream_id,
                           uint64_t error_code) {
    // STOP_SENDING frame type (0x05)
    if (!writer->WriteUint8(frame::kStopSending)) {
        return false;
    }
    
    // Stream ID
    if (!writer->WriteVarint(stream_id)) {
        return false;
    }
    
    // Application Protocol Error Code
    if (!writer->WriteVarint(error_code)) {
        return false;
    }
    
    return true;
}

bool BuildMaxDataFrame(BufferWriter* writer, uint64_t max_data) {
    if (!writer->WriteUint8(frame::kMaxData)) {
        return false;
    }
    return writer->WriteVarint(max_data);
}

bool BuildMaxStreamDataFrame(BufferWriter* writer,
                              uint64_t stream_id,
                              uint64_t max_stream_data) {
    if (!writer->WriteUint8(frame::kMaxStreamData)) {
        return false;
    }
    if (!writer->WriteVarint(stream_id)) {
        return false;
    }
    return writer->WriteVarint(max_stream_data);
}

bool BuildMaxStreamsFrame(BufferWriter* writer,
                          uint64_t max_streams,
                          bool bidi) {
    uint8_t ft = bidi ? frame::kMaxStreamsBidi : frame::kMaxStreamsUni;
    if (!writer->WriteUint8(ft)) {
        return false;
    }
    return writer->WriteVarint(max_streams);
}

bool BuildConnectionCloseFrame(BufferWriter* writer,
                                uint64_t error_code,
                                uint64_t frame_type,
                                const std::string& reason) {
    if (!writer->WriteUint8(frame::kConnectionClose)) {
        return false;
    }
    if (!writer->WriteVarint(error_code)) {
        return false;
    }
    if (!writer->WriteVarint(frame_type)) {
        return false;
    }
    if (!writer->WriteVarint(reason.size())) {
        return false;
    }
    if (!reason.empty()) {
        if (!writer->WriteBytes(reinterpret_cast<const uint8_t*>(reason.data()),
                                 reason.size())) {
            return false;
        }
    }
    return true;
}

bool BuildApplicationCloseFrame(BufferWriter* writer,
                                 uint64_t error_code,
                                 const std::string& reason) {
    if (!writer->WriteUint8(frame::kConnectionCloseApp)) {
        return false;
    }
    if (!writer->WriteVarint(error_code)) {
        return false;
    }
    if (!writer->WriteVarint(reason.size())) {
        return false;
    }
    if (!reason.empty()) {
        if (!writer->WriteBytes(reinterpret_cast<const uint8_t*>(reason.data()),
                                 reason.size())) {
            return false;
        }
    }
    return true;
}

bool BuildHandshakeDoneFrame(BufferWriter* writer) {
    return writer->WriteUint8(frame::kHandshakeDone);
}

bool BuildNewConnectionIdFrame(BufferWriter* writer,
                                uint64_t sequence_number,
                                uint64_t retire_prior_to,
                                const ConnectionId& connection_id,
                                const uint8_t* stateless_reset_token) {
    if (!writer->WriteUint8(frame::kNewConnectionId)) {
        return false;
    }
    if (!writer->WriteVarint(sequence_number)) {
        return false;
    }
    if (!writer->WriteVarint(retire_prior_to)) {
        return false;
    }
    if (!writer->WriteUint8(connection_id.length)) {
        return false;
    }
    if (!writer->WriteBytes(connection_id.Data(), connection_id.Length())) {
        return false;
    }
    if (!writer->WriteBytes(stateless_reset_token, 16)) {
        return false;
    }
    return true;
}

bool BuildRetireConnectionIdFrame(BufferWriter* writer,
                                   uint64_t sequence_number) {
    if (!writer->WriteUint8(frame::kRetireConnectionId)) {
        return false;
    }
    return writer->WriteVarint(sequence_number);
}

bool BuildPathChallengeFrame(BufferWriter* writer, const uint8_t* data) {
    if (!writer->WriteUint8(frame::kPathChallenge)) {
        return false;
    }
    return writer->WriteBytes(data, 8);
}

bool BuildPathResponseFrame(BufferWriter* writer, const uint8_t* data) {
    if (!writer->WriteUint8(frame::kPathResponse)) {
        return false;
    }
    return writer->WriteBytes(data, 8);
}

bool BuildDatagramFrame(BufferWriter* writer, const uint8_t* data, size_t len,
                         bool include_length) {
    // DATAGRAM frame type: 0x30 (no length) or 0x31 (with length)
    uint8_t frame_type = include_length ? frame::kDatagramLen : frame::kDatagram;
    if (!writer->WriteUint8(frame_type)) {
        return false;
    }
    
    // Optional length field
    if (include_length) {
        if (!writer->WriteVarint(len)) {
            return false;
        }
    }
    
    // Data
    return writer->WriteBytes(data, len);
}

//=============================================================================
// Frame Parsing
//=============================================================================

size_t ParsePaddingFrames(BufferReader* reader) {
    size_t count = 0;
    while (reader->Remaining() > 0) {
        const uint8_t* current = reader->Current();
        if (*current != 0x00) {
            break;
        }
        reader->Skip(1);
        count++;
    }
    return count;
}

bool ParseAckFrame(BufferReader* reader, AckFrameData* out) {
    if (!reader->ReadVarint(&out->largest_ack)) {
        return false;
    }
    if (!reader->ReadVarint(&out->ack_delay)) {
        return false;
    }
    
    uint64_t range_count;
    if (!reader->ReadVarint(&range_count)) {
        return false;
    }
    
    if (!reader->ReadVarint(&out->first_ack_range)) {
        return false;
    }
    
    out->ack_ranges.clear();
    for (uint64_t i = 0; i < range_count; i++) {
        uint64_t gap, range;
        if (!reader->ReadVarint(&gap)) {
            return false;
        }
        if (!reader->ReadVarint(&range)) {
            return false;
        }
        out->ack_ranges.push_back({gap, range});
    }
    
    return true;
}

bool ParseAckEcnFrame(BufferReader* reader, AckFrameData* out) {
    if (!ParseAckFrame(reader, out)) {
        return false;
    }
    
    out->ecn_present = true;
    if (!reader->ReadVarint(&out->ect0_count)) {
        return false;
    }
    if (!reader->ReadVarint(&out->ect1_count)) {
        return false;
    }
    if (!reader->ReadVarint(&out->ecn_ce_count)) {
        return false;
    }
    
    return true;
}

bool ParseCryptoFrame(BufferReader* reader, CryptoFrameData* out) {
    if (!reader->ReadVarint(&out->offset)) {
        return false;
    }
    
    uint64_t length;
    if (!reader->ReadVarint(&length)) {
        return false;
    }
    
    if (reader->Remaining() < length) {
        return false;
    }
    
    out->data = reader->Current();
    out->length = static_cast<size_t>(length);
    reader->Skip(length);
    
    return true;
}

bool ParseStreamFrame(BufferReader* reader, uint8_t frame_type, StreamFrameData* out) {
    // Decode flags from frame type
    bool has_offset = (frame_type & 0x04) != 0;
    bool has_length = (frame_type & 0x02) != 0;
    out->fin = (frame_type & 0x01) != 0;
    
    // Stream ID
    if (!reader->ReadVarint(&out->stream_id)) {
        return false;
    }
    
    // Offset (if present)
    if (has_offset) {
        if (!reader->ReadVarint(&out->offset)) {
            return false;
        }
    } else {
        out->offset = 0;
    }
    
    // Length (if present, else consume rest of packet)
    if (has_length) {
        uint64_t length;
        if (!reader->ReadVarint(&length)) {
            return false;
        }
        if (reader->Remaining() < length) {
            return false;
        }
        out->length = static_cast<size_t>(length);
    } else {
        out->length = reader->Remaining();
    }
    
    out->data = reader->Current();
    reader->Skip(out->length);
    
    return true;
}

bool ParseConnectionCloseFrame(BufferReader* reader,
                                bool is_application,
                                ConnectionCloseData* out) {
    out->is_application = is_application;
    
    if (!reader->ReadVarint(&out->error_code)) {
        return false;
    }
    
    if (!is_application) {
        if (!reader->ReadVarint(&out->frame_type)) {
            return false;
        }
    } else {
        out->frame_type = 0;
    }
    
    uint64_t reason_len;
    if (!reader->ReadVarint(&reason_len)) {
        return false;
    }
    
    if (reader->Remaining() < reason_len) {
        return false;
    }
    
    if (reason_len > 0) {
        out->reason.assign(reinterpret_cast<const char*>(reader->Current()),
                           static_cast<size_t>(reason_len));
        reader->Skip(reason_len);
    }
    
    return true;
}

bool ParseMaxDataFrame(BufferReader* reader, uint64_t* max_data) {
    return reader->ReadVarint(max_data);
}

bool ParseMaxStreamDataFrame(BufferReader* reader,
                              uint64_t* stream_id,
                              uint64_t* max_stream_data) {
    if (!reader->ReadVarint(stream_id)) {
        return false;
    }
    return reader->ReadVarint(max_stream_data);
}

bool ParseMaxStreamsFrame(BufferReader* reader, uint64_t* max_streams) {
    return reader->ReadVarint(max_streams);
}

bool ParseNewConnectionIdFrame(BufferReader* reader,
                                uint64_t* sequence_number,
                                uint64_t* retire_prior_to,
                                ConnectionId* connection_id,
                                uint8_t* stateless_reset_token) {
    if (!reader->ReadVarint(sequence_number)) {
        return false;
    }
    if (!reader->ReadVarint(retire_prior_to)) {
        return false;
    }
    
    uint8_t cid_len;
    if (!reader->ReadUint8(&cid_len)) {
        return false;
    }
    
    if (cid_len > kMaxConnectionIdLen || reader->Remaining() < cid_len + 16) {
        return false;
    }
    
    uint8_t cid_data[kMaxConnectionIdLen];
    if (!reader->ReadBytes(cid_data, cid_len)) {
        return false;
    }
    connection_id->Set(cid_data, cid_len);
    
    if (!reader->ReadBytes(stateless_reset_token, 16)) {
        return false;
    }
    
    return true;
}

bool ParseHandshakeDoneFrame(BufferReader* reader) {
    (void)reader;  // No content to parse
    return true;
}

//=============================================================================
// Transport Parameters
//=============================================================================

size_t BuildTransportParameters(const TransportParameters& params,
                                 uint8_t* out, size_t out_len) {
    BufferWriter writer(out, out_len);
    
    // Helper to write a parameter
    auto write_param = [&writer](uint64_t id, uint64_t value) -> bool {
        if (!writer.WriteVarint(id)) return false;
        
        // Calculate value size
        size_t value_size = VarintEncodedSize(value);
        if (!writer.WriteVarint(value_size)) return false;
        if (!writer.WriteVarint(value)) return false;
        return true;
    };
    
    // initial_max_stream_data_bidi_local (0x05)
    if (params.initial_max_stream_data_bidi_local > 0) {
        if (!write_param(0x05, params.initial_max_stream_data_bidi_local)) {
            return 0;
        }
    }
    
    // initial_max_stream_data_bidi_remote (0x06)
    if (params.initial_max_stream_data_bidi_remote > 0) {
        if (!write_param(0x06, params.initial_max_stream_data_bidi_remote)) {
            return 0;
        }
    }
    
    // initial_max_stream_data_uni (0x07)
    if (params.initial_max_stream_data_uni > 0) {
        if (!write_param(0x07, params.initial_max_stream_data_uni)) {
            return 0;
        }
    }
    
    // initial_max_data (0x04)
    if (params.initial_max_data > 0) {
        if (!write_param(0x04, params.initial_max_data)) {
            return 0;
        }
    }
    
    // initial_max_streams_bidi (0x08)
    if (params.initial_max_streams_bidi > 0) {
        if (!write_param(0x08, params.initial_max_streams_bidi)) {
            return 0;
        }
    }
    
    // initial_max_streams_uni (0x09)
    if (params.initial_max_streams_uni > 0) {
        if (!write_param(0x09, params.initial_max_streams_uni)) {
            return 0;
        }
    }
    
    // max_idle_timeout (0x01)
    if (params.max_idle_timeout > 0) {
        if (!write_param(0x01, params.max_idle_timeout)) {
            return 0;
        }
    }
    
    // max_udp_payload_size (0x03)
    if (params.max_udp_payload_size != 65527) {
        if (!write_param(0x03, params.max_udp_payload_size)) {
            return 0;
        }
    }
    
    // ack_delay_exponent (0x0a)
    if (params.ack_delay_exponent != 3) {
        if (!write_param(0x0a, params.ack_delay_exponent)) {
            return 0;
        }
    }
    
    // max_ack_delay (0x0b)
    if (params.max_ack_delay != 25) {
        if (!write_param(0x0b, params.max_ack_delay)) {
            return 0;
        }
    }
    
    // active_connection_id_limit (0x0e)
    if (params.active_connection_id_limit != 2) {
        if (!write_param(0x0e, params.active_connection_id_limit)) {
            return 0;
        }
    }
    
    // initial_source_connection_id (0x0f)
    if (!params.initial_source_connection_id.Empty()) {
        if (!writer.WriteVarint(0x0f)) return 0;
        if (!writer.WriteVarint(params.initial_source_connection_id.Length())) return 0;
        if (!writer.WriteBytes(params.initial_source_connection_id.Data(),
                                params.initial_source_connection_id.Length())) {
            return 0;
        }
    }
    
    // max_datagram_frame_size (0x20) - RFC 9221
    if (params.max_datagram_frame_size > 0) {
        if (!write_param(transport_param::kMaxDatagramFrameSize, 
                         params.max_datagram_frame_size)) {
            return 0;
        }
    }
    
    return writer.Offset();
}

bool ParseTransportParameters(const uint8_t* data, size_t len,
                               TransportParameters* out) {
    BufferReader reader(data, len);
    
    while (reader.Remaining() > 0) {
        uint64_t param_id, param_len;
        if (!reader.ReadVarint(&param_id)) {
            return false;
        }
        if (!reader.ReadVarint(&param_len)) {
            return false;
        }
        
        if (reader.Remaining() < param_len) {
            return false;
        }
        
        const uint8_t* param_data = reader.Current();
        BufferReader param_reader(param_data, param_len);
        
        switch (param_id) {
            case 0x00:  // original_destination_connection_id
                out->original_destination_connection_id.Set(param_data, param_len);
                break;
            case 0x01:  // max_idle_timeout
                if (!param_reader.ReadVarint(&out->max_idle_timeout)) {
                    return false;
                }
                break;
            case 0x02:  // stateless_reset_token
                if (param_len != 16) return false;
                std::memcpy(out->stateless_reset_token, param_data, 16);
                out->stateless_reset_token_present = true;
                break;
            case 0x03:  // max_udp_payload_size
                if (!param_reader.ReadVarint(&out->max_udp_payload_size)) {
                    return false;
                }
                break;
            case 0x04:  // initial_max_data
                if (!param_reader.ReadVarint(&out->initial_max_data)) {
                    return false;
                }
                break;
            case 0x05:  // initial_max_stream_data_bidi_local
                if (!param_reader.ReadVarint(&out->initial_max_stream_data_bidi_local)) {
                    return false;
                }
                break;
            case 0x06:  // initial_max_stream_data_bidi_remote
                if (!param_reader.ReadVarint(&out->initial_max_stream_data_bidi_remote)) {
                    return false;
                }
                break;
            case 0x07:  // initial_max_stream_data_uni
                if (!param_reader.ReadVarint(&out->initial_max_stream_data_uni)) {
                    return false;
                }
                break;
            case 0x08:  // initial_max_streams_bidi
                if (!param_reader.ReadVarint(&out->initial_max_streams_bidi)) {
                    return false;
                }
                break;
            case 0x09:  // initial_max_streams_uni
                if (!param_reader.ReadVarint(&out->initial_max_streams_uni)) {
                    return false;
                }
                break;
            case 0x0a:  // ack_delay_exponent
                if (!param_reader.ReadVarint(&out->ack_delay_exponent)) {
                    return false;
                }
                break;
            case 0x0b:  // max_ack_delay
                if (!param_reader.ReadVarint(&out->max_ack_delay)) {
                    return false;
                }
                break;
            case 0x0c:  // disable_active_migration
                out->disable_active_migration = true;
                break;
            case 0x0e:  // active_connection_id_limit
                if (!param_reader.ReadVarint(&out->active_connection_id_limit)) {
                    return false;
                }
                break;
            case 0x0f:  // initial_source_connection_id
                out->initial_source_connection_id.Set(param_data, param_len);
                break;
            case 0x10:  // retry_source_connection_id
                out->retry_source_connection_id.Set(param_data, param_len);
                break;
            case 0x20:  // max_datagram_frame_size (RFC 9221)
                if (!param_reader.ReadVarint(&out->max_datagram_frame_size)) {
                    return false;
                }
                break;
            default:
                // Unknown parameter, skip
                break;
        }
        
        reader.Skip(param_len);
    }
    
    return true;
}

} // namespace quic
} // namespace esp_http3

