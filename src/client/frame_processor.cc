/**
 * @file frame_processor.cc
 * @brief QUIC Frame Processor Implementation
 */

#include "client/frame_processor.h"
#include "quic/quic_frame.h"

#include <esp_log.h>

namespace esp_http3 {

static const char* TAG = "FrameProcessor";

// Helper to get packet type string for logging
static const char* GetPacketTypeStr(quic::PacketType pkt_type) {
    switch (pkt_type) {
        case quic::PacketType::kInitial: return "Initial";
        case quic::PacketType::kHandshake: return "Handshake";
        case quic::PacketType::k0Rtt: return "0-RTT";
        case quic::PacketType::k1Rtt: return "1-RTT";
        default: return "Unknown";
    }
}

//=============================================================================
// Constructor
//=============================================================================

FrameProcessor::FrameProcessor() = default;

//=============================================================================
// Main Processing Entry Point
//=============================================================================

bool FrameProcessor::ProcessPayload(const uint8_t* data, size_t len,
                                     quic::PacketType pkt_type) {
    quic::BufferReader reader(data, len);
    ack_eliciting_count_ = 0;
    
    const char* pkt_type_str = GetPacketTypeStr(pkt_type);
    
    while (reader.Remaining() > 0) {
        uint8_t frame_type;
        if (!reader.ReadUint8(&frame_type)) {
            break;
        }
        
        // PADDING (0x00)
        if (frame_type == 0x00) {
            // Skip consecutive padding bytes
            quic::ParsePaddingFrames(&reader);
            continue;
        }
        
        // PING (0x01)
        if (frame_type == 0x01) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: PING", pkt_type_str);
            }
            if (on_ping_) {
                on_ping_();
            }
            continue;
        }
        
        // ACK (0x02) or ACK_ECN (0x03)
        if (frame_type == 0x02 || frame_type == 0x03) {
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: ACK%s", pkt_type_str, 
                         frame_type == 0x03 ? "_ECN" : "");
            }
            ParseAckFrame(&reader, frame_type == 0x03);
            continue;
        }
        
        // RESET_STREAM (0x04)
        if (frame_type == 0x04) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: RESET_STREAM", pkt_type_str);
            }
            ParseResetStreamFrame(&reader);
            continue;
        }
        
        // STOP_SENDING (0x05)
        if (frame_type == 0x05) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: STOP_SENDING", pkt_type_str);
            }
            ParseStopSendingFrame(&reader);
            continue;
        }
        
        // CRYPTO (0x06)
        if (frame_type == 0x06) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: CRYPTO", pkt_type_str);
            }
            ParseCryptoFrame(&reader);
            continue;
        }
        
        // NEW_TOKEN (0x07)
        if (frame_type == 0x07) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: NEW_TOKEN", pkt_type_str);
            }
            ParseNewTokenFrame(&reader);
            continue;
        }
        
        // STREAM (0x08-0x0f)
        if (frame_type >= 0x08 && frame_type <= 0x0f) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: STREAM (type=0x%02x)", pkt_type_str, frame_type);
            }
            ParseStreamFrame(&reader, frame_type);
            continue;
        }
        
        // MAX_DATA (0x10)
        if (frame_type == 0x10) {
            ack_eliciting_count_++;
            uint64_t max_data;
            if (reader.ReadVarint(&max_data)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: MAX_DATA = %llu", pkt_type_str,
                             (unsigned long long)max_data);
                }
                if (on_max_data_) {
                    on_max_data_(max_data);
                }
            }
            continue;
        }
        
        // MAX_STREAM_DATA (0x11)
        if (frame_type == 0x11) {
            ack_eliciting_count_++;
            uint64_t stream_id, max_stream_data;
            if (reader.ReadVarint(&stream_id) && reader.ReadVarint(&max_stream_data)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: MAX_STREAM_DATA stream=%llu, max=%llu",
                             pkt_type_str, (unsigned long long)stream_id,
                             (unsigned long long)max_stream_data);
                }
                if (on_max_stream_data_) {
                    on_max_stream_data_(stream_id, max_stream_data);
                }
            }
            continue;
        }
        
        // MAX_STREAMS (0x12=bidi, 0x13=uni)
        if (frame_type == 0x12 || frame_type == 0x13) {
            ack_eliciting_count_++;
            uint64_t max_streams;
            if (reader.ReadVarint(&max_streams)) {
                bool is_bidi = (frame_type == 0x12);
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: MAX_STREAMS_%s = %llu", pkt_type_str,
                             is_bidi ? "BIDI" : "UNI", (unsigned long long)max_streams);
                }
                if (on_max_streams_) {
                    on_max_streams_(max_streams, is_bidi);
                }
            }
            continue;
        }
        
        // DATA_BLOCKED (0x14)
        if (frame_type == 0x14) {
            ack_eliciting_count_++;
            uint64_t limit;
            if (reader.ReadVarint(&limit)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: DATA_BLOCKED at %llu", pkt_type_str,
                             (unsigned long long)limit);
                }
                if (on_data_blocked_) {
                    on_data_blocked_(limit);
                }
            }
            continue;
        }
        
        // STREAM_DATA_BLOCKED (0x15)
        if (frame_type == 0x15) {
            ack_eliciting_count_++;
            uint64_t stream_id, limit;
            if (reader.ReadVarint(&stream_id) && reader.ReadVarint(&limit)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: STREAM_DATA_BLOCKED stream=%llu, limit=%llu",
                             pkt_type_str, (unsigned long long)stream_id,
                             (unsigned long long)limit);
                }
                if (on_stream_data_blocked_) {
                    on_stream_data_blocked_(stream_id, limit);
                }
            }
            continue;
        }
        
        // STREAMS_BLOCKED (0x16=bidi, 0x17=uni)
        if (frame_type == 0x16 || frame_type == 0x17) {
            ack_eliciting_count_++;
            uint64_t limit;
            if (reader.ReadVarint(&limit)) {
                bool is_bidi = (frame_type == 0x16);
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: STREAMS_BLOCKED_%s at %llu", pkt_type_str,
                             is_bidi ? "BIDI" : "UNI", (unsigned long long)limit);
                }
                if (on_streams_blocked_) {
                    on_streams_blocked_(limit, is_bidi);
                }
            }
            continue;
        }
        
        // NEW_CONNECTION_ID (0x18)
        if (frame_type == 0x18) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: NEW_CONNECTION_ID", pkt_type_str);
            }
            ParseNewConnectionIdFrame(&reader);
            continue;
        }
        
        // RETIRE_CONNECTION_ID (0x19)
        if (frame_type == 0x19) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: RETIRE_CONNECTION_ID", pkt_type_str);
            }
            ParseRetireConnectionIdFrame(&reader);
            continue;
        }
        
        // PATH_CHALLENGE (0x1a)
        if (frame_type == 0x1a) {
            ack_eliciting_count_++;
            uint8_t path_data[8];
            if (reader.ReadBytes(path_data, 8)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: PATH_CHALLENGE", pkt_type_str);
                }
                if (on_path_challenge_) {
                    on_path_challenge_(path_data);
                }
            }
            continue;
        }
        
        // PATH_RESPONSE (0x1b)
        if (frame_type == 0x1b) {
            ack_eliciting_count_++;
            uint8_t path_data[8];
            if (reader.ReadBytes(path_data, 8)) {
                if (debug_) {
                    ESP_LOGI(TAG, "[%s] Frame: PATH_RESPONSE", pkt_type_str);
                }
                if (on_path_response_) {
                    on_path_response_(path_data);
                }
            }
            continue;
        }
        
        // CONNECTION_CLOSE (0x1c=QUIC, 0x1d=App)
        if (frame_type == 0x1c || frame_type == 0x1d) {
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: CONNECTION_CLOSE%s", pkt_type_str,
                         frame_type == 0x1d ? " (App)" : "");
            }
            ParseConnectionCloseFrame(&reader, frame_type == 0x1d);
            continue;
        }
        
        // HANDSHAKE_DONE (0x1e)
        if (frame_type == 0x1e) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: HANDSHAKE_DONE", pkt_type_str);
            }
            if (on_handshake_done_) {
                on_handshake_done_();
            }
            continue;
        }
        
        // DATAGRAM (0x30=no length, 0x31=with length)
        if (frame_type == 0x30 || frame_type == 0x31) {
            ack_eliciting_count_++;
            if (debug_) {
                ESP_LOGI(TAG, "[%s] Frame: DATAGRAM", pkt_type_str);
            }
            ParseDatagramFrame(&reader, frame_type == 0x31);
            continue;
        }
        
        // Unknown frame type
        if (debug_) {
            ESP_LOGW(TAG, "[%s] Unknown frame type: 0x%02x at offset %zu, remaining=%zu",
                     pkt_type_str, frame_type, reader.Offset() - 1, reader.Remaining());
        }
        // Cannot safely skip unknown frames, must stop processing
        break;
    }
    
    return ack_eliciting_count_ > 0;
}

//=============================================================================
// Individual Frame Parsers
//=============================================================================

size_t FrameProcessor::ParseAckFrame(quic::BufferReader* reader, bool has_ecn) {
    AckFrameData ack_data;
    
    // Parse using existing quic::ParseAckFrame
    quic::AckFrameData raw_ack;
    bool ok = has_ecn ? 
              quic::ParseAckEcnFrame(reader, &raw_ack) :
              quic::ParseAckFrame(reader, &raw_ack);
    
    if (!ok) {
        return 0;
    }
    
    // Copy to our data structure
    ack_data.largest_ack = raw_ack.largest_ack;
    ack_data.ack_delay = raw_ack.ack_delay;
    ack_data.first_ack_range = raw_ack.first_ack_range;
    ack_data.ack_ranges = raw_ack.ack_ranges;
    ack_data.ect0_count = raw_ack.ect0_count;
    ack_data.ect1_count = raw_ack.ect1_count;
    ack_data.ecn_ce_count = raw_ack.ecn_ce_count;
    
    if (on_ack_) {
        on_ack_(ack_data);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseCryptoFrame(quic::BufferReader* reader) {
    quic::CryptoFrameData crypto_data;
    if (!quic::ParseCryptoFrame(reader, &crypto_data)) {
        return 0;
    }
    
    if (on_crypto_) {
        on_crypto_(crypto_data.offset, crypto_data.data, crypto_data.length);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseStreamFrame(quic::BufferReader* reader, uint8_t frame_type) {
    quic::StreamFrameData stream_data;
    if (!quic::ParseStreamFrame(reader, frame_type, &stream_data)) {
        return 0;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  STREAM: id=%llu, offset=%llu, len=%zu, fin=%d",
                 (unsigned long long)stream_data.stream_id,
                 (unsigned long long)stream_data.offset,
                 stream_data.length, stream_data.fin ? 1 : 0);
    }
    
    if (on_stream_) {
        on_stream_(stream_data.stream_id, stream_data.offset,
                   stream_data.data, stream_data.length, stream_data.fin);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseResetStreamFrame(quic::BufferReader* reader) {
    ResetStreamData data;
    if (!reader->ReadVarint(&data.stream_id) ||
        !reader->ReadVarint(&data.error_code) ||
        !reader->ReadVarint(&data.final_size)) {
        return 0;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  RESET_STREAM: stream=%llu, error=%llu, final_size=%llu",
                 (unsigned long long)data.stream_id,
                 (unsigned long long)data.error_code,
                 (unsigned long long)data.final_size);
    }
    
    if (on_reset_stream_) {
        on_reset_stream_(data);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseStopSendingFrame(quic::BufferReader* reader) {
    StopSendingData data;
    if (!reader->ReadVarint(&data.stream_id) ||
        !reader->ReadVarint(&data.error_code)) {
        return 0;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  STOP_SENDING: stream=%llu, error=%llu",
                 (unsigned long long)data.stream_id,
                 (unsigned long long)data.error_code);
    }
    
    if (on_stop_sending_) {
        on_stop_sending_(data);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseNewConnectionIdFrame(quic::BufferReader* reader) {
    NewConnectionIdData data;
    uint8_t cid_len;
    
    if (!reader->ReadVarint(&data.sequence_number) ||
        !reader->ReadVarint(&data.retire_prior_to) ||
        !reader->ReadUint8(&cid_len) ||
        cid_len > 20) {
        return 0;
    }
    
    data.connection_id.length = cid_len;
    if (!reader->ReadBytes(data.connection_id.data.data(), cid_len) ||
        !reader->ReadBytes(data.stateless_reset_token, 16)) {
        return 0;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  NEW_CONNECTION_ID: seq=%llu, retire_prior=%llu, cid_len=%u",
                 (unsigned long long)data.sequence_number,
                 (unsigned long long)data.retire_prior_to, cid_len);
    }
    
    if (on_new_connection_id_) {
        on_new_connection_id_(data);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseRetireConnectionIdFrame(quic::BufferReader* reader) {
    uint64_t sequence_number;
    if (!reader->ReadVarint(&sequence_number)) {
        return 0;
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  RETIRE_CONNECTION_ID: seq=%llu",
                 (unsigned long long)sequence_number);
    }
    
    if (on_retire_connection_id_) {
        on_retire_connection_id_(sequence_number);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseConnectionCloseFrame(quic::BufferReader* reader, bool is_app) {
    ConnectionCloseData data;
    data.is_application = is_app;
    
    if (!reader->ReadVarint(&data.error_code)) {
        return 0;
    }
    
    // QUIC-level close has frame type field
    if (!is_app) {
        if (!reader->ReadVarint(&data.frame_type)) {
            return 0;
        }
    }
    
    // Reason phrase
    uint64_t reason_len;
    if (!reader->ReadVarint(&reason_len)) {
        return 0;
    }
    
    if (reason_len > 0 && reason_len <= reader->Remaining()) {
        const uint8_t* reason_data = reader->Current();
        reader->Skip(reason_len);
        data.reason.assign(reinterpret_cast<const char*>(reason_data), reason_len);
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  CONNECTION_CLOSE: error=%llu, reason=%s",
                 (unsigned long long)data.error_code, data.reason.c_str());
    }
    
    if (on_connection_close_) {
        on_connection_close_(data);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseNewTokenFrame(quic::BufferReader* reader) {
    uint64_t token_len;
    if (!reader->ReadVarint(&token_len) || token_len > reader->Remaining()) {
        return 0;
    }
    
    const uint8_t* token = reader->Current();
    reader->Skip(token_len);
    
    if (debug_) {
        ESP_LOGI(TAG, "  NEW_TOKEN: len=%llu", (unsigned long long)token_len);
    }
    
    if (on_new_token_) {
        on_new_token_(token, token_len);
    }
    
    return reader->Offset();
}

size_t FrameProcessor::ParseDatagramFrame(quic::BufferReader* reader, bool has_length) {
    const uint8_t* data;
    size_t len;
    
    if (has_length) {
        uint64_t data_len;
        if (!reader->ReadVarint(&data_len) || data_len > reader->Remaining()) {
            return 0;
        }
        data = reader->Current();
        len = data_len;
        reader->Skip(data_len);
    } else {
        // No length field, data extends to end of packet
        data = reader->Current();
        len = reader->Remaining();
        reader->Skip(len);
    }
    
    if (debug_) {
        ESP_LOGI(TAG, "  DATAGRAM: len=%zu", len);
    }
    
    if (on_datagram_) {
        on_datagram_(data, len);
    }
    
    return reader->Offset();
}

} // namespace esp_http3

