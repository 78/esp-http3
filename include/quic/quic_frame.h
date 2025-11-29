/**
 * @file quic_frame.h
 * @brief QUIC Frame Building and Parsing (RFC 9000)
 */

#pragma once

#include "quic/quic_types.h"
#include "quic/quic_constants.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace esp_http3 {
namespace quic {

//=============================================================================
// Frame Building
//=============================================================================

/**
 * @brief Build PADDING frame
 * 
 * @param writer Buffer writer
 * @param count Number of padding bytes
 * @return true on success
 */
bool BuildPaddingFrame(BufferWriter* writer, size_t count);

/**
 * @brief Build PING frame
 * 
 * @param writer Buffer writer
 * @return true on success
 */
bool BuildPingFrame(BufferWriter* writer);

/**
 * @brief Build ACK frame
 * 
 * @param writer Buffer writer
 * @param largest_ack Largest acknowledged packet number
 * @param ack_delay ACK delay in microseconds
 * @param first_ack_range First ACK range (packets before largest_ack)
 * @param ack_ranges Additional ACK ranges (gap, ack_range pairs)
 * @return true on success
 */
bool BuildAckFrame(BufferWriter* writer,
                   uint64_t largest_ack,
                   uint64_t ack_delay,
                   uint64_t first_ack_range,
                   const std::vector<std::pair<uint64_t, uint64_t>>& ack_ranges = {});

/**
 * @brief Build CRYPTO frame
 * 
 * @param writer Buffer writer
 * @param offset Offset in crypto stream
 * @param data Crypto data
 * @param len Data length
 * @return true on success
 */
bool BuildCryptoFrame(BufferWriter* writer,
                      uint64_t offset,
                      const uint8_t* data,
                      size_t len);

/**
 * @brief Build STREAM frame
 * 
 * @param writer Buffer writer
 * @param stream_id Stream ID
 * @param offset Offset in stream (0 means no offset field)
 * @param data Stream data
 * @param len Data length
 * @param fin FIN flag
 * @return true on success
 */
bool BuildStreamFrame(BufferWriter* writer,
                      uint64_t stream_id,
                      uint64_t offset,
                      const uint8_t* data,
                      size_t len,
                      bool fin);

/**
 * @brief Build MAX_DATA frame
 * 
 * @param writer Buffer writer
 * @param max_data Maximum data value
 * @return true on success
 */
bool BuildMaxDataFrame(BufferWriter* writer, uint64_t max_data);

/**
 * @brief Build MAX_STREAM_DATA frame
 * 
 * @param writer Buffer writer
 * @param stream_id Stream ID
 * @param max_stream_data Maximum stream data value
 * @return true on success
 */
bool BuildMaxStreamDataFrame(BufferWriter* writer,
                              uint64_t stream_id,
                              uint64_t max_stream_data);

/**
 * @brief Build MAX_STREAMS frame
 * 
 * @param writer Buffer writer
 * @param max_streams Maximum streams
 * @param bidi True for bidirectional, false for unidirectional
 * @return true on success
 */
bool BuildMaxStreamsFrame(BufferWriter* writer,
                          uint64_t max_streams,
                          bool bidi);

/**
 * @brief Build CONNECTION_CLOSE frame (QUIC layer)
 * 
 * @param writer Buffer writer
 * @param error_code QUIC error code
 * @param frame_type Frame type that triggered the error (0 if N/A)
 * @param reason Reason phrase
 * @return true on success
 */
bool BuildConnectionCloseFrame(BufferWriter* writer,
                                uint64_t error_code,
                                uint64_t frame_type,
                                const std::string& reason = "");

/**
 * @brief Build CONNECTION_CLOSE frame (Application layer)
 * 
 * @param writer Buffer writer
 * @param error_code Application error code
 * @param reason Reason phrase
 * @return true on success
 */
bool BuildApplicationCloseFrame(BufferWriter* writer,
                                 uint64_t error_code,
                                 const std::string& reason = "");

/**
 * @brief Build HANDSHAKE_DONE frame
 * 
 * @param writer Buffer writer
 * @return true on success
 */
bool BuildHandshakeDoneFrame(BufferWriter* writer);

/**
 * @brief Build NEW_CONNECTION_ID frame
 * 
 * @param writer Buffer writer
 * @param sequence_number Sequence number
 * @param retire_prior_to Retire Prior To value
 * @param connection_id Connection ID
 * @param stateless_reset_token Stateless reset token (16 bytes)
 * @return true on success
 */
bool BuildNewConnectionIdFrame(BufferWriter* writer,
                                uint64_t sequence_number,
                                uint64_t retire_prior_to,
                                const ConnectionId& connection_id,
                                const uint8_t* stateless_reset_token);

/**
 * @brief Build RETIRE_CONNECTION_ID frame
 * 
 * @param writer Buffer writer
 * @param sequence_number Sequence number to retire
 * @return true on success
 */
bool BuildRetireConnectionIdFrame(BufferWriter* writer,
                                   uint64_t sequence_number);

/**
 * @brief Build PATH_CHALLENGE frame
 * 
 * @param writer Buffer writer
 * @param data 8-byte challenge data
 * @return true on success
 */
bool BuildPathChallengeFrame(BufferWriter* writer, const uint8_t* data);

/**
 * @brief Build PATH_RESPONSE frame
 * 
 * @param writer Buffer writer
 * @param data 8-byte response data (same as challenge)
 * @return true on success
 */
bool BuildPathResponseFrame(BufferWriter* writer, const uint8_t* data);

//=============================================================================
// Frame Parsing
//=============================================================================

/**
 * @brief Parsed ACK frame data
 */
struct AckFrameData {
    uint64_t largest_ack = 0;
    uint64_t ack_delay = 0;
    uint64_t first_ack_range = 0;
    std::vector<std::pair<uint64_t, uint64_t>> ack_ranges;  // (gap, range)
    bool ecn_present = false;
    uint64_t ect0_count = 0;
    uint64_t ect1_count = 0;
    uint64_t ecn_ce_count = 0;
};

/**
 * @brief Parsed CRYPTO frame data
 */
struct CryptoFrameData {
    uint64_t offset = 0;
    const uint8_t* data = nullptr;
    size_t length = 0;
};

/**
 * @brief Parsed STREAM frame data
 */
struct StreamFrameData {
    uint64_t stream_id = 0;
    uint64_t offset = 0;
    const uint8_t* data = nullptr;
    size_t length = 0;
    bool fin = false;
};

/**
 * @brief Parsed CONNECTION_CLOSE frame data
 */
struct ConnectionCloseData {
    bool is_application = false;
    uint64_t error_code = 0;
    uint64_t frame_type = 0;
    std::string reason;
};

/**
 * @brief Parse PADDING frames (skip them)
 * 
 * @param reader Buffer reader
 * @return Number of padding bytes skipped
 */
size_t ParsePaddingFrames(BufferReader* reader);

/**
 * @brief Parse ACK frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param out Output data
 * @return true on success
 */
bool ParseAckFrame(BufferReader* reader, AckFrameData* out);

/**
 * @brief Parse ACK frame with ECN
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param out Output data
 * @return true on success
 */
bool ParseAckEcnFrame(BufferReader* reader, AckFrameData* out);

/**
 * @brief Parse CRYPTO frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param out Output data
 * @return true on success
 */
bool ParseCryptoFrame(BufferReader* reader, CryptoFrameData* out);

/**
 * @brief Parse STREAM frame
 * 
 * @param reader Buffer reader (positioned after frame type byte)
 * @param frame_type The frame type byte (to determine flags)
 * @param out Output data
 * @return true on success
 */
bool ParseStreamFrame(BufferReader* reader, uint8_t frame_type, StreamFrameData* out);

/**
 * @brief Parse CONNECTION_CLOSE frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param is_application True if APPLICATION_CLOSE (0x1d)
 * @param out Output data
 * @return true on success
 */
bool ParseConnectionCloseFrame(BufferReader* reader,
                                bool is_application,
                                ConnectionCloseData* out);

/**
 * @brief Parse MAX_DATA frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param max_data Output value
 * @return true on success
 */
bool ParseMaxDataFrame(BufferReader* reader, uint64_t* max_data);

/**
 * @brief Parse MAX_STREAM_DATA frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param stream_id Output stream ID
 * @param max_stream_data Output value
 * @return true on success
 */
bool ParseMaxStreamDataFrame(BufferReader* reader,
                              uint64_t* stream_id,
                              uint64_t* max_stream_data);

/**
 * @brief Parse MAX_STREAMS frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param max_streams Output value
 * @return true on success
 */
bool ParseMaxStreamsFrame(BufferReader* reader, uint64_t* max_streams);

/**
 * @brief Parse NEW_CONNECTION_ID frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @param sequence_number Output sequence number
 * @param retire_prior_to Output retire prior to
 * @param connection_id Output connection ID
 * @param stateless_reset_token Output token (16 bytes)
 * @return true on success
 */
bool ParseNewConnectionIdFrame(BufferReader* reader,
                                uint64_t* sequence_number,
                                uint64_t* retire_prior_to,
                                ConnectionId* connection_id,
                                uint8_t* stateless_reset_token);

/**
 * @brief Parse HANDSHAKE_DONE frame
 * 
 * @param reader Buffer reader (positioned after frame type)
 * @return true (frame has no content)
 */
bool ParseHandshakeDoneFrame(BufferReader* reader);

//=============================================================================
// Transport Parameters
//=============================================================================

/**
 * @brief QUIC Transport Parameters
 */
struct TransportParameters {
    // Required for client
    uint64_t max_idle_timeout = 0;
    uint64_t max_udp_payload_size = 65527;
    uint64_t initial_max_data = 0;
    uint64_t initial_max_stream_data_bidi_local = 0;
    uint64_t initial_max_stream_data_bidi_remote = 0;
    uint64_t initial_max_stream_data_uni = 0;
    uint64_t initial_max_streams_bidi = 0;
    uint64_t initial_max_streams_uni = 0;
    uint64_t ack_delay_exponent = 3;
    uint64_t max_ack_delay = 25;
    bool disable_active_migration = false;
    uint64_t active_connection_id_limit = 2;
    
    // Server-provided
    ConnectionId original_destination_connection_id;
    ConnectionId initial_source_connection_id;
    ConnectionId retry_source_connection_id;
    uint8_t stateless_reset_token[16] = {0};
    bool stateless_reset_token_present = false;
};

/**
 * @brief Build Transport Parameters extension
 * 
 * @param params Parameters to encode
 * @param out Output buffer
 * @param out_len Output length
 * @return Size written, or 0 on failure
 */
size_t BuildTransportParameters(const TransportParameters& params,
                                 uint8_t* out, size_t out_len);

/**
 * @brief Parse Transport Parameters extension
 * 
 * @param data Input data
 * @param len Data length
 * @param out Output parameters
 * @return true on success
 */
bool ParseTransportParameters(const uint8_t* data, size_t len,
                               TransportParameters* out);

} // namespace quic
} // namespace esp_http3

