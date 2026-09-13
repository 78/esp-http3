// The runner extracts these connection methods from production source. Packet
// encryption and socket I/O are stubbed; frame/ACK/tracker/flow logic is real.
#include "core/ack_manager.h"
#include "core/loss_detector.h"
#include "core/flow_controller.h"
#include "quic/quic_frame.h"
#include "quic/quic_packet.h"
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <esp_log.h>

namespace esp_http3::memory {
void* Allocate(size_t size, size_t) noexcept { return std::malloc(size); }
void Deallocate(void* p) noexcept { std::free(p); }
bool UsesPsram() noexcept { return false; }
}
namespace esp_http3 {
static bool fail_packet_build = false;
static std::vector<std::vector<uint8_t>> built_payloads;
namespace quic {
static size_t CapturePacket(const uint8_t* payload, size_t len, uint8_t* out,
                            size_t capacity, size_t overhead) {
    if (fail_packet_build || len + overhead > capacity) return 0;
    built_payloads.emplace_back(payload, payload + len);
    std::memset(out, 0, len + overhead);
    return len + overhead;
}
size_t Build1RttPacket(const ConnectionId& dcid, uint64_t, bool, bool,
                       const uint8_t* payload, size_t len, const CryptoSecrets&,
                       uint8_t* out, size_t capacity) {
    return CapturePacket(payload, len, out, capacity, 1 + dcid.Length() + 4 + 16);
}
size_t BuildHandshakePacket(const ConnectionId&, const ConnectionId&, uint64_t,
                            const uint8_t* payload, size_t len, const CryptoSecrets&,
                            uint8_t* out, size_t capacity) {
    return CapturePacket(payload, len, out, capacity, 48);
}
size_t BuildInitialPacket(const ConnectionId&, const ConnectionId&, const uint8_t*,
                          size_t, uint64_t, const uint8_t* payload, size_t len,
                          const CryptoSecrets&, uint8_t* out, size_t capacity, size_t) {
    return CapturePacket(payload, len, out, capacity, 48);
}
}
enum class ConnectionState { kHandshakeInProgress, kConnected };
class QuicConnection {
public:
    class Impl;
};
class QuicConnection::Impl {
public:
    struct TestCrypto {
        quic::CryptoSecrets secrets;
        bool HasApplicationKeys() const { return true; }
        bool HasHandshakeKeys() const { return true; }
        int GetKeyPhase() const { return 0; }
        const quic::CryptoSecrets& GetClientAppSecrets() const { return secrets; }
        const quic::CryptoSecrets& GetClientHandshakeSecrets() const { return secrets; }
        const quic::CryptoSecrets& GetClientInitialSecrets() const { return secrets; }
        bool BuildClientFinished(uint8_t* out, size_t* length) {
            *length = 36;
            std::memset(out, 0xab, *length);
            return true;
        }
        void UpdateTranscript(const uint8_t*, size_t) {}
    } crypto_;
    struct { bool enable_debug = false; } config_;
    struct BatchState {
        bool active = false;
        quic::BufferWriter* writer = nullptr;
        struct StreamFrameInfo { uint64_t stream_id; size_t frame_start; size_t frame_len; };
        std::vector<StreamFrameInfo> stream_frames;
        Http3Vector<uint8_t> control_frames;
        void Reset() { active = false; writer = nullptr; stream_frames.clear(); control_frames.clear(); }
    } batch_state_;
    AckManager app_ack_mgr_, handshake_ack_mgr_, initial_ack_mgr_;
    SentPacketTracker app_tracker_, handshake_tracker_, initial_tracker_;
    FlowController flow_controller_;
    LossDetector loss_detector_;
    quic::ConnectionId dcid_, scid_;
    quic::TransportParameters peer_params_;
    Http3Vector<uint8_t> packet_buf_ = Http3Vector<uint8_t>(1500);
    Http3Vector<uint8_t> frame_buf_ = Http3Vector<uint8_t>(1500);
    Http3Vector<uint8_t> batch_frames_ = Http3Vector<uint8_t>(1500);
    Http3Vector<uint8_t> retry_token_;
    uint64_t current_time_us_ = 1100;
    ConnectionState state_ = ConnectionState::kHandshakeInProgress;
    bool handshake_complete_ = false;
    bool send_success = true;
    size_t send_count = 0;
    std::function<void()> on_send;
    Impl() { dcid_.length = 8; }
    ~Impl() { delete batch_state_.writer; }
    bool SendPacket(const uint8_t*, size_t len) {
        assert(len <= packet_buf_.size());
        ++send_count;
        if (on_send) on_send();
        return send_success;
    }
    void BeginBatch();
    bool EndBatch();
    bool SendStreamData(uint64_t, const uint8_t*, size_t, bool);
    void HandlePto();
    bool SendClientFinished();
    bool SendAckIfNeeded(quic::PacketType);
    void SendCoalescedAcks();
    void SendInitialPacket(bool) { assert(false); }
    void SendHandshakePtoProbe() { assert(false); }
    void SendPtoProbe() { assert(false); }
};
#include "connection_methods.inc"
}
using namespace esp_http3;
static void FillSparse(AckManager& ack) {
    for (uint64_t pn = 0; pn < 512; pn += 2) ack.OnPacketReceived(pn, 1000);
}
static void CheckAck(quic::BufferReader& reader) {
    uint8_t type;
    quic::AckFrameData ack;
    assert(reader.ReadUint8(&type) && type == quic::frame::kAck);
    assert(quic::ParseAckFrame(&reader, &ack));
    assert(ack.largest_ack == 510);
    assert(!ack.ack_ranges.empty());
    assert(reader.Remaining() == 0);
}
static void CheckStreamAndAck(const std::vector<uint8_t>& payload) {
    quic::BufferReader reader(payload.data(), payload.size());
    uint8_t type;
    quic::StreamFrameData stream;
    assert(reader.ReadUint8(&type));
    assert(quic::ParseStreamFrame(&reader, type, &stream));
    assert(stream.stream_id == 4 && stream.offset == 0 && stream.length == 1200);
    for (size_t i = 0; i < stream.length; ++i) assert(stream.data[i] == 0x5a);
    CheckAck(reader);
}
static void TestStream() {
    QuicConnection::Impl connection;
    FillSparse(connection.app_ack_mgr_);
    uint8_t payload[1200];
    std::memset(payload, 0x5a, sizeof(payload));
    connection.on_send = [&] { assert(connection.app_ack_mgr_.HasPendingAck()); };
    assert(connection.SendStreamData(4, payload, sizeof(payload), false));
    CheckStreamAndAck(built_payloads.back());
    assert(!connection.app_ack_mgr_.HasPendingAck());
    auto packets = connection.app_tracker_.GetUnackedPackets();
    assert(packets.size() == 1 && packets[0]->frames.size() == 1204);
}
static void TestPto() {
    QuicConnection::Impl connection;
    FillSparse(connection.handshake_ack_mgr_);
    connection.on_send = [&] { assert(connection.handshake_ack_mgr_.HasPendingAck()); };
    connection.HandlePto();
    assert(connection.send_count == 1);
    auto& payload = built_payloads.back();
    quic::BufferReader reader(payload.data(), payload.size());
    uint8_t type;
    assert(reader.ReadUint8(&type) && type == quic::frame::kPing);
    CheckAck(reader);
    assert(!connection.handshake_ack_mgr_.HasPendingAck());
}
static void TestBatch() {
    QuicConnection::Impl connection;
    FillSparse(connection.app_ack_mgr_);
    uint8_t payload[1200];
    std::memset(payload, 0x5a, sizeof(payload));
    connection.on_send = [&] { assert(connection.app_ack_mgr_.HasPendingAck()); };
    connection.BeginBatch();
    assert(connection.app_ack_mgr_.HasPendingAck());
    assert(connection.SendStreamData(4, payload, sizeof(payload), false));
    assert(connection.EndBatch());
    CheckStreamAndAck(built_payloads.back());
    assert(!connection.app_ack_mgr_.HasPendingAck());
    auto packets = connection.app_tracker_.GetUnackedPackets();
    assert(packets.size() == 1 && packets[0]->frames.size() == 1204);
}
static void TestFinished() {
    QuicConnection::Impl connection;
    FillSparse(connection.handshake_ack_mgr_);
    FillSparse(connection.initial_ack_mgr_);
    connection.on_send = [&] {
        assert(connection.handshake_ack_mgr_.HasPendingAck());
        assert(connection.initial_ack_mgr_.HasPendingAck());
    };
    assert(connection.SendClientFinished());
    auto& payload = built_payloads.back();
    quic::BufferReader reader(payload.data(), payload.size());
    uint8_t type;
    quic::CryptoFrameData crypto;
    assert(reader.ReadUint8(&type) && type == quic::frame::kCrypto);
    assert(quic::ParseCryptoFrame(&reader, &crypto));
    assert(crypto.length == 36);
    CheckAck(reader);
    assert(!connection.handshake_ack_mgr_.HasPendingAck());
    assert(!connection.initial_ack_mgr_.HasPendingAck());
}
static void TestFailedSends() {
    for (int build_failure = 0; build_failure < 2; ++build_failure) {
        fail_packet_build = build_failure;
        for (int path = 0; path < 6; ++path) {
            QuicConnection::Impl connection;
            connection.send_success = false;
            FillSparse(connection.app_ack_mgr_);
            FillSparse(connection.handshake_ack_mgr_);
            FillSparse(connection.initial_ack_mgr_);
            uint8_t payload = 0;
            switch (path) {
                case 0: assert(!connection.SendStreamData(4, &payload, 1, false)); break;
                case 1: connection.HandlePto(); break;
                case 2: assert(!connection.SendClientFinished()); break;
                case 3: assert(!connection.SendAckIfNeeded(quic::PacketType::k1Rtt)); break;
                case 4: connection.SendCoalescedAcks(); break;
                case 5:
                    connection.BeginBatch();
                    assert(connection.SendStreamData(4, &payload, 1, false));
                    assert(!connection.EndBatch());
                    break;
            }
            assert(connection.app_ack_mgr_.HasPendingAck());
            assert(connection.handshake_ack_mgr_.HasPendingAck());
            assert(connection.initial_ack_mgr_.HasPendingAck());
        }
    }
    fail_packet_build = false;
}
int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "all";
    if (!std::strcmp(mode, "stream") || !std::strcmp(mode, "all")) TestStream();
    if (!std::strcmp(mode, "pto") || !std::strcmp(mode, "all")) TestPto();
    if (!std::strcmp(mode, "batch") || !std::strcmp(mode, "all")) TestBatch();
    if (!std::strcmp(mode, "finished") || !std::strcmp(mode, "all")) TestFinished();
    if (!std::strcmp(mode, "failure") || !std::strcmp(mode, "all")) TestFailedSends();
    std::cout << "connection ACK regression tests passed\n";
}
