// Active connection dispatcher, CID lifecycle and retransmission methods are
// extracted from production at test time. Encryption/socket I/O are stand-ins;
// STREAM dispatch is observed with the real parser, without starting HTTP/TLS.
#include "connection_path_features.inc"
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
#include <map>
#include <set>
#include <array>
#include <string>

namespace esp_http3::memory {
void* Allocate(size_t size, size_t) noexcept { return std::malloc(size); }
void Deallocate(void* p) noexcept { std::free(p); }
bool UsesPsram() noexcept { return false; }
}
namespace esp_http3 {
static bool fail_packet_build = false;
static std::vector<std::vector<uint8_t>> built_payloads;
namespace quic {
#include "packet_number_method.inc"
static size_t CapturePacket(const uint8_t* payload, size_t len, uint8_t* out,
                            size_t capacity, size_t overhead) {
    if (fail_packet_build || len + overhead > capacity) return 0;
    built_payloads.emplace_back(payload, payload + len);
    std::memset(out, 0, len + overhead);
    return len + overhead;
}
size_t Build1RttPacket(const ConnectionId& dcid, uint64_t pn, bool, bool,
                       const uint8_t* payload, size_t len, const CryptoSecrets&,
                       uint8_t* out, size_t capacity) {
    return CapturePacket(payload, len, out, capacity, 1 + dcid.Length() + GetPacketNumberLength(pn) + 16);
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
enum class ConnectionState { kIdle, kHandshakeInProgress, kConnected, kClosed };
static uint32_t esp_random() { static uint32_t value = 1; return ++value; }
static const char* TAG = "connection_path_test";
static bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t length) {
    uint8_t delta = 0;
    for (size_t i = 0; i < length; ++i) delta |= a[i] ^ b[i];
    return delta == 0;
}
class QuicConnection { public: class Impl; };
class QuicConnection::Impl {
public:
    using OnMigrationCompleteCallback = std::function<void(bool)>;
#include "connection_path_state.inc"
    struct TestCrypto {
        quic::CryptoSecrets secrets;
        bool HasApplicationKeys() const { return true; }
        int GetKeyPhase() const { return 0; }
        const quic::CryptoSecrets& GetClientAppSecrets() const { return secrets; }
    } crypto_;
    struct { bool enable_debug = false; } config_;
    BatchState batch_state_;
    AckManager app_ack_mgr_;
    SentPacketTracker app_tracker_;
    FlowController flow_controller_;
    LossDetector loss_detector_;
    quic::TransportParameters peer_params_;
    Http3Vector<uint8_t> packet_buf_ = Http3Vector<uint8_t>(1500);
    Http3Vector<uint8_t> frame_buf_ = Http3Vector<uint8_t>(1500);
    Http3Vector<uint8_t> batch_frames_ = Http3Vector<uint8_t>(1500);
    uint64_t current_time_us_ = 1100;
    ConnectionState state_ = ConnectionState::kConnected;
    bool handshake_complete_ = true;
    std::set<uint64_t> reset_streams_, remote_stop_sending_streams_;
    std::function<void(int, uint64_t)> on_stream_reset_, on_stream_stop_sending_;
    bool send_success = true;
    size_t send_count = 0, stream_count = 0, last_send_size = 0;
    std::vector<uint8_t> received_stream_bytes;
    std::string close_reason;
    Impl() {
        dcid_.length = scid_.length = 8;
#ifdef HAS_InitializeLocalConnectionIds
        InitializeLocalConnectionIds();
#else
        // Fixture handshake state only: the pre-fix constructor didn't register seq0.
        LocalConnectionIdInfo initial{};
        initial.cid = scid_;
        local_connection_ids_[0] = initial;
#endif
    }
    ~Impl() { delete batch_state_.writer; }
    bool SendPacket(const uint8_t*, size_t len) {
        assert(len <= packet_buf_.size());
        ++send_count;
        last_send_size = len;
        return send_success;
    }
    void ProcessFrames(const uint8_t*, size_t, quic::PacketType);
    void OnFramePathChallenge(const uint8_t*);
    void OnFramePathResponse(const uint8_t*);
    bool SendPathChallenge();
    bool SendNewConnectionId();
    bool SendRetireConnectionId(uint64_t);
    void InitializeLocalConnectionIds();
    void EnsureLocalConnectionIdSupply();
    void OnFrameRetireConnectionId(uint64_t);
    void PruneRetiredConnectionIdFrames(Http3Vector<uint8_t>&);
    void BeginBatch();
    bool EndBatch();
    bool SendStreamData(uint64_t, const uint8_t*, size_t, bool);
    void RetransmitLostPackets(const std::vector<SentPacketInfo*>&);
    void SendPtoProbe();
    void GenerateRandom(uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(esp_random());
    }
    void CompleteMigration(bool success) { assert(success); migration_in_progress_ = false; }
    void Close(int, const std::string& reason) { state_ = ConnectionState::kClosed; close_reason = reason; }
    void FailHandshake(const char* reason) { Close(0, reason); }
    // These are unrelated dispatch destinations, intentionally fail if reached.
    void ProcessAckFrame(quic::BufferReader*, quic::PacketType) { assert(false); }
    void ProcessCryptoFrame(quic::BufferReader*, quic::PacketType) { assert(false); }
    void ProcessMaxDataFrame(quic::BufferReader*) { assert(false); }
    void ProcessMaxStreamDataFrame(quic::BufferReader*) { assert(false); }
    void ProcessNewConnectionIdFrame(quic::BufferReader*) { assert(false); }
    void ProcessConnectionCloseFrame(quic::BufferReader*, bool) { assert(false); }
    void ProcessHandshakeDoneFrame() { assert(false); }
    bool SendMaxDataFrame() { assert(false); return false; }
    bool SendMaxStreamDataFrame(uint64_t) { assert(false); return false; }
    // Observe the dispatch boundary with the real wire parser, without HTTP/TLS.
    void ProcessStreamFrame(quic::BufferReader* reader, uint8_t type) {
        quic::StreamFrameData frame;
        assert(quic::ParseStreamFrame(reader, type, &frame));
        assert(frame.stream_id == 4 && frame.offset == 0);
        received_stream_bytes.insert(received_stream_bytes.end(), frame.data, frame.data + frame.length);
        ++stream_count;
    }
};
#include "connection_path_methods.inc"
}
using namespace esp_http3;
using Connection = QuicConnection::Impl;
static const std::array<uint8_t, 8> challenge{0, 0xff, 2, 3, 0x80, 5, 6, 7};
static std::vector<uint8_t> PayloadWithStream(bool response = false) {
    std::vector<uint8_t> payload(100);
    quic::BufferWriter writer(payload.data(), payload.size());
    assert(response ? quic::BuildPathResponseFrame(&writer, challenge.data())
                    : quic::BuildPathChallengeFrame(&writer, challenge.data()));
    const uint8_t body[] = {0xde, 0xad, 0xbe, 0xef};
    assert(quic::BuildStreamFrame(&writer, 4, 0, body, sizeof(body), true));
    payload.resize(writer.Offset());
    return payload;
}
static void TestChallengeDispatch() {
    Connection c;
    auto payload = PayloadWithStream();
    c.ProcessFrames(payload.data(), payload.size(), quic::PacketType::k1Rtt);
    assert(c.send_count == 1);
    const auto& response = built_payloads.back();
    assert(response.size() >= 9 && response[0] == 0x1b);
    assert(c.last_send_size == 1200);
    assert(std::all_of(response.begin() + 9, response.end(), [](uint8_t b) { return b == 0; }));
    assert(std::equal(challenge.begin(), challenge.end(), response.begin() + 1));
    assert(c.stream_count == 1);
    assert((c.received_stream_bytes == std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
}
static void TestUnsolicitedResponse() {
    Connection c;
    c.path_validated_ = false;
    uint8_t unsolicited[8] = {};
    c.OnFramePathResponse(unsolicited);
    assert(!c.path_validated_);
    // Wrong response doesn't finish an outstanding challenge.
    assert(c.SendPathChallenge());
    c.OnFramePathResponse(unsolicited);
    assert(!c.path_validated_);
    uint8_t correct[8];
    std::copy(c.path_challenge_data_, c.path_challenge_data_ + 8, correct);
    c.OnFramePathResponse(correct);
    assert(c.path_validated_);
    c.path_validated_ = false;
    c.OnFramePathResponse(correct);
    assert(!c.path_validated_); // completed response cannot be replayed
    auto payload = PayloadWithStream(true);
    c.ProcessFrames(payload.data(), payload.size(), quic::PacketType::k1Rtt);
    assert(c.stream_count == 1 && !c.path_validated_);
}
static void TestPathResponseNotRetransmitted() {
    Connection c;
    c.OnFramePathChallenge(challenge.data());
    const auto packets = c.app_tracker_.GetUnackedPackets();
    assert(packets.size() == 1 && packets[0]->frames.empty());
    SentPacketInfo lost = *packets[0];
    const auto before = c.send_count;
    c.RetransmitLostPackets({&lost});
    assert(c.send_count == before);
    c.SendPtoProbe();
    assert(built_payloads.back().size() == 1 && built_payloads.back()[0] == 0x01);
}
struct DecodedFrames {
    std::vector<uint64_t> new_ids, retired_ids, stream_ids;
    size_t pings = 0, path_responses = 0;
};
template<class Bytes> static DecodedFrames Decode(const Bytes& bytes) {
    DecodedFrames result;
    quic::BufferReader r(bytes.data(), bytes.size());
    while (r.Remaining()) {
        uint8_t type;
        assert(r.ReadUint8(&type));
        if (type == 0) continue;
        if (type == 1) { ++result.pings; continue; }
        if (type >= 8 && type <= 15) {
            quic::StreamFrameData stream;
            assert(quic::ParseStreamFrame(&r, type, &stream));
            result.stream_ids.push_back(stream.stream_id);
        } else if (type == 0x18) {
            uint64_t seq, prior;
            quic::ConnectionId id;
            uint8_t token[16];
            assert(quic::ParseNewConnectionIdFrame(&r, &seq, &prior, &id, token));
            assert(id.length == 8 && prior <= seq);
            result.new_ids.push_back(seq);
        } else if (type == 0x19) {
            uint64_t seq;
            assert(r.ReadVarint(&seq));
            result.retired_ids.push_back(seq);
        } else if (type == 0x1b) {
            assert(r.Skip(8));
            ++result.path_responses;
        } else {
            assert(false && "unexpected frame in retransmission payload");
        }
    }
    return result;
}
static void Retire(Connection& c, uint64_t sequence) {
    uint8_t payload[16];
    quic::BufferWriter writer(payload, sizeof(payload));
    assert(quic::BuildRetireConnectionIdFrame(&writer, sequence));
    c.ProcessFrames(payload, writer.Offset(), quic::PacketType::k1Rtt);
}
static void TestRetireReplenishes() {
    Connection c;
    c.peer_params_.active_connection_id_limit = 2;
    assert(c.SendNewConnectionId());
    assert(c.local_connection_ids_.size() == 2);
    const auto before = c.send_count;
#ifdef HAS_OnFrameRetireConnectionId
    c.processing_1rtt_packet_ = true;
    c.received_dcid_ = c.local_connection_ids_.at(1).cid;
#endif
    Retire(c, 0);
    assert(c.state_ == ConnectionState::kConnected);
    assert(c.send_count == before + 1);
    assert(c.local_connection_ids_.count(0) == 0);
    assert(c.local_connection_ids_.count(1) == 1 && c.local_connection_ids_.count(2) == 1);
    assert((Decode(built_payloads.back()).new_ids == std::vector<uint64_t>{2}));
    const auto after = c.send_count;
    Retire(c, 0);
    assert(c.send_count == after && c.local_cid_sequence_ == 2);
}
static void TestPeerLimit() {
    Connection c;
    c.peer_params_.active_connection_id_limit = 2;
    assert(c.SendNewConnectionId());
    assert(!c.SendNewConnectionId());
    assert(c.local_connection_ids_.size() == 2 && c.local_cid_sequence_ == 1);
#ifdef HAS_EnsureLocalConnectionIdSupply
    Connection large;
    large.peer_params_.active_connection_id_limit = 100;
    large.EnsureLocalConnectionIdSupply();
    assert(large.local_connection_ids_.size() == 4);
    const auto sent = large.send_count;
    large.EnsureLocalConnectionIdSupply();
    assert(large.send_count == sent);
    Connection invalid;
    invalid.peer_params_.active_connection_id_limit = 1;
    invalid.EnsureLocalConnectionIdSupply();
    assert(invalid.state_ == ConnectionState::kClosed);
#endif
}
static void TestInvalidRetire() {
    Connection future;
    Retire(future, 1);
    assert(future.state_ == ConnectionState::kClosed);
#ifdef HAS_OnFrameRetireConnectionId
    Connection current;
    current.processing_1rtt_packet_ = true;
    current.received_dcid_ = current.scid_;
    Retire(current, 0);
    assert(current.state_ == ConnectionState::kClosed);
    assert(current.local_connection_ids_.count(0) == 1);
#endif
}
static void TestCidRetransmission(bool batch, bool retire) {
    for (bool pto : {false, true}) {
        Connection c;
        c.peer_params_.active_connection_id_limit = 2;
        if (batch) {
            c.BeginBatch();
            const uint8_t settings[] = {0, 4, 0};
            assert(c.SendStreamData(2, settings, sizeof(settings), false));
        }
        assert(retire ? c.SendRetireConnectionId(7) : c.SendNewConnectionId());
        if (batch) assert(c.EndBatch());
        auto packets = c.app_tracker_.GetUnackedPackets();
        assert(packets.size() == 1 && !packets[0]->frames.empty());
        auto saved = Decode(packets[0]->frames);
        assert(retire ? saved.retired_ids == std::vector<uint64_t>{7}
                      : saved.new_ids == std::vector<uint64_t>{1});
        if (batch) assert(saved.stream_ids == std::vector<uint64_t>{2});
        // This is the same tracker cleanup used by ResetStream(0).
        c.app_tracker_.ClearStreamFrames(0);
        assert(!packets[0]->frames.empty());
        assert(c.loss_detector_.IsPtoArmed());
        const auto before = c.send_count;
        if (pto) {
            c.SendPtoProbe();
        } else {
            // A detached loss snapshot matches the real LossDetector callback contract.
            SentPacketInfo lost = *packets[0];
            c.RetransmitLostPackets({&lost});
        }
        assert(c.send_count == before + 1);
        const auto resent = Decode(built_payloads.back());
        assert(resent.new_ids == saved.new_ids && resent.retired_ids == saved.retired_ids);
        assert(resent.stream_ids == saved.stream_ids && resent.path_responses == 0);
    }
}
static void TestRetiredNewNotRetransmitted(bool batch) {
    for (bool pto : {false, true}) {
        Connection c;
        c.peer_params_.active_connection_id_limit = 2;
        if (batch) {
            c.BeginBatch();
            const uint8_t settings[] = {0, 4, 0};
            assert(c.SendStreamData(2, settings, sizeof(settings), false));
        }
        assert(c.SendNewConnectionId());
        if (batch) assert(c.EndBatch());
        SentPacketInfo original = *c.app_tracker_.GetUnackedPackets()[0];
        ++c.current_time_us_;
#ifdef HAS_OnFrameRetireConnectionId
        c.processing_1rtt_packet_ = true;
        c.received_dcid_ = c.scid_;
#endif
        Retire(c, 1);
        assert(c.local_connection_ids_.count(1) == 0);
        const auto before = c.send_count;
        if (pto) c.SendPtoProbe();
        else c.RetransmitLostPackets({&original});
        if (!pto && !batch) assert(c.send_count == before);
        if (c.send_count > before) {
            const auto sent = Decode(built_payloads.back());
            assert(std::find(sent.new_ids.begin(), sent.new_ids.end(), 1) == sent.new_ids.end());
            if (batch) assert(sent.stream_ids == std::vector<uint64_t>{2});
        }
    }
}
static void TestMalformedPath() {
    for (uint8_t type : {uint8_t(0x1a), uint8_t(0x1b)}) {
        Connection c;
        const uint8_t malformed[] = {type, 1, 2, 3, 4, 5, 6, 7};
        c.ProcessFrames(malformed, sizeof(malformed), quic::PacketType::k1Rtt);
        assert(c.state_ == ConnectionState::kClosed);
        assert(c.send_count == 0 && c.stream_count == 0);
    }
}
static void TestCidSendFailure() {
    Connection build;
    build.peer_params_.active_connection_id_limit = 2;
    fail_packet_build = true;
    assert(!build.SendNewConnectionId());
    fail_packet_build = false;
    assert(build.local_cid_sequence_ == 0 && build.local_connection_ids_.size() == 1);
    assert(build.send_count == 0 && build.app_tracker_.GetUnackedPackets().empty());
    assert(build.SendNewConnectionId());
    assert((Decode(built_payloads.back()).new_ids == std::vector<uint64_t>{1}));

    Connection socket;
    socket.peer_params_.active_connection_id_limit = 2;
    socket.send_success = false;
    assert(!socket.SendNewConnectionId());
    assert(socket.local_cid_sequence_ == 1 && socket.local_connection_ids_.size() == 2);
    const auto pending = socket.app_tracker_.GetUnackedPackets();
    assert(pending.size() == 1 && !pending[0]->frames.empty());
    assert(socket.loss_detector_.IsPtoArmed());
    socket.send_success = true;
    socket.SendPtoProbe();
    assert(socket.send_count == 2);
    assert((Decode(built_payloads.back()).new_ids == std::vector<uint64_t>{1}));
    assert(socket.local_cid_sequence_ == 1);
}
static void TestReceivedPacketHistory() {
    AckManager ack;
    assert(!ack.HasReceivedPacket(42));
    ack.OnPacketReceived(42, 1000);
    assert(ack.HasReceivedPacket(42));
    assert(!ack.HasReceivedPacket(43));
    ack.Reset();
    assert(!ack.HasReceivedPacket(42));
    for (uint64_t pn = 0; pn < 300; ++pn) ack.OnPacketReceived(pn, 1000 + pn);
    assert(!ack.HasReceivedPacket(0) && ack.HasReceivedPacket(299));
}
int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "all";
    if (mode == "challenge" || mode == "all") TestChallengeDispatch();
    if (mode == "unsolicited" || mode == "all") TestUnsolicitedResponse();
    if (mode == "response-loss" || mode == "all") TestPathResponseNotRetransmitted();
    if (mode == "retire" || mode == "all") TestRetireReplenishes();
    if (mode == "limit" || mode == "all") TestPeerLimit();
    if (mode == "invalid-retire" || mode == "all") TestInvalidRetire();
    if (mode == "cid-loss" || mode == "all") TestCidRetransmission(false, false);
    if (mode == "retire-loss" || mode == "all") TestCidRetransmission(false, true);
    if (mode == "batch-loss" || mode == "all") TestCidRetransmission(true, false);
    if (mode == "retired-loss" || mode == "all") TestRetiredNewNotRetransmitted(false);
    if (mode == "retired-batch-loss" || mode == "all") TestRetiredNewNotRetransmitted(true);
    if (mode == "malformed" || mode == "all") TestMalformedPath();
    if (mode == "send-failure" || mode == "all") TestCidSendFailure();
    if (mode == "history" || mode == "all") TestReceivedPacketHistory();
    std::cout << "connection path regression tests passed (" << mode << ")\n";
}
