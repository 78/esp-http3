#include "core/ack_manager.h"
#include "core/loss_detector.h"
#include "quic/quic_frame.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>

// Host allocator makes use-after-free visible to AddressSanitizer.
namespace esp_http3::memory {
void* Allocate(size_t size, size_t) noexcept { return std::malloc(size); }
void Deallocate(void* p) noexcept { std::free(p); }
bool UsesPsram() noexcept { return false; }
}
using namespace esp_http3;

static void TestLossCallbackLifetime(size_t count) {
    SentPacketTracker tracker;
    LossDetector loss;
    for (size_t i = 0; i < count; ++i) {
        tracker.OnPacketSent(i, 1000, 100, true,
                            Http3Vector<uint8_t>{0x0a, uint8_t(i), 0}, i * 4);
    }
    size_t retransmitted = 0;
    loss.SetOnLoss([&](const std::vector<SentPacketInfo*>& packets) {
        assert(packets.size() == count);
        for (auto* packet : packets) {
            assert(packet->packet_number == retransmitted);
            assert(packet->stream_id == retransmitted * 4);
            assert(packet->frames.size() == 3);
            assert(packet->frames[1] == uint8_t(retransmitted));
            auto frames = packet->frames;
            tracker.OnPacketSent(tracker.AllocatePacketNumber(), 2000000, 100,
                                 true, std::move(frames), packet->stream_id);
            ++retransmitted;
        }
    });
    loss.OnAckReceived(count + 3, 0, 2000000, &tracker);
    assert(retransmitted == count);
}

static void TestFailedFrameDoesNotContaminateBatch() {
    uint8_t buffer[32] = {};
    quic::BufferWriter writer(buffer, sizeof(buffer));
    assert(quic::BuildPingFrame(&writer));
    uint8_t payload[40] = {};
    assert(!quic::BuildStreamFrame(&writer, 4, 64, payload, sizeof(payload), false));
    assert(writer.Offset() == 1);
    assert(quic::BuildStreamFrame(&writer, 4, 64, payload, 1, true));
    quic::BufferReader reader(buffer + 1, writer.Offset() - 1);
    uint8_t type;
    assert(reader.ReadUint8(&type));
    quic::StreamFrameData parsed;
    assert(quic::ParseStreamFrame(&reader, type, &parsed));
    assert(parsed.stream_id == 4 && parsed.offset == 64 && parsed.length == 1 && parsed.fin);
    assert(reader.Remaining() == 0);

    writer.Reset();
    assert(quic::BuildPingFrame(&writer));
    std::vector<std::pair<uint64_t, uint64_t>> ranges(40, {0, 0});
    assert(!quic::BuildAckFrame(&writer, 100, 0, 0, ranges));
    assert(writer.Offset() == 1);
}

static void TestFragmentedAckFits() {
    AckManager ack;
    // Reordering / gaps produce more ACK ranges than a 64-byte buffer fits.
    for (uint64_t pn = 0; pn < 256; pn += 2) ack.OnPacketReceived(pn, 1000);
    uint8_t buffer[64] = {};
    quic::BufferWriter writer(buffer, sizeof(buffer));
    assert(ack.BuildAckFrame(&writer, 1100));
    quic::BufferReader reader(buffer, writer.Offset());
    uint8_t type;
    assert(reader.ReadUint8(&type) && type == 2);
    quic::AckFrameData parsed;
    assert(quic::ParseAckFrame(&reader, &parsed));
    assert(reader.Remaining() == 0);
    assert(parsed.largest_ack == 254);
    assert(parsed.first_ack_range == 0);
    for (const auto& range : parsed.ack_ranges) assert(range.first == 0 && range.second == 0);
    // All capacities either contain a complete ACK or leave the writer unchanged.
    for (size_t capacity = 0; capacity <= 300; ++capacity) {
        uint8_t data[300] = {};
        quic::BufferWriter candidate(data, capacity);
        if (!ack.BuildAckFrame(&candidate, 1100)) {
            assert(candidate.Offset() == 0);
            continue;
        }
        quic::BufferReader check(data, candidate.Offset());
        assert(check.ReadUint8(&type) && type == 2);
        assert(quic::ParseAckFrame(&check, &parsed));
        assert(check.Remaining() == 0);
    }
}

static void TestAllAckRangesAreApplied() {
    SentPacketTracker tracker;
    for (uint64_t pn = 0; pn <= 10; ++pn) {
        tracker.OnPacketSent(pn, 1000, 100, true, Http3Vector<uint8_t>{1});
    }
    // ACK [9,10], [5,6], [1,1]; gaps encode unacknowledged count minus one.
    const std::vector<std::pair<uint64_t, uint64_t>> ranges{{1, 1}, {2, 0}};
    size_t bytes = 0;
    assert(tracker.OnAckReceived(10, 0, 1, ranges, 2000, &bytes));
    assert(bytes == 500);
    const auto remaining = tracker.GetUnackedPackets();
    const uint64_t expected[] = {0, 2, 3, 4, 7, 8};
    assert(remaining.size() == 6);
    for (size_t i = 0; i < remaining.size(); ++i) {
        assert(remaining[i]->packet_number == expected[i]);
        assert(remaining[i]->frames.size() == 1);
    }
    assert(tracker.GetLatestRttUs() == 1000);
    assert(!tracker.OnAckReceived(10, 0, 1, ranges, 3000, &bytes));
    assert(bytes == 0);
}

static void TestInvalidAckRangesAreRejected() {
    // Underflow in first range, gap, or a subsequent range length.
    struct Case { uint64_t largest, first; std::vector<std::pair<uint64_t, uint64_t>> ranges; };
    const Case cases[] = {{2, 3, {}}, {2, 1, {{0, 0}}},
                          {10, 0, {{9, 0}}}, {10, 0, {{1, 8}}}};
    for (const auto& c : cases) {
        uint8_t data[128] = {};
        quic::BufferWriter writer(data, sizeof(data));
        assert(quic::BuildAckFrame(&writer, c.largest, 0, c.first, c.ranges));
        quic::BufferReader reader(data + 1, writer.Offset() - 1);
        quic::AckFrameData parsed;
        assert(!quic::ParseAckFrame(&reader, &parsed));

        SentPacketTracker tracker;
        tracker.OnPacketSent(c.largest, 1000, 100, true, Http3Vector<uint8_t>{1});
        size_t bytes = 123;
        assert(!tracker.OnAckReceived(c.largest, 0, c.first, c.ranges, 2000, &bytes));
        assert(bytes == 0 && tracker.GetLargestAcked() == -1);
        assert(tracker.GetUnackedPackets().size() == 1);
    }
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "all";
    if (!std::strcmp(mode, "loss") || !std::strcmp(mode, "all")) {
        TestLossCallbackLifetime(4);   // vector reallocation
        TestLossCallbackLifetime(300); // pruning within existing vector capacity
    }
    if (!std::strcmp(mode, "frames") || !std::strcmp(mode, "all")) TestFailedFrameDoesNotContaminateBatch();
    if (!std::strcmp(mode, "ack") || !std::strcmp(mode, "all")) {
        TestFragmentedAckFits();
        TestAllAckRangesAreApplied();
        TestInvalidAckRangesAreRejected();
    }
    std::cout << "transport regression tests passed\n";
}
