#include "h3/h3_handler.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace esp_http3::memory {
void* Allocate(size_t size, size_t) noexcept { return std::malloc(size); }
void Deallocate(void* pointer) noexcept { std::free(pointer); }
bool UsesPsram() noexcept { return false; }
}
using namespace esp_http3;
using namespace esp_http3::h3;

// Control stream type=0, SETTINGS frame(type=4, length=2), setting6=value1.
static const uint8_t settings_bytes[] = {0,4,2,6,1};
static void VerifyDrained(H3Handler& handler) {
    auto* stream = handler.GetStream(3);
    assert(stream && stream->is_control);
    std::cout << "control contiguous_end=" << stream->contiguous_end
              << " pending=" << stream->pending_chunks.size()
              << " buffered=" << stream->recv_buffer.size() << std::endl;
    assert(stream->contiguous_end == sizeof(settings_bytes));
    assert(stream->pending_chunks.empty());
    assert(stream->recv_buffer.empty());
}

static void TestOutOfOrderControl() {
    H3Handler handler;
    handler.Initialize(0, 2);
    handler.OnStreamData(3, 0, settings_bytes, 1, false);
    handler.OnStreamData(3, 3, settings_bytes + 3, 2, false);
    handler.OnStreamData(3, 1, settings_bytes + 1, 2, false);
    VerifyDrained(handler);
}

static void TestRetransmittedControlPrefix() {
    H3Handler handler;
    handler.Initialize(0, 2);
    handler.OnStreamData(3, 0, settings_bytes, 2, false);
    handler.OnStreamData(3, 0, settings_bytes, 2, false); // Same stream bytes, another packet.
    handler.OnStreamData(3, 2, settings_bytes + 2, 3, false);
    VerifyDrained(handler);
    handler.OnStreamData(3, 1, settings_bytes + 1, 4, false); // Fully overlapping retransmission.
    VerifyDrained(handler);
}

static void TestPrefixArrivesLast() {
    H3Handler handler;
    handler.Initialize(0, 2);
    handler.OnStreamData(3, 1, settings_bytes + 1, 4, false);
    auto* stream = handler.GetStream(3);
    assert(stream && !stream->is_control);
    assert(stream->contiguous_end == 0 && stream->pending_chunks.size() == 1);
    handler.OnStreamData(3, 0, settings_bytes, 1, false);
    VerifyDrained(handler);
}

static void TestQpackOffsetsSurviveBufferDrain() {
    H3Handler handler;
    handler.Initialize(0, 2);
    const uint8_t encoder[] = {2, 0x20};
    handler.OnStreamData(7, 1, encoder + 1, 1, false);
    handler.OnStreamData(7, 0, encoder, 1, false);
    auto* stream = handler.GetStream(7);
    assert(stream && stream->is_qpack_encoder);
    assert(stream->contiguous_end == 2 && stream->recv_buffer.empty());
    handler.OnStreamData(7, 0, encoder, sizeof(encoder), false);
    assert(stream->contiguous_end == 2 && stream->recv_buffer.empty());
}
static void TestRequestReassemblyStillDeliversOnce() {
    H3Handler handler;
    handler.Initialize(0, 2);
    const auto stream_id = handler.CreateRequestStream();
    int status = 0;
    std::string body;
    int finished = 0;
    handler.SetOnResponse([&](uint64_t, const H3Response& response) { status = response.status; });
    handler.SetOnStreamData([&](uint64_t, const uint8_t* data, size_t length, bool fin) {
        if (length > 0) body.append(reinterpret_cast<const char*>(data), length);
        if (fin) ++finished;
    });
    const uint8_t response[] = {1,3,0,0,0xd9,0,3,'a','b','c'};
    handler.OnStreamData(stream_id, 7, response + 7, 3, true);
    handler.OnStreamData(stream_id, 0, response, 7, false);
    assert(status == 200 && body == "abc" && finished == 1);
}
int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "all";
    if (!std::strcmp(mode, "reorder") || !std::strcmp(mode, "all")) TestOutOfOrderControl();
    if (!std::strcmp(mode, "duplicate") || !std::strcmp(mode, "all")) TestRetransmittedControlPrefix();
    if (!std::strcmp(mode, "prefix") || !std::strcmp(mode, "all")) TestPrefixArrivesLast();
    if (!std::strcmp(mode, "qpack") || !std::strcmp(mode, "all")) TestQpackOffsetsSurviveBufferDrain();
    if (!std::strcmp(mode, "request") || !std::strcmp(mode, "all")) TestRequestReassemblyStillDeliversOnce();
    std::cout << "H3 reassembly regression tests passed\n";
}
