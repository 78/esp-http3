#include "quic/quic_packet.h"
#include "quic/quic_aead.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace esp_http3::memory {
void* Allocate(size_t size, size_t) noexcept { return std::malloc(size); }
void Deallocate(void* pointer) noexcept { std::free(pointer); }
bool UsesPsram() noexcept { return false; }
}

// Packet layout tests use deterministic AEAD/HP stand-ins. They exercise the
// real packet builders, including their copies and capacity checks; they do
// not test cryptographic primitives. HP verifies the actual ciphertext extent,
// not the capacity of the reusable output allocation.
static const uint8_t* ciphertext_end = nullptr;
static std::vector<uint8_t> last_plaintext;
namespace esp_http3::quic {
size_t AeadEncrypt(const uint8_t*, const uint8_t*, uint64_t,
                   const uint8_t*, size_t, const uint8_t* plaintext,
                   size_t length, uint8_t* output) {
    last_plaintext.clear();
    if (length > 0) {
        last_plaintext.assign(plaintext, plaintext + length);
        std::memcpy(output, plaintext, length);
    }
    std::memset(output + length, 0xa5, 16);
    ciphertext_end = output + length + 16;
    return length + 16;
}
size_t AeadDecrypt(const uint8_t*, const uint8_t*, uint64_t,
                   const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*) { return 0; }
bool ApplyHeaderProtection(const uint8_t*, const uint8_t* sample,
                            uint8_t*, uint8_t*, size_t) {
    assert(sample + 16 <= ciphertext_end);
    return true;
}
bool RemoveHeaderProtection(const uint8_t*, uint8_t*, size_t,
                             size_t, bool, size_t*) { return false; }
bool VerifyRetryIntegrityTag(const uint8_t*, size_t, const uint8_t*, size_t) { return true; }
}
using namespace esp_http3;
using namespace esp_http3::quic;

static CryptoSecrets Secrets() {
    CryptoSecrets secrets;
    secrets.valid = true;
    return secrets;
}
static ConnectionId Cid() {
    const uint8_t bytes[8] = {1,2,3,4,5,6,7,8};
    return ConnectionId(bytes, sizeof(bytes));
}

static void TestRetryTokenBounds() {
    const auto cid = Cid();
    const auto secrets = Secrets();
    uint8_t output[1500] = {};
    const uint8_t payload[] = {1,0,0};
    for (size_t size : {size_t(0), size_t(232), size_t(256), size_t(512), size_t(1024)}) {
        std::vector<uint8_t> token(size, 0x7b);
        const size_t length = BuildInitialPacket(cid, cid, token.data(), token.size(), 0,
                                                 payload, sizeof(payload), secrets,
                                                 output, sizeof(output), 1200);
        assert(length >= 1200 && length <= sizeof(output));
        PacketInfo info;
        assert(ParsePacketHeader(output, length, 0, &info));
        assert(info.token.size() == token.size());
        assert(std::equal(info.token.begin(), info.token.end(), token.begin()));
    }
    // Reject impossible lengths before reading the source or allocating.
    assert(BuildInitialPacket(cid, cid, payload, std::numeric_limits<size_t>::max(), 0,
                              payload, sizeof(payload), secrets, output, sizeof(output), 1200) == 0);
}

static size_t BuildPacket(int kind, uint64_t pn, const uint8_t* payload, size_t length,
                          uint8_t* output, size_t capacity) {
    const auto cid = Cid();
    const auto secrets = Secrets();
    if (kind == 0) {
        return BuildInitialPacket(cid, cid, nullptr, 0, pn, payload, length,
                                   secrets, output, capacity, 0);
    }
    if (kind == 1) {
        return BuildHandshakePacket(cid, cid, pn, payload, length, secrets, output, capacity);
    }
    return Build1RttPacket(cid, pn, false, false, payload, length, secrets, output, capacity);
}

static void TestHeaderProtectionPadding() {
    uint8_t output[1500] = {};
    const uint8_t payload[] = {1,0,0,0};
    for (int kind = 0; kind < 3; ++kind) {
        for (uint64_t pn : {uint64_t(0), uint64_t(256), uint64_t(65536), uint64_t(16777216)}) {
            for (size_t length = 0; length <= sizeof(payload); ++length) {
                assert(BuildPacket(kind, pn, payload, length, output, sizeof(output)) > 0);
                assert(last_plaintext.size() >= 4 - GetPacketNumberLength(pn));
                assert(last_plaintext.size() >= length);
                for (size_t i = 0; i < length; ++i) assert(last_plaintext[i] == payload[i]);
                for (size_t i = length; i < last_plaintext.size(); ++i) assert(last_plaintext[i] == 0);
            }
        }
    }
}

static void TestSmallOutputBuffers() {
    const uint8_t payload[] = {1,0,0};
    for (int kind = 0; kind < 3; ++kind) {
        uint8_t reference[128] = {};
        const size_t needed = BuildPacket(kind, 0, payload, sizeof(payload), reference, sizeof(reference));
        assert(needed > 0);
        for (size_t capacity = 0; capacity <= needed + 1; ++capacity) {
            std::vector<uint8_t> output(capacity, 0xcc);
            const size_t actual = BuildPacket(kind, 0, payload, sizeof(payload), output.data(), output.size());
            if (capacity < needed) {
                assert(actual == 0);
                for (auto byte : output) assert(byte == 0xcc);
            } else {
                assert(actual == needed);
                assert(std::equal(reference, reference + needed, output.begin()));
            }
        }
    }
}
int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "all";
    if (!std::strcmp(mode, "retry") || !std::strcmp(mode, "all")) TestRetryTokenBounds();
    if (!std::strcmp(mode, "padding") || !std::strcmp(mode, "all")) TestHeaderProtectionPadding();
    if (!std::strcmp(mode, "bounds") || !std::strcmp(mode, "all")) TestSmallOutputBuffers();
    std::cout << "packet regression tests passed\n";
}
