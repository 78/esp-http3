#pragma once

#include <cstddef>
#include <cstdint>

namespace esp_http3 {

// Incremental gzip framing around ESP ROM tinfl. The decoder state and 32 KiB
// history live in the component heap, never in the calling task's stack.
class GzipDecoder {
public:
    enum class Result { kPending, kData, kFinished, kError };

    static GzipDecoder* Create(size_t decoded_body_limit);
    static void Destroy(GzipDecoder* decoder);

    // input_finished means input contains every remaining wire byte and FIN has
    // arrived. EOF is reported only after all member trailers have validated.
    Result Decode(const uint8_t* input, size_t input_size, bool input_finished,
                  size_t& consumed, uint8_t* output, size_t output_size, size_t& written);
    const char* GetError() const;
    size_t DecodedBytes() const;

private:
    struct State;
    explicit GzipDecoder(size_t decoded_body_limit);
    ~GzipDecoder();
    State* state_ = nullptr;
};

}  // namespace esp_http3
