/**
 * @file esp_http3_memory.h
 * @brief Capability-aware allocator for ESP HTTP/3 dynamic buffers.
 */

#pragma once

#include <cstddef>
#include <cstdlib>
#include <limits>
#include <new>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace esp_http3 {
namespace memory {

/**
 * Allocate byte-addressable memory using the heap selected by Kconfig.
 *
 * When CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR is enabled, PSRAM is attempted
 * first. CONFIG_ESP_HTTP3_PSRAM_ALLOCATOR_FALLBACK controls whether a failed
 * PSRAM allocation is retried from internal RAM.
 */
void* Allocate(size_t size, size_t alignment = alignof(std::max_align_t)) noexcept;

/** Free memory returned by Allocate(). */
void Deallocate(void* pointer) noexcept;

/** Return true when the configured primary heap is PSRAM. */
bool UsesPsram() noexcept;

}  // namespace memory

/**
 * STL allocator backed by the component's capability-aware heap policy.
 *
 * The component is built with exceptions disabled. If an STL container cannot
 * allocate, the allocator aborts after the low-level allocator logs the failed
 * size, matching the behavior of libstdc++ operator new in no-exception builds.
 */
template <typename T>
class Http3Allocator {
public:
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    Http3Allocator() noexcept = default;

    template <typename U>
    Http3Allocator(const Http3Allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(size_t count) {
        if (count > max_size()) {
            AllocationFailure();
        }

        void* pointer = memory::Allocate(count * sizeof(T), alignof(T));
        if (!pointer) {
            AllocationFailure();
        }
        return static_cast<T*>(pointer);
    }

    void deallocate(T* pointer, size_t) noexcept { memory::Deallocate(pointer); }

    constexpr size_t max_size() const noexcept { return std::numeric_limits<size_t>::max() / sizeof(T); }

private:
    [[noreturn]] static void AllocationFailure() {
#if defined(__cpp_exceptions)
        throw std::bad_alloc();
#else
        std::abort();
#endif
    }
};

template <typename T, typename U>
constexpr bool operator==(const Http3Allocator<T>&, const Http3Allocator<U>&) noexcept {
    return true;
}

template <typename T, typename U>
constexpr bool operator!=(const Http3Allocator<T>&, const Http3Allocator<U>&) noexcept {
    return false;
}

template <typename T>
using Http3Vector = std::vector<T, Http3Allocator<T>>;

using Http3String = std::basic_string<char, std::char_traits<char>, Http3Allocator<char>>;
using Http3Header = std::pair<Http3String, Http3String>;
using Http3Headers = Http3Vector<Http3Header>;

}  // namespace esp_http3
