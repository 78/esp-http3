/**
 * @file esp_http3_memory.cc
 * @brief Capability-aware allocator for ESP HTTP/3 dynamic buffers.
 */

#include "esp_http3_memory.h"

#include "sdkconfig.h"

#include <esp_heap_caps.h>
#include <esp_log.h>

namespace esp_http3 {
namespace memory {
namespace {

constexpr char kTag[] = "Http3Memory";

void* AllocateWithCaps(size_t size, size_t alignment, uint32_t caps) noexcept {
    const size_t allocation_size = size == 0 ? 1 : size;
    if (alignment > alignof(std::max_align_t)) {
        return heap_caps_aligned_alloc(alignment, allocation_size, caps);
    }
    return heap_caps_malloc(allocation_size, caps);
}

}  // namespace

void* Allocate(size_t size, size_t alignment) noexcept {
#if defined(CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR) && CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR
    void* pointer = AllocateWithCaps(size, alignment, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#if defined(CONFIG_ESP_HTTP3_PSRAM_ALLOCATOR_FALLBACK) && CONFIG_ESP_HTTP3_PSRAM_ALLOCATOR_FALLBACK
    if (!pointer) {
        ESP_LOGW(kTag, "PSRAM allocation of %zu bytes failed; trying internal RAM", size);
        pointer = AllocateWithCaps(size, alignment, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
#endif
#else
    void* pointer = AllocateWithCaps(size, alignment, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
#endif

    if (!pointer) {
        ESP_LOGE(kTag, "HTTP/3 allocation of %zu bytes failed", size);
    }
    return pointer;
}

void Deallocate(void* pointer) noexcept { heap_caps_free(pointer); }

bool UsesPsram() noexcept {
#if defined(CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR) && CONFIG_ESP_HTTP3_USE_PSRAM_ALLOCATOR
    return true;
#else
    return false;
#endif
}

}  // namespace memory
}  // namespace esp_http3
