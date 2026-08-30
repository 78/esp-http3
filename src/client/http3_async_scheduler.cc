#include "client/http3_async_client.h"

#include <algorithm>
#include <array>
#include <utility>

#include "esp_log.h"
#include "esp_timer.h"

namespace {

constexpr size_t kReadChunkSize = 1024;
constexpr char kTag[] = "Http3AsyncClient";

}  // namespace

bool Http3AsyncClient::Start() {
    if (async_started_.load() && IsConnected()) {
        return true;
    }
    async_started_.store(false);
    if (!initialized_ || !EnsureConnected(config_.connect_timeout_ms)) {
        return false;
    }
    xEventGroupClearBits(event_group_, EVENT_ASYNC_STOPPED);
    async_stop_requested_.store(false);
    async_started_.store(true);
    ESP_LOGI(kTag, "Asynchronous requests enabled: mode=event-driven max=%u",
             static_cast<unsigned>(config_.max_concurrent_requests));
    WakeEventLoop();
    return true;
}

void Http3AsyncClient::Stop() {
    if (!async_started_.exchange(false)) {
        std::lock_guard<std::mutex> lock(async_mutex_);
        for (Slot& slot : async_slots_) {
            slot = Slot{};
        }
        return;
    }

    async_stop_requested_.store(true);
    WakeEventLoop();
    if (event_loop_task_ != nullptr && xTaskGetCurrentTaskHandle() != event_loop_task_) {
        constexpr TickType_t kStopTimeoutTicks = pdMS_TO_TICKS(1000);
        const EventBits_t bits =
            xEventGroupWaitBits(event_group_, EVENT_ASYNC_STOPPED, pdTRUE, pdFALSE, kStopTimeoutTicks);
        if ((bits & EVENT_ASYNC_STOPPED) == 0) {
            ESP_LOGW(kTag, "Async request state machine did not stop within 1000 ms; stopping transport tasks");
            StopBackgroundTasks();
        }
    } else {
        AdvanceAsyncRequests();
    }

    std::lock_guard<std::mutex> lock(async_mutex_);
    for (Slot& slot : async_slots_) {
        slot = Slot{};
    }
}

Http3AsyncRequestHandle Http3AsyncClient::Submit(Http3AsyncRequest request) {
    if (!async_started_.load() || async_stop_requested_.load() || !IsConnected() || request.path.empty() ||
        request.body.size() > config_.max_request_body_size) {
        return {};
    }
    if (request.timeout_ms == 0) {
        request.timeout_ms = config_.request_timeout_ms;
    }
    if (request.max_response_body_size == 0) {
        request.max_response_body_size = config_.default_max_response_body_size;
    }

    Http3AsyncRequestHandle handle{};
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        for (Slot& slot : async_slots_) {
            if (slot.state != SlotState::kFree) {
                continue;
            }
            if (next_async_generation_ == 0) {
                ++next_async_generation_;
            }
            handle.value = next_async_generation_++;
            slot.handle = handle;
            slot.request = std::move(request);
            slot.result = Http3AsyncResult{};
            slot.result.handle = handle;
            slot.deadline_us = esp_timer_get_time() + static_cast<int64_t>(slot.request.timeout_ms) * 1000;
            slot.state = SlotState::kPending;
            break;
        }
    }
    if (handle.valid()) {
        WakeEventLoop();
    }
    return handle;
}

bool Http3AsyncClient::Cancel(Http3AsyncRequestHandle handle) {
    if (!handle.valid()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(async_mutex_);
    Slot* slot = FindSlot(handle);
    if (slot == nullptr || slot->state == SlotState::kComplete) {
        return false;
    }
    slot->cancel_requested = true;
    WakeEventLoop();
    return true;
}

bool Http3AsyncClient::PollCompletion(Http3AsyncResult& result_out) {
    std::lock_guard<std::mutex> lock(async_mutex_);
    for (Slot& slot : async_slots_) {
        if (slot.state != SlotState::kComplete) {
            continue;
        }
        result_out = std::move(slot.result);
        slot = Slot{};
        return true;
    }
    return false;
}

void Http3AsyncClient::SetCompletionReadySink(Http3ReadySink sink, void* context) {
    if (sink == nullptr) {
        completion_ready_sink_.store(nullptr, std::memory_order_release);
        completion_ready_context_.store(nullptr, std::memory_order_release);
        return;
    }
    completion_ready_context_.store(context, std::memory_order_release);
    completion_ready_sink_.store(sink, std::memory_order_release);
}

void Http3AsyncClient::NotifyCompletionReady() {
    Http3ReadySink sink = completion_ready_sink_.load(std::memory_order_acquire);
    if (sink != nullptr) {
        sink(completion_ready_context_.load(std::memory_order_acquire));
    }
}

size_t Http3AsyncClient::InFlight() const {
    std::lock_guard<std::mutex> lock(async_mutex_);
    size_t count = 0;
    for (const Slot& slot : async_slots_) {
        if (slot.state == SlotState::kPending || slot.state == SlotState::kOpening ||
            slot.state == SlotState::kActive) {
            ++count;
        }
    }
    return count;
}

void Http3AsyncClient::AdvanceAsyncRequests() {
    if (async_stop_requested_.load()) {
        for (size_t index = 0; index < async_slots_.size(); ++index) {
            bool needs_completion = false;
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                const SlotState state = async_slots_[index].state;
                needs_completion = state != SlotState::kFree && state != SlotState::kComplete;
            }
            if (needs_completion) {
                CompleteSlot(index, Http3AsyncOutcome::kCancelled, "Async client stopped");
            }
        }
        async_stop_requested_.store(false);
        xEventGroupSetBits(event_group_, EVENT_ASYNC_STOPPED);
        return;
    }
    if (!async_started_.load()) {
        return;
    }
    for (size_t index = 0; index < async_slots_.size(); ++index) {
        AdvanceSlot(index);
    }
}

void Http3AsyncClient::FailAsyncRequests(Http3AsyncOutcome outcome, const char* error) {
    for (size_t index = 0; index < async_slots_.size(); ++index) {
        bool needs_completion = false;
        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            const SlotState state = async_slots_[index].state;
            needs_completion = state != SlotState::kFree && state != SlotState::kComplete;
        }
        if (needs_completion) {
            CompleteSlot(index, outcome, error);
        }
    }
}

void Http3AsyncClient::AdvanceSlot(size_t index) {
    SlotState state = SlotState::kFree;
    bool cancel_requested = false;
    int64_t deadline_us = 0;
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        state = async_slots_[index].state;
        cancel_requested = async_slots_[index].cancel_requested;
        deadline_us = async_slots_[index].deadline_us;
    }
    if (state == SlotState::kFree || state == SlotState::kComplete) {
        return;
    }
    if (cancel_requested) {
        CompleteSlot(index, Http3AsyncOutcome::kCancelled, "Request cancelled");
        return;
    }
    if (esp_timer_get_time() >= deadline_us) {
        CompleteSlot(index, Http3AsyncOutcome::kTimedOut, "Request timed out");
        return;
    }

    if (state == SlotState::kPending) {
        Http3Request request{};
        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            Slot& slot = async_slots_[index];
            slot.state = SlotState::kOpening;
            request.method.assign(slot.request.method.data(), slot.request.method.size());
            request.path.assign(slot.request.path.data(), slot.request.path.size());
            request.headers.reserve(slot.request.headers.size());
            for (const auto& [name, value] : slot.request.headers) {
                request.headers.emplace_back(std::string(name.data(), name.size()),
                                             std::string(value.data(), value.size()));
            }
            request.body = slot.request.body.empty() ? nullptr : slot.request.body.data();
            request.body_size = slot.request.body.size();
        }

        std::unique_ptr<Http3Stream> stream = Open(request);
        if (!stream) {
            const std::string error = GetLastError();
            CompleteSlot(index, Http3AsyncOutcome::kTransportError,
                         error.empty() ? "Failed to open request stream" : error.c_str());
            return;
        }
        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            Slot& slot = async_slots_[index];
            slot.stream = std::move(stream);
            slot.state = SlotState::kActive;
        }
        return;
    }

    if (state != SlotState::kActive) {
        return;
    }

    Http3Stream* stream = nullptr;
    bool headers_received = false;
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        Slot& slot = async_slots_[index];
        stream = slot.stream.get();
        headers_received = slot.headers_received;
    }
    if (stream == nullptr) {
        CompleteSlot(index, Http3AsyncOutcome::kTransportError, "Request stream is unavailable");
        return;
    }
    if (!headers_received) {
        int status = -1;
        const Http3StreamStatusPollResult status_result = stream->TryGetStatus(status);
        if (status_result == Http3StreamStatusPollResult::kError) {
            const std::string error = stream->GetError();
            CompleteSlot(index, Http3AsyncOutcome::kTransportError,
                         error.empty() ? "Failed to receive response headers" : error.c_str());
            return;
        }
        if (status_result == Http3StreamStatusPollResult::kPending) {
            return;
        }
        std::lock_guard<std::mutex> lock(async_mutex_);
        Slot& slot = async_slots_[index];
        slot.result.status = status;
        slot.result.headers = stream->GetHeaders();
        slot.headers_received = true;
    }

    std::array<uint8_t, kReadChunkSize> buffer{};
    while (true) {
        size_t bytes_read = 0;
        const Http3StreamReadPollResult read_result = stream->TryRead(buffer.data(), buffer.size(), bytes_read);
        if (read_result == Http3StreamReadPollResult::kPending) {
            return;
        }
        if (read_result == Http3StreamReadPollResult::kError) {
            const std::string error = stream->GetError();
            CompleteSlot(index, Http3AsyncOutcome::kTransportError,
                         error.empty() ? "Failed to receive response body" : error.c_str());
            return;
        }
        if (read_result == Http3StreamReadPollResult::kFinished) {
            CompleteSlot(index, Http3AsyncOutcome::kSucceeded);
            return;
        }

        bool response_too_large = false;
        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            Slot& slot = async_slots_[index];
            if (bytes_read > slot.request.max_response_body_size -
                                 std::min(slot.result.body.size(), slot.request.max_response_body_size)) {
                response_too_large = true;
            } else {
                slot.result.body.insert(slot.result.body.end(), buffer.begin(), buffer.begin() + bytes_read);
            }
        }
        if (response_too_large) {
            CompleteSlot(index, Http3AsyncOutcome::kResponseTooLarge, "Response body exceeds configured limit");
            return;
        }
    }
}

uint32_t Http3AsyncClient::LimitWaitToAsyncDeadline(uint32_t wait_ms) const {
    if (!async_started_.load()) {
        return wait_ms;
    }

    const int64_t now_us = esp_timer_get_time();
    std::lock_guard<std::mutex> lock(async_mutex_);
    for (const Slot& slot : async_slots_) {
        if (slot.state == SlotState::kFree || slot.state == SlotState::kComplete) {
            continue;
        }
        if (slot.cancel_requested || slot.state == SlotState::kPending || slot.deadline_us <= now_us) {
            return 0;
        }
        const uint64_t remaining_us = static_cast<uint64_t>(slot.deadline_us - now_us);
        const uint32_t remaining_ms = static_cast<uint32_t>((remaining_us + 999U) / 1000U);
        wait_ms = std::min(wait_ms, remaining_ms);
    }
    return wait_ms;
}

void Http3AsyncClient::CompleteSlot(size_t index, Http3AsyncOutcome outcome, const char* error) {
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        Slot& slot = async_slots_[index];
        slot.stream.reset();
        slot.result.outcome = outcome;
        slot.result.error = error != nullptr ? error : "";
        slot.request = Http3AsyncRequest{};
        slot.state = SlotState::kComplete;
    }
    NotifyCompletionReady();
}

Http3AsyncClient::Slot* Http3AsyncClient::FindSlot(Http3AsyncRequestHandle handle) {
    for (Slot& slot : async_slots_) {
        if (slot.state != SlotState::kFree && slot.handle.value == handle.value) {
            return &slot;
        }
    }
    return nullptr;
}
