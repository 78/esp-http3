#pragma once
#include <cstdint>
using TickType_t = uint32_t;
using BaseType_t = int;
constexpr BaseType_t pdTRUE=1, pdFALSE=0, pdPASS=1;
#define pdMS_TO_TICKS(value) (value)
