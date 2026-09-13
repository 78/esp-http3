#pragma once
#include "FreeRTOS.h"
#include <chrono>
using TaskHandle_t=void*;
struct TimeOut_t{std::chrono::steady_clock::time_point start;};
inline void vTaskSetTimeOutState(TimeOut_t* t){t->start=std::chrono::steady_clock::now();}
inline int xTaskCheckForTimeOut(TimeOut_t* t,TickType_t* ticks){auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-t->start).count();if(elapsed>=*ticks){*ticks=0;return pdTRUE;}*ticks-=elapsed;t->start=std::chrono::steady_clock::now();return pdFALSE;}
inline int xTaskCreate(void(*)(void*),const char*,int,void*,int,TaskHandle_t*){return 0;}
inline void vTaskDelete(TaskHandle_t){}
inline TaskHandle_t xTaskGetCurrentTaskHandle(){return nullptr;}
