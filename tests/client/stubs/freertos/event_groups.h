#pragma once
#include "FreeRTOS.h"
#include <mutex>
#include <condition_variable>
#include <chrono>
using EventBits_t = uint32_t;
struct TestEventGroup { std::mutex mutex; std::condition_variable changed; EventBits_t bits=0; };
using EventGroupHandle_t=TestEventGroup*;
inline EventGroupHandle_t xEventGroupCreate(){return new TestEventGroup;}
inline void vEventGroupDelete(EventGroupHandle_t g){delete g;}
inline EventBits_t xEventGroupSetBits(EventGroupHandle_t g,EventBits_t bits){std::lock_guard<std::mutex> lock(g->mutex);g->bits|=bits;g->changed.notify_all();return g->bits;}
inline EventBits_t xEventGroupClearBits(EventGroupHandle_t g,EventBits_t bits){std::lock_guard<std::mutex> lock(g->mutex);auto before=g->bits;g->bits&=~bits;return before;}
inline EventBits_t xEventGroupWaitBits(EventGroupHandle_t g,EventBits_t bits,int clear,int all,TickType_t timeout){std::unique_lock<std::mutex> lock(g->mutex);g->changed.wait_for(lock,std::chrono::milliseconds(timeout),[&]{return all?(g->bits&bits)==bits:(g->bits&bits)!=0;});auto result=g->bits;if(clear)g->bits&=~bits;return result;}
