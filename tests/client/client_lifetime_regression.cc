// Compile the production client and scheduler; only QUIC/network/RTOS boundaries
// are substituted so response arrival and connection generations are deterministic.
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "core/quic_connection.h"
#include "esp_http3_memory.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#define private public
#include "client/http3_async_client.h"
#undef private

namespace {
std::function<void()> send_hook;
std::function<void(size_t)> allocation_hook;
int writes=0, finishes=0, resets=0;
int write_result=1;
bool finish_result=true;
}
namespace esp_http3::memory {
void* Allocate(size_t n,size_t) noexcept {if(allocation_hook)allocation_hook(n);return std::malloc(n?n:1);}
void Deallocate(void* p) noexcept {std::free(p);}
bool UsesPsram() noexcept {return false;}
}
namespace esp_http3 {
class QuicConnection::Impl {public:int next_id=0;OnDisconnectedCallback disconnected;};
QuicConnection::QuicConnection(SendCallback,const QuicConfig&):impl_(std::make_unique<Impl>()){}
QuicConnection::~QuicConnection()=default;
bool QuicConnection::StartHandshake(){return true;}
void QuicConnection::Close(int code,const std::string& reason){if(impl_->disconnected)impl_->disconnected(code,reason);}
int QuicConnection::SendRequest(const std::string&,const std::string&,const std::vector<std::pair<std::string,std::string>>&,const uint8_t*,size_t){int id=impl_->next_id;impl_->next_id+=4;if(send_hook)send_hook();return id;}
int QuicConnection::OpenStream(const std::string& m,const std::string& p,const std::vector<std::pair<std::string,std::string>>& h){return SendRequest(m,p,h,nullptr,0);}
ssize_t QuicConnection::WriteStream(int,const uint8_t*,size_t n){++writes;return write_result>0?static_cast<ssize_t>(n):write_result;}
bool QuicConnection::FinishStream(int){++finishes;return finish_result;}
bool QuicConnection::ResetStream(int,uint64_t){++resets;return true;}
void QuicConnection::AcknowledgeStreamData(int,size_t){}
uint32_t QuicConnection::OnTimerTick(uint32_t){return 100;}
void QuicConnection::ProcessReceivedData(uint8_t*,size_t){}
QuicConnection::Stats QuicConnection::GetStats() const{return {};}
bool QuicConnection::GetPrivateKey(uint8_t*) const{return false;}
bool QuicConnection::GetPublicKey(uint8_t*) const{return false;}
void QuicConnection::SetOnDisconnected(OnDisconnectedCallback callback){impl_->disconnected=std::move(callback);}
void QuicConnection::SetOnConnected(OnConnectedCallback){}
void QuicConnection::SetOnResponse(OnResponseCallback){}
void QuicConnection::SetOnStreamData(OnStreamDataCallback){}
void QuicConnection::SetOnStreamWritable(OnStreamWritableCallback){}
void QuicConnection::SetOnWritable(OnWritableCallback){}
void QuicConnection::SetOnSessionTicket(OnSessionTicketCallback){}
void QuicConnection::SetOnStreamReset(OnStreamResetCallback){}
void QuicConnection::SetOnStreamStopSending(OnStreamStopSendingCallback){}
}
namespace {
void Connect(Http3AsyncClient& client){
    client.connection_=std::make_unique<esp_http3::QuicConnection>([](const uint8_t*,size_t n){return static_cast<int>(n);},esp_http3::QuicConfig{});
    client.connection_->SetOnDisconnected([&client](int code,const std::string& reason){client.OnDisconnected(code,reason);});
    client.connected_=true;
    client.needs_cleanup_.store(false);
    client.stop_tasks_.store(false);
}
std::unique_ptr<Http3Stream> Open(Http3AsyncClient& c){Http3Request request;request.path="/test";request.streaming_upload=true;return c.Open(request);}
void ResponseBeforeRegistration(){
    Http3AsyncClient c({});Connect(c);
    std::thread response;
    send_hook=[&]{response=std::thread([&]{std::lock_guard<std::mutex> lock(c.connection_mutex_);c.OnResponse(0,{200,{},"",false});const uint8_t body[]={42};c.OnStreamData(0,body,sizeof(body),true);});};
    // The original client allocates its receive buffer after releasing the
    // transport lock. Deliver the response entirely in that exposed interval.
    allocation_hook=[&](size_t n){if(n==c.GetConfig().receive_buffer_size&&response.joinable())response.join();};
    auto stream=Open(c);
    allocation_hook={};send_hook={};if(response.joinable())response.join();
    assert(stream);
    int status=-1;
    assert(stream->TryGetStatus(status)==Http3StreamStatusPollResult::kReady&&status==200);
    uint8_t body=0;size_t count=0;
    assert(stream->TryRead(&body,1,count)==Http3StreamReadPollResult::kData&&count==1&&body==42);
}
void ReconnectKeepsNewStream(){
    auto c=std::make_unique<Http3AsyncClient>(Http3AsyncClientConfig{});Connect(*c);
    auto old=Open(*c);assert(old&&old->GetStreamId()==0);
    c->Disconnect();Connect(*c);
    auto current=Open(*c);assert(current&&current->GetStreamId()==0);
    writes=finishes=resets=0;
    uint8_t body=42;
    assert(old->Write(&body,1,1)<0);
    assert(!old->Finish());
    assert(writes==0&&finishes==0);
    old->Close();
    assert(resets==0);
    assert(c->streams_.at(0)==current.get());
    // Both previous- and current-generation stream handles may outlive client.
    c.reset();old.reset();current.reset();
}
void ReconnectCloseKeepsNewStream(){
    Http3AsyncClient c({});Connect(c);
    auto old=Open(c);assert(old);
    c.Disconnect();Connect(c);
    auto current=Open(c);assert(current&&current->GetStreamId()==old->GetStreamId());
    resets=0;
    old->Close();
    assert(resets==0);
    assert(c.streams_.count(0)==1&&c.streams_.at(0)==current.get());
}
void DetachedStreamOutlivesClient(){
    auto c=std::make_unique<Http3AsyncClient>(Http3AsyncClientConfig{});Connect(*c);
    auto old=Open(*c);assert(old);
    c->Disconnect();Connect(*c);
    auto current=Open(*c);assert(current);
    current.reset();
    c.reset();
    old.reset();
}
void FailedWriteIsError(){
    Http3AsyncClient c({});Connect(c);auto stream=Open(c);assert(stream);
    write_result=-1;
    const uint8_t body=42;
    const int result=stream->Write(&body,1,10);
    write_result=1;
    assert(result<0);
    assert(!stream->IsValid());
    assert(stream->GetError()=="Failed to write request body");
    assert(c.write_queues_.empty());
}
void FailedQueuedFinishIsError(){
    Http3AsyncClient c({});Connect(c);auto stream=Open(c);assert(stream);
    write_result=0;
    assert(c.StreamWrite(0,esp_http3::Http3Vector<uint8_t>{42}));
    assert(c.StreamFinish(0));
    write_result=1;finish_result=false;
    c.ProcessAllWriteQueues();
    finish_result=true;
    assert(!stream->IsValid());
    assert(stream->GetError()=="Failed to finish request body");
    assert(c.write_queues_.empty());
}
}
int main(int argc,char** argv){std::string test=argc>1?argv[1]:"all";if(test=="registration"||test=="all")ResponseBeforeRegistration();if(test=="reconnect"||test=="all")ReconnectKeepsNewStream();if(test=="reconnect_close"||test=="all")ReconnectCloseKeepsNewStream();if(test=="detached"||test=="all")DetachedStreamOutlivesClient();if(test=="write"||test=="all")FailedWriteIsError();if(test=="finish"||test=="all")FailedQueuedFinishIsError();std::puts("client lifecycle regressions passed");}
