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
#include <zlib.h>
#include "miniz.h"
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
size_t acknowledged=0;
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
void QuicConnection::AcknowledgeStreamData(int,size_t bytes){acknowledged+=bytes;}
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
void CloseRacingResponseFin(){
    Http3AsyncClient c({});Connect(c);auto stream=Open(c);assert(stream);
    std::mutex ready_mutex;
    std::condition_variable ready_condition;
    bool closing=false;
    struct ReadyContext {
        std::mutex* mutex;
        std::condition_variable* condition;
        bool* closing;
    } ready{&ready_mutex,&ready_condition,&closing};
    stream->SetReadReadySink([](void* context){
        auto* ready=static_cast<ReadyContext*>(context);
        std::lock_guard<std::mutex> lock(*ready->mutex);
        *ready->closing=true;
        ready->condition->notify_one();
    },&ready);
    resets=0;
    std::unique_lock<std::mutex> connection_lock(c.connection_mutex_);
    std::thread close([&]{stream->Close();});
    {
        std::unique_lock<std::mutex> lock(ready_mutex);
        assert(ready_condition.wait_for(lock,std::chrono::seconds(2),[&]{return closing;}));
    }
    assert(stream->closed_.load());
    // The real event loop completes FIN and transport cleanup while holding
    // this lock, after Close marks the handle closed but before unregistering.
    c.OnStreamData(0,nullptr,0,true);
    connection_lock.unlock();
    close.join();
    assert(resets==0);
    assert(stream->finished_receiving_.load());
    assert(c.streams_.empty());
}
void CancelUnfinishedResponseStillResets(){
    Http3AsyncClient c({});Connect(c);auto stream=Open(c);assert(stream);
    resets=0;
    stream->Close();
    assert(resets==1);
    assert(c.streams_.empty());
}

std::vector<uint8_t> Gzip(const std::string& text) {
    z_stream z{};
    assert(deflateInit2(&z,6,Z_DEFLATED,MAX_WBITS+16,8,Z_DEFAULT_STRATEGY)==Z_OK);
    std::vector<uint8_t> out(deflateBound(&z,text.size()));
    z.next_in=reinterpret_cast<Bytef*>(const_cast<char*>(text.data()));z.avail_in=text.size();
    z.next_out=out.data();z.avail_out=out.size();
    assert(deflate(&z,Z_FINISH)==Z_STREAM_END);
    out.resize(z.total_out);deflateEnd(&z);return out;
}
std::unique_ptr<Http3Stream> OpenDecoded(Http3AsyncClient& c,size_t limit=512*1024,bool decode=true,
                                       const std::string& method="GET") {
    Http3Request request;request.path="/gzip";request.method=method;request.decode_gzip_response=decode;request.decoded_body_limit=limit;
    return c.Open(request);
}
void DeliverHeaders(Http3AsyncClient& c,Http3Stream& stream,const std::string& encoding,size_t wire_size) {
    c.OnResponse(stream.GetStreamId(),{200,{{"content-encoding",encoding},{"content-length",std::to_string(wire_size)}},"",false});
}
Http3StreamReadPollResult Drain(Http3Stream& stream,std::string& output,size_t buffer_size=17) {
    std::vector<uint8_t> buffer(buffer_size);
    for(size_t calls=0;calls<200000;++calls) {
        size_t size=0;auto result=stream.TryRead(buffer.data(),buffer.size(),size);
        if(result!=Http3StreamReadPollResult::kData)return result;
        assert(size>0&&size<=buffer_size);
        output.append(reinterpret_cast<const char*>(buffer.data()),size);
    }
    assert(false&&"decoder did not make progress");return Http3StreamReadPollResult::kError;
}
void GzipChunkedAndFin() {
    Http3AsyncClientConfig config;config.receive_buffer_size=53;
    Http3AsyncClient c(config);Connect(c);auto stream=OpenDecoded(c);assert(stream);
    std::string text;for(size_t i=0;i<7000;++i)text+="中文Markdown **安全带** "+std::to_string(i%43)+"\n";
    const auto compressed=Gzip(text);DeliverHeaders(c,*stream," GZip\t",compressed.size());
    acknowledged=0;std::string actual;
    for(size_t offset=0;offset<compressed.size();) {
        const size_t size=std::min<size_t>(7,compressed.size()-offset);
        c.OnStreamData(stream->GetStreamId(),compressed.data()+offset,size,false);offset+=size;
        assert(Drain(*stream,actual)==Http3StreamReadPollResult::kPending);
    }
    assert(actual==text); // decoded data is available before response FIN.
    assert(acknowledged==compressed.size());
    assert(stream->GetHeader("content-length")==std::to_string(compressed.size()));
    assert(stream->GetHeader("content-encoding")==" GZip\t");
    c.OnStreamData(stream->GetStreamId(),nullptr,0,true);
    assert(Drain(*stream,actual)==Http3StreamReadPollResult::kFinished);
    const auto metrics=stream->GetBodyStatistics();
    assert(metrics.wire_received_bytes==compressed.size());
    assert(metrics.wire_consumed_bytes==compressed.size()&&metrics.decoded_bytes==text.size());
    assert(metrics.first_wire_at_us>0&&metrics.wire_finished_at_us>=metrics.first_wire_at_us);
    resets=0;stream->Close();assert(resets==0&&c.IsConnected());
}
std::vector<uint8_t> OptionalHeader(const std::vector<uint8_t>& gzip) {
    std::vector<uint8_t> out(gzip.begin(),gzip.begin()+10);out[3]=2|4|8|16;
    out.insert(out.end(),{3,0,1,2,3,'f','i','l','e',0,'c','o','m','m','e','n','t',0});
    const uint32_t crc=crc32(0,out.data(),out.size());
    out.push_back(crc&255);out.push_back((crc>>8)&255);
    out.insert(out.end(),gzip.begin()+10,gzip.end());return out;
}
void GzipMembersAndHeader() {
    Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);assert(stream);
    auto wire=OptionalHeader(Gzip("第一段"));const auto second=Gzip("第二段");
    wire.insert(wire.end(),second.begin(),second.end());DeliverHeaders(c,*stream,"gzip",wire.size());
    std::string actual;
    for(size_t offset=0;offset<wire.size();++offset) {
        c.OnStreamData(stream->GetStreamId(),wire.data()+offset,1,offset+1==wire.size());
        const auto result=Drain(*stream,actual,1);
        assert(result==(offset+1==wire.size()?Http3StreamReadPollResult::kFinished:Http3StreamReadPollResult::kPending));
    }
    assert(actual=="第一段第二段");
}
void MustFailGzip(const std::vector<uint8_t>& wire,size_t limit=512*1024,const std::string& error="") {
    Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,limit);assert(stream);
    DeliverHeaders(c,*stream,"gzip",wire.size());
    c.OnStreamData(stream->GetStreamId(),wire.data(),wire.size(),true);
    std::string actual;assert(Drain(*stream,actual)==Http3StreamReadPollResult::kError);
    assert(!stream->IsValid()&&!stream->GetError().empty());
    if(!error.empty())assert(stream->GetError()==error);
    // Payload failure after transport FIN must not reset a completed QUIC stream.
    resets=0;stream->Close();assert(resets==0&&c.IsConnected());
}
void GzipCorruptionAndBounds() {
    const auto valid=Gzip(std::string(90000,'x'));
    // Every possible truncation of this member must fail, including no header,
    // partial deflate and a partial trailer. Test valid stream separately.
    for(size_t cut=0;cut<valid.size();++cut)MustFailGzip({valid.begin(),valid.begin()+cut});
    auto corrupt=valid;corrupt[corrupt.size()-8]^=1;MustFailGzip(corrupt,512*1024,"Gzip body CRC mismatch");
    corrupt=valid;corrupt.back()^=1;MustFailGzip(corrupt,512*1024,"Gzip body size mismatch");
    corrupt=valid;corrupt[3]|=0x20;MustFailGzip(corrupt,512*1024,"Invalid gzip header");
    corrupt=OptionalHeader(valid);corrupt[28]^=1;MustFailGzip(corrupt,512*1024,"Gzip header CRC mismatch");
    corrupt=valid;corrupt.push_back(1);MustFailGzip(corrupt);
    MustFailGzip(valid,89999,"Decoded gzip body exceeds limit");
    auto empty=Gzip("");Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,0);
    DeliverHeaders(c,*stream,"gzip",empty.size());c.OnStreamData(0,empty.data(),empty.size(),true);
    std::string actual;assert(Drain(*stream,actual)==Http3StreamReadPollResult::kFinished&&actual.empty());
}
void EncodingCompatibility() {
    for(const auto& encoding:std::vector<std::string>{"","identity"}) {
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);
        DeliverHeaders(c,*stream,encoding,4);const uint8_t body[]={1,2,3,4};c.OnStreamData(0,body,4,true);
        uint8_t out[4]{};assert(stream->Read(out,sizeof(out),1)==4&&!memcmp(body,out,4));
        assert(stream->Read(out,sizeof(out),1)==0&&stream->GetBodyStatistics().inflate_us==0);
    }
    for(const auto& encoding:std::vector<std::string>{"br","zstd","gzip, identity"}) {
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);
        DeliverHeaders(c,*stream,encoding,0);c.OnStreamData(0,nullptr,0,true);
        std::string actual;assert(Drain(*stream,actual)==Http3StreamReadPollResult::kError);
        assert(stream->GetError()=="Unsupported response Content-Encoding");
    }
    {
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);
        c.OnResponse(0,{200,{{"Content-Encoding","gzip"},{"content-encoding","identity"}},"",false});
        c.OnStreamData(0,nullptr,0,true);std::string actual;
        assert(Drain(*stream,actual)==Http3StreamReadPollResult::kError);
        assert(stream->GetBodyStatistics().first_wire_at_us==0&&stream->GetBodyStatistics().wire_finished_at_us>0);
    }
    {
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);
        const std::string text="blocking Read also decodes gzip";const auto wire=Gzip(text);
        DeliverHeaders(c,*stream,"gzip",wire.size());c.OnStreamData(0,wire.data(),wire.size(),true);
        uint8_t out[7]{};std::string actual;int size=0;
        while((size=stream->Read(out,sizeof(out),1))>0)actual.append(reinterpret_cast<const char*>(out),size);
        assert(size==0&&actual==text);
    }
    {
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,3);
        DeliverHeaders(c,*stream,"identity",4);const uint8_t bytes[]={1,2,3,4};c.OnStreamData(0,bytes,4,true);
        std::string actual;assert(Drain(*stream,actual)==Http3StreamReadPollResult::kError);
        assert(stream->GetError()=="Decoded response body exceeds limit");
    }
    const auto wire=Gzip("raw audio consumer");
    Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,512*1024,false);
    DeliverHeaders(c,*stream,"gzip",wire.size());c.OnStreamData(0,wire.data(),wire.size(),true);
    std::string actual;assert(Drain(*stream,actual)==Http3StreamReadPollResult::kFinished);
    assert(actual==std::string(reinterpret_cast<const char*>(wire.data()),wire.size()));
    assert(stream->GetBodyStatistics().inflate_us==0);
}
void NoContentResponses() {
    for(const auto& response:std::vector<std::pair<std::string,int>>{{"HEAD",200},{"GET",204},{"GET",304}}) {
        for(const auto& encoding:std::vector<std::string>{"gzip","zstd"}) {
            Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,0,true,response.first);
            c.OnResponse(0,{response.second,{{"content-encoding",encoding},{"content-length","123"}},"",false});
            std::string actual;
            assert(Drain(*stream,actual)==Http3StreamReadPollResult::kPending);
            c.OnStreamData(0,nullptr,0,true);
            assert(Drain(*stream,actual)==Http3StreamReadPollResult::kFinished&&actual.empty());
            assert(stream->GetHeader("content-length")=="123"&&stream->gzip_decoder_==nullptr);
            const auto metrics=stream->GetBodyStatistics();
            assert(metrics.wire_received_bytes==0&&metrics.wire_consumed_bytes==0&&metrics.decoded_bytes==0);
            assert(metrics.inflate_us==0&&metrics.first_wire_at_us==0&&metrics.wire_finished_at_us>0);
            resets=0;stream->Close();assert(resets==0&&c.IsConnected());
        }
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c,0,true,response.first);
        c.OnResponse(0,{response.second,{{"content-encoding","gzip"}},"",false});
        const uint8_t byte=42;c.OnStreamData(0,&byte,1,true);std::string actual;
        assert(Drain(*stream,actual)==Http3StreamReadPollResult::kError);
        assert(stream->GetError()=="Unexpected body for no-content response"&&stream->gzip_decoder_==nullptr);
    }
}
#ifdef HTTP3_HOST_TINFL_TEST_ADAPTER
void GzipLegacyReadAhead() {
    for(bool deferred:std::vector<bool>{false,true}) {
        host_tinfl_legacy_lookahead=true;host_tinfl_legacy_defer_done=deferred;
        host_tinfl_prefetched_bytes=host_tinfl_deferred_completions=0;
        std::string text;for(size_t i=0;i<20;++i)text+="旧版 ROM tinfl 会提前读取 gzip trailer\n";
        const auto wire=Gzip(text);const size_t prefix_size=wire.size()-6;
        Http3AsyncClient c({});Connect(c);auto stream=OpenDecoded(c);
        DeliverHeaders(c,*stream,"gzip",wire.size());acknowledged=0;
        // The first chunk includes two CRC bytes. Deferred DONE receives no
        // input at all, so rewinding only the current input cannot recover them.
        c.OnStreamData(0,wire.data(),prefix_size,false);std::string actual;
        assert(Drain(*stream,actual,11)==Http3StreamReadPollResult::kPending&&actual==text);
        assert(host_tinfl_prefetched_bytes==2);
        assert(host_tinfl_deferred_completions==(deferred?1u:0u));
        assert(acknowledged==prefix_size&&stream->GetBodyStatistics().wire_consumed_bytes==prefix_size);
        c.OnStreamData(0,wire.data()+prefix_size,6,true);
        assert(Drain(*stream,actual)==Http3StreamReadPollResult::kFinished&&actual==text);
        assert(acknowledged==wire.size()&&stream->GetBodyStatistics().wire_consumed_bytes==wire.size());
        auto corrupt=wire;corrupt[corrupt.size()-8]^=1;
        MustFailGzip(corrupt,512*1024,"Gzip body CRC mismatch");
        GzipChunkedAndFin();GzipMembersAndHeader();GzipCorruptionAndBounds();
    }
    host_tinfl_legacy_lookahead=host_tinfl_legacy_defer_done=false;
}
#endif
}
int main(int argc,char** argv){std::string test=argc>1?argv[1]:"all";if(test=="registration"||test=="all")ResponseBeforeRegistration();if(test=="reconnect"||test=="all")ReconnectKeepsNewStream();if(test=="reconnect_close"||test=="all")ReconnectCloseKeepsNewStream();if(test=="detached"||test=="all")DetachedStreamOutlivesClient();if(test=="write"||test=="all")FailedWriteIsError();if(test=="finish"||test=="all")FailedQueuedFinishIsError();if(test=="close_fin"||test=="all")CloseRacingResponseFin();if(test=="cancel"||test=="all")CancelUnfinishedResponseStillResets();if(test=="gzip_chunks"||test=="all")GzipChunkedAndFin();if(test=="gzip_members"||test=="all")GzipMembersAndHeader();if(test=="gzip_errors"||test=="all")GzipCorruptionAndBounds();if(test=="encoding"||test=="all")EncodingCompatibility();if(test=="no_content"||test=="all")NoContentResponses();
#ifdef HTTP3_HOST_TINFL_TEST_ADAPTER
if(test=="gzip_legacy"||test=="all")GzipLegacyReadAhead();
#endif
std::puts("client lifecycle and gzip regressions passed");}
