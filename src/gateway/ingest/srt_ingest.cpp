#include "gateway/ingest/srt_ingest.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <future>
#include <memory>
#include <utility>

#include <arpa/inet.h>

namespace websrt::gateway
{

namespace
{

// SRTO_RCVBUF and the UDP socket buffers are in BYTES; srt converts with the
// UDP header size (1500 - 28 = 1472) - the same trap srt_initiator.cpp and
// the oracle's receiver.buffer_size (srt_listener.rs:54) spell out.
constexpr int kBytesPerPacket = 1500 - 28;

// The oracle's UDP_BUF_SIZE (srt_listener.rs:12): 8 MB. The srt default is
// only 64 KB, ~57 ms of OBS data - easily overflowed when the process is
// briefly starved.
constexpr int kUdpBufBytes = 8 * 1024 * 1024;

// How long the ingest thread's srt_epoll_wait blocks before it re-reads the
// stop flag. Bounds Stop() latency; nothing else is timed off it.
constexpr int kPollTimeoutMs = 100;

// Ready-set ceiling for one srt_epoll_wait: the listener plus the publishers.
constexpr int kMaxPollFds = 64;

// Accept backlog.
constexpr int kListenBacklog = 64;

// SRTO_STREAMID is a 512-byte field in the fork's config (MAX_SID_LENGTH)
// and the getter NUL-terminates into the caller's buffer.
constexpr int kStreamIdBufBytes = 513;

// srt_recvmsg silently copies only what fits and reports nothing (see
// CRcvBuffer::readMessage, "small dst buffer, copied only X/Y"), so the
// per-connection receive buffer must hold the largest message a publisher
// may send whole. OBS/ffmpeg send one muxed packet cluster (<= 1316 B); 1
// MiB is a generous ceiling that keeps one connection's footprint sane.
constexpr std::size_t kRecvBufBytes = std::size_t{1024} * 1024;

// MPEG-TS packet size - every framed message is a whole number of these
// (libwebsrt's kTsPacketSize, publisher.h:103).
constexpr std::size_t kTsPacketSize = 188;

void Log(const char* fmt, ...)
{
    std::fputs("srt-ingest: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

bool SetOptInt(SRTSOCKET u, SRT_SOCKOPT opt, int value)
{
    return srt_setsockopt(u, 0, opt, &value, sizeof value) != SRT_ERROR;
}

bool SetOptString(SRTSOCKET u, SRT_SOCKOPT opt, const std::string& value)
{
    return srt_setsockopt(u, 0, opt, value.data(), static_cast<int>(value.size())) != SRT_ERROR;
}

void Bump(std::atomic<std::uint64_t>& counter, std::uint64_t by = 1)
{
    counter.fetch_add(by, std::memory_order_relaxed);
}

} // namespace

std::int64_t RecvBufferPackets(std::uint64_t latency_ms) noexcept
{
    // srt_listener.rs:22-25 verbatim: (ms * 20_000 / 1000 * 2).clamp(8192, 320_000).
    // At the 120 ms default that is 4800 -> the 8192 floor; the 320000
    // ceiling is reached at 8000 ms.
    const std::uint64_t pkts = latency_ms * 20'000 / 1'000 * 2;
    return static_cast<std::int64_t>(std::clamp<std::uint64_t>(pkts, 8'192, 320'000));
}

SrtIngest::SrtIngest(SrtIngestConfig config, Sink sink, websrt::EventLoop& loop)
    : config_(std::move(config))
    , sink_(std::move(sink))
    , loop_(loop)
{
    std::memset(&local_, 0, sizeof local_);
    local_.sin_family = AF_INET;
    if (config_.bind.empty() || ::inet_pton(AF_INET, config_.bind.c_str(), &local_.sin_addr) != 1)
    {
        local_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    local_.sin_port = htons(config_.port);
}

SrtIngest::~SrtIngest()
{
    Stop();
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

bool SrtIngest::Start(std::string* error)
{
    if (running_.load(std::memory_order_relaxed))
    {
        *error = "already started";
        return false;
    }
    if (!SetupListener(error))
    {
        CloseAllSockets();
        return false;
    }
    stop_.store(false, std::memory_order_relaxed);
    thread_ = std::thread([this] { ThreadMain(); });
    running_.store(true, std::memory_order_relaxed);
    Log("listening on %s:%u (latency %llu ms, recv buffer %lld pkts, encrypted=%s)",
        config_.bind.c_str(),
        ntohs(local_.sin_port),
        static_cast<unsigned long long>(config_.latency_ms),
        static_cast<long long>(RecvBufferPackets(config_.latency_ms)),
        config_.passphrase.has_value() ? "yes" : "no");
    return true;
}

void SrtIngest::Stop()
{
    if (!running_.exchange(false))
    {
        return;
    }
    stop_.store(true, std::memory_order_relaxed);
    if (thread_.joinable())
    {
        thread_.join();
    }
    // The thread returns without touching its sockets; drain them here, on
    // the caller's thread, so no socket outlives the class. EndConn also
    // releases each publisher's claim, which closes that stream's viewers.
    while (!conns_.empty())
    {
        EndConn(conns_.begin()->first, "ingest shutdown");
    }
    CloseAllSockets();
    Log("stopped: %llu publisher(s) accepted, %llu rejected, %llu message(s) in, %llu chunk(s) out",
        accepted_.load(std::memory_order_relaxed),
        rejected_.load(std::memory_order_relaxed),
        messages_in_.load(std::memory_order_relaxed),
        chunks_out_.load(std::memory_order_relaxed));
}

bool SrtIngest::SetupListener(std::string* error)
{
    do
    {
        // libsrt's runtime is process-global and refcounted; holding a
        // reference keeps another holder's srt_cleanup() (libwebsrt client
        // sessions do exactly that on teardown) from stopping the garbage
        // collector and force-breaking this listener.
        if (srt_startup() < 0)
        {
            *error = "srt_startup failed";
            break;
        }
        srt_runtime_ = true;

        listener_ = srt_create_socket();
        if (listener_ == SRT_INVALID_SOCK)
        {
            *error = std::string("srt_create_socket: ") + srt_getlasterror_str();
            break;
        }

        // SRTO_TRANSTYPE first: it resets the live presets.
        const bool live = SetOptInt(listener_, SRTO_TRANSTYPE, SRTT_LIVE) &&
                          SetOptInt(listener_, SRTO_LATENCY, static_cast<int>(config_.latency_ms));
        if (!live)
        {
            *error = std::string("srt socket option (transtype/latency): ") + srt_getlasterror_str();
            break;
        }

        // Latency-scaled receiver buffer, raised in lockstep with the
        // flow-control window: srt clamps SRTO_RCVBUF to the CURRENT SRTO_FC
        // when it is set (RcvBufferSizeOptionToValue), so FC has to be
        // raised FIRST or RCVBUF silently stays at the 8192-packet preset.
        const std::int64_t pkts = RecvBufferPackets(config_.latency_ms);
        if (!SetOptInt(listener_, SRTO_FC, static_cast<int>(pkts)) ||
            !SetOptInt(listener_, SRTO_RCVBUF, static_cast<int>(pkts * kBytesPerPacket)) ||
            !SetOptInt(listener_, SRTO_UDP_RCVBUF, kUdpBufBytes) ||
            !SetOptInt(listener_, SRTO_UDP_SNDBUF, kUdpBufBytes))
        {
            *error = std::string("srt socket option (buffers): ") + srt_getlasterror_str();
            break;
        }

        // Inherited by the accepted sockets: receiving never blocks (readiness
        // comes from srt_epoll), so the ingest thread is never parked inside
        // srt and Stop() is observed within one poll slice.
        if (!SetOptInt(listener_, SRTO_RCVSYN, 0) || !SetOptInt(listener_, SRTO_SNDTIMEO, 0))
        {
            *error = std::string("srt socket option (non-blocking): ") + srt_getlasterror_str();
            break;
        }

        // Encryption. The oracle hands the passphrase to every accept
        // (srt_listener.rs:40, 96); libwebsrt builds its srt fork with
        // ENABLE_ENCRYPTION=OFF, where the library itself rejects a non-empty
        // SRTO_PASSPHRASE (socketconfig.cpp: "encryption not enabled at
        // compile time"). Fail loudly rather than listen unencrypted behind
        // the operator's back.
        if (config_.passphrase.has_value() && !SetOptString(listener_, SRTO_PASSPHRASE, *config_.passphrase))
        {
            *error = "srt_passphrase needs an srt build with encryption enabled (this build has "
                     "ENABLE_ENCRYPTION=OFF); SRTO_PASSPHRASE: " +
                     std::string{srt_getlasterror_str()};
            break;
        }

        if (srt_bind(listener_, reinterpret_cast<const sockaddr*>(&local_), sizeof local_) == SRT_ERROR)
        {
            *error = std::string("srt_bind ") + config_.bind + ":" + std::to_string(config_.port) + ": " +
                     srt_getlasterror_str();
            break;
        }
        int              bound_len = sizeof local_;
        sockaddr_storage bound{};
        bound_len = sizeof bound;
        if (srt_getsockname(listener_, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0)
        {
            local_.sin_port = reinterpret_cast<const sockaddr_in*>(&bound)->sin_port;
        }
        if (srt_listen(listener_, kListenBacklog) == SRT_ERROR)
        {
            *error = std::string("srt_listen: ") + srt_getlasterror_str();
            break;
        }

        epoll_ = srt_epoll_create();
        if (epoll_ == SRT_ERROR)
        {
            *error = std::string("srt_epoll_create: ") + srt_getlasterror_str();
            break;
        }
        const int events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
        if (srt_epoll_add_usock(epoll_, listener_, &events) == SRT_ERROR)
        {
            *error = std::string("srt_epoll_add_usock(listener): ") + srt_getlasterror_str();
            break;
        }
        return true;
    } while (false);

    CloseAllSockets();
    return false;
}

void SrtIngest::CloseAllSockets()
{
    if (listener_ != SRT_INVALID_SOCK)
    {
        // No explicit srt_epoll_remove_usock: srt_close drops the socket
        // from every epoll it is subscribed to (CUDT::closeInternal), and
        // doing it twice makes the library log a spurious error.
        srt_close(listener_);
        listener_ = SRT_INVALID_SOCK;
    }
    if (epoll_ != SRT_ERROR)
    {
        srt_epoll_release(epoll_);
        epoll_ = SRT_ERROR;
    }
    // Released only once every socket of ours is closed - a stray srt_close
    // racing the reference drop would be force-broken by the collector.
    if (srt_runtime_)
    {
        srt_cleanup();
        srt_runtime_ = false;
    }
}

// ---------------------------------------------------------------------------
// ingest thread
// ---------------------------------------------------------------------------

void SrtIngest::ThreadMain()
{
    while (!stop_.load(std::memory_order_relaxed))
    {
        SRTSOCKET ready[kMaxPollFds];
        int       ready_len = kMaxPollFds;
        const int n         = srt_epoll_wait(
            epoll_, ready, &ready_len, nullptr, nullptr, kPollTimeoutMs, nullptr, nullptr, nullptr, nullptr);
        if (n < 0)
        {
            // srt reports a poll TIMEOUT as -1/SRT_ETIMEOUT (CEPoll::wait
            // throws MJ_AGAIN/MN_XMTIMEOUT), not as 0 - that is the normal
            // "nothing ready" wakeup, not a failure.
            const int err = srt_getlasterror(nullptr);
            if (err == SRT_ETIMEOUT || err == SRT_EASYNCRCV || stop_.load(std::memory_order_relaxed))
            {
                continue;
            }
            Log("srt_epoll_wait failed: %s", srt_getlasterror_str());
            break;
        }
        for (int i = 0; i < ready_len; ++i)
        {
            HandleReady(ready[i]);
        }
        RefreshSnapshot();
    }
}

void SrtIngest::HandleReady(SRTSOCKET sock)
{
    if (sock == listener_)
    {
        AcceptOne();
        return;
    }
    if (!conns_.contains(sock))
    {
        return;
    }
    const SRT_SOCKSTATUS state = srt_getsockstate(sock);
    if (state == SRTS_CONNECTING)
    {
        return; // the handshake is still running; SRT_EPOLL_ERR woke us, not data
    }
    if (state != SRTS_CONNECTED)
    {
        EndConn(sock, "srt socket state " + std::to_string(static_cast<int>(state)));
        return;
    }
    Drain(sock);
}

std::string SrtIngest::StreamIdOf(SRTSOCKET sock)
{
    char buf[kStreamIdBufBytes];
    int  len = sizeof buf;
    if (srt_getsockopt(sock, 0, SRTO_STREAMID, buf, &len) == SRT_ERROR || len <= 0)
    {
        return {};
    }
    return {buf, static_cast<std::size_t>(len)};
}

std::string SrtIngest::PeerText(const sockaddr_storage& peer)
{
    char        host[INET6_ADDRSTRLEN] = {};
    const auto* in4                    = reinterpret_cast<const sockaddr_in*>(&peer);
    if (in4->sin_family != AF_INET || ::inet_ntop(AF_INET, &in4->sin_addr, host, sizeof host) == nullptr)
    {
        return "unknown";
    }
    return std::string{host} + ":" + std::to_string(ntohs(in4->sin_port));
}

void SrtIngest::AcceptOne()
{
    sockaddr_storage peer{};
    int              peer_len = sizeof peer;
    const SRTSOCKET  ns       = srt_accept(listener_, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (ns == SRT_INVALID_SOCK)
    {
        Log("srt_accept failed: %s", srt_getlasterror_str());
        return;
    }

    // The oracle refuses a publisher with no streamid (srt_listener.rs:92-95)
    // - never a "default" name. The streamid only exists on the accepted
    // socket, so this is where the refusal happens; closing it ends the
    // caller's connection.
    const std::string stream = StreamIdOf(ns);
    if (stream.empty())
    {
        Bump(rejected_);
        Bump(rejected_sid_);
        Log("rejected publisher from %s: no streamid", PeerText(peer).c_str());
        srt_close(ns);
        return;
    }
    // The policy half of the WT accept path: the allowlist decides whether
    // this name may be published at all (PLAN.md refinement item 2 - an
    // ingest publisher that no [[stream]] entry with publish = true covers
    // is refused, the connection-refused analogue of the WT 403).
    if (!GateOnLoop(stream))
    {
        Bump(rejected_);
        Bump(rejected_gate_);
        Log("rejected publisher from %s: publish not allowed on stream '%s'", PeerText(peer).c_str(), stream.c_str());
        srt_close(ns);
        return;
    }
    // The occupancy half: the oracle's registry.try_publish_ingester
    // (srt_listener.rs:106). Refused while a live publisher - a WebTransport
    // session or another ingest connection - holds the name.
    if (!ClaimOnLoop(stream))
    {
        Bump(rejected_);
        Bump(rejected_occ_);
        Log("rejected publisher from %s: stream '%s' is already live", PeerText(peer).c_str(), stream.c_str());
        srt_close(ns);
        return;
    }

    const std::string   remote     = PeerText(peer);
    const std::uint64_t session_id = next_webhook_session_id_++;
    // Fresh per-name continuity counters: the oracle inserts a new
    // TsStatsHandle at connection setup (main.rs:562-568), replacing any
    // frozen entry a previous publisher on this name left behind.
    stream_cc_[stream] = TsCcStats{};
    Conn conn;
    conn.sock       = ns;
    conn.stream     = stream;
    conn.remote     = remote;
    conn.session_id = session_id;
    conn.recv_buf.resize(kRecvBufBytes);
    conns_.emplace(ns, std::move(conn));
    Bump(accepted_);

    const int events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
    if (srt_epoll_add_usock(epoll_, ns, &events) == SRT_ERROR)
    {
        EndConn(ns, std::string{"srt_epoll_add_usock: "} + srt_getlasterror_str());
        return;
    }
    Log("publisher connected: stream '%s' from %s", stream.c_str(), remote.c_str());
    // P4.3 webhook - the ingest's publisher_connect (enqueue-only; the
    // gateway's dispatcher owns delivery on its own thread).
    if (sink_.webhook)
    {
        sink_.webhook(WebhookEvent{.event      = "publisher_connect",
                                   .stream     = stream,
                                   .role       = "publisher",
                                   .remote     = remote,
                                   .session_id = session_id});
    }
}

void SrtIngest::Drain(SRTSOCKET sock)
{
    for (;;)
    {
        const auto it = conns_.find(sock);
        if (it == conns_.end())
        {
            return;
        }
        Conn&     conn = it->second;
        const int n    = srt_recvmsg(sock, conn.recv_buf.data(), static_cast<int>(conn.recv_buf.size()));
        if (n > 0)
        {
            Bump(messages_in_);
            Bump(bytes_in_, static_cast<std::uint64_t>(n));
            ++conn.messages_in;
            conn.bytes_in += static_cast<std::uint64_t>(n);
            FeedAndChunk(
                sock, reinterpret_cast<const std::uint8_t*>(conn.recv_buf.data()), static_cast<std::size_t>(n));
            continue;
        }
        const int err = srt_getlasterror(nullptr);
        if (err == SRT_EASYNCRCV || err == SRT_ETIMEOUT)
        {
            return; // nothing released yet; TSBPD wakes the epoll again
        }
        EndConn(sock, std::string{"srt_recvmsg: "} + srt_getlasterror_str());
        return;
    }
}

void SrtIngest::FeedAndChunk(SRTSOCKET sock, const std::uint8_t* data, std::size_t len)
{
    const auto it = conns_.find(sock);
    if (it == conns_.end())
    {
        return;
    }
    Conn& conn = it->second;
    conn.pending.insert(conn.pending.end(), data, data + len);

    // TsChunker framing, ported from libwebsrt's publisher
    // (publisher.cpp:69-80): each message is the largest whole multiple of
    // 188 that fits the payload size, and a sub-188 remainder carries over
    // between messages. Messages must be TS-aligned and <= the payload
    // ceiling because the viewers drop anything larger than what they
    // negotiated (Broadcaster::Pump: never truncate, never retry).
    const std::size_t per_msg = static_cast<std::size_t>(config_.payload_size) / kTsPacketSize;
    std::size_t       emitted = 0;
    for (;;)
    {
        const std::size_t whole_ts = (conn.pending.size() - emitted) / kTsPacketSize;
        if (whole_ts == 0)
        {
            break;
        }
        const std::size_t take = std::min(whole_ts, per_msg) * kTsPacketSize;
        PublishChunk(sock, conn.pending.data() + emitted, take);
        emitted += take;
    }
    if (emitted > 0)
    {
        conn.pending.erase(conn.pending.begin(), conn.pending.begin() + static_cast<std::ptrdiff_t>(emitted));
    }
}

void SrtIngest::PublishChunk(SRTSOCKET sock, const std::uint8_t* data, std::size_t len)
{
    const auto it = conns_.find(sock);
    if (it == conns_.end() || !sink_.publish)
    {
        return;
    }
    Conn& conn = it->second;
    ++conn.chunks_out;
    Bump(chunks_out_);
    Bump(bytes_out_, len);

    // The read-only TS-continuity probe (the oracle's TsContinuityChecker
    // wrapping its ingester): every published chunk is a whole number of
    // 188-byte packets, so this scans every complete TS packet exactly
    // once. Never modifies the bytes.
    conn.cc.Scan(data, len);
    stream_cc_[conn.stream] = conn.cc.Stats();

    // Hand the bytes to the gateway loop. The sink is COPIED into the
    // functor on purpose: a posted media chunk outlives this call and may
    // outlive the ingest itself, so it must not reach back into `this`.
    auto        publish = sink_.publish;
    auto        payload = std::make_shared<std::vector<std::uint8_t>>(data, data + len);
    std::string stream  = it->second.stream;
    loop_.Post([publish, stream = std::move(stream), payload] { publish(stream, payload->data(), payload->size()); });
}

void SrtIngest::EndConn(SRTSOCKET sock, const std::string& why)
{
    const auto it = conns_.find(sock);
    if (it == conns_.end())
    {
        return;
    }
    const std::string   stream     = it->second.stream;
    const std::string   remote     = it->second.remote;
    const std::uint64_t session_id = it->second.session_id;
    const std::uint64_t messages   = it->second.messages_in;
    const std::uint64_t bytes      = it->second.bytes_in;
    const std::uint64_t chunks     = it->second.chunks_out;

    // A sub-188 tail is not a whole TS packet, but dropping it would lose
    // bytes: libwebsrt's publisher flushes it on End()
    // (publisher.cpp:628-635) and so do we, then the viewers get their EOF.
    if (!it->second.pending.empty())
    {
        const std::size_t tail = it->second.pending.size();
        PublishChunk(sock, it->second.pending.data(), tail);
        Bump(tail_flushes_);
        Log("stream '%s': flushed a %zu-byte sub-188 tail before the publisher went away", stream.c_str(), tail);
    }

    ReleaseOnLoop(stream);
    // No explicit srt_epoll_remove_usock: srt_close drops the socket from
    // every epoll it is subscribed to (CUDT::closeInternal), and asking
    // twice makes the library log a spurious "not found" error.
    srt_close(sock);
    conns_.erase(it);
    Bump(ended_);
    Log("publisher disconnected: stream '%s' from %s (%llu message(s), %llu byte(s), %llu chunk(s); %s)",
        stream.c_str(),
        remote.c_str(),
        static_cast<unsigned long long>(messages),
        static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(chunks),
        why.c_str());
    // P4.3 webhook - the ingest's publisher_disconnect. Emitted after the
    // release round-trip so the matching publisher_end (EndPublish, on the
    // gateway loop) is observed after it.
    if (sink_.webhook)
    {
        sink_.webhook(WebhookEvent{.event      = "publisher_disconnect",
                                   .stream     = stream,
                                   .role       = "publisher",
                                   .remote     = remote,
                                   .session_id = session_id});
    }
}

void SrtIngest::RefreshSnapshot()
{
    std::vector<SrtConnectionStats> live;
    live.reserve(conns_.size());
    for (const auto& [_, conn] : conns_)
    {
        SrtConnectionStats s;
        s.stream      = conn.stream;
        s.remote      = conn.remote;
        s.bytes_in    = conn.bytes_in;
        s.messages_in = conn.messages_in;
        s.chunks_out  = conn.chunks_out;
        s.tail_bytes  = conn.pending.size();
        s.cc          = conn.cc.Stats();
        s.srt_stats   = srt_bstats(conn.sock, &s.srt, 0) == 0;
        live.push_back(std::move(s));
    }
    const std::lock_guard<std::mutex> lock(stats_mutex_);
    snapshot_           = std::move(live);
    stream_cc_snapshot_ = stream_cc_;
}

// ---------------------------------------------------------------------------
// evidence + loop-thread round-trips
// ---------------------------------------------------------------------------

SrtIngestStats SrtIngest::Stats() const
{
    const std::lock_guard<std::mutex> lock(stats_mutex_);
    SrtIngestStats                    out;
    out.publishers_accepted  = accepted_.load(std::memory_order_relaxed);
    out.publishers_rejected  = rejected_.load(std::memory_order_relaxed);
    out.rejected_no_streamid = rejected_sid_.load(std::memory_order_relaxed);
    out.rejected_not_allowed = rejected_gate_.load(std::memory_order_relaxed);
    out.rejected_occupied    = rejected_occ_.load(std::memory_order_relaxed);
    out.publishers_ended     = ended_.load(std::memory_order_relaxed);
    out.messages_in          = messages_in_.load(std::memory_order_relaxed);
    out.bytes_in             = bytes_in_.load(std::memory_order_relaxed);
    out.chunks_out           = chunks_out_.load(std::memory_order_relaxed);
    out.bytes_out            = bytes_out_.load(std::memory_order_relaxed);
    out.tail_flushes         = tail_flushes_.load(std::memory_order_relaxed);
    out.connections          = snapshot_;
    out.streams              = stream_cc_snapshot_;
    return out;
}

bool SrtIngest::GateOnLoop(const std::string& stream)
{
    if (!sink_.publish_gate)
    {
        return true;
    }
    if (!loop_.IsRunning())
    {
        return false;
    }
    std::promise<bool> done;
    auto               future = done.get_future();
    loop_.Post([this, &done, stream] { done.set_value(sink_.publish_gate(stream)); });
    return future.get();
}

bool SrtIngest::ClaimOnLoop(const std::string& stream)
{
    if (!sink_.claim || !loop_.IsRunning())
    {
        return false;
    }
    std::promise<bool> done;
    auto               future = done.get_future();
    loop_.Post([this, &done, stream] { done.set_value(sink_.claim(stream)); });
    return future.get();
}

void SrtIngest::ReleaseOnLoop(const std::string& stream)
{
    if (!sink_.release || !loop_.IsRunning())
    {
        return;
    }
    std::promise<void> done;
    auto               future = done.get_future();
    loop_.Post(
        [this, &done, stream]
        {
            sink_.release(stream);
            done.set_value();
        });
    future.wait();
}

} // namespace websrt::gateway