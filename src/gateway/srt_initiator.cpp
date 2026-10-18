#include "gateway/srt_initiator.h"
#include "srt_session/negotiate.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace quicsrt::gateway
{

namespace
{

// SRTO_SNDBUF/SRTO_RCVBUF are in BYTES; srt converts with MSS - UDP header
// (1500 - 28 = 1472) - see the M0 loopback harness and libquicsrt's
// sessions (the bytes-vs-packets trap).
constexpr int kBytesPerPacket = 1500 - 28;

// The fake peer network the per-session labels live in (M0's harness
// addressing; the libquicsrt listener side binds 10.213.255.254 as its
// label). Distinct ports keep concurrent session pairs apart.
constexpr const char*   kPeerLabelIp       = "10.213.255.254";
constexpr std::uint16_t kPeerLabelPortBase = 20000;

bool SetOptInt(SRTSOCKET u, SRT_SOCKOPT opt, int value)
{
    return srt_setsockopt(u, 0, opt, &value, sizeof value) != SRT_ERROR;
}

} // namespace

SrtInitiator::SrtInitiator(WtServer&                 server,
                           WtSessionHandle           handle,
                           InitiatorConfig           config,
                           std::chrono::microseconds initial_rtt)
    : server_(server)
    , handle_(handle)
    , config_(config)
    , max_payload_(config.payload_size)
{
    // SRTO_INITIAL_RTT bounds are 1..30000 ms; 0 = disabled (unmeasured
    // RTT leaves srt's default estimator). A measured-but-sub-millisecond
    // RTT (loopback) clamps up to 1 ms - the same clamp as libquicsrt's
    // listener sessions.
    const long long rtt_us = initial_rtt.count();
    if (rtt_us > 0)
    {
        initial_rtt_ms_ = static_cast<int>(std::clamp<long long>(rtt_us / 1000, 1, 30000));
    }

    std::memset(&peer_label_, 0, sizeof peer_label_);
    peer_label_.sin_family      = AF_INET;
    peer_label_.sin_port        = htons(kPeerLabelPortBase + static_cast<std::uint16_t>(handle.Id() & 0x3FFF));
    peer_label_.sin_addr.s_addr = inet_addr(kPeerLabelIp);
}

SrtInitiator::~SrtInitiator()
{
    Teardown();
}

bool SrtInitiator::Setup(std::string* error)
{
    if (sock_ != SRT_INVALID_SOCK)
    {
        return true; // already set up
    }

    do
    {
        sock_ = srt_create_socket();
        if (sock_ == SRT_INVALID_SOCK)
        {
            *error = std::string("srt_create_socket: ") + srt_getlasterror_str();
            break;
        }

        // SRTO_TRANSTYPE first: it resets the latency/payload presets.
        bool      ok      = SetOptInt(sock_, SRTO_TRANSTYPE, SRTT_LIVE);
        const int snd_buf = config_.send_buffer_pkts * kBytesPerPacket;
        const int rcv_buf = config_.recv_buffer_pkts * kBytesPerPacket;
        ok                = ok && SetOptInt(sock_, SRTO_PAYLOADSIZE, config_.payload_size);
        ok                = ok && SetOptInt(sock_, SRTO_RCVLATENCY, config_.latency_ms);
        ok                = ok && SetOptInt(sock_, SRTO_PEERLATENCY, config_.latency_ms);
        ok                = ok && SetOptInt(sock_, SRTO_SNDBUF, snd_buf);
        ok                = ok && SetOptInt(sock_, SRTO_RCVBUF, rcv_buf);
        ok                = ok && SetOptInt(sock_, SRTO_SKIP_INDUCTION, 1);
        ok                = ok && SetOptInt(sock_, SRTO_TLPKTDROP, 1);
        ok                = ok && SetOptInt(sock_, SRTO_CONNTIMEO, config_.connect_timeout_ms);
        ok                = ok && SetOptInt(sock_, SRTO_RCVSYN, 0);
        ok                = ok && SetOptInt(sock_, SRTO_SNDTIMEO, 0);
        if (ok && initial_rtt_ms_ > 0)
        {
            ok = ok && SetOptInt(sock_, SRTO_INITIAL_RTT, initial_rtt_ms_);
        }
        if (!ok)
        {
            *error = std::string("srt socket option: ") + srt_getlasterror_str();
            break;
        }

        vt_ = srt_attach_virtual_transport(sock_, VtSendThunk, this);
        if (vt_ == nullptr)
        {
            *error = std::string("srt_attach_virtual_transport: ") + srt_getlasterror_str();
            break;
        }

        // Writability gate for Send(): level-triggered SRT_EPOLL_OUT
        // (also fires on connect completion; Send is only called once
        // connected) plus SRT_EPOLL_ERR for the failure signal.
        epoll_ = srt_epoll_create();
        if (epoll_ == SRT_ERROR)
        {
            *error = std::string("srt_epoll_create: ") + srt_getlasterror_str();
            break;
        }
        const int events = SRT_EPOLL_OUT | SRT_EPOLL_ERR;
        if (srt_epoll_add_usock(epoll_, sock_, &events) == SRT_ERROR)
        {
            *error = std::string("srt_epoll_add_usock: ") + srt_getlasterror_str();
            break;
        }

        // Asynchronous caller connect (Conclusion-first, cookie 0 - the
        // skip-induction fork): returns after starting; the handshake
        // completes on srt's threads as WT datagrams are injected.
        if (srt_connect(sock_, reinterpret_cast<const sockaddr*>(&peer_label_), sizeof peer_label_) == SRT_ERROR)
        {
            *error = std::string("srt_connect: ") + srt_getlasterror_str();
            break;
        }
        return true;
    } while (false);

    // Setup failure: undo in the teardown order (socket close before the
    // transport release; the epoll last).
    Teardown();
    return false;
}

void SrtInitiator::Inject(const std::uint8_t* data, std::size_t size)
{
    // Loop thread only (WtServerListener::OnDatagram), serialized with
    // Teardown on the same thread - a null vt_ can only be observed
    // between callbacks, never raced.
    if (vt_ == nullptr || closed_.load(std::memory_order_relaxed))
    {
        return;
    }
    srt_virtual_transport_inject(vt_,
                                 reinterpret_cast<const char*>(data),
                                 static_cast<int>(size),
                                 reinterpret_cast<const sockaddr*>(&peer_label_),
                                 static_cast<int>(sizeof peer_label_));
}

int SrtInitiator::ReceiveNext(char* buf, int len)
{
    if (buf == nullptr || len <= 0)
    {
        return kRecvInvalidArg;
    }
    if (!IsConnected())
    {
        return kRecvNotConnected;
    }
    const int n = srt_recvmsg(sock_, buf, len);
    if (n > 0)
    {
        return n;
    }
    const int err = srt_getlasterror(nullptr);
    if (err == SRT_EASYNCRCV)
    {
        return kRecvWouldBlock;
    }
    if (err == SRT_ESCLOSED || err == SRT_ECONNLOST || err == SRT_ENOCONN)
    {
        return kRecvClosed;
    }
    return kRecvError;
}

int SrtInitiator::Send(const void* data, int len)
{
    if (data == nullptr || len <= 0)
    {
        return kSendInvalidArg;
    }
    if (!IsConnected())
    {
        return kSendNotConnected;
    }
    // No max_payload ceiling here: SRT messages span many payload packets
    // (srt_sendmsg2 re-fragments; the send buffer bounds the message).
    // Writability first: the socket is registered with SRT_EPOLL_OUT in
    // Setup (level-triggered, so it reports on every poll while the send
    // buffer has room). A zero-timeout uwait never blocks the caller.
    SRT_EPOLL_EVENT ready;
    const int       nready = srt_epoll_uwait(epoll_, &ready, 1, 0);
    if (nready < 1 || (ready.events & SRT_EPOLL_OUT) == 0)
    {
        return kSendWouldBlock;
    }

    // SRTO_SNDTIMEO = 0 bounds the blocking part of srt_sendmsg2 to
    // nothing: a full send buffer returns an error instead of parking
    // the loop thread.
    const int n = srt_sendmsg2(sock_, static_cast<const char*>(data), len, nullptr);
    if (n == len)
    {
        return n;
    }
    const int err = srt_getlasterror(nullptr);
    if (err == SRT_ETIMEOUT || err == SRT_EASYNCSND)
    {
        return kSendWouldBlock;
    }
    if (err == SRT_ESCLOSED || err == SRT_ECONNLOST || err == SRT_ENOCONN)
    {
        return kSendClosed;
    }
    return kSendError;
}

SRT_SOCKSTATUS SrtInitiator::ConnectionState()
{
    const std::lock_guard<std::mutex> lock(sock_mutex_);
    if (sock_ == SRT_INVALID_SOCK || closed_.load(std::memory_order_relaxed))
    {
        return SRTS_CLOSED;
    }
    const SRT_SOCKSTATUS state = srt_getsockstate(sock_);
    if (state == SRTS_BROKEN && break_reason_.load(std::memory_order_relaxed) < 0)
    {
        // First BROKEN observation: capture why srt broke the socket
        // (handshake rejection / peer error) while it is still open.
        break_reason_.store(srt_getrejectreason(sock_), std::memory_order_relaxed);
    }
    if (state != SRTS_CONNECTED || payload_read_done_.load(std::memory_order_acquire))
    {
        return state;
    }

    // First connected observation: read back the negotiated payload cap
    // via libquicsrt's NegotiatePayload (the same readback the publisher
    // session performs; srt_session/negotiate.h carries the full
    // MSS/MTU-field story). The value is stored before the flag
    // (release/acquire), so an observed set flag implies the negotiated
    // cap; max_payload() itself only needs a coherent value.
    const int negotiated = NegotiatePayload(sock_, config_.payload_size);
    max_payload_.store(negotiated, std::memory_order_relaxed);
    payload_read_done_.store(true, std::memory_order_release);
    return state;
}

bool SrtInitiator::IsConnected()
{
    return ConnectionState() == SRTS_CONNECTED;
}

bool SrtInitiator::StatsOut(SRT_TRACEBSTATS* out)
{
    if (out == nullptr)
    {
        return false;
    }
    // Under sock_mutex_ across the whole sample: Teardown nulls and
    // closes the socket under the same mutex, so this either samples the
    // live socket before the close or observes SRT_INVALID_SOCK after -
    // never a handle mid-close (or its id recycled into a new socket).
    const std::lock_guard<std::mutex> lock(sock_mutex_);
    if (sock_ == SRT_INVALID_SOCK || closed_.load(std::memory_order_relaxed))
    {
        return false;
    }
    if (srt_getsockstate(sock_) != SRTS_CONNECTED)
    {
        return false;
    }
    return srt_bstats(sock_, out, 0) == 0;
}

void SrtInitiator::Teardown()
{
    // Unregister from the epoll before the close fires its events, park
    // the send callback (it swallows sends and claims success so srt's
    // control machinery stays quiet), close the socket - it sends the SRT
    // shutdown through the still-attached transport - then release the
    // transport handle and the epoll (the enforced fork order). The
    // handle is detached under sock_mutex_ BEFORE the close: a concurrent
    // off-loop scrape (StatsOut/ConnectionState) either completes on the
    // live socket before this or sees SRT_INVALID_SOCK after - the close
    // itself runs outside the mutex so no scrape ever waits on it.
    closed_.store(true, std::memory_order_relaxed);
    SRTSOCKET sock = SRT_INVALID_SOCK;
    {
        const std::lock_guard<std::mutex> lock(sock_mutex_);
        sock  = sock_;
        sock_ = SRT_INVALID_SOCK;
    }
    if (epoll_ != SRT_ERROR && sock != SRT_INVALID_SOCK)
    {
        srt_epoll_remove_usock(epoll_, sock);
    }
    if (sock != SRT_INVALID_SOCK)
    {
        srt_close(sock);
    }
    if (vt_ != nullptr)
    {
        srt_virtual_transport_release(vt_);
        vt_ = nullptr;
    }
    if (epoll_ != SRT_ERROR)
    {
        srt_epoll_release(epoll_);
        epoll_ = SRT_ERROR;
    }
}

// ---- srt threads: virtual transport send callback ----

int SrtInitiator::VtSendThunk(void* opaq, const char* data, int len, const struct sockaddr* /*dst*/, int /*dstlen*/)
{
    return static_cast<SrtInitiator*>(opaq)->VtSend(data, len);
}

int SrtInitiator::VtSend(const char* data, int len)
{
    // Runs on srt's internal threads. Touches nothing but the
    // thread-safe WtServer: a full datagram queue returns false, which we
    // report as a send failure - UDP-like loss that srt retransmits.
    // Never block an srt thread. Once torn down the WT session is gone
    // for good: swallow the send and claim success so srt's control
    // machinery stays quiet. (Relaxed atomic: a stale false only risks
    // one send attempt into the closed server, which fails harmlessly.)
    if (closed_.load(std::memory_order_relaxed))
    {
        return len;
    }
    return server_.SendDatagram(handle_, data, static_cast<std::size_t>(len)) ? len : -1;
}

} // namespace quicsrt::gateway
