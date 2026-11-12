#include "gateway/srt_initiator.h"
#include "srt_session/negotiate.h"

// The fork's internal C++ bind path carrying the conclusion-first
// (skip-induction) handshake form - deliberately not public C API.
#include "core.h"

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
    // listener sessions. The seed rides the transport config (see Setup),
    // no longer a socket option.
    const long long rtt_us = initial_rtt.count();
    if (rtt_us > 0)
    {
        initial_rtt_ms_ = static_cast<int>(std::clamp<long long>(rtt_us / 1000, 1, 30000));
    }

    std::memset(&peer_label_, 0, sizeof peer_label_);
    peer_label_.sin_family      = AF_INET;
    peer_label_.sin_port        = htons(kPeerLabelPortBase + static_cast<std::uint16_t>(handle.Id() & 0x3FFF));
    peer_label_.sin_addr.s_addr = inet_addr(kPeerLabelIp);

    // The caller's bind label: the fake gateway address the browser
    // sessions report as their peer (the M0 caller label; also what
    // libquicsrt's receiver core dials toward).
    std::memset(&local_label_, 0, sizeof local_label_);
    local_label_.sin_family      = AF_INET;
    local_label_.sin_port        = htons(5556);
    local_label_.sin_addr.s_addr = inet_addr("10.220.0.1");
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
        ok                = ok && SetOptInt(sock_, SRTO_TLPKTDROP, 1);
        ok                = ok && SetOptInt(sock_, SRTO_CONNTIMEO, config_.connect_timeout_ms);
        ok                = ok && SetOptInt(sock_, SRTO_RCVSYN, 0);
        ok                = ok && SetOptInt(sock_, SRTO_SNDTIMEO, 0);
        if (!ok)
        {
            *error = std::string("srt socket option: ") + srt_getlasterror_str();
            break;
        }

        // Bind the caller to a label address over the virtual transport
        // BEFORE connecting: the bind wires the queue's callbacks into a
        // dedicated multiplexer (dispatch by socket id, the label is only
        // what srt_getsockname reports). The conclusion-first
        // (skip-induction) handshake form rides the fork's INTERNAL C++
        // bind path, and the config's initial_rtt_ms carries the QUIC-RTT
        // seed (mirrors libquicsrt's sessions and the M0 loopback harness).
        const SRT_VirtualTransportConfig cfg = vt_queue_.getConfig(initial_rtt_ms_);
        if (srt::CUDT::bind_virtual(sock_,
                                    reinterpret_cast<const sockaddr*>(&local_label_),
                                    static_cast<int>(sizeof local_label_),
                                    &cfg,
                                    /*conclusion_first=*/true) == SRT_ERROR)
        {
            *error = std::string("bind_virtual: ") + srt_getlasterror_str();
            break;
        }

        // Readiness gates: level-triggered SRT_EPOLL_OUT for Send()
        // (also fires on connect completion; Send is only called once
        // connected) and SRT_EPOLL_IN for ReceiveNext (a CONNECTED
        // status alone does not mean TSBPD-released data), plus
        // SRT_EPOLL_ERR for the failure signal.
        epoll_ = srt_epoll_create();
        if (epoll_ == SRT_ERROR)
        {
            *error = std::string("srt_epoll_create: ") + srt_getlasterror_str();
            break;
        }
        const int events = SRT_EPOLL_IN | SRT_EPOLL_OUT | SRT_EPOLL_ERR;
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
    // Teardown on the same thread. The push queue plays the kernel UDP
    // receive buffer: a full queue drops the datagram (UDP-like loss
    // that srt retransmits); after Teardown's detach the push fails
    // harmlessly.
    if (closed_.load(std::memory_order_relaxed))
    {
        return;
    }
    vt_queue_.push(
        data, size, reinterpret_cast<const sockaddr*>(&peer_label_), static_cast<socklen_t>(sizeof peer_label_));
}

int SrtInitiator::ReceiveNext(char* buf, int len)
{
    if (buf == nullptr || len <= 0)
    {
        return kRecvInvalidArg;
    }
    // Connected receives normally; a BROKEN socket still drains its
    // TSBPD-released tail (the fork's receiveMessage keeps reading from
    // a broken socket "just for formality" until nothing released
    // remains), so the pump can deliver the tail and classify the close
    // in the same terminal receive.
    const SRT_SOCKSTATUS state = ConnectionState();
    if (state != SRTS_CONNECTED && state != SRTS_BROKEN)
    {
        return kRecvNotConnected;
    }
    // Readiness first, the receive twin of Send's writability gate: a
    // CONNECTED socket is read only while epoll reports SRT_EPOLL_IN
    // (level-triggered, so a pump drains every released message before
    // the gate re-engages). A BROKEN socket reads ungated: its terminal
    // receive must run to drain the released tail and classify the
    // close (the fork guards a broken socket's empty read itself).
    if (state == SRTS_CONNECTED)
    {
        SRT_EPOLL_EVENT ready;
        const int       nready = srt_epoll_uwait(epoll_, &ready, 1, 0);
        if (nready < 1 || (ready.events & SRT_EPOLL_IN) == 0)
        {
            return kRecvWouldBlock;
        }
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
        // The errnos cannot separate a graceful peer shutdown from a
        // lost connection on live/message sockets: a peer srt_close and
        // a peer-idle expiry both drain to SRT_ECONNLOST once nothing
        // TSBPD-released remains (verified against the fork over
        // virtual transports). The fork's close ledger can.
        return PeerClosedGracefully() ? kRecvPeerClosed : kRecvClosed;
    }
    return kRecvError;
}

bool SrtInitiator::PeerClosedGracefully()
{
    // Loop thread only (ReceiveNext), so sock_ is alive and not being
    // torn down. agent = SRT_CLS_PEER is set exclusively by the fork's
    // UMSG_SHUTDOWN processing (the peer's own reason then rides
    // info.peer, e.g. SRT_CLS_API for srt_close); a silent death
    // leaves SRT_CLS_PEERIDLE there instead.
    srt::CUDT* core = srt::CUDT::getUDTHandle(sock_);
    if (core == nullptr)
    {
        return false;
    }
    SRT_CLOSE_INFO info;
    std::memset(&info, 0, sizeof info);
    core->copyCloseInfo(info);
    return info.agent == SRT_CLS_PEER;
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

void SrtInitiator::Park()
{
    // The cheap first step of Teardown alone: from here VtSend swallows
    // sends and Inject is a no-op, so nothing touches the WtServer or the
    // socket while the heavy close waits for its loop job. Teardown
    // stores the same flag again (idempotent).
    closed_.store(true, std::memory_order_relaxed);
}

void SrtInitiator::Teardown()
{
    // Unregister from the epoll before the close fires its events, park
    // the send callback (it swallows sends and claims success so srt's
    // control machinery stays quiet), close the socket - it sends the SRT
    // shutdown through the still-attached transport - then detach the
    // transport queue and release the epoll (the enforced fork order; the
    // queue detach blocks until an in-flight send callback returns). The
    // socket is nulled under sock_mutex_ BEFORE the close: a concurrent
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
    // Only after the close: it sends the SRT shutdown through the still-
    // attached queue; detach then parks push() and the send callback
    // (idempotent - every Teardown path may run it).
    vt_queue_.detach();
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
