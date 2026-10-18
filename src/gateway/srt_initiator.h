// Per-session SRT initiator (caller role) over the fork's virtual
// transport - the C++ analogue of the Rust oracle's srt_sender.rs
// (WebSRT crates/websrt/src/srt_sender.rs), with one architectural
// difference the PLAN fixes: srt-rs is threadless, so the Rust gateway
// hand-drives the Connect/DuplexConnection state machines from its ~2 ms
// ticker. The fork is real libsrt with its own internal send/receive
// threads - THIS initiator socket handshakes, retransmits and ACKs by
// itself. The ticker's remaining jobs (publisher pumping, viewer pacing,
// health, drop_backlog) live in session_registry.h, not here.
//
// One instance per WebTransport session, EITHER direction
// (publisher-receiving or viewer-sending): the SRT role is identical -
// the gateway is always the CALLER (skip-induction, Conclusion-first,
// cookie 0; WT's TLS replaces the SRT cookie's DoS role) and the browser
// peer is the listener. Only the data flow differs: a viewer session
// SENDS into the socket (ring messages via the registry's credit-paced
// ticker), a publisher session RECEIVES from it (the registry pumps
// released messages toward the stream sink).
//
// Socket options, set BEFORE srt_connect and mirroring SrtConfig defaults
// (srt_sender.rs:51-63) plus the M0 caller lessons
// (libquicsrt tests/loopback_srt.cpp):
//   SRTO_TRANSTYPE      SRTT_LIVE (first - it resets the presets)
//   SRTO_PAYLOADSIZE    1128 (6 x 188 TS packets; HSv5 negotiates
//                       min(gateway, peer) - see ConnectionState() for the
//                       effective-cap readback)
//   SRTO_RCVLATENCY     params.latency_ms (gateway floor 10 ms)
//   SRTO_PEERLATENCY    params.latency_ms (TSBPD = max(sender, receiver))
//   SRTO_SNDBUF         snd packets x 1472 bytes (SRTO_SNDBUF is in BYTES;
//                       srt converts with MSS - UDP header = 1500 - 28)
//   SRTO_RCVBUF         rcv packets x 1472 bytes (same trap)
//   SRTO_SKIP_INDUCTION 1 (caller, Conclusion-first, cookie 0)
//   SRTO_TLPKTDROP      1 (Rust ConnInitSettings too_late_packet_drop)
//   SRTO_INITIAL_RTT    the WT session's QUIC smoothed RTT, us -> ms
//                       clamped to 1..30000, skipped when unmeasured
//   SRTO_CONNTIMEO      params.connect_timeout_ms (bounds the handshake)
//   SRTO_RCVSYN         0 (ReceiveNext never blocks the loop thread)
//   SRTO_SNDTIMEO       0 (Send never blocks: a full send buffer surfaces
//                       as would-block, retried by the ticker)
//
// WIRING. The virtual transport's send callback runs on srt's internal
// threads and touches nothing but the thread-safe WtServer::SendDatagram
// (a full datagram queue returns false = UDP-like loss that srt
// retransmits; never block an srt thread). Ingress WT datagrams arrive as
// WtServerListener::OnDatagram on the loop thread and are injected with
// the session's stable fake peer label - the same address srt_connect
// dialed, so the socket accepts them as its peer (the label never reaches
// a network; dispatch is by socket id inside the socket's dedicated
// virtual multiplexer).
//
// THREADS AND TEARDOWN ORDER. Everything except the send callback runs on
// the EventLoop thread (Setup at session accept, Inject from OnDatagram,
// ReceiveNext/Send/Teardown from the ticker or close path); they serialize
// on the single loop thread. The exceptions are the any-thread surface the
// /health and /stats workers scrape: ConnectionState/IsConnected/StatsOut
// (sock_'s lifetime is guarded by sock_mutex_ - Teardown nulls and closes
// under it, so a racing scrape can never sample a handle being closed or
// a recycled id) and max_payload() (atomic; the loop writes the
// negotiated cap at the first connected observation). Teardown follows
// the fork's enforced order: mark closed (the send callback swallows
// further sends), remove the socket from the srt epoll, srt_close the
// socket (it sends the SRT shutdown through the still-attached transport
// - the M0 lesson), then release the transport handle, then release the
// epoll. The handshake completes asynchronously on srt's threads; poll
// ConnectionState() for the CONNECTED transition (first observation also
// reads back the negotiated payload cap).

#ifndef WEBSRT_GATEWAY_SRT_INITIATOR_H
#define WEBSRT_GATEWAY_SRT_INITIATOR_H

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

#include "gateway/wt_server.h"

// The fork's gated API (build with SRT_ENABLE_VIRTUAL_TRANSPORT defined).
#include "srt.h"

namespace quicsrt::gateway
{

/// Initiator-side SRT parameters, mirroring the Rust oracle's SrtConfig
/// defaults (srt_sender.rs). Latency is the gateway-side TSBPD floor.
struct InitiatorConfig
{
    int payload_size       = 1128; // WebSRT constant: 6 x 188-byte TS packets
    int latency_ms         = 10;   // gateway floor; TSBPD = max(sender, receiver)
    int send_buffer_pkts   = 65536;
    int recv_buffer_pkts   = 8192;
    int connect_timeout_ms = 5000; // SRTO_CONNTIMEO bound on the handshake
};

class SrtInitiator final
{
public:
    // Send outcomes; positive values carry the accepted byte count, so
    // Send() returns plain int and these are its documented constants.
    enum SendResult
    {
        kSendWouldBlock   = -1, // send buffer full (or socket not writable); retry next tick
        kSendNotConnected = -2, // handshake not complete (or already closed)
        kSendClosed       = -3, // the connection ended; Teardown is due
        kSendError        = -4, // srt-level error (see the log/last error)
        kSendInvalidArg   = -5, // null buffer, empty or over max_payload()
    };

    // ReceiveNext outcomes; positive values carry the delivered byte count.
    enum ReceiveResult
    {
        kRecvWouldBlock   = -1, // nothing released yet; retry next tick
        kRecvNotConnected = -2,
        kRecvClosed       = -3, // peer shut the stream down (or the socket broke)
        kRecvError        = -4,
        kRecvInvalidArg   = -5,
    };

    /// `server` (with `handle`) is the egress path: the virtual transport
    /// send callback hands srt's datagrams to WtServer::SendDatagram.
    /// `initial_rtt` is the WT session's QUIC smoothed RTT used to seed
    /// SRTO_INITIAL_RTT (0 = unmeasured, leave srt's estimator default).
    /// The fake peer label is derived from the handle so every session
    /// pair gets a stable, distinct address.
    SrtInitiator(WtServer&                 server,
                 WtSessionHandle           handle,
                 InitiatorConfig           config,
                 std::chrono::microseconds initial_rtt);
    ~SrtInitiator();

    SrtInitiator(const SrtInitiator&)            = delete;
    SrtInitiator& operator=(const SrtInitiator&) = delete;

    /// Loop thread (session accept). Creates the socket, sets every option
    /// above, attaches the virtual transport, registers SRT_EPOLL_OUT |
    /// SRT_EPOLL_ERR for the writability gate, and starts the asynchronous
    /// connect toward the fake peer label. Returns false with *error set
    /// on any setup failure (the object is then inert).
    [[nodiscard]] bool Setup(std::string* error);

    /// Loop thread (WtServerListener::OnDatagram). One WT datagram from
    /// the browser peer, injected into the srt receive queue with the
    /// session's fake source label. No-op after Teardown.
    void Inject(const std::uint8_t* data, std::size_t size);

    /// Loop thread (ticker). One non-blocking receive of a released
    /// message (TSBPD has released it); see ReceiveResult.
    int ReceiveNext(char* buf, int len);

    /// Loop thread (ticker). One non-blocking send: gated on the socket's
    /// srt_epoll writability (SRT_EPOLL_OUT, registered per socket in
    /// Setup) and bounded by SRTO_SNDTIMEO = 0, so a full send buffer
    /// returns kSendWouldBlock for the ticker to retry. Never blocks.
    int Send(const void* data, int len);

    /// Any thread. The socket's status (SRTS_CONNECTING / SRTS_CONNECTED /
    /// SRTS_BROKEN / ...); sock_mutex_ serializes the sample against
    /// Teardown's close. The FIRST connected observation reads back the
    /// negotiated payload cap (SRTO_PAYLOADSIZE vs SRTO_MSS - 44 floored
    /// to whole TS packets, mirroring libquicsrt's publisher session: the
    /// Rust initiator fills the HSv5 MTU field with its payload size
    /// although the field includes UDP/IP headers, which can cap a
    /// fork-to-Rust session below 1128).
    [[nodiscard]] SRT_SOCKSTATUS ConnectionState();

    /// Any thread, best effort (false once torn down or not connected).
    [[nodiscard]] bool IsConnected();

    /// Any thread, best effort. The srt reject reason captured when
    /// ConnectionState() first observed SRTS_BROKEN (srt_getrejectreason:
    /// why a handshake-stage or connected socket broke), -1 when none was
    /// captured. Purely diagnostic - appended to the session-end reason.
    [[nodiscard]] int BreakReason() const { return break_reason_.load(std::memory_order_relaxed); }

    /// Effective per-message payload ceiling after the handshake
    /// negotiation; the configured payload until ConnectionState() has
    /// observed the connection. Send() rejects anything larger. Any
    /// thread: atomic (the loop thread writes it at the first connected
    /// observation; off-loop info/stats paths read a coherent value).
    [[nodiscard]] int max_payload() const { return max_payload_.load(std::memory_order_relaxed); }

    /// Any thread, best effort. Snapshots the socket stats (srt_bstats,
    /// no clear). False when there is no connected socket; sock_mutex_
    /// serializes the sample against Teardown's close.
    bool StatsOut(SRT_TRACEBSTATS* out);

    /// Idempotent terminal cleanup in the fork's enforced order (see the
    /// file comment). Safe with the loop still running.
    void Teardown();

    [[nodiscard]] WtSessionHandle handle() const { return handle_; }

private:
    // ---- srt send callback (srt internal threads) ----
    static int VtSendThunk(void* opaq, const char* data, int len, const struct sockaddr* dst, int dstlen);
    int        VtSend(const char* data, int len);

    WtServer&       server_;
    WtSessionHandle handle_;
    InitiatorConfig config_;
    int             initial_rtt_ms_ = 0; // clamped QUIC seed; 0 = unmeasured

    // Fake address labeling the browser peer for srt dispatch (mirrors
    // M0's harness addressing; stable and distinct per session, derived
    // from the handle). The address never reaches a network.
    sockaddr_in peer_label_ = {};

    // sock_'s lifetime is guarded by sock_mutex_ for the any-thread stats
    // surface: Teardown nulls and srt_closes under it while
    // ConnectionState/StatsOut sample under it, so a racing scrape can
    // never observe a handle being closed (or its id recycled). The
    // loop-only paths (Setup, Send, ReceiveNext) serialize with Teardown
    // on the loop thread.
    SRTSOCKET            sock_  = SRT_INVALID_SOCK;
    SRTVirtualTransport* vt_    = nullptr;
    int                  epoll_ = SRT_ERROR;
    std::mutex           sock_mutex_;
    // Negotiated payload: written once on the loop thread at the first
    // connected ConnectionState() observation, read off-loop - atomics,
    // with the value published before the flag (release/acquire), so an
    // observed set flag implies the negotiated cap.
    std::atomic<int>  max_payload_; // configured until the connected readback
    std::atomic<bool> payload_read_done_ = false;

    // srt reject reason at the first BROKEN observation (-1 = not captured).
    std::atomic<int> break_reason_{-1};

    // Lock-free mirror of "torn down" for the srt send callback.
    std::atomic<bool> closed_{false};
};

} // namespace quicsrt::gateway

#endif // WEBSRT_GATEWAY_SRT_INITIATOR_H
