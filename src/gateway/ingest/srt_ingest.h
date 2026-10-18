// SRT/UDP INGEST - the SRT-native entry point (G6): the multi-publisher
// listener bound for OBS/ffmpeg.
//
// WHAT IT IS. Unlike every other socket in this gateway, the ingest is NOT
// virtual-transport: it is an ordinary stock-mode libsrt socket on a real
// UDP port, driven with the plain API (srt_bind/srt_listen/srt_accept/
// srt_recvmsg plus srt_epoll). It is the only place in the process where
// srt speaks to the network, and it is independent of the WebTransport
// server: an OBS client never learns that lsquic exists.
//
// SEMANTICS PORTED FROM THE ORACLE (srt_listener.rs):
//   - MULTI-PUBLISHER. One listener, one socket per publisher; a peer's
//     SRTO_STREAMID names the stream it publishes under.
//   - STREAMID REQUIRED. A connection with no streamid (or an empty one)
//     is refused - never a "default" name.
//   - FIRST-WINS via the gateway's registry: the claim refuses while a
//     live broadcaster holds the name. Here the
//     claim rides the same StreamRegistry::PublishAttempt a WebTransport
//     publisher session runs (Gateway::ClaimIngestPublish), so an OBS
//     publisher and a WT publisher contend for the SAME occupancy slot and
//     neither can preempt the other.
//   - LATENCY-SCALED BUFFERS: see
//     RecvBufferPackets() and the Start() docs for the formula and for the
//     flow-control window discipline it must be set in.
//   - ENCRYPTION: the configured passphrase is passed to every
//     accept. See Start() for what happens on a build without srt's
//     encryption support.
//
// FRAMING (the one deliberate addition). A raw passthrough would hand
// srt's messages straight to the broadcaster, but this
// gateway's viewers negotiate <= 1128-byte SRT payloads and DROP anything
// larger (Broadcaster::Pump, never truncate, never retry). So the ingest
// frames the received byte stream itself with libquicsrt's TsChunker rules
// (publisher.h:106-141): every message is a whole number of 188-byte TS
// packets and at most `payload_size` long, with a sub-188 remainder carried
// over between messages. Byte order is preserved exactly.
//
// THREADING. One dedicated thread owns every socket this class creates
// (listener + accepted) and the srt_epoll they share; nothing else touches
// them, so there is no socket mutex. The thread never blocks on srt: the
// sockets are non-blocking (SRTO_RCVSYN=0) and readiness comes from
// srt_epoll_wait with a bounded timeout, so Stop() is observed within one
// poll slice. Media leaves the thread through the injected sink, invoked on
// the GATEWAY LOOP THREAD (the ingest Posts to `loop`; main wires the sink
// to Gateway::PublishMedia) - the ring is loop-thread-only. The claim and
// release round-trips are synchronous Posts answered by the same loop.
//
// TEARDOWN. Stop() sets the stop flag and joins; the joined thread leaves
// its sockets alone, Stop() then closes them and releases the claims. The
// EventLoop MUST outlive SrtIngest: a claim/release that cannot be answered
// is skipped rather than waited on, and posted media is dropped with the
// loop.
//
// THE PROCESS-GLOBAL srt RUNTIME. libsrt's startup is refcounted
// (srt_startup/srt_cleanup) and its teardown is GLOBAL: when the last holder
// calls srt_cleanup() the garbage collector stops and force-breaks EVERY
// socket in the process. libquicsrt's Subscriber/Publisher each hold a
// reference, so in the gateway the ingest MUST hold one too - otherwise the
// end of any browser session would yank the ingest listener out from under
// the next OBS connection. SetupListener takes the reference, CloseAllSockets
// releases it (after every socket is closed).

#ifndef QUICSRT_GATEWAY_INGEST_SRT_INGEST_H
#define QUICSRT_GATEWAY_INGEST_SRT_INGEST_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <netinet/in.h>

#include "core/event_loop.h"
#include "gateway/ingest/ts_continuity.h"
#include "gateway/webhooks.h"
#include "srt.h"
#include "srt_session/publisher.h"

namespace quicsrt::gateway
{

/// Receiver buffer depth in SRT PACKETS, sized from the TSBPD latency,
/// verbatim:
/// `clamp(ms * 20000 / 1000 * 2, 8192, 320000)` - "TSBPD holds latency x
/// packet_rate packets in the receiver buffer simultaneously; the
/// srt-protocol default (8192x1500 B) overflows at high channel counts and
/// silently caps ingest throughput, stalling publishers on flow control".
/// Same formula as the browser side.
[[nodiscard]] std::int64_t RecvBufferPackets(std::uint64_t latency_ms) noexcept;

/// Ingest listener knobs, from [server] (config.h). The buffers are derived
/// from `latency_ms` (see RecvBufferPackets), not configured separately.
struct SrtIngestConfig
{
    std::string   bind         = "127.0.0.1"; ///< IPv4 literal
    std::uint16_t port         = 9000;
    std::uint64_t latency_ms   = 120;  ///< TSBPD latency (floor 10 ms)
    int           payload_size = 1128; ///< quicsrt:// protocol constant: 6 x 188 TS packets
    /// Concurrent publisher connections, 0 = unlimited. Past the cap a new
    /// connection is refused at accept, before any per-connection resource
    /// or loop round-trip is spent.
    int                        max_sessions = 100;
    std::optional<std::string> passphrase; ///< SRT PBKEYLEN passphrase (10-79 chars)
};

/// One live publisher connection, as the ingest sees it (the health/stats
/// endpoint's per-connection view).
struct SrtConnectionStats
{
    std::string     stream;
    std::string     remote;            ///< "ip:port" of the publisher
    std::uint64_t   bytes_in    = 0;   ///< SRT payload bytes received
    std::uint64_t   messages_in = 0;   ///< SRT messages received
    std::uint64_t   chunks_out  = 0;   ///< TS-framed messages handed to the gateway
    std::uint64_t   tail_bytes  = 0;   ///< sub-188 bytes still buffered
    TsCcStats       cc;                ///< the connection's TS-continuity probe
    bool            srt_stats = false; ///< `srt` is populated
    SRT_TRACEBSTATS srt{};
};

/// Ingest-wide counters (the health/stats endpoint's ingest view).
struct SrtIngestStats
{
    std::uint64_t                   publishers_accepted  = 0;
    std::uint64_t                   publishers_rejected  = 0; ///< sum of the four reasons below
    std::uint64_t                   rejected_no_streamid = 0;
    std::uint64_t                   rejected_not_allowed = 0; ///< refused by `publish_gate` (the allowlist)
    std::uint64_t                   rejected_occupied    = 0; ///< first-wins: a live publisher held the name
    std::uint64_t                   rejected_session_cap = 0; ///< admission: the concurrent-publisher cap was hit
    std::uint64_t                   publishers_ended     = 0;
    std::uint64_t                   messages_in          = 0;
    std::uint64_t                   bytes_in             = 0;
    std::uint64_t                   chunks_out           = 0;
    std::uint64_t                   bytes_out            = 0;
    std::uint64_t                   tail_flushes         = 0; ///< connections that ended with a buffered sub-188 tail
    std::vector<SrtConnectionStats> connections;
    /// Per-stream-name TS-continuity probe - /health's ingester slot (a
    /// map keyed by stream name). An entry appears
    /// when a publisher claims the name, survives the connection's end
    /// (frozen at its final counters), and starts fresh when the name is
    /// claimed again.
    std::map<std::string, TsCcStats> streams;
};

/// SRT/UDP ingest: a stock libsrt multi-publisher listener that feeds the
/// gateway's broadcaster ring.
class SrtIngest final
{
public:
    /// The gateway-side seam, injected so the ingest depends on nothing but
    /// the loop it posts to. All four callbacks are invoked ON THE GATEWAY
    /// LOOP THREAD.
    struct Sink
    {
        /// PUBLISH GATE - the policy half of the WT accept path ("may this
        /// caller address this name at all"): false refuses the connection
        /// at accept. Unset allows every name. Consulted BEFORE `claim`.
        std::function<bool(const std::string& stream)> publish_gate;
        /// ADMISSION - the occupancy half ("can this stream take it right
        /// now"): claims the publisher slot, false while a live publisher
        /// (a WebTransport session or another ingest connection) holds it.
        std::function<bool(const std::string& stream)> claim;
        /// One TS-framed message (see the framing note in the file header).
        std::function<void(const std::string& stream, const void* data, std::size_t len)> publish;
        /// The publisher went away: release the slot and close the stream's
        /// viewers (publisher-end parity with the WT path).
        std::function<void(const std::string& stream)> release;
        /// P4.3 webhooks: publisher_connect / publisher_disconnect for the
        /// ingest's own connections (the WT side notifies from the
        /// gateway's session callbacks). Unlike the four above this fires
        /// ON THE INGEST THREAD - the sink must only enqueue, never
        /// deliver (Gateway::NotifyWebhook is exactly that). Unset = no
        /// events.
        std::function<void(const WebhookEvent&)> webhook;
    };

    /// `sink` must outlive the ingest; `loop` must outlive it too and must be
    /// running before Start(). Not started yet - see Start().
    SrtIngest(SrtIngestConfig config, Sink sink, quicsrt::EventLoop& loop);
    ~SrtIngest();

    SrtIngest(const SrtIngest&)            = delete;
    SrtIngest& operator=(const SrtIngest&) = delete;

    /// Creates the listener socket, binds it and starts the ingest thread.
    /// Returns false with *error set (the object stays inert) on a bind or
    /// socket-option failure, or when a passphrase was configured but the
    /// linked srt build has no encryption support - libquicsrt builds its srt
    /// fork with ENABLE_ENCRYPTION=OFF ("no built-in crypto: WebTransport's
    /// TLS provides it"), where a non-empty SRTO_PASSPHRASE is rejected by
    /// the library itself. We surface that as a startup failure rather than
    /// listening unencrypted behind the operator's back.
    [[nodiscard]] bool Start(std::string* error);

    /// Idempotent: stops the thread (within one poll slice), closes every
    /// socket, releases every claim the publishers still hold, joins.
    void Stop();

    [[nodiscard]] bool Running() const { return running_.load(std::memory_order_relaxed); }

    /// Snapshot of the counters and the live connections (health/stats).
    [[nodiscard]] SrtIngestStats Stats() const;

private:
    struct Conn
    {
        SRTSOCKET           sock = SRT_INVALID_SOCK;
        std::string         stream;
        std::string         remote;
        std::uint64_t       session_id = 0; ///< webhook identity (ingest-minted, nothing else consumes it)
        std::vector<char>   recv_buf;
        quicsrt::TsChunker  chunker; ///< 188-aligned framing (libquicsrt's TsChunker rules)
        std::uint64_t       bytes_in    = 0;
        std::uint64_t       messages_in = 0;
        std::uint64_t       chunks_out  = 0;
        TsContinuityChecker cc; ///< the connection's TS-continuity probe
    };

    // ---- ingest thread ----
    void                             ThreadMain();
    void                             HandleReady(SRTSOCKET sock);
    void                             AcceptOne();
    void                             Drain(SRTSOCKET sock);
    void                             FeedAndChunk(SRTSOCKET sock, const std::uint8_t* data, std::size_t len);
    void                             PublishChunk(SRTSOCKET sock, const std::uint8_t* data, std::size_t len);
    void                             EndConn(SRTSOCKET sock, const std::string& why);
    void                             RefreshSnapshot();
    [[nodiscard]] bool               SetupListener(std::string* error);
    void                             CloseAllSockets();
    [[nodiscard]] static std::string StreamIdOf(SRTSOCKET sock);
    [[nodiscard]] static std::string PeerText(const sockaddr_storage& peer);

    // ---- loop-thread round-trips (issued from, and blocked on, the ingest thread) ----
    [[nodiscard]] bool GateOnLoop(const std::string& stream);
    [[nodiscard]] bool ClaimOnLoop(const std::string& stream);
    void               ReleaseOnLoop(const std::string& stream);

    SrtIngestConfig     config_;
    Sink                sink_;
    quicsrt::EventLoop& loop_;

    SRTSOCKET                 listener_ = SRT_INVALID_SOCK;
    int                       epoll_    = SRT_ERROR;
    sockaddr_in               local_{};
    std::thread               thread_;
    std::map<SRTSOCKET, Conn> conns_;
    /// Per-name continuity counters (ingest thread; mirrored into
    /// stream_cc_snapshot_ by RefreshSnapshot). Written from the live
    /// connection's probe, never erased on connection end - the /health
    /// behavior.
    std::map<std::string, TsCcStats> stream_cc_;
    std::uint64_t                    next_webhook_session_id_ = 1;     ///< mints Conn::session_id
    bool                             srt_runtime_             = false; ///< holds an srt_startup() reference

    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};

    // Counters: written only by the ingest thread, read by Stats() from
    // anywhere (health endpoint), hence atomic.
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> rejected_{0};
    std::atomic<std::uint64_t> rejected_sid_{0};
    std::atomic<std::uint64_t> rejected_gate_{0};
    std::atomic<std::uint64_t> rejected_occ_{0};
    std::atomic<std::uint64_t> rejected_cap_{0};
    std::atomic<std::uint64_t> ended_{0};
    std::atomic<std::uint64_t> messages_in_{0};
    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> chunks_out_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> tail_flushes_{0};

    mutable std::mutex               stats_mutex_;
    std::vector<SrtConnectionStats>  snapshot_;
    std::map<std::string, TsCcStats> stream_cc_snapshot_; ///< mirror of stream_cc_ (Stats())
};

} // namespace quicsrt::gateway

#endif // QUICSRT_GATEWAY_INGEST_SRT_INGEST_H