// Session registry + ticker (P3 step 3): owns every live SrtInitiator and
// drives them from ONE ~2 ms repeating EventLoop timer - the C++ mapping
// of the Rust oracle's registry.rs, budget-for-budget, with the mechanics
// adapted to real libsrt (see srt_initiator.h: the sockets run themselves;
// the ticker here only pumps, paces and reaps).
//
// RUST NUMBER -> C++ MECHANIC MAPPING (registry.rs):
//   TICKS_PER_SEC 500 / 2 ms interval   -> RegistryConfig::tick_interval
//                                         (EventLoop repeating timer).
//   MAX_MSGS_PER_TICK 256               -> send_credit_per_tick: one
//                                         viewer session sends at most 256
//                                         backlog messages per tick.
//   TICK_CONCURRENCY 16                 -> sessions_serviced_per_tick: the
//                                         Rust ticker runs at most 16
//                                         sessions' state machines in
//                                         parallel inside one tick_all;
//                                         this single-threaded tick
//                                         instead SERVICES (sends >= 1
//                                         message for) at most 16 viewer
//                                         sessions per tick, rotating a
//                                         cursor through the session list
//                                         so starved sessions go first on
//                                         the next tick. Same bound: one
//                                         slow viewer cannot consume the
//                                         whole tick.
//   drain_credits rate math             -> NOT carried over: the Rust
//                                         credit formula paces the drain
//                                         against the broadcaster's EWMA
//                                         rate; here G5's ring will own
//                                         rate tracking and EnqueueForViewer
//                                         feeds what it wants sent. The
//                                         hard 256 cap is kept.
//   drop_backlog / viewer_primed        -> on the first tick a viewer
//                                         session is observed connected,
//                                         its handshake-era send backlog is
//                                         cleared and the session is marked
//                                         "backlog-dropped" (PopBacklogDrop
//                                         hands the marker to G5 once, to
//                                         position the ring cursor at the
//                                         live edge).
//   tick timing stats                   -> tick count + max tick duration
//                                         getters, warn past 2 ms.
//
// THREADING. All WtServerListener callbacks and Tick run on the EventLoop
// thread; SrtInitiator methods are loop-thread by contract, so the tick
// path needs no per-entry locking. Explicitly thread-safe entry points:
// EnqueueForViewer (guarded backlog deque, called by G5's ring feed or
// tests from any thread), PopBacklogDrop / SessionInfoFor / Stats /
// IsConnected (map mutex + atomics; srt's own API is thread-safe),
// CloseSession (posts to the loop when called off it). AttachServer must
// run before the WtServer binds; Start arms the timer (loop thread or
// while the loop is not running - it posts when the loop already runs).

#ifndef WEBSRT_GATEWAY_SESSION_REGISTRY_H
#define WEBSRT_GATEWAY_SESSION_REGISTRY_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "gateway/srt_initiator.h"
#include "gateway/wt_server.h"

namespace quicsrt::gateway
{

/// Ticker + pacing parameters (the Rust numbers - see the file comment).
struct RegistryConfig
{
    std::chrono::milliseconds tick_interval{2};                  ///< Rust 2 ms cadence (500/s)
    int                       send_credit_per_tick       = 256;  ///< Rust MAX_MSGS_PER_TICK
    int                       sessions_serviced_per_tick = 16;   ///< Rust TICK_CONCURRENCY mapping
    int                       recv_budget_per_tick       = 256;  ///< publisher pump bound per session per tick
    std::size_t               viewer_backlog_max         = 4096; ///< drop-oldest bound until G5's ring takes over
    int                       latency_ms                 = 10;   ///< per-session SRTO_RCVLATENCY/PEERLATENCY
                                                                 ///< (the server latency_ms; senders
                                                                 ///  too-late-drop against a tiny window)
};

/// Per-session evidence snapshot (SessionInfoFor).
struct SessionInfo
{
    std::string   stream_name;
    bool          publisher_role         = false;
    bool          connected              = false; ///< the ticker observed SRTS_CONNECTED
    int           max_payload            = 0;     ///< negotiated payload ceiling
    std::uint64_t messages_sent          = 0;     ///< viewer direction: handed to srt
    std::uint64_t messages_received      = 0;     ///< publisher direction: pumped to the sink
    std::uint64_t backlog_size           = 0;     ///< viewer messages queued, not yet sent
    std::uint64_t backlog_start_drops    = 0;     ///< cleared by the first-connect drop_backlog
    std::uint64_t backlog_overflow_drops = 0;     ///< drop-oldest when the backlog bound was hit
};

/// One live session's evidence in one shot (SnapshotSessions): the C++
/// counterpart of the oracle's snapshot_sessions(), which /health's
/// per_session array is built from.
struct SessionSnapshot
{
    std::uint64_t   session_id = 0; ///< WtSessionHandle::Id()
    SessionInfo     info{};
    bool            srt_valid = false; ///< `srt` is populated (the initiator has stats)
    SRT_TRACEBSTATS srt{};
};

/// Consumer callbacks. ALL fire on the EventLoop thread and may call back
/// into the registry (e.g. CloseSession from OnSessionEnded).
class SessionRegistryListener
{
public:
    virtual ~SessionRegistryListener() = default;

    /// The G5 ring interface concept (minimal for now): one SRT message a
    /// publisher session released - a 188-aligned TS chunk of at most the
    /// negotiated payload size, bytes never modified. G5 implements this
    /// to feed the broadcaster ring.
    virtual void OnMedia(const std::string& stream_name, const std::uint8_t* data, std::size_t len) = 0;

    /// A session started (pass-through of the accept for occupancy and
    /// test visibility; G5's stream registry decides first-wins here).
    virtual void OnSessionStart(WtSessionHandle /*handle*/, const WtSessionStart& /*start*/) {}

    /// Terminal: the session's SRT initiator was torn down and its WT
    /// session asked to close (WT close, SRT failure, health reap, EOF).
    virtual void OnSessionEnded(WtSessionHandle /*handle*/, const std::string& /*reason*/) {}
};

/// The per-message size EnqueueForViewer slices a viewer's ring message
/// into: the negotiated payload ceiling, clamped UP to one 188-byte TS
/// packet when the value lands below that (the degenerate end of the
/// HSv5 MTU-field quirk ConnectionState documents). The clamp direction
/// matters: falling back to the WHOLE message would silently disable
/// chunking, and a publish-side message reassembles up to 4 MiB - one
/// unbounded backlog entry. One 188-byte message still fits the
/// transport's 1200-byte minimum datagram, and a bounded backlog beats
/// honoring a sub-packet payload hint.
[[nodiscard]] constexpr std::size_t ViewerChunkSize(int negotiated_payload)
{
    return negotiated_payload >= 188 ? static_cast<std::size_t>(negotiated_payload) : std::size_t{188};
}

/// One registry of all live sessions, polled by a single repeating timer.
/// Construct, AttachServer, then Start (before or after the loop runs);
/// destroy with the WtServer still alive (teardown posts to the loop when
/// it is still running and waits).
class SessionRegistry final : public WtServerListener
{
public:
    SessionRegistry(quicsrt::EventLoop&      loop,
                    SessionRegistryListener& listener,
                    RegistryConfig           config = RegistryConfig{});
    ~SessionRegistry() override;

    SessionRegistry(const SessionRegistry&)            = delete;
    SessionRegistry& operator=(const SessionRegistry&) = delete;

    /// Two-phase wiring (the sessions' pattern): the registry must be the
    /// WtServer's listener, and it needs the server for egress/close.
    void AttachServer(WtServer& server);

    /// Arms the ~2 ms repeating tick. Call once, after AttachServer and
    /// before/after the loop starts (posts when the loop already runs).
    void Start();

    /// Thread-safe. Queue one message (<= max_payload bytes) for a
    /// viewer-role session to send on the next ticks (the G5 ring feed).
    /// False for an unknown/publisher/finished session or a bad size. A
    /// full backlog drops the OLDEST message (counted) - live-stream
    /// semantics until G5's ring owns positioning.
    bool EnqueueForViewer(WtSessionHandle handle, const void* data, std::size_t len);

    /// Thread-safe, consume-once: true the first call after the session's
    /// first connected tick cleared its backlog (the drop_backlog marker
    /// G5 uses to position the ring cursor at the live edge).
    bool PopBacklogDrop(WtSessionHandle handle);

    /// Thread-safe. Graceful per-session end (viewer EOF when the stream
    /// ends): tears the SRT initiator down and closes the WT session.
    void CloseSession(WtSessionHandle handle, const std::string& reason);

    /// Thread-safe evidence.
    [[nodiscard]] bool SessionInfoFor(WtSessionHandle handle, SessionInfo* out) const;
    /// Every live (not-yet-finished) session's identity + counters + SRT
    /// stats, in handle order (health/stats). Thread-safe for an off-loop
    /// health worker: copies the live entries under the map mutex, then
    /// samples each entry outside it (each entry's own synchronization -
    /// atomics, backlog_mutex, the initiator's socket guard), so the map
    /// mutex is never held across srt calls.
    [[nodiscard]] std::vector<SessionSnapshot> SnapshotSessions() const;
    [[nodiscard]] bool                         IsConnected(WtSessionHandle handle) const;
    [[nodiscard]] bool                         Stats(WtSessionHandle handle, SRT_TRACEBSTATS* out) const;
    [[nodiscard]] int                          ActiveSessionCount() const;
    [[nodiscard]] std::uint64_t                TickCount() const { return tick_count_.load(); }
    /// Longest tick so far, microseconds (the Rust tick budget monitor).
    [[nodiscard]] std::uint64_t TickMaxUs() const { return tick_max_us_.load(); }
    /// Mean tick over the process lifetime, microseconds. The oracle's
    /// ticker.avg_us in /health is a rolling window average; ours is
    /// cumulative, because a moving window would have to be shared with
    /// the ticker under a lock for no decision ever reads it.
    [[nodiscard]] std::uint64_t TickAvgUs() const
    {
        const std::uint64_t count = tick_count_.load(std::memory_order_relaxed);
        return count == 0 ? 0 : tick_total_us_.load(std::memory_order_relaxed) / count;
    }

private:
    // ---- WtServerListener (loop thread) ----
    void OnWtSession(WtSessionHandle handle, const WtSessionStart& start) override;
    void OnSessionClosed(WtSessionHandle handle, const std::string& reason) override;
    void OnDatagram(WtSessionHandle handle, const std::uint8_t* data, std::size_t size) override;

    // ---- ticker (loop thread) ----
    void Tick();
    void PumpPublisher(const std::shared_ptr<struct RegistryEntry>& entry);
    /// Returns true when at least one message was sent (an "actively
    /// serviced" session against sessions_serviced_per_tick).
    bool ServiceViewer(const std::shared_ptr<struct RegistryEntry>& entry);
    void FinishEntry(const std::shared_ptr<struct RegistryEntry>& entry, const std::string& reason);
    void CloseSessionOnLoop(WtSessionHandle handle, const std::string& reason);
    void CancelAndDrain();

    [[nodiscard]] std::shared_ptr<struct RegistryEntry>              Find(WtSessionHandle handle) const;
    [[nodiscard]] std::vector<std::shared_ptr<struct RegistryEntry>> Snapshot() const;

    quicsrt::EventLoop&      loop_;
    SessionRegistryListener& listener_;
    RegistryConfig           config_;
    WtServer*                server_        = nullptr; // set by AttachServer, pre-use
    bool                     shutting_down_ = false;   // dtor path: no WtServer calls

    // Live sessions keyed by handle id. The mutex guards the MAP only
    // (insert/erase/snapshot); entry internals are loop-thread except
    // the atomics, the backlog-mutex-guarded viewer backlog (including
    // its drop counters) and the initiator's any-thread stats surface
    // (max_payload/StatsOut - see srt_initiator.h). Never held across
    // srt calls outside FinishEntry's erase.
    mutable std::map<std::uint64_t, std::shared_ptr<struct RegistryEntry>> entries_;
    mutable std::mutex                                                     entries_mutex_;

    quicsrt::EventLoop::TimerId timer_id_    = quicsrt::EventLoop::kInvalidTimerId;
    std::size_t                 tick_cursor_ = 0; // rotating viewer-service cursor

    // Ticker evidence.
    std::atomic<std::uint64_t> tick_count_{0};
    std::atomic<std::uint64_t> tick_max_us_{0};
    std::atomic<std::uint64_t> tick_total_us_{0};
};

} // namespace quicsrt::gateway

#endif // WEBSRT_GATEWAY_SESSION_REGISTRY_H
