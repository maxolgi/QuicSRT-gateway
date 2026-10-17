#include "gateway/session_registry.h"

#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <future>
#include <utility>

#include "core/event_loop.h"

namespace websrt::gateway
{

namespace
{

// Publisher pump receive buffer: one released SRT message. Senders are
// NOT bounded by the negotiated payload size - a message spans many payload
// packets and reassembles whole (the SlopShady wasm muxer frames whole
// ~0.3 MB GOPs as single messages; srt_recvmsg silently truncates to the
// buffer, so it grows on a full read, Rust-oracle style unbounded-in-kind).
constexpr std::size_t kRecvBufInitial = 1024 * 1024;
constexpr std::size_t kRecvBufMax     = 4 * 1024 * 1024;

// Largest single EnqueueForViewer payload accepted (int return of Send).
constexpr std::size_t kMaxEnqueueSize = 4ULL * 1024ULL * 1024ULL;

void Log(const char* fmt, ...)
{
    std::fputs("session-registry: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

const char* StateName(SRT_SOCKSTATUS state)
{
    switch (state)
    {
    case SRTS_INIT:
        return "init";
    case SRTS_OPENED:
        return "opened";
    case SRTS_LISTENING:
        return "listening";
    case SRTS_CONNECTING:
        return "connecting";
    case SRTS_CONNECTED:
        return "connected";
    case SRTS_CLOSING:
        return "closing";
    case SRTS_CLOSED:
        return "closed";
    case SRTS_BROKEN:
        return "broken";
    case SRTS_NONEXIST:
        return "nonexistent";
    }
    return "unknown";
}

} // namespace

// All mutable per-session state. Loop-thread except where noted.
struct RegistryEntry
{
    WtSessionHandle               handle;
    std::string                   stream_name;
    bool                          publisher_role = false;
    std::unique_ptr<SrtInitiator> initiator;

    // Viewer send backlog: EnqueueForViewer (any thread) vs the ticker's
    // ServiceViewer (loop thread) - guarded, unlike everything else here.
    // The drop counters live under the same mutex (their off-loop reads
    // in InfoOf take it too).
    std::mutex                            backlog_mutex;
    std::deque<std::vector<std::uint8_t>> backlog;
    std::uint64_t                         backlog_start_drops    = 0; // first-connect drop_backlog
    std::uint64_t                         backlog_overflow_drops = 0; // drop-oldest at the bound

    // Set on the first tick the initiator is observed connected; for a
    // viewer it also clears the backlog (Rust viewer_primed/drop_backlog)
    // and raises the consume-once marker G5 reads via PopBacklogDrop.
    std::atomic<bool> connected_seen{false};
    std::atomic<bool> backlog_drop_marked{false};

    std::atomic<bool>          finished{false};
    std::atomic<std::uint64_t> messages_sent{0};
    std::atomic<std::uint64_t> messages_received{0};

    // Publisher pump buffer (grows on full reads; see kRecvBufInitial).
    std::vector<std::uint8_t> recv_buf = std::vector<std::uint8_t>(kRecvBufInitial);
};

namespace
{

/// The evidence both SessionInfoFor and SnapshotSessions report (one
/// definition, so the two views can never disagree). Any thread:
/// immutable-after-publication fields, atomics, and the backlog evidence
/// under the same mutex its writes take.
SessionInfo InfoOf(RegistryEntry& entry)
{
    SessionInfo info;
    info.stream_name       = entry.stream_name;
    info.publisher_role    = entry.publisher_role;
    info.connected         = entry.connected_seen.load(std::memory_order_relaxed);
    info.max_payload       = entry.initiator->max_payload();
    info.messages_sent     = entry.messages_sent.load(std::memory_order_relaxed);
    info.messages_received = entry.messages_received.load(std::memory_order_relaxed);
    {
        // Backlog evidence under backlog_mutex: every write to the drop
        // counters takes it (Tick's drop_backlog, EnqueueForViewer's
        // drop-oldest, ServiceViewer's oversize drop) - reading them
        // unlocked raced the loop thread's writes.
        const std::lock_guard<std::mutex> lock(entry.backlog_mutex);
        info.backlog_size           = entry.backlog.size();
        info.backlog_start_drops    = entry.backlog_start_drops;
        info.backlog_overflow_drops = entry.backlog_overflow_drops;
    }
    return info;
}

} // namespace

SessionRegistry::SessionRegistry(websrt::EventLoop& loop, SessionRegistryListener& listener, RegistryConfig config)
    : loop_(loop)
    , listener_(listener)
    , config_(config)
{
}

SessionRegistry::~SessionRegistry()
{
    if (loop_.IsRunning() && !loop_.OnLoopThread())
    {
        // Mirror WtServer's destructor: drain on the loop thread, wait.
        std::promise<void> done;
        auto               future = done.get_future();
        (void)loop_.Post(
            [this, &done]
            {
                CancelAndDrain();
                done.set_value();
            });
        future.wait();
    }
    else
    {
        CancelAndDrain();
    }
}

void SessionRegistry::AttachServer(WtServer& server)
{
    server_ = &server;
}

void SessionRegistry::Start()
{
    auto arm = [this] { timer_id_ = loop_.SetTimer(config_.tick_interval, true, [this] { Tick(); }); };
    if (loop_.IsRunning() && !loop_.OnLoopThread())
    {
        (void)loop_.Post(std::move(arm));
    }
    else
    {
        arm();
    }
}

// ---- WtServerListener (loop thread) ----

void SessionRegistry::OnWtSession(WtSessionHandle handle, const WtSessionStart& start)
{
    if (server_ == nullptr)
    {
        return;
    }
    const bool        publisher = start.publish_name.has_value();
    const std::string name      = publisher ? *start.publish_name : start.subscribe_name.value_or(std::string{});
    if (name.empty())
    {
        server_->CloseSession(handle, "session without a stream name");
        return;
    }

    auto entry            = std::make_shared<RegistryEntry>();
    entry->handle         = handle;
    entry->stream_name    = name;
    entry->publisher_role = publisher;
    // RTT seeding: the WT session's QUIC smoothed RTT at accept, zero
    // when unmeasured (the initiator then leaves srt's estimator alone).
    entry->initiator = std::make_unique<SrtInitiator>(
        *server_, handle, InitiatorConfig{.latency_ms = config_.latency_ms}, server_->SmoothedRtt(handle));

    std::string error;
    if (!entry->initiator->Setup(&error))
    {
        Log("session %" PRIu64 " srt setup failed: %s", handle.Id(), error.c_str());
        // The WT rejection path is TerminateSession via CloseSession -
        // the same inline-safe pattern as the policy rejections.
        server_->CloseSession(handle, "srt setup failed: " + error);
        return;
    }

    {
        const std::lock_guard<std::mutex> lock(entries_mutex_);
        entries_[handle.Id()] = entry;
    }
    listener_.OnSessionStart(handle, start);
}

void SessionRegistry::OnSessionClosed(WtSessionHandle handle, const std::string& reason)
{
    const auto entry = Find(handle);
    if (entry == nullptr)
    {
        return;
    }
    FinishEntry(entry, "wt session closed: " + reason);
}

void SessionRegistry::OnDatagram(WtSessionHandle handle, const std::uint8_t* data, std::size_t size)
{
    const auto entry = Find(handle);
    if (entry == nullptr || entry->finished.load(std::memory_order_relaxed))
    {
        return;
    }
    entry->initiator->Inject(data, size);
}

// ---- ticker (loop thread) ----

void SessionRegistry::Tick()
{
    const auto t0      = std::chrono::steady_clock::now();
    const auto entries = Snapshot();
    tick_count_.fetch_add(1, std::memory_order_relaxed);

    // Rotating start: a viewer starved by the service cap this tick is
    // first in line the next one.
    const std::size_t n                = entries.size();
    int               viewers_serviced = 0;

    for (std::size_t i = 0; i < n; ++i)
    {
        const auto& entry = entries[(tick_cursor_ + i) % n];
        if (entry->finished.load(std::memory_order_relaxed))
        {
            continue;
        }

        const SRT_SOCKSTATUS state = entry->initiator->ConnectionState();
        if (state == SRTS_CONNECTED && !entry->connected_seen.exchange(true))
        {
            if (!entry->publisher_role)
            {
                // drop_backlog on the first connected tick: discard what
                // accumulated during the handshake and mark the session
                // for G5's ring-cursor positioning.
                const std::lock_guard<std::mutex> lock(entry->backlog_mutex);
                entry->backlog_start_drops += entry->backlog.size();
                entry->backlog.clear();
                entry->backlog_drop_marked.store(true, std::memory_order_relaxed);
            }
        }

        if (state == SRTS_CONNECTING)
        {
            continue; // SRTO_CONNTIMEO bounds the wait; health reaps failures
        }
        if (state != SRTS_CONNECTED)
        {
            FinishEntry(entry, std::string("srt connection ") + StateName(state));
            continue;
        }

        if (entry->publisher_role)
        {
            PumpPublisher(entry);
        }
        else if (viewers_serviced < config_.sessions_serviced_per_tick && ServiceViewer(entry))
        {
            ++viewers_serviced;
        }
    }
    tick_cursor_ = n > 0 ? (tick_cursor_ + 1) % n : 0;

    const auto elapsed = std::chrono::steady_clock::now() - t0;
    const auto us      = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    if (static_cast<std::uint64_t>(us) > tick_max_us_.load(std::memory_order_relaxed))
    {
        tick_max_us_.store(static_cast<std::uint64_t>(us), std::memory_order_relaxed);
    }
    tick_total_us_.fetch_add(static_cast<std::uint64_t>(us), std::memory_order_relaxed);
    if (elapsed > std::chrono::milliseconds{2})
    {
        Log("tick exceeded the 2 ms budget: %lld us across %zu sessions", static_cast<long long>(us), n);
    }
}

void SessionRegistry::PumpPublisher(const std::shared_ptr<RegistryEntry>& entry)
{
    for (int i = 0; i < config_.recv_budget_per_tick; ++i)
    {
        const int n = entry->initiator->ReceiveNext(reinterpret_cast<char*>(entry->recv_buf.data()),
                                                    static_cast<int>(entry->recv_buf.size()));
        if (n > 0)
        {
            if (static_cast<std::size_t>(n) == entry->recv_buf.size() && entry->recv_buf.size() < kRecvBufMax)
            {
                // A full read may have truncated the message - grow for the
                // next one (the fork logs the true size when it truncates).
                entry->recv_buf.resize(std::min(entry->recv_buf.size() * 2, kRecvBufMax));
                Log("session %" PRIu64 " recv buffer grows to %zu bytes", entry->handle.Id(), entry->recv_buf.size());
            }
            listener_.OnMedia(entry->stream_name, entry->recv_buf.data(), static_cast<std::size_t>(n));
            entry->messages_received.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (n == SrtInitiator::kRecvWouldBlock)
        {
            return;
        }
        if (n == SrtInitiator::kRecvClosed)
        {
            // The browser publisher ended the stream (SRT shutdown after
            // its TSBPD window drained). Parity with the Rust oracle:
            // the session ends; G5 releases the stream name from here.
            FinishEntry(entry, "publisher closed the stream");
            return;
        }
        FinishEntry(entry, "srt receive error");
        return;
    }
}

bool SessionRegistry::ServiceViewer(const std::shared_ptr<RegistryEntry>& entry)
{
    bool        sent_any = false;
    bool        need_end = false;
    std::string reason;
    {
        const std::lock_guard<std::mutex> lock(entry->backlog_mutex);
        auto                              budget = static_cast<std::size_t>(config_.send_credit_per_tick);
        while (budget > 0 && !entry->backlog.empty())
        {
            const std::vector<std::uint8_t>& msg = entry->backlog.front();
            const int                        r   = entry->initiator->Send(msg.data(), static_cast<int>(msg.size()));
            if (r == static_cast<int>(msg.size()))
            {
                entry->backlog.pop_front();
                --budget;
                sent_any = true;
                entry->messages_sent.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (r == SrtInitiator::kSendWouldBlock)
            {
                break; // socket not writable; retry next tick
            }
            if (r == SrtInitiator::kSendInvalidArg)
            {
                // Larger than the negotiated payload ceiling: drop it
                // (G5's ring framing is expected to chunk to max_payload).
                entry->backlog.pop_front();
                entry->backlog_overflow_drops += 1;
                continue;
            }
            reason   = r == SrtInitiator::kSendClosed ? "viewer srt connection closed"
                                                      : std::string("viewer srt send failed: ") + srt_getlasterror_str();
            need_end = true;
            break;
        }
    }
    if (need_end)
    {
        FinishEntry(entry, reason);
    }
    return sent_any;
}

void SessionRegistry::FinishEntry(const std::shared_ptr<RegistryEntry>& entry, const std::string& reason)
{
    bool expected = false;
    if (!entry->finished.compare_exchange_strong(expected, true))
    {
        return;
    }

    entry->initiator->Teardown();
    {
        const std::lock_guard<std::mutex> lock(entries_mutex_);
        entries_.erase(entry->handle.Id());
    }
    Log("session %" PRIu64 " (%s) ended: %s", entry->handle.Id(), entry->stream_name.c_str(), reason.c_str());
    listener_.OnSessionEnded(entry->handle, reason);
    // When the WT session is still alive (an SRT-side end), close it so
    // the browser observes the end; a no-op when it already closed (the
    // OnSessionClosed path - WtSessionClosed fired first). Skipped during
    // the registry's own shutdown: the WtServer may already be gone (the
    // registry is constructed before the server that uses it as listener,
    // so it destructs after).
    if (server_ != nullptr && !shutting_down_)
    {
        server_->CloseSession(entry->handle, reason);
    }
}

// ---- thread-safe entry points ----

bool SessionRegistry::EnqueueForViewer(WtSessionHandle handle, const void* data, std::size_t len)
{
    if (data == nullptr || len == 0 || len > kMaxEnqueueSize)
    {
        return false;
    }
    const auto entry = Find(handle);
    if (entry == nullptr || entry->publisher_role || entry->finished.load(std::memory_order_relaxed))
    {
        return false;
    }
    const auto*                       bytes = static_cast<const std::uint8_t*>(data);
    const std::lock_guard<std::mutex> lock(entry->backlog_mutex);
    // The fork's live send API caps one message at the negotiated payload
    // (LiveCC checkTransArgs; stock srt would fragment) - re-chunk ring
    // messages there. Payload is 188-aligned, so a TS byte stream is
    // split transparently for the receiver's demuxer.
    const int         payload  = entry->initiator->max_payload();
    const std::size_t chunk    = ViewerChunkSize(payload);
    bool              enqueued = false;
    for (std::size_t off = 0; off < len; off += chunk)
    {
        if (entry->backlog.size() >= config_.viewer_backlog_max)
        {
            entry->backlog.pop_front(); // live-stream semantics: drop the oldest
            entry->backlog_overflow_drops += 1;
        }
        const std::size_t end = std::min(off + chunk, len);
        entry->backlog.emplace_back(bytes + off, bytes + end);
        enqueued = true;
    }
    return enqueued;
}

bool SessionRegistry::PopBacklogDrop(WtSessionHandle handle)
{
    const auto entry = Find(handle);
    return entry != nullptr && entry->backlog_drop_marked.exchange(false, std::memory_order_relaxed);
}

void SessionRegistry::CloseSession(WtSessionHandle handle, const std::string& reason)
{
    if (loop_.OnLoopThread())
    {
        CloseSessionOnLoop(handle, reason);
    }
    else
    {
        (void)loop_.Post([this, handle, reason] { CloseSessionOnLoop(handle, reason); });
    }
}

void SessionRegistry::CloseSessionOnLoop(WtSessionHandle handle, const std::string& reason)
{
    const auto entry = Find(handle);
    if (entry == nullptr)
    {
        return;
    }
    FinishEntry(entry, reason);
}

bool SessionRegistry::SessionInfoFor(WtSessionHandle handle, SessionInfo* out) const
{
    if (out == nullptr)
    {
        return false;
    }
    const auto entry = Find(handle);
    if (entry == nullptr)
    {
        return false;
    }
    *out = InfoOf(*entry);
    return true;
}

std::vector<SessionSnapshot> SessionRegistry::SnapshotSessions() const
{
    // Live entries copied under the map mutex (the shared_ptrs keep them
    // alive), each sampled OUTSIDE it: per-entry state has its own
    // synchronization (atomics, backlog_mutex, the initiator's socket
    // guard), and holding the map mutex across the srt sampling would
    // contend with the 2 ms tick's own Snapshot().
    std::vector<std::shared_ptr<RegistryEntry>> live;
    {
        const std::lock_guard<std::mutex> lock(entries_mutex_);
        live.reserve(entries_.size());
        for (const auto& entry : entries_)
        {
            // Finished entries are on their way out; the oracle filters
            // them out of snapshot_sessions for the same reason.
            if (!entry.second->finished.load(std::memory_order_relaxed))
            {
                live.push_back(entry.second);
            }
        }
    }

    std::vector<SessionSnapshot> out;
    out.reserve(live.size());
    for (const auto& entry : live)
    {
        SessionSnapshot snapshot;
        snapshot.session_id = entry->handle.Id();
        snapshot.info       = InfoOf(*entry);
        snapshot.srt_valid  = entry->initiator->StatsOut(&snapshot.srt);
        out.push_back(snapshot);
    }
    return out;
}

bool SessionRegistry::IsConnected(WtSessionHandle handle) const
{
    const auto entry = Find(handle);
    return entry != nullptr && entry->connected_seen.load(std::memory_order_relaxed);
}

bool SessionRegistry::Stats(WtSessionHandle handle, SRT_TRACEBSTATS* out) const
{
    const auto entry = Find(handle);
    return entry != nullptr && entry->initiator->StatsOut(out);
}

int SessionRegistry::ActiveSessionCount() const
{
    const std::lock_guard<std::mutex> lock(entries_mutex_);
    return static_cast<int>(entries_.size());
}

void SessionRegistry::CancelAndDrain()
{
    shutting_down_ = true;
    if (timer_id_ != websrt::EventLoop::kInvalidTimerId)
    {
        loop_.CancelTimer(timer_id_);
        timer_id_ = websrt::EventLoop::kInvalidTimerId;
    }
    const auto entries = Snapshot();
    for (const auto& entry : entries)
    {
        FinishEntry(entry, "registry shutdown");
    }
}

std::shared_ptr<struct RegistryEntry> SessionRegistry::Find(WtSessionHandle handle) const
{
    const std::lock_guard<std::mutex> lock(entries_mutex_);
    const auto                        it = entries_.find(handle.Id());
    return it == entries_.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<struct RegistryEntry>> SessionRegistry::Snapshot() const
{
    const std::lock_guard<std::mutex>           lock(entries_mutex_);
    std::vector<std::shared_ptr<RegistryEntry>> out;
    out.reserve(entries_.size());
    for (const auto& [_, entry] : entries_)
    {
        out.push_back(entry);
    }
    return out;
}

} // namespace websrt::gateway
