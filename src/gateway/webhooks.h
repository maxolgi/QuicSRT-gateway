// on_connect/on_close webhooks (P4 step 3, PLAN.md P4.3): session
// lifecycle events POSTed as small JSON payloads to a configured URL -
// the SLS-parity feature. Event sources (where each lifecycle fact is
// observed):
//   viewer_connect / viewer_disconnect      Gateway::OnSessionStart /
//                                           OnSessionEnded (viewer role)
//   publisher_connect / publisher_disconnect  WT: the same two, publisher
//                                           role; SRT ingest: SrtIngest's
//                                           AcceptOne / EndConn
//   publisher_end (a.k.a. stream end)       Gateway::EndPublish - the ONE
//                                           shared publisher-end path both
//                                           source kinds land on
//
// THREADING. Notify() may be called from ANY thread - the event loop
// (WT session lifecycle) and the ingest thread alike - and only ENQUEUES:
// a mutex-guarded deque push that counts and drops when the bound is hit.
// Delivery NEVER runs on the event loop: a dedicated worker thread pops
// and performs one blocking plain-socket HTTP/1.1 POST (SLS-style
// webhooks target local receivers; https is not supported - the config
// rejects the scheme). A failed POST (connect/send/recv error, timeout,
// non-2xx status) is retried EXACTLY once, then counted as failed.
//
// SETTINGS SWAP. SetSettings is thread-safe; the worker reads the current
// settings when it pops an event, so a hot-reload swap (Gateway::
// ApplyRuntimeConfig, P4.1's single post) affects deliveries from the
// next pop on - queued events may drain under old or new settings, by
// design. An empty URL is "off": Notify enqueues nothing, and events
// still queued when the URL turns empty are dropped (counted).

#ifndef WEBSRT_GATEWAY_WEBHOOKS_H
#define WEBSRT_GATEWAY_WEBHOOKS_H

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace websrt::gateway
{

/// Webhook knobs (the [webhooks] table). Empty URL = feature off.
struct WebhookSettings
{
    std::string               url;           ///< "http://host[:port][/path]"
    std::chrono::milliseconds timeout{2000}; ///< per-attempt POST timeout
};

/// One lifecycle event, JSON-encoded 1:1 into the POST body:
///   {"event":..., "stream":..., "role":..., "remote":...,
///    "session_id":..., "timestamp_ms":...}
/// `timestamp_ms` is filled by Notify (Unix epoch milliseconds); callers
/// never set it. `publisher_end` is a stream-level event: no single
/// connection owns it, so `remote` is empty and `session_id` is 0.
struct WebhookEvent
{
    std::string
        event; ///< viewer_connect | viewer_disconnect | publisher_connect | publisher_disconnect | publisher_end
    std::string   stream;
    std::string   role;   ///< "viewer" | "publisher"
    std::string   remote; ///< "ip:port" of the session's peer
    std::uint64_t session_id   = 0;
    std::int64_t  timestamp_ms = 0;
};

/// Evidence (the /stats webhooks object).
struct WebhookSnapshot
{
    bool          enabled   = false;
    std::uint64_t delivered = 0;
    std::uint64_t dropped   = 0; ///< queue-full drops + off-swallow + shutdown drops
    std::uint64_t failed    = 0; ///< both POST attempts failed
};

class WebhookDispatcher final
{
public:
    /// Queue bound: events beyond this are dropped and counted. 256 is
    /// far above any sane session churn and keeps a stuck receiver from
    /// ballooning memory.
    static constexpr std::size_t kQueueBound = 256;

    /// Starts the worker thread (it idles on the condition variable until
    /// an event or the destructor wakes it).
    explicit WebhookDispatcher(WebhookSettings settings = WebhookSettings{});
    ~WebhookDispatcher();

    WebhookDispatcher(const WebhookDispatcher&)            = delete;
    WebhookDispatcher& operator=(const WebhookDispatcher&) = delete;

    /// Thread-safe. Swap the URL/timeout (hot reload). Never blocks.
    void SetSettings(const WebhookSettings& settings);

    /// Thread-safe, NON-blocking: enqueue one event (timestamp filled
    /// here). A disabled (empty-URL) dispatcher drops nothing and queues
    /// nothing; a full queue drops the event and counts it.
    void Notify(WebhookEvent event);

    /// Thread-safe evidence.
    [[nodiscard]] WebhookSnapshot Snapshot() const;

private:
    void Run();
    /// One POST attempt; false on any transport error, timeout or
    /// non-2xx status.
    [[nodiscard]] static bool PostOnce(const WebhookSettings& settings, const std::string& body);

    mutable std::mutex       mutex_;
    std::condition_variable  cv_;
    std::deque<WebhookEvent> queue_;
    WebhookSettings          settings_;
    bool                     stop_      = false;
    std::uint64_t            delivered_ = 0;
    std::uint64_t            dropped_   = 0;
    std::uint64_t            failed_    = 0;
    std::thread              worker_;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_WEBHOOKS_H
