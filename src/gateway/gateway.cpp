#include "gateway/gateway.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <future>
#include <thread>
#include <utility>

namespace websrt::gateway
{

namespace
{

// How often the housekeeping timer sweeps for drop_backlog markers. The
// markers themselves are consumed on the media path (the prime must happen
// before the next message is handed over); this slow sweep is the backstop
// for a stream whose publisher has gone quiet mid-handshake.
constexpr std::chrono::milliseconds kHousekeepingInterval{500};

// Bounded wait for the sessions to finish closing during Shutdown (the Rust
// oracle's 3 s session drain, gateway.rs:487-497).
constexpr auto kDrainTimeout = std::chrono::seconds{3};

void Log(const char* fmt, ...)
{
    std::fputs("gateway: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

/// The stream a session addresses, and whether it publishes it. Mirrors
/// SessionRegistry::OnWtSession - the admission consult and the claim must
/// agree, so both resolve the role the same way.
struct Role
{
    bool        publisher = false;
    std::string stream;
};

Role ResolveRole(const WtSessionStart& start)
{
    if (start.publish_name.has_value())
    {
        return Role{.publisher = true, .stream = *start.publish_name};
    }
    if (start.subscribe_name.has_value())
    {
        return Role{.publisher = false, .stream = *start.subscribe_name};
    }
    return Role{};
}

const char* DecisionText(Decision d)
{
    switch (d)
    {
    case Decision::Accept:
        return "accept";
    case Decision::Reject:
        return "404";
    case Decision::Forbidden:
        return "403";
    case Decision::TooManyRequests:
        return "429";
    }
    return "?";
}

/// One webhook payload, minus the timestamp (Notify stamps it).
WebhookEvent LifecycleEvent(
    const char* event, const std::string& stream, const char* role, const std::string& remote, std::uint64_t session_id)
{
    return WebhookEvent{.event = event, .stream = stream, .role = role, .remote = remote, .session_id = session_id};
}

} // namespace

Gateway::Gateway(const CertProvider& cert, std::shared_ptr<const SessionPolicy> policy, GatewayConfig config)
    : webhooks_{config.webhooks}
    , streams_{StreamRegistryConfig{.max_viewers           = config.max_viewers,
                                    .broadcast_capacity    = config.broadcast_capacity,
                                    .broadcast_byte_budget = config.broadcast_byte_budget}}
    , policy_{std::move(policy)}
    , registry_{loop_, *this, config.registry}
    , server_{loop_, cert, policy_, registry_, [this](const WtSessionStart& start) { return Admit(start); }, config.wt}
{
    // The registry needs the server it serves (egress + close); the server
    // is constructed after it, so the wiring happens here.
    registry_.AttachServer(server_);
    fanout_budget_ =
        config.registry.send_credit_per_tick > 0 ? static_cast<std::size_t>(config.registry.send_credit_per_tick) : 256;
}

Gateway::~Gateway()
{
    // The housekeeping timer must be gone before the members it touches die.
    if (loop_.OnLoopThread())
    {
        CancelHousekeeping();
        return;
    }
    std::promise<void> done;
    // Post false = the loop already stopped: no thread can be inside the
    // timer callback, so cancelling here races nothing.
    if (loop_.Post(
            [this, &done]
            {
                CancelHousekeeping();
                done.set_value();
            }))
    {
        done.get_future().wait(); // Post true guarantees the job ran
    }
    else
    {
        CancelHousekeeping();
    }
}

bool Gateway::Start(const std::string& host, std::uint16_t port)
{
    if (running_ || shut_down_)
    {
        return false;
    }
    loop_.Start();
    if (!server_.Bind(host, port))
    {
        loop_.Stop();
        return false;
    }
    registry_.Start();
    housekeeping_timer_ = loop_.SetTimer(kHousekeepingInterval, true, [this] { PrimePendingViewers(); });
    running_            = true;
    Log("serving WebTransport on %s:%u (max_viewers %zu, broadcast_capacity %zu)",
        host.c_str(),
        port,
        streams_.MaxViewers(),
        streams_.BroadcastCapacity());
    return true;
}

void Gateway::Shutdown()
{
    if (shut_down_)
    {
        return;
    }
    shut_down_ = true;
    if (!running_)
    {
        return;
    }
    running_ = false;
    Log("draining %d session(s)", registry_.ActiveSessionCount());
    server_.Close(); // CONNECTION_CLOSE to every client; sessions reap themselves
    const auto deadline = std::chrono::steady_clock::now() + kDrainTimeout;
    while (registry_.ActiveSessionCount() > 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    const int left = registry_.ActiveSessionCount();
    if (left > 0)
    {
        Log("drain timed out with %d session(s) left; stopping the loop anyway", left);
    }
    loop_.Stop(); // joins the engine thread
    Log("shutdown complete (%llu unclaimed message(s))", static_cast<unsigned long long>(media_unclaimed_));
}

void Gateway::CancelHousekeeping()
{
    if (housekeeping_timer_ != websrt::EventLoop::kInvalidTimerId)
    {
        loop_.CancelTimer(housekeeping_timer_);
        housekeeping_timer_ = websrt::EventLoop::kInvalidTimerId;
    }
}

void Gateway::ApplyRuntimeConfig(std::shared_ptr<const SessionPolicy> policy,
                                 std::size_t                          max_viewers,
                                 WebhookSettings                      webhooks)
{
    // One posted function = one atomic swap: a CONNECT the engine admits
    // meanwhile is judged by the fully-old or the fully-new config, never
    // a mix. Off-loop callers wait for the swap to land (the
    // SnapshotStreams discipline) so a reload that returned HAS applied.
    const auto apply = [this, &policy, max_viewers, &webhooks]
    {
        policy_ = policy;
        server_.SetPolicy(policy_);
        streams_.SetMaxViewers(max_viewers);
        webhooks_.SetSettings(webhooks);
        Log("runtime config applied (max_viewers %zu)", streams_.MaxViewers());
    };
    if (loop_.OnLoopThread())
    {
        apply();
        return;
    }
    std::promise<void> done;
    // Post false = the loop already stopped: no CONNECT can interleave, so
    // applying here is atomic too - and the "returned HAS applied"
    // contract above still holds.
    if (loop_.Post(
            [&]
            {
                apply();
                done.set_value();
            }))
    {
        done.get_future().wait();
    }
    else
    {
        apply();
    }
}

// ---- SessionRegistryListener (loop thread) ----

void Gateway::OnMedia(const std::string& stream_name, const std::uint8_t* data, std::size_t len)
{
    // Prime before handing over: a viewer that just finished its handshake
    // must have its cursor snapped to the live edge BEFORE this message, or
    // it would replay the handshake-era backlog.
    PrimePendingViewers();

    Broadcaster* bc = streams_.Find(stream_name);
    if (bc == nullptr)
    {
        ++media_unclaimed_;
        return;
    }
    // Framing: SRT messages are whole frames - the negotiated payload size
    // caps the PACKET, not the message (the wasm muxers frame ~9-37 KB
    // frames as single messages; srt_sendmsg2 re-fragments per viewer).
    // Viewer-side Send/buffer bounds are the enforcement point.
    bc->Append(data, len);
    bc->Pump([this](WtSessionHandle viewer, const void* bytes, std::size_t n)
             { return registry_.EnqueueForViewer(viewer, bytes, n); },
             fanout_budget_);
}

void Gateway::OnSessionStart(WtSessionHandle handle, const WtSessionStart& start)
{
    const Role role = ResolveRole(start);
    if (role.stream.empty())
    {
        registry_.CloseSession(handle, "session without a stream name");
        return;
    }

    SessionInfo info;
    const bool  have_info = registry_.SessionInfoFor(handle, &info);

    const Decision decision =
        role.publisher
            ? streams_.PublishAttempt(role.stream, handle)
            : streams_.AttachViewer(role.stream, handle, have_info ? static_cast<std::size_t>(info.max_payload) : 0);
    if (decision != Decision::Accept)
    {
        // The admission consult let this one through but the claim lost the
        // race (or the cap filled in between): the 200 is already out, so
        // the session ends instead.
        Log("session %" PRIu64 " claim refused on stream '%s' (HTTP %s)",
            handle.Id(),
            role.stream.c_str(),
            DecisionText(decision));
        registry_.CloseSession(handle, "stream claim refused: HTTP " + std::string{DecisionText(decision)});
        return;
    }

    sessions_.emplace(handle.Id(),
                      SessionRec{.stream = role.stream, .publisher = role.publisher, .remote = start.remote});
    if (!role.publisher)
    {
        // The drop_backlog marker may already have been raised (the tick
        // can land between the registry's accept and this callback); in
        // that case the viewer is primed immediately.
        pending_prime_.push_back(handle);
        PrimePendingViewers();
    }
    Log("session %" PRIu64 " %s stream '%s'",
        handle.Id(),
        role.publisher ? "publishing" : "viewing",
        role.stream.c_str());
    // P4.3 webhook: the session's claim succeeded, so it is live - one
    // connect event per accepted session, WT only (ingest publishers
    // notify from their own accept path).
    NotifyWebhook(LifecycleEvent(role.publisher ? "publisher_connect" : "viewer_connect",
                                 role.stream,
                                 role.publisher ? "publisher" : "viewer",
                                 start.remote,
                                 handle.Id()));
}

void Gateway::OnSessionEnded(WtSessionHandle handle, const std::string& reason)
{
    const auto it = sessions_.find(handle.Id());
    if (it == sessions_.end())
    {
        return;
    }
    const SessionRec rec = it->second;
    sessions_.erase(it);
    std::erase(pending_prime_, handle);

    if (rec.publisher)
    {
        // P4.3 webhook: the publisher's connection went away; EndPublish
        // below emits the stream-level publisher_end.
        NotifyWebhook(LifecycleEvent("publisher_disconnect", rec.stream, "publisher", rec.remote, handle.Id()));
        EndPublish(rec.stream, reason);
    }
    else
    {
        NotifyWebhook(LifecycleEvent("viewer_disconnect", rec.stream, "viewer", rec.remote, handle.Id()));
        streams_.DetachViewer(rec.stream, handle);
    }
}

// ---- the shared publisher-end path (a WT publisher session AND the G6
// ---- SRT/UDP ingest both land here) ----

void Gateway::EndPublish(const std::string& stream, const std::string& reason)
{
    // Parity: viewers see a clean EOF when the source ends. Two closes per
    // viewer, in this order:
    //   CloseConnection - the WT CONNECTION_CLOSE the Rust oracle sends
    //     (registry.rs:370-386: "closes the WT connection, which the browser
    //     surfaces as wtClosed so its auto-reconnect can resubscribe"). It is
    //     also the only close a WT client sees as a session end - a
    //     session-stream FIN leaves the connection (and a libwebsrt
    //     Subscriber's SRT session) running.
    //   CloseSession    - the registry teardown of that viewer's SRT
    //     initiator, which also FINs the (now closing) session stream.
    // Stream drop, both paths: with viewers attached their OnSessionEnded
    // -> DetachViewer drops the now-idle stream (the last detach); with
    // none attached OnPublisherEnd already dropped it. Either way a
    // reconnecting viewer recreates it as waiting.
    const std::vector<WtSessionHandle> closing = streams_.OnPublisherEnd(stream);
    for (const WtSessionHandle viewer : closing)
    {
        server_.CloseConnection(viewer, "stream ended");
        registry_.CloseSession(viewer, "stream ended");
    }
    Log("stream '%s' publisher ended (%s); %zu viewer(s) closed", stream.c_str(), reason.c_str(), closing.size());
    // P4.3 webhook: the stream-level end - no single connection owns it,
    // so remote/session_id carry no peer identity (empty/0). Both source
    // kinds (WT publisher session, SRT ingest) land here.
    NotifyWebhook(LifecycleEvent("publisher_end", stream, "publisher", "", 0));
}

// ---- admission ----

Decision Gateway::Admit(const WtSessionStart& start) const
{
    const Role role = ResolveRole(start);
    if (role.stream.empty())
    {
        return Decision::Reject; // neither ?publish= nor ?stream=/?subscribe=
    }
    if (role.publisher)
    {
        // First-wins occupancy: 403 while a live publisher (WT or G6
        // ingest) holds the name.
        return streams_.Publishable(role.stream) ? Decision::Accept : Decision::Forbidden;
    }
    return streams_.ViewerSlotFree(role.stream) ? Decision::Accept : Decision::TooManyRequests;
}

void Gateway::PrimePendingViewers()
{
    for (auto it = pending_prime_.begin(); it != pending_prime_.end();)
    {
        const WtSessionHandle handle = *it;
        if (!registry_.PopBacklogDrop(handle))
        {
            ++it;
            continue;
        }
        // The handshake settled: the negotiated payload ceiling is final.
        SessionInfo info;
        const bool  have_info = registry_.SessionInfoFor(handle, &info);
        const auto  rec       = sessions_.find(handle.Id());
        if (rec != sessions_.end())
        {
            streams_.PrimeViewer(
                rec->second.stream, handle, have_info ? static_cast<std::size_t>(info.max_payload) : 0);
        }
        it = pending_prime_.erase(it);
    }
}

// ---- the ingest source contract ----

bool Gateway::PublishMedia(const std::string& stream, const void* data, std::size_t len)
{
    if (data == nullptr || len == 0 || streams_.Find(stream) == nullptr)
    {
        return false;
    }
    OnMedia(stream, static_cast<const std::uint8_t*>(data), len);
    return true;
}

bool Gateway::ClaimIngestPublish(const std::string& stream)
{
    // The same claim a WT publisher session runs in OnSessionStart; the
    // handle is synthetic because an ingest publisher has no WT session (see
    // WtSessionHandle::ExternalSource). Occupancies are therefore shared:
    // PublishAttempt refuses while either source kind holds the name.
    return streams_.PublishAttempt(stream, WtSessionHandle::ExternalSource(next_ingest_handle_++)) == Decision::Accept;
}

void Gateway::ReleaseIngestPublish(const std::string& stream)
{
    EndPublish(stream, "ingest source ended");
}

bool Gateway::PublishAllowed(const std::string& stream) const
{
    // The synthetic ?publish= request the WT CONNECT path would have
    // judged (wt_server.cpp ProcessConnectHeaders): path /wt, the name
    // percent-encoded into the query. A named string - SessionRequest's
    // query is a string_view, so a temporary spliced into it would dangle.
    const std::string query = "publish=" + PercentEncodeQueryValue(stream);
    SessionRequest    req;
    req.path  = "/wt";
    req.query = query;
    return policy_->Decide(req) == Decision::Accept;
}

std::vector<StreamStats> Gateway::SnapshotStreams() const
{
    auto& loop = const_cast<websrt::EventLoop&>(loop_); // Post only enqueues
    if (loop.OnLoopThread())
    {
        return streams_.SnapshotStreams();
    }
    std::promise<std::vector<StreamStats>> done;
    // Post decides atomically whether the loop will answer; only a true
    // return resolves the future (the loop drains before its thread
    // exits), so a stopped loop can never hang the caller.
    if (!loop.Post([this, &done] { done.set_value(streams_.SnapshotStreams()); }))
    {
        return {}; // the loop is gone: no snapshot exists to wait for
    }
    return done.get_future().get();
}

} // namespace websrt::gateway