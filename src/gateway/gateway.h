// The gateway core: the composition root that wires the WebTransport server,
// the per-session SRT initiator registry and the broadcaster ring together
// (P3 step 4). This is the embeddable unit of refinement item 1 - an
// application links websrtgw, constructs a Gateway with its own
// SessionPolicy and cert, calls Start() and feeds TS bytes in through the
// SessionRegistryListener sink the Gateway itself exposes; the CLI binary
// (src/main.cpp) only adds config parsing and signal handling on top.
//
// OWNERSHIP. One Gateway owns exactly one EventLoop (the gateway hosts the
// only lsquic engine in the process) and, in destruction order:
//   loop_        the engine thread
//   streams_     the broadcaster ring registry
//   registry_    the per-session SRT initiators + the ~2 ms ticker
//   server_      the WT server (listens to registry_, consults Admit())
// server_ is destroyed first so the registry's teardown never touches a dead
// WtServer, and the loop outlives every callback that can post to it.
//
// THE TWO ENTRY DUTS, and why both exist:
//   - ADMISSION (WtServer::AdmissionCheck, pre-200, loop thread). Consults
//     the stream registry's live occupancy and viewer cap so a refused
//     caller sees the status on its CONNECT response - the Rust oracle's
//     pre-accept check (gateway.rs:343-355) and the contract libwebsrt's
//     Publisher::Start already asserts (HTTP 403 -> kPublishRejected).
//     It only CHECKS: two handshakes can interleave between the admission
//     consult and the claim below.
//   - THE CLAIM (SessionRegistryListener::OnSessionStart, post-200, loop
//     thread). Re-checks and then claims, exactly the oracle's try_publish
//     after its pre-check (gateway.rs:408-417). Losing that race is not a
//     protocol violation: the 200 is already out, so the session is closed
//     with CloseSession instead.
//
// ROLE RESOLUTION mirrors SessionRegistry::OnWtSession exactly: a session
// with ?publish= is a PUBLISHER (its ?stream=/?subscribe= leg is not
// served), otherwise it is a VIEWER of ?stream=/?subscribe=. Both live in
// this file so the admission consult and the claim can never disagree about
// which stream a session addresses.
//
// MEDIA PATH. SessionRegistry pumps a publisher's released SRT messages into
// OnMedia (loop thread). Here they are checked against the negotiated
// payload ceiling, appended byte-exact to the stream's ring, and handed to
// every attached viewer through EnqueueForViewer - the ring hands over, the
// registry's credit-paced ticker paces the actual sends. A non-SRT source
// (the SRT/UDP ingest of G6) feeds the same OnMedia sink.

#ifndef WEBSRT_GATEWAY_GATEWAY_H
#define WEBSRT_GATEWAY_GATEWAY_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/event_loop.h"
#include "gateway/cert.h"
#include "gateway/policy.h"
#include "gateway/session_registry.h"
#include "gateway/stream_registry.h"
#include "gateway/wt_server.h"

namespace websrt::gateway
{

struct GatewayConfig
{
    /// Per-stream concurrent viewer cap (403/429 at the cap).
    std::size_t max_viewers = 16;
    /// Per-stream broadcaster ring depth in messages.
    std::size_t broadcast_capacity = 32768;
    /// Ticker/pacing knobs, passed through to the SessionRegistry.
    RegistryConfig registry{};
};

class Gateway final : public SessionRegistryListener
{
public:
    /// `cert` and `policy` must outlive the Gateway. Not started yet; see
    /// Start(). Destroy a started Gateway after Stop()/Shutdown(), or let
    /// the destructor do it.
    Gateway(const CertProvider&                  cert,
            std::shared_ptr<const SessionPolicy> policy,
            GatewayConfig                        config = GatewayConfig{});
    ~Gateway() override;

    Gateway(const Gateway&)            = delete;
    Gateway& operator=(const Gateway&) = delete;

    /// Starts the event loop and binds the WebTransport server on
    /// `host`:`port`. Returns false on a bind failure or when already
    /// started (the Gateway stays inert in that case).
    bool Start(const std::string& host, std::uint16_t port);

    /// Graceful shutdown: closes every live session (the browsers observe
    /// the WT close, the SRT initiators tear down through the registry),
    /// waits bounded for the drain, then stops and joins the event loop.
    /// Idempotent; the Gateway cannot be restarted.
    void Shutdown();

    /// Whether Start() succeeded and Shutdown() has not run yet.
    [[nodiscard]] bool Running() const { return running_; }

    // ---- the ingest source contract (G6 feeds this; the WT publisher
    // ---- path reaches it through the registry's OnMedia) ----

    /// Publish TS bytes into `stream` as if a publisher session had released
    /// them: the ring fans them out to the attached viewers. Loop thread
    /// only (the ring is not synchronized). False when no stream by that
    /// name exists, or when `len` exceeds the SRT payload ceiling (counted
    /// as a drop, never truncated).
    bool PublishMedia(const std::string& stream, const void* data, std::size_t len);

    /// The ingest (SRT/UDP, P3 step 5) publisher claim: the SAME
    /// StreamRegistry::PublishAttempt a WebTransport publisher session runs
    /// (OnSessionStart), so first-wins occupancy is shared - an OBS publisher
    /// and a WT publisher contend for one slot and neither can preempt the
    /// other, and the waiting-viewer/EOF semantics are identical. The stream
    /// is CREATED here when absent, which is the oracle's try_publish_ingester
    /// (stream_registry.rs:89-106): a publisher never needs a viewer to
    /// attach first. False when a live publisher holds the name - the caller
    /// (SrtIngest) then refuses the connection.
    /// Loop thread only (the ingest reaches it through an EventLoop Post).
    bool ClaimIngestPublish(const std::string& stream);

    /// The ingest publisher's connection ended: release the slot and close
    /// the stream's viewers with a clean EOF - the publisher-end path
    /// OnSessionEnded runs for a WT publisher. Loop thread only.
    void ReleaseIngestPublish(const std::string& stream);

    // ---- evidence ----

    /// Every live stream's state, in name order (health/stats; G6/G7).
    /// Thread-safe: the registry itself is loop-thread-only, so an off-loop
    /// caller rides a Post to the engine thread and waits for the snapshot
    /// (empty when the loop is not running). Streams with no publisher and
    /// no viewers are dropped, so an idle waiting stream shows up exactly
    /// while it is waiting.
    [[nodiscard]] std::vector<StreamStats> SnapshotStreams() const;
    /// Per-stream viewer cap as configured (health's max_viewers).
    [[nodiscard]] std::size_t            MaxViewers() const { return streams_.MaxViewers(); }
    [[nodiscard]] int                    ActiveSessionCount() const { return registry_.ActiveSessionCount(); }
    [[nodiscard]] const SessionRegistry& Sessions() const { return registry_; }
    [[nodiscard]] const WtServer&        Server() const { return server_; }
    /// The gateway's event loop - the thread every loop-thread-only API
    /// above belongs to. An off-loop source (the SRT/UDP ingest) Posts its
    /// media here to reach PublishMedia.
    websrt::EventLoop& Loop() { return loop_; }
    /// Longest registry tick so far, microseconds (the Rust tick monitor).
    [[nodiscard]] std::uint64_t TickMaxUs() const { return registry_.TickMaxUs(); }
    /// Mean registry tick over the process lifetime, microseconds
    /// (SessionRegistry::TickAvgUs - the concurrency gate's budget check).
    [[nodiscard]] std::uint64_t TickAvgUs() const { return registry_.TickAvgUs(); }
    [[nodiscard]] std::uint64_t TickCount() const { return registry_.TickCount(); }

private:
    // ---- SessionRegistryListener (loop thread) ----
    void OnMedia(const std::string& stream_name, const std::uint8_t* data, std::size_t len) override;
    void OnSessionStart(WtSessionHandle handle, const WtSessionStart& start) override;
    void OnSessionEnded(WtSessionHandle handle, const std::string& reason) override;

    /// The pre-200 admission gate (WtServer::AdmissionCheck).
    [[nodiscard]] Decision Admit(const WtSessionStart& start) const;

    /// Loop thread: the shared publisher-end path - release the stream's
    /// publisher slot and close every attached viewer with a clean EOF
    /// (on-session-end parity, see OnSessionEnded).
    void EndPublish(const std::string& stream, const std::string& reason);

    /// Consume the drop_backlog markers of viewers whose handshake finished
    /// (positions their ring cursors at the live edge). Cheap: the pending
    /// list is empty once every viewer is primed.
    void PrimePendingViewers();

    /// Loop-thread teardown: cancel the housekeeping timer.
    void CancelHousekeeping();

    struct SessionRec
    {
        std::string stream;
        bool        publisher = false;
    };

    websrt::EventLoop                   loop_;
    StreamRegistry                      streams_;
    SessionRegistry                     registry_;
    WtServer                            server_;
    std::map<std::uint64_t, SessionRec> sessions_;
    std::vector<WtSessionHandle>        pending_prime_; // awaiting drop_backlog
    websrt::EventLoop::TimerId          housekeeping_timer_ = websrt::EventLoop::kInvalidTimerId;
    std::size_t                         fanout_budget_      = 256;
    std::uint64_t                       next_ingest_handle_ = 1;
    std::uint64_t                       media_unclaimed_    = 0;
    std::uint64_t                       media_oversize_     = 0;
    bool                                running_            = false;
    bool                                shut_down_          = false;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_GATEWAY_H