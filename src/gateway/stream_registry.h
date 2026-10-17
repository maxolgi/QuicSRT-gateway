// Multi-stream registry: maps stream names to broadcasters, owns the
// first-wins publisher occupancy and the per-stream viewer cap (P3 step 4).
// The C++ port of the Rust oracle's stream_registry.rs (HashMap<String,
// Arc<Broadcaster>> + try_publish/subscribe), adapted to two deliberate
// divergences locked for refinement item 2:
//
//   - WAITING VIEWERS. The oracle's subscribe() returns None for a stream
//     that has no live broadcaster and the accept loop answers 404
//     (gateway.rs:339-344). Here a stream with no publisher is an IDLE
//     (waiting) stream: it is created by the first viewer attach, accepts
//     subscribers that wait for a publisher to appear, and serves them the
//     moment media flows. Publisher END closes the attached viewers (parity)
//     - after which a reconnecting viewer recreates the idle stream.
//   - STREAM LIFETIME. The oracle keeps dead broadcasters in the map until
//     cleanup(); here a stream is dropped as soon as it has no publisher
//     and no viewers, so no ring outlives its last participant.
//
// Occupancy is source-agnostic: a WT publisher cannot preempt a live SRT
// ingest stream or another publisher, and vice versa (the oracle's unified
// is_alive invariant, stream_registry.rs:449-457).
//
// THREADING: loop-thread only. The gateway drives every call from the
// SessionRegistryListener callbacks; the admission consult happens inline in
// the accept path, on the same thread.

#ifndef WEBSRT_GATEWAY_STREAM_REGISTRY_H
#define WEBSRT_GATEWAY_STREAM_REGISTRY_H

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gateway/broadcaster.h"
#include "gateway/policy.h"

namespace websrt::gateway
{

/// Registry-wide knobs (the oracle's StreamRegistry::new arguments).
struct StreamRegistryConfig
{
    /// Per-stream concurrent viewer cap; clamps to 1 (the oracle's
    /// `max_viewers.max(1)`).
    std::size_t max_viewers = 16;
    /// Per-stream ring depth in messages; clamps to 1 (the oracle's
    /// `broadcast_capacity.max(1)`).
    std::size_t broadcast_capacity = 32768;
};

/// Stream name -> Broadcaster, with occupancy and the viewer cap.
class StreamRegistry
{
public:
    explicit StreamRegistry(StreamRegistryConfig config)
        : config_{.capacity    = config.broadcast_capacity == 0 ? std::size_t{1} : config.broadcast_capacity,
                  .max_viewers = config.max_viewers == 0 ? std::size_t{1} : config.max_viewers}
    {
    }

    [[nodiscard]] std::size_t MaxViewers() const { return config_.max_viewers; }
    [[nodiscard]] std::size_t BroadcastCapacity() const { return config_.capacity; }

    /// Hot-reload the viewer cap (P4.1): applies to the admission consult
    /// AND every live broadcaster's per-attach check, so a stream created
    /// under the old cap enforces the new one too. Attached viewers stay.
    /// Loop thread (same discipline as AttachViewer).
    void SetMaxViewers(std::size_t max_viewers)
    {
        config_.max_viewers = max_viewers == 0 ? std::size_t{1} : max_viewers;
        for (auto& [_, bc] : streams_)
        {
            bc->SetMaxViewers(config_.max_viewers);
        }
    }

    // ---- admission (side-effect free, consultable before the WT 200) ----

    /// Whether a publisher may claim `stream` right now: true when no live
    /// publisher holds the name.
    [[nodiscard]] bool Publishable(const std::string& stream) const
    {
        const Broadcaster* bc = Find(stream);
        return bc == nullptr || !bc->HasPublisher();
    }

    /// Whether one more viewer fits on `stream` right now.
    [[nodiscard]] bool ViewerSlotFree(const std::string& stream) const
    {
        const Broadcaster* bc = Find(stream);
        return bc == nullptr || bc->ViewerCount() < config_.max_viewers;
    }

    // ---- lifecycle (claim/detach, called from the session callbacks) ----

    /// Claim `stream`'s publisher slot for `handle`, creating the stream when
    /// absent (a first publisher creates a LIVE stream; no waiting viewer
    /// needs to exist first). Forbidden while a publisher holds the name
    /// (first-wins: the challenger is answered 403).
    Decision PublishAttempt(const std::string& stream, WtSessionHandle handle)
    {
        Broadcaster& bc = Ensure(stream);
        if (bc.HasPublisher())
        {
            return Decision::Forbidden;
        }
        bc.ClaimPublisher(handle);
        return Decision::Accept;
    }

    /// Attach a viewer to `stream`, creating an IDLE (waiting) stream when
    /// absent. TooManyRequests at the per-stream cap.
    Decision AttachViewer(const std::string& stream, WtSessionHandle handle, std::size_t max_payload)
    {
        Broadcaster& bc = Ensure(stream);
        if (!bc.AttachViewer(handle, max_payload))
        {
            return Decision::TooManyRequests; // the cap, or a duplicate attach
        }
        return Decision::Accept;
    }

    /// The viewer's handshake completed: snap its ring cursor to the live
    /// edge (drop_backlog) and refresh its negotiated payload ceiling.
    void PrimeViewer(const std::string& stream, WtSessionHandle handle, std::size_t max_payload) const
    {
        if (Broadcaster* bc = Find(stream))
        {
            bc->PrimeViewer(handle, max_payload);
        }
    }

    /// Detach a viewer; drops the stream when it is the last participant and
    /// no publisher holds it.
    void DetachViewer(const std::string& stream, WtSessionHandle handle)
    {
        Broadcaster* bc = Find(stream);
        if (bc == nullptr)
        {
            return;
        }
        bc->DetachViewer(handle);
        MaybeDrop(stream);
    }

    /// The publisher's session ended: release the name and report every
    /// attached viewer so the caller can close them (Rust parity: viewers
    /// see EOF when the source ends). The handles are snapshotted BEFORE
    /// the release because closing them re-enters the registry through each
    /// viewer's OnSessionEnded -> DetachViewer; with viewers attached that
    /// last detach drops the stream (MaybeDrop below is then a no-op - the
    /// broadcaster still holds viewers). With ZERO viewers nothing ever
    /// re-enters, so the stream is dropped right here, after the release
    /// leaves it holding neither participant - safe because `closing` is a
    /// by-value snapshot, so erasing the broadcaster cannot dangle it.
    [[nodiscard]] std::vector<WtSessionHandle> OnPublisherEnd(const std::string& stream)
    {
        Broadcaster* bc = Find(stream);
        if (bc == nullptr)
        {
            return {};
        }
        std::vector<WtSessionHandle> closing = bc->Viewers();
        bc->ReleasePublisher(bc->Publisher());
        MaybeDrop(stream);
        return closing;
    }

    // ---- introspection ----

    /// The broadcaster for `stream`, or nullptr when the registry holds none.
    [[nodiscard]] Broadcaster* Find(const std::string& stream) const
    {
        const auto it = streams_.find(stream);
        return it == streams_.end() ? nullptr : it->second.get();
    }

    [[nodiscard]] bool IsLive(const std::string& stream) const
    {
        const Broadcaster* bc = Find(stream);
        return bc != nullptr && bc->HasPublisher();
    }
    [[nodiscard]] std::size_t ViewerCount(const std::string& stream) const
    {
        const Broadcaster* bc = Find(stream);
        return bc == nullptr ? 0 : bc->ViewerCount();
    }
    [[nodiscard]] std::size_t StreamCount() const { return streams_.size(); }
    [[nodiscard]] std::size_t TotalViewers() const
    {
        std::size_t total = 0;
        for (const auto& [_, bc] : streams_)
        {
            total += bc->ViewerCount();
        }
        return total;
    }

    /// Every stream's snapshot, in name order (stable health/stats output).
    [[nodiscard]] std::vector<StreamStats> SnapshotStreams() const
    {
        std::vector<StreamStats> out;
        out.reserve(streams_.size());
        for (const auto& [_, bc] : streams_)
        {
            out.push_back(bc->Stats());
        }
        return out; // std::map already iterates in key order
    }

private:
    /// The broadcaster for `stream`, creating it (idle) when absent.
    Broadcaster& Ensure(const std::string& stream)
    {
        const auto it = streams_.find(stream);
        if (it != streams_.end())
        {
            return *it->second;
        }
        return *streams_.emplace(stream, std::make_unique<Broadcaster>(stream, config_)).first->second;
    }

    /// Drop the stream once it holds neither a publisher nor a viewer.
    void MaybeDrop(const std::string& stream)
    {
        const auto it = streams_.find(stream);
        if (it != streams_.end() && !it->second->HasPublisher() && it->second->ViewerCount() == 0)
        {
            streams_.erase(it);
        }
    }

    BroadcasterConfig                                   config_;
    std::map<std::string, std::unique_ptr<Broadcaster>> streams_;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_STREAM_REGISTRY_H