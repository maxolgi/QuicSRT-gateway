// Multi-stream registry: maps stream names to broadcasters, owns the
// first-wins publisher occupancy, the per-stream viewer cap and the
// ended-name tombstones. Three deliberate design points:
//
//   - WAITING VIEWERS. A stream with no publisher is an IDLE
//     (waiting) stream: it is created by the first viewer attach, accepts
//     subscribers that wait for a publisher to appear, and serves them the
//     moment media flows (instead of answering 404 until media exists).
//     Publisher END closes the attached viewers.
//   - TOMBSTONES. A name whose publisher just ENDED is not a never-live
//     name: for a short TTL (kStreamTombstoneTtl) it is tombstoned, and a
//     subscriber of it is answered 404 ("was live, ended recently")
//     instead of being parked as a waiting viewer that no publisher will
//     ever feed again. Never-live names keep the waiting semantics above;
//     a publisher claim clears the tombstone (a restarted stream is live
//     again immediately); the housekeeping timer sweeps expired entries.
//   - STREAM LIFETIME. A stream is dropped as soon as it has no publisher
//     and no viewers, so no ring outlives its last participant.
//
// Occupancy is source-agnostic: a WT publisher cannot preempt a live SRT
// ingest stream or another publisher, and vice versa (the unified
// is_alive invariant).
//
// THREADING: loop-thread only. The gateway drives every call from the
// SessionRegistryListener callbacks; the admission consult happens inline in
// the accept path, on the same thread.

#ifndef QUICSRT_GATEWAY_STREAM_REGISTRY_H
#define QUICSRT_GATEWAY_STREAM_REGISTRY_H

#include <chrono>
#include <cstddef>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gateway/broadcaster.h"
#include "gateway/policy.h"

namespace quicsrt::gateway
{

/// How long a publisher-ended name stays tombstoned. Seconds, not
/// minutes, on purpose: it must cover the joiners that arrive just
/// after an end (the ffmpeg-push case: the session closes in ~0.5 s
/// while viewers keep connecting for seconds more) while staying well
/// inside the clients' retry windows - the ffmpeg protocol patch
/// retries a 404 for QUICSRT_OPEN_RETRY_MS = 20 s at 500 ms cadence,
/// and the browser player reconnects on a 2 s base backoff. Past the
/// TTL the name reverts to the never-live waiting-viewer semantics, so
/// a viewer that genuinely waits for a scheduled restart parks at most
/// this long after the previous broadcast's end.
inline constexpr std::chrono::milliseconds kStreamTombstoneTtl{5000};

/// Registry-wide knobs.
struct StreamRegistryConfig
{
    /// Per-stream concurrent viewer cap; clamps to 1.
    std::size_t max_viewers = 16;
    /// Per-stream ring depth in messages; clamps to 1.
    std::size_t broadcast_capacity = 32768;
    /// Per-ring retained-bytes budget (drop-oldest past it, counted in
    /// ring_drops). No clamp here: the operator path ([server].
    /// broadcast_byte_budget) validates a 4 MiB floor, and code-side
    /// embedders own the value they set.
    std::size_t broadcast_byte_budget = 64 * 1024 * 1024;
    /// Ended-name tombstone TTL (see kStreamTombstoneTtl); 0 or less
    /// disables tombstoning. Not clamped: one entry per name,
    /// overwritten on re-end and swept by the housekeeping timer.
    std::chrono::milliseconds tombstone_ttl = kStreamTombstoneTtl;
};

/// Stream name -> Broadcaster, with occupancy and the viewer cap.
class StreamRegistry
{
public:
    explicit StreamRegistry(StreamRegistryConfig config)
        : config_{.capacity    = config.broadcast_capacity == 0 ? std::size_t{1} : config.broadcast_capacity,
                  .byte_budget = config.broadcast_byte_budget,
                  .max_viewers = config.max_viewers == 0 ? std::size_t{1} : config.max_viewers}
        , tombstone_ttl_{config.tombstone_ttl}
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

    /// Whether `stream`'s publisher ended within the TTL: subscribers of
    /// such a name are answered 404 ("was live, ended recently") instead
    /// of parked on a waiting stream that will never be fed. Lazy: an
    /// expired entry reads as false here and is erased by SweepTombstones.
    [[nodiscard]] bool Tombstoned(const std::string& stream) const
    {
        const auto it = tombstones_.find(stream);
        return it != tombstones_.end() && std::chrono::steady_clock::now() < it->second;
    }

    /// Erase expired tombstones - the housekeeping sweep that bounds the
    /// map (one entry per name, overwritten on re-end).
    void SweepTombstones()
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = tombstones_.begin(); it != tombstones_.end();)
        {
            it = now < it->second ? std::next(it) : tombstones_.erase(it);
        }
    }

    // ---- lifecycle (claim/detach, called from the session callbacks) ----

    /// Claim `stream`'s publisher slot for `handle`, creating the stream when
    /// absent (a first publisher creates a LIVE stream; no waiting viewer
    /// needs to exist first). Forbidden while a publisher holds the name
    /// (first-wins: the challenger is answered 403). A successful claim
    /// clears any tombstone: a restarted stream is live again immediately.
    Decision PublishAttempt(const std::string& stream, WtSessionHandle handle)
    {
        Broadcaster& bc = Ensure(stream);
        if (bc.HasPublisher())
        {
            return Decision::Forbidden;
        }
        bc.ClaimPublisher(handle);
        tombstones_.erase(stream);
        return Decision::Accept;
    }

    /// Attach a viewer to `stream`, creating an IDLE (waiting) stream when
    /// absent. Reject (404) while the name is tombstoned - the stream WAS
    /// live and ended recently, so waiting would hang a reconnecting viewer
    /// forever; the never-live waiting semantics resume once the TTL
    /// passes. TooManyRequests at the per-stream cap.
    Decision AttachViewer(const std::string& stream, WtSessionHandle handle, std::size_t max_payload)
    {
        if (Tombstoned(stream))
        {
            return Decision::Reject;
        }
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
    /// attached viewer so the caller can close them (viewers
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
        // The name WAS live and just ended: tombstone it so subscribers
        // arriving next are answered 404 instead of parked as waiting
        // viewers (never-live names keep the waiting semantics).
        if (tombstone_ttl_ > std::chrono::milliseconds::zero())
        {
            tombstones_[stream] = std::chrono::steady_clock::now() + tombstone_ttl_;
        }
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
    std::chrono::milliseconds                           tombstone_ttl_;
    std::map<std::string, std::unique_ptr<Broadcaster>> streams_;
    /// Ended-name tombstones: name -> expiry (steady clock). Loop thread,
    /// like the rest of the registry.
    std::map<std::string, std::chrono::steady_clock::time_point> tombstones_;
};

} // namespace quicsrt::gateway

#endif // QUICSRT_GATEWAY_STREAM_REGISTRY_H