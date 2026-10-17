// Per-stream broadcaster: the bounded message ring plus the viewers attached
// to it (P3 step 4). This is the C++ mapping of the Rust oracle's
// broadcaster.rs + its tokio::sync::broadcast channel:
//
//   tokio broadcast::channel(capacity) -> the deque + sequence numbering below
//   ViewerRx (one per viewer)          -> Broadcaster::ViewerState (a cursor)
//   Lagged(n) on a slow receiver       -> lagged_drops_ (cursor jumped)
//   drop_backlog() on first connect    -> PrimeViewer() (cursor -> live edge)
//
// RING SEMANTICS (identical to tokio's broadcast):
//   - Every message a publisher appends is stored BYTE-EXACT (TS bytes are
//     never touched) and is handed to every attached viewer, oldest first.
//   - On overflow the OLDEST message is dropped (tokio overwrites the oldest
//     slot and reports Lagged to the slow receivers) - live-stream
//     semantics: a slow viewer misses messages, it never blocks the source.
//     Overflow is reached through EITHER bound: the message-count cap or
//     the retained-bytes budget (the memory bound - messages range from
//     1128-byte payloads to whole multi-packet frames).
//   - A viewer lagging further behind than the ring depth skips the
//     messages it can no longer see and counts them in lagged_drops (the
//     per-viewer drop accounting the Rust oracle surfaces as Lagged(n)).
//
// CURSOR / PRIMED MECHANICS. A viewer that attaches starts at the ring's
// TAIL, not at its head: it must not replay whatever accumulated while its
// SRT handshake was in flight (those messages are already past the TSBPD
// deadline; delivering them only triggers NAK/retransmit churn - the reason
// the oracle calls drop_backlog on the first connected tick). The gateway
// signals that moment through SessionRegistry::PopBacklogDrop; until it
// arrives the viewer is NOT primed, Pump skips it entirely, and PrimeViewer
// then snaps its cursor to the live edge. Viewers of an idle (no publisher
// yet) stream are attached and primed but receive nothing until a publisher
// appends - the "waiting viewer" semantics locked for refinement item 2.
//
// FRAMING. SRT messages are whole frames: the negotiated payload size caps
// the WIRE PACKET, not the message - srt_sendmsg2 re-fragments per viewer
// (the wasm muxers frame ~9-37 KB frames as single messages). The registry's
// EnqueueForViewer bound is the size enforcement point.
//
// THREADING: loop-thread only (the gateway owns the ring and appends from
// SessionRegistryListener::OnMedia). Snapshots/counters are plain reads.

#ifndef WEBSRT_GATEWAY_BROADCASTER_H
#define WEBSRT_GATEWAY_BROADCASTER_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "gateway/wt_server.h"

namespace websrt::gateway
{

/// Per-stream broadcaster knobs.
struct BroadcasterConfig
{
    /// Ring depth in messages. The Rust oracle's default
    /// (gateway.rs:27 DEFAULT_BROADCAST_CAPACITY) - at the 1128-byte WebSRT
    /// payload this is ~37 MiB of buffering per live stream, which absorbs
    /// long viewer-side stalls (drop-oldest, never backpressure). At LARGE
    /// messages (whole multi-packet SRT frames, ~0.3 MB GOP keyframes; the
    /// registry's receive buffer grows to 4 MB for those) the count alone
    /// bounds no byte volume - byte_budget is the memory bound.
    std::size_t capacity = 32768;
    /// Retained-payload-bytes ceiling per ring: after an append, oldest
    /// messages are dropped until the ring holds at most this many bytes.
    /// Byte-overflow drops are counted in ring_drops exactly like
    /// count-cap drops; a budget smaller than one message leaves the ring
    /// empty (the config layer's 4 MiB floor - the largest message the
    /// publish path reassembles - keeps that off operator configs).
    std::size_t byte_budget = 64 * 1024 * 1024;
    /// Per-stream concurrent viewer cap (the oracle's max_viewers; enforced
    /// by the registry's AttachViewer, carried here for the snapshot).
    std::size_t max_viewers = 16;
};

/// Snapshot of one stream's state for health/stats reporting (the oracle's
/// StreamStats, plus the ring accounting this implementation owns).
struct StreamStats
{
    std::string   name;
    bool          publisher_live = false;
    std::size_t   viewers        = 0;
    std::size_t   ring_size      = 0;
    std::uint64_t messages_sent  = 0; ///< appended to the ring by a publisher
    ///< Kept at 0, exactly like the oracle: appends never fail here, and the
    ///< oracle's own increment path (tokio send err with a receiver-race) is
    ///< effectively unreachable - it does NOT count no-viewer appends. The
    ///< field stays for /health key parity.
    std::uint64_t send_failures  = 0;
    std::uint64_t ring_drops     = 0; ///< drop-oldest past the count cap OR the byte budget
    std::uint64_t oversize_drops = 0; ///< over a viewer's negotiated payload ceiling
};

/// One stream: its bounded ring, its publisher occupancy, its viewers.
class Broadcaster
{
public:
    Broadcaster(std::string name, BroadcasterConfig config)
        : name_(std::move(name))
        , config_(config)
    {
    }

    [[nodiscard]] const std::string& Name() const { return name_; }

    // ---- publisher occupancy (first-wins) ----

    [[nodiscard]] bool            HasPublisher() const { return publisher_.IsValid(); }
    [[nodiscard]] WtSessionHandle Publisher() const { return publisher_; }

    /// Claim the stream's publisher slot; false while another publisher
    /// holds it (the Rust oracle's try_publish occupancy check).
    bool ClaimPublisher(WtSessionHandle handle)
    {
        if (publisher_.IsValid())
        {
            return false;
        }
        publisher_ = handle;
        return true;
    }

    /// Release the slot. False when `handle` is not the holder (a stale end
    /// from a publisher that was already replaced).
    bool ReleasePublisher(WtSessionHandle handle)
    {
        if (publisher_ != handle)
        {
            return false;
        }
        publisher_ = WtSessionHandle{};
        return true;
    }

    // ---- the ring ----

    /// Append one message, byte-exact. Drop-OLDEST on overflow - past the
    /// message-count cap OR the retained-bytes budget (one shared loop; a
    /// message dropped by either bound decrements the byte tracker). Both
    /// bounds move BaseSeq forward, so viewer cursors snap up with
    /// lagged_drops in Pump exactly as before - drop-oldest never
    /// backpressures the publisher. Amortized O(1): each message is pushed
    /// once and popped at most once.
    void Append(const void* data, std::size_t len)
    {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        ring_.push_back(Message{.bytes = std::vector<std::uint8_t>(bytes, bytes + len)});
        ring_bytes_ += len;
        ++next_seq_;
        ++messages_sent_;
        while (!ring_.empty() && (ring_.size() > config_.capacity || ring_bytes_ > config_.byte_budget))
        {
            ring_bytes_ -= ring_.front().bytes.size();
            ring_.pop_front();
            ++ring_drops_;
        }
    }

    /// A publisher message exceeded a viewer's negotiated payload ceiling.
    void CountOversizeDrop() { ++oversize_drops_; }

    // ---- viewers ----

    /// Attach a viewer positioned at the ring's tail. False at the cap.
    bool AttachViewer(WtSessionHandle handle, std::size_t max_payload)
    {
        if (viewers_.size() >= config_.max_viewers || viewers_.contains(handle.Id()))
        {
            return false;
        }
        viewers_.emplace(
            handle.Id(),
            ViewerState{.handle = handle, .next_seq = next_seq_, .primed = false, .max_payload = max_payload});
        return true;
    }

    void DetachViewer(WtSessionHandle handle) { viewers_.erase(handle.Id()); }

    /// Hot-reload the viewer cap (P4.1): the cap is checked at every
    /// attach, so attached viewers stay and only future attaches see the
    /// new limit. Loop thread (same discipline as AttachViewer).
    void SetMaxViewers(std::size_t max_viewers)
    {
        config_.max_viewers = max_viewers == 0 ? std::size_t{1} : max_viewers;
    }

    /// The viewer's SRT handshake completed (drop_backlog): snap its cursor
    /// to the live edge - everything appended until now is dropped - and
    /// refresh its negotiated payload ceiling. False for an unknown viewer.
    bool PrimeViewer(WtSessionHandle handle, std::size_t max_payload)
    {
        const auto it = viewers_.find(handle.Id());
        if (it == viewers_.end())
        {
            return false;
        }
        it->second.next_seq    = next_seq_;
        it->second.primed      = true;
        it->second.max_payload = max_payload;
        return true;
    }

    /// Hand every not-yet-seen message to `enqueue` (the gateway's
    /// SessionRegistry::EnqueueForViewer), at most `max_send` per viewer -
    /// the catch-up bound, since each publisher append is normally the only
    /// new message. Unprimed viewers are skipped (their backlog is dropped
    /// wholesale at PrimeViewer). Returns the number of hand-overs.
    template <typename Enqueue>
    std::size_t Pump(const Enqueue& enqueue, std::size_t max_send)
    {
        std::size_t handed = 0;
        for (auto& [_, viewer] : viewers_)
        {
            if (!viewer.primed || viewer.next_seq >= next_seq_)
            {
                continue;
            }
            // The ring may have dropped past this viewer's cursor.
            const std::uint64_t head = BaseSeq();
            if (viewer.next_seq < head)
            {
                viewer.lagged_drops += head - viewer.next_seq;
                viewer.next_seq = head;
            }
            std::size_t sent = 0;
            while (viewer.next_seq < next_seq_ && sent < max_send)
            {
                const Message& msg = ring_[static_cast<std::size_t>(viewer.next_seq - head)];
                ++viewer.next_seq;
                ++sent;
                if (enqueue(viewer.handle, msg.bytes.data(), msg.bytes.size()))
                {
                    ++viewer.handed;
                    ++handed;
                }
                else
                {
                    ++viewer.enqueue_failures; // the session is being reaped
                }
            }
        }
        return handed;
    }

    // ---- introspection ----

    [[nodiscard]] std::size_t ViewerCount() const { return viewers_.size(); }
    [[nodiscard]] bool        HasViewer(WtSessionHandle handle) const { return viewers_.contains(handle.Id()); }

    /// Attached viewer handles in attach order (a copy - safe to close the
    /// sessions it names while iterating).
    [[nodiscard]] std::vector<WtSessionHandle> Viewers() const
    {
        std::vector<WtSessionHandle> out;
        out.reserve(viewers_.size());
        for (const auto& [id, viewer] : viewers_)
        {
            out.push_back(viewer.handle);
        }
        return out;
    }

    [[nodiscard]] StreamStats Stats() const
    {
        return StreamStats{.name           = name_,
                           .publisher_live = HasPublisher(),
                           .viewers        = viewers_.size(),
                           .ring_size      = ring_.size(),
                           .messages_sent  = messages_sent_,
                           .send_failures  = send_failures_,
                           .ring_drops     = ring_drops_,
                           .oversize_drops = oversize_drops_};
    }

private:
    struct Message
    {
        std::vector<std::uint8_t> bytes;
    };

    /// One viewer's ring cursor. `next_seq` is the sequence number of the
    /// next message it will receive; the ring's live edge is Broadcaster's
    /// next_seq_.
    struct ViewerState
    {
        WtSessionHandle handle;
        std::uint64_t   next_seq         = 0;
        bool            primed           = false;
        std::size_t     max_payload      = 0;
        std::uint64_t   handed           = 0;
        std::uint64_t   lagged_drops     = 0;
        std::uint64_t   oversize_drops   = 0;
        std::uint64_t   enqueue_failures = 0;
    };

    /// Sequence number of ring_.front(); messages dropped off the front move
    /// every viewer's cursor forward past them.
    [[nodiscard]] std::uint64_t BaseSeq() const { return next_seq_ - ring_.size(); }

    std::string                          name_;
    BroadcasterConfig                    config_;
    std::deque<Message>                  ring_;
    std::size_t                          ring_bytes_ = 0; // retained payload bytes (incremental; the byte-budget bound)
    std::uint64_t                        next_seq_   = 0; // sequence number the next Append will use
    WtSessionHandle                      publisher_;
    std::map<std::uint64_t, ViewerState> viewers_; // handle id -> cursor

    std::uint64_t messages_sent_  = 0;
    std::uint64_t send_failures_  = 0;
    std::uint64_t ring_drops_     = 0;
    std::uint64_t oversize_drops_ = 0;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_BROADCASTER_H