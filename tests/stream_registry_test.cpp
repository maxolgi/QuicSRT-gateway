// Stream registry units: the stream-lifetime contract gateway.h documents
// ("streams with no publisher and no viewers are dropped, so an idle
// waiting stream shows up exactly while it is waiting"). The publisher-end
// path must not leak the broadcaster when no viewer ever attached - the
// publish-then-end-before-viewers-arrive case that would otherwise leave
// ghost streams in /stats and grow the registry without bound.
//
//   1. PUBLISHER END, ZERO VIEWERS. A publish to a fresh name, ended with
//      no viewer attached, returns an empty close set and leaves the
//      registry empty: no ghost stream in StreamCount or the snapshot.
//   2. SEQUENTIAL FRESH NAMES. Publishing to fresh names one after another
//      (each ended with no viewers) keeps the stream count at zero - the
//      registry does not accumulate dead broadcasters.
//   3. VIEWERS STILL OWN THE DROP. With a viewer attached, OnPublisherEnd
//      reports it for closing and KEEPS the stream: the close re-enters
//      through DetachViewer, and that last detach drops it - the
//      re-entrancy ordering the registry's comments document.
//   4. TOMBSTONE. A publisher end tombstones the name: a subscriber
//      attach is refused (Reject/404), a publisher claim clears the
//      tombstone (the attach then succeeds), a never-live name is never
//      tombstoned, and tombstone_ttl = 0 disables the whole mechanism.
//   5. TTL EXPIRY. Past the TTL (and the sweep) the name reverts to the
//      never-live waiting-viewer semantics: the attach is accepted and
//      creates an idle stream.

#include "gateway/stream_registry.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace
{

using quicsrt::gateway::Broadcaster;
using quicsrt::gateway::Decision;
using quicsrt::gateway::StreamRegistry;
using quicsrt::gateway::StreamRegistryConfig;
using quicsrt::gateway::WtSessionHandle;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "stream_registry_test: FAIL: %s\n", what);
    }
    return cond;
}

/// A publisher identity that is not a WT session (the registry is
/// source-agnostic; WtSessionHandle::ExternalSource is the one public
/// handle factory - the ingest publisher path uses the same).
WtSessionHandle Handle(std::uint64_t ordinal)
{
    return WtSessionHandle::ExternalSource(ordinal);
}

bool TestPublisherEndNoViewers()
{
    StreamRegistry reg(StreamRegistryConfig{});
    Check(reg.PublishAttempt("solo", Handle(1)) == Decision::Accept, "1: the publish claims the fresh name");
    Check(reg.StreamCount() == 1 && reg.IsLive("solo"), "1: the stream exists and is live");
    const std::vector<WtSessionHandle> closing = reg.OnPublisherEnd("solo");
    Check(closing.empty(), "1: no viewer is reported for closing");
    Check(reg.StreamCount() == 0, "1: the registry count returns to zero");
    Check(reg.Find("solo") == nullptr, "1: the broadcaster is gone");
    Check(reg.SnapshotStreams().empty(), "1: the stats snapshot carries no ghost stream");
    return true;
}

bool TestSequentialFreshNamesStayBounded()
{
    StreamRegistry     reg(StreamRegistryConfig{});
    const std::uint8_t ts_packet[188]{}; // one TS packet, so the dropped ring held data
    for (std::uint64_t i = 0; i < 64; ++i)
    {
        const std::string name = "seq-" + std::to_string(i);
        Check(reg.PublishAttempt(name, Handle(i + 1)) == Decision::Accept, "2: the publish claims the fresh name");
        if (Broadcaster* bc = reg.Find(name))
        {
            bc->Append(ts_packet, sizeof ts_packet);
        }
        Check(reg.OnPublisherEnd(name).empty(), "2: the publisher ends with no viewers");
        Check(reg.StreamCount() == 0, "2: no dead stream accumulates");
    }
    Check(reg.SnapshotStreams().empty(), "2: the snapshot stays empty across the run");
    return true;
}

bool TestViewerPathStillDropsOnLastDetach()
{
    StreamRegistry        reg(StreamRegistryConfig{});
    const WtSessionHandle pub    = Handle(1);
    const WtSessionHandle viewer = Handle(2);
    Check(reg.PublishAttempt("with-viewer", pub) == Decision::Accept, "3: the publish claims the name");
    Check(reg.AttachViewer("with-viewer", viewer, 1128) == Decision::Accept, "3: one viewer attaches");
    const std::vector<WtSessionHandle> closing = reg.OnPublisherEnd("with-viewer");
    Check(closing.size() == 1 && closing[0] == viewer, "3: the attached viewer is reported for closing");
    Check(reg.StreamCount() == 1, "3: the stream outlives the release - the close re-enters DetachViewer");
    reg.DetachViewer("with-viewer", viewer); // the re-entrant close of that last viewer
    Check(reg.StreamCount() == 0, "3: the last detach drops the idle stream");
    return true;
}

bool TestPublisherEndTombstonesTheName()
{
    StreamRegistry reg(StreamRegistryConfig{});
    Check(reg.PublishAttempt("tomb", Handle(1)) == Decision::Accept, "4: the publish claims the fresh name");
    Check(reg.OnPublisherEnd("tomb").empty(), "4: the publisher ends with no viewers");
    Check(reg.Tombstoned("tomb"), "4: the ended name is tombstoned");
    Check(reg.AttachViewer("tomb", Handle(2), 1128) == Decision::Reject,
          "4: a subscriber of the tombstoned name is refused (404)");
    Check(reg.StreamCount() == 0, "4: the refusal does not recreate a waiting stream");

    // A publisher claim clears the tombstone: the attach then succeeds.
    Check(reg.PublishAttempt("tomb", Handle(3)) == Decision::Accept, "4: a returning publisher reclaims the name");
    Check(!reg.Tombstoned("tomb"), "4: the claim cleared the tombstone");
    Check(reg.AttachViewer("tomb", Handle(4), 1128) == Decision::Accept, "4: a subscriber of the live name attaches");

    // A never-live name is never tombstoned (waiting semantics).
    Check(reg.OnPublisherEnd("never-live").empty(), "4: publisher end on a never-live name is a no-op");
    Check(!reg.Tombstoned("never-live"), "4: the never-live name is not tombstoned");
    Check(reg.AttachViewer("never-live", Handle(5), 1128) == Decision::Accept,
          "4: a subscriber of a never-live name still waits");

    // ttl = 0 disables the mechanism entirely.
    StreamRegistry off(StreamRegistryConfig{.tombstone_ttl = std::chrono::milliseconds{0}});
    Check(off.PublishAttempt("off", Handle(1)) == Decision::Accept, "4: the publish claims the name (ttl 0)");
    off.OnPublisherEnd("off");
    Check(!off.Tombstoned("off"), "4: ttl 0 writes no tombstone");
    Check(off.AttachViewer("off", Handle(2), 1128) == Decision::Accept, "4: ttl 0 keeps the waiting semantics");
    return true;
}

bool TestTombstoneExpiresBackToWaiting()
{
    StreamRegistry reg(StreamRegistryConfig{.tombstone_ttl = std::chrono::milliseconds{30}});
    Check(reg.PublishAttempt("exp", Handle(1)) == Decision::Accept, "5: the publish claims the fresh name");
    reg.OnPublisherEnd("exp");
    Check(reg.Tombstoned("exp"), "5: the name is tombstoned at first");
    Check(reg.AttachViewer("exp", Handle(2), 1128) == Decision::Reject, "5: the attach is refused inside the TTL");

    // Past the TTL the lazy read already reports false; the sweep erases
    // the entry and the name reverts to the waiting-viewer semantics.
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    reg.SweepTombstones();
    Check(!reg.Tombstoned("exp"), "5: the tombstone expired and was swept");
    Check(reg.AttachViewer("exp", Handle(3), 1128) == Decision::Accept,
          "5: past the TTL the name takes a waiting viewer again");
    Check(reg.StreamCount() == 1 && !reg.IsLive("exp"), "5: the recreated stream is idle (no publisher)");
    return true;
}

} // namespace

int main()
{
    struct Section
    {
        const char* name;
        bool (*fn)();
    };

    const Section sections[] = {
        {.name = "publisher-end-no-viewers", .fn = TestPublisherEndNoViewers},
        {.name = "sequential-fresh-names", .fn = TestSequentialFreshNamesStayBounded},
        {.name = "viewer-path-drops-on-last-detach", .fn = TestViewerPathStillDropsOnLastDetach},
        {.name = "publisher-end-tombstones-the-name", .fn = TestPublisherEndTombstonesTheName},
        {.name = "tombstone-expires-back-to-waiting", .fn = TestTombstoneExpiresBackToWaiting},
    };

    for (const Section& section : sections)
    {
        section.fn();
    }
    if (!g_ok)
    {
        return 1;
    }
    std::printf("stream_registry_test: all sections passed\n");
    return 0;
}
