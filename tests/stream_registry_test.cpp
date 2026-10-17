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

#include "gateway/stream_registry.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace
{

using websrt::gateway::Broadcaster;
using websrt::gateway::Decision;
using websrt::gateway::StreamRegistry;
using websrt::gateway::StreamRegistryConfig;
using websrt::gateway::WtSessionHandle;

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
    StreamRegistry    reg(StreamRegistryConfig{});
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
    StreamRegistry reg(StreamRegistryConfig{});
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
