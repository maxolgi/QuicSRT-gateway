// Broadcaster ring units: the per-ring byte budget alongside the message
// count cap. The WT publish path accepts whole multi-packet SRT messages
// (~0.3 MB GOP frames; the registry's receive buffer grows to 4 MB for
// those), so the count cap alone bounds no byte volume - the budget is the
// memory bound, enforced drop-oldest exactly like the count cap.
//
//   1. BYTE BUDGET BOUNDS RETENTION. Messages far larger than a small
//      budget keep retained bytes at/below it (uniform sizes: ring_size x
//      size <= budget), the drops land in ring_drops (the /stats surface
//      web_server.cpp serializes), and a single message over the whole
//      budget empties the ring - the documented edge the config layer's
//      4 MiB floor keeps off operator configs.
//   2. UNDER BOTH BUDGETS, UNCHANGED. A stream below the count cap AND the
//      byte budget behaves exactly as before: nothing drops, every message
//      reaches a primed viewer byte-exact through Pump.
//   3. COUNT CAP INDEPENDENT. With the byte budget effectively infinite,
//      the count cap still drops oldest past capacity.

#include "gateway/broadcaster.h"

#include <cstdint>
#include <cstdio>

namespace
{

using websrt::gateway::Broadcaster;
using websrt::gateway::BroadcasterConfig;
using websrt::gateway::StreamStats;
using websrt::gateway::WtSessionHandle;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "broadcaster_test: FAIL: %s\n", what);
    }
    return cond;
}

bool TestByteBudgetBoundsRetention()
{
    Broadcaster        bc("budget", BroadcasterConfig{.capacity = 1024, .byte_budget = 2048, .max_viewers = 1});
    const std::uint8_t frame[1024]{};
    for (int i = 0; i < 8; ++i)
    {
        bc.Append(frame, sizeof frame);
    }
    // 8 x 1024 B against a 2048 B budget: the ring settles at 2 messages
    // (2 x 1024 <= 2048; the third append tips it past and drops oldest).
    const StreamStats st = bc.Stats();
    Check(st.ring_size == 2, "1: retained bytes stay at/below the budget (2 x 1024 B <= 2048 B)");
    Check(st.ring_drops == 6, "1: budget drops counted in ring_drops");
    Check(st.messages_sent == 8, "1: every append counted");
    // One message larger than the whole budget: drop-oldest runs until the
    // ring is empty (it is the oldest too once alone) - zero retention, the
    // edge the 4 MiB config floor rules out for real streams.
    const std::uint8_t gop[4096]{};
    bc.Append(gop, sizeof gop);
    const StreamStats after = bc.Stats();
    Check(after.ring_size == 0, "1: an over-budget message leaves nothing retained");
    Check(after.ring_drops == 9, "1: the over-budget append drops everything (2 held + itself)");
    return true;
}

bool TestUnderBothBudgetsUnchanged()
{
    Broadcaster           bc("free", BroadcasterConfig{.capacity = 8, .byte_budget = 64 * 1024, .max_viewers = 2});
    const WtSessionHandle viewer = WtSessionHandle::ExternalSource(7);
    Check(bc.AttachViewer(viewer, 4096), "2: the viewer attaches");
    Check(bc.PrimeViewer(viewer, 4096), "2: the viewer primes at the live edge");
    const std::uint8_t payload[2048]{};
    for (int i = 0; i < 4; ++i)
    {
        bc.Append(payload, sizeof payload);
    }
    std::size_t       bytes  = 0;
    const std::size_t handed = bc.Pump(
        [&](WtSessionHandle, const void*, std::size_t len)
        {
            bytes += len;
            return true;
        },
        64);
    Check(handed == 4 && bytes == 4 * sizeof payload, "2: every message reaches the viewer, byte-exact");
    const StreamStats st = bc.Stats();
    Check(st.ring_size == 4 && st.ring_drops == 0 && st.messages_sent == 4 && st.send_failures == 0,
          "2: no budget interference below both bounds");
    return true;
}

bool TestCountCapIndependent()
{
    Broadcaster        bc("count", BroadcasterConfig{.capacity = 4, .byte_budget = 1ULL << 30, .max_viewers = 1});
    const std::uint8_t ts_packet[188]{};
    for (int i = 0; i < 8; ++i)
    {
        bc.Append(ts_packet, sizeof ts_packet);
    }
    const StreamStats st = bc.Stats();
    Check(st.ring_size == 4, "3: the count cap still drops oldest past capacity");
    Check(st.ring_drops == 4, "3: count-cap drops counted in ring_drops");
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
        {.name = "byte-budget-bounds-retention", .fn = TestByteBudgetBoundsRetention},
        {.name = "under-both-budgets-unchanged", .fn = TestUnderBothBudgetsUnchanged},
        {.name = "count-cap-independent", .fn = TestCountCapIndependent},
    };

    for (const Section& section : sections)
    {
        section.fn();
    }
    if (!g_ok)
    {
        return 1;
    }
    std::printf("broadcaster_test: all sections passed\n");
    return 0;
}
