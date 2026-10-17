// Session registry units: the viewer chunk-sizing clamp of
// EnqueueForViewer (ViewerChunkSize). The send path must never fall back
// to the WHOLE message when the negotiated payload readback lands below
// one TS packet: publish-side messages reassemble up to 4 MiB, so an
// unchunked message is one unbounded backlog entry. The clamp sizes
// chunks at one 188-byte TS packet instead - still a fit for the
// transport's 1200-byte minimum datagram.
//
//   1. SUB-188 CLAMPS UP. Payloads below one TS packet size chunks at
//      188 - chunking can never silently turn off.
//   2. NORMAL PASSES THROUGH. 188 and the whole-packet payloads above it
//      (940 = the negotiated 5 x 188, 1128 = the configured 6 x 188)
//      size chunks at the payload unchanged.

#include "gateway/session_registry.h"

#include <cstddef>
#include <cstdio>

namespace
{

using websrt::gateway::ViewerChunkSize;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "session_registry_test: FAIL: %s\n", what);
    }
    return cond;
}

bool TestSub188ClampsUpToOnePacket()
{
    bool ok = true;
    ok &= Check(ViewerChunkSize(0) == std::size_t{188}, "clamp: 0 -> 188");
    ok &= Check(ViewerChunkSize(44) == std::size_t{188}, "clamp: 44 (mss - 44 degenerate) -> 188");
    ok &= Check(ViewerChunkSize(187) == std::size_t{188}, "clamp: 187 -> 188");
    return ok;
}

bool TestNormalPayloadPassesThrough()
{
    bool ok = true;
    ok &= Check(ViewerChunkSize(188) == std::size_t{188}, "boundary: exactly one packet stays 188");
    ok &= Check(ViewerChunkSize(940) == std::size_t{940}, "pass: 940 (negotiated 5 x 188) unchanged");
    ok &= Check(ViewerChunkSize(1128) == std::size_t{1128}, "pass: 1128 (configured 6 x 188) unchanged");
    return ok;
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestSub188ClampsUpToOnePacket();
    ok &= TestNormalPayloadPassesThrough();
    std::fprintf(stderr, "session_registry_test: %s\n", ok && g_ok ? "PASS" : "FAIL");
    return ok && g_ok ? 0 : 1;
}
