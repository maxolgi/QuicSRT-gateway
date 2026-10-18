// Consumer gate: the srt fork under the virtual-transport gate, the
// lsquic/BoringSSL chain, and the single-threaded EventLoop every engine
// call and callback will live on. Ported verbatim from the former
// src/main.cpp when the library/binary split landed (refinement item 1).

#include "gateway/selftest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include "core/event_loop.h" // internal header via websrt::websrt
#include "lsquic.h"          // via websrt::wt-deps
#include "srt.h"             // via websrt::websrt -> websrt::srt-deps
#include "websrt/websrt_c.h" // public API

namespace
{
int g_failures = 0;

void check(bool ok, const char* what)
{
    if (!ok)
    {
        std::fprintf(stderr, "QuicSRT-gateway: FAIL: %s\n", what);
        ++g_failures;
    }
}
} // namespace

namespace websrt::gateway
{

int RunSelftest()
{
    // The srt fork under the virtual-transport gate: the enum and the
    // attach entry point only exist when the define rides the export.
    static_assert(SRTO_SKIP_INDUCTION == 64,
                  "SRTO_SKIP_INDUCTION missing: SRT_ENABLE_VIRTUAL_TRANSPORT "
                  "did not reach the consumer");
    (void)&srt_attach_virtual_transport;
    check(srt_startup() == 0, "srt_startup/srt_cleanup");
    srt_cleanup();

    // The lsquic/BoringSSL chain: the gateway hosts the server side of
    // WebTransport (the CLIENT bit is initialized too - the interop probes
    // and self-checks run client role in-process during P3).
    check(lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER) == 0,
          "lsquic_global_init/lsquic_global_cleanup");
    lsquic_global_cleanup();

    // The single-threaded loop every engine call and callback will live on.
    {
        websrt::EventLoop loop;
        std::atomic<bool> posted{false};
        loop.Start();
        // Post's contract under test: true on a live loop (the job is
        // guaranteed to run), false once it has stopped - never a wait.
        const bool accepted = loop.Post([&posted] { posted = true; });
        for (int i = 0; i < 500 && !posted; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        check(accepted, "EventLoop Post accepted the job on a live loop");
        check(posted, "EventLoop Post ran on the loop thread");
        loop.Stop();
    }

    const char* v = websrt_version();
    check(v != nullptr && v[0] != '\0', "websrt_version()");

    if (g_failures != 0)
    {
        std::fprintf(stderr, "QuicSRT-gateway: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("QuicSRT-gateway skeleton OK (libwebsrt %s)\n", v);
    return 0;
}

} // namespace websrt::gateway
