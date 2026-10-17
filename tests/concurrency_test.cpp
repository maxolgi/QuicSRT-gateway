// G8 concurrency gate (P3): 50 concurrent viewers + 1 publisher against one
// live gateway core, at a realistic ~2.7 Mbps live rate for ~15 s.
//
// SHAPE. Every viewer is a real libwebsrt Subscriber on its OWN event loop
// (G3: one lsquic engine per loop - the Subscriber spawns it internally),
// started on its own thread so the 50 WT+SRT handshakes land on the accept
// path in one burst (the Rust oracle's accept-stall defect scenario). The
// publisher (libwebsrt Publisher) then claims the name and paces a
// deterministic 188-aligned pattern for ~15 s: 11280 bytes (10 x 1128, the
// WebSRT payload) every 33 ms = ~2.73 Mbps, 455 ticks = 5,132,400 bytes.
//
// GATE (PLAN.md): zero viewer lag - every viewer receives the stream,
// byte counts within a sane window of each other; ticker avg < 5 ms; no
// session errors; fd/memory accounting clean afterwards. Because the
// viewers attach BEFORE the publisher (waiting viewers), every viewer is
// primed at its handshake and sees the stream from byte 0 - so the tight
// expectation is every viewer receiving EXACTLY the published total,
// verified byte-exact via FNV-1a (no 250 MB of stored copies).
//
// This run doubles as the no-throttle evidence for the no-op-CC
// approximation (P3 step 7): send throughput equals the app write rate -
// 50 viewers each sustaining the full 2.7 Mbps the publisher writes.
//
// Ports: 127.0.0.1:4436 with an ephemeral fallback. The Rust gateway's
// 4433/9000 and the dev gateway's 4434/9100 are never touched.

#include "gateway/cert.h"
#include "gateway/gateway.h"

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <algorithm>
#include <ranges>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "websrt/publisher.hpp"
#include "websrt/subscriber.hpp"

namespace
{

using websrt::gateway::Gateway;
using websrt::gateway::GatewayConfig;

constexpr int         kViewers    = 50;
constexpr int         kMaxPayload = 1128;  // WebSRT constant: 6 x 188-byte TS packets
constexpr std::size_t kTickBytes  = 11280; // 10 messages per 33 ms frame cadence
constexpr int         kTickMs     = 33;
constexpr int         kTicks      = 455; // ~15 s
constexpr std::size_t kTotalBytes = kTickBytes * kTicks;
constexpr std::size_t kMaxViewers = 64;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "concurrency_test: FAIL: %s\n", what);
    }
    return cond;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms, int slice_ms = 20)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (!pred())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{slice_ms});
    }
    return true;
}

/// 127.0.0.1:4436 when free, else an ephemeral port (gateway_e2e_test's
/// probe-bind recipe).
std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port              = htons(4436);
        const bool port4436_free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (port4436_free)
        {
            return 4436;
        }
    }
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_port = 0;
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "concurrency_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

/// The deterministic stream pattern: xorshift32 over 188-aligned bytes.
std::vector<std::uint8_t> PatternBytes(std::size_t len)
{
    std::vector<std::uint8_t> bytes(len);
    std::uint32_t             state = 0x9E3779B9U;
    for (std::uint8_t& byte : bytes)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<std::uint8_t>(state >> 24);
    }
    return bytes;
}

std::uint64_t Fnv1a(const std::uint8_t* data, std::size_t len)
{
    std::uint64_t hash = 1469598103934665603ULL;
    for (std::size_t i = 0; i < len; ++i)
    {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

int CountFds()
{
    DIR* dir = ::opendir("/proc/self/fd");
    if (dir == nullptr)
    {
        return -1;
    }
    int            count = 0;
    struct dirent* ent;
    while ((ent = ::readdir(dir)) != nullptr)
    {
        if (ent->d_name[0] != '.')
        {
            ++count;
        }
    }
    ::closedir(dir);
    return count - 1; // exclude the opendir fd itself
}

/// "fd -> target" lines for the fds open now (fd-accounting diff).
std::vector<std::string> FdTargets()
{
    std::vector<std::string> out;
    DIR*                     dir = ::opendir("/proc/self/fd");
    if (dir == nullptr)
    {
        return out;
    }
    struct dirent* ent;
    while ((ent = ::readdir(dir)) != nullptr)
    {
        if (ent->d_name[0] == '.')
        {
            continue;
        }
        char        link[256];
        const char* name = ent->d_name;
        if (const long n = ::readlink((std::string("/proc/self/fd/") + name).c_str(), link, sizeof link - 1); n > 0)
        {
            link[n] = '\0';
            out.push_back(std::string(name) + " -> " + link);
        }
    }
    ::closedir(dir);
    return out;
}

std::optional<std::uint64_t> RssKib()
{
    std::FILE* f = std::fopen("/proc/self/status", "r");
    if (f == nullptr)
    {
        return std::nullopt;
    }
    char          line[256];
    std::uint64_t rss = 0;
    while (std::fgets(line, sizeof line, f) != nullptr)
    {
        if (std::sscanf(line, "VmRSS: %lu kB", &rss) == 1)
        {
            ::fclose(f);
            return rss;
        }
    }
    ::fclose(f);
    return std::nullopt;
}

/// One viewer thread's evidence.
struct ViewerResult
{
    websrt::StartStatus start_status = websrt::kStartInternal;
    int                 terminal     = websrt::kReadError; // final Read result
    std::uint64_t       bytes        = 0;
    std::uint64_t       hash         = 0;
    std::string         error;
};

} // namespace

int main()
{
    const auto                          t0        = std::chrono::steady_clock::now();
    const std::vector<std::uint8_t>     pat       = PatternBytes(kTotalBytes);
    const std::uint64_t                 want_hash = Fnv1a(pat.data(), pat.size());
    const websrt::gateway::CertProvider cert;
    const std::uint16_t                 port = ChoosePort();

    // Open mode (no allowlist): PathPolicy + AcceptAll, viewer cap 64.
    const auto policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                               std::make_shared<websrt::gateway::AcceptAll>());
    // 50 viewers from one loopback IP: lift the Rust-default per-IP cap
    // (the oracle's own concurrency test lifts it via the builder too).
    websrt::gateway::GatewayConfig gw_cfg{.max_viewers = kMaxViewers};
    gw_cfg.wt.max_sessions_per_ip = 0;
    Gateway gateway(cert, policy, gw_cfg);
    if (!Check(gateway.Start("127.0.0.1", port), "gateway binds 127.0.0.1:4436 (or the ephemeral fallback)"))
    {
        return 1;
    }
    const std::string hash = cert.Sha256Hex();
    std::fprintf(stderr,
                 "concurrency_test: gateway on 127.0.0.1:%u, open mode, %d viewers, %zu B pattern, hash %s\n",
                 port,
                 kViewers,
                 kTotalBytes,
                 hash.c_str());

    // The publisher object is constructed BEFORE the fd baseline: its
    // EventLoop (epoll + eventfd pair) is created eagerly at construction
    // (libwebsrt Publisher::Publisher), so it belongs in the harness
    // baseline, not in the run's delta.
    websrt::Publisher pub;
    const int         fds_before = CountFds();
    const auto        fd_base    = FdTargets();
    const auto        rss_before = RssKib();
    const auto        t_viewers0 = std::chrono::steady_clock::now();

    // ---- 50 viewers on 50 threads, all landing at once ----
    std::vector<ViewerResult> results(kViewers);
    std::atomic<int>          started{0};
    std::atomic<bool>         publish_done{false};
    std::vector<std::thread>  threads;
    threads.reserve(kViewers);
    for (int i = 0; i < kViewers; ++i)
    {
        threads.emplace_back(
            [i, port, &hash, &results, &started, &publish_done]
            {
                websrt::SubscriberConfig cfg;
                cfg.host             = "127.0.0.1";
                cfg.port             = port;
                cfg.stream_name      = "g8-load";
                cfg.cert_sha256_hex  = hash;
                cfg.tsbpd_latency_ms = 120;

                websrt::Subscriber sub;
                ViewerResult&      r = results[static_cast<std::size_t>(i)];
                r.start_status       = sub.Start(cfg);
                ++started;
                if (r.start_status != websrt::kStartOk)
                {
                    r.error = sub.LastError();
                    return;
                }
                char          buf[kMaxPayload];
                std::uint64_t fnv = 1469598103934665603ULL;
                for (;;)
                {
                    const int n = sub.Read(buf, sizeof buf, 20000);
                    if (n > 0)
                    {
                        r.bytes += static_cast<std::uint64_t>(n);
                        for (int j = 0; j < n; ++j)
                        {
                            fnv ^= static_cast<std::uint8_t>(buf[j]);
                            fnv *= 1099511628211ULL;
                        }
                        continue;
                    }
                    if (n == websrt::kReadTimeout && !publish_done.load())
                    {
                        continue; // still streaming (or waiting for the publisher)
                    }
                    r.terminal = n < 0 ? n : websrt::kReadEnd;
                    if (n != websrt::kReadEnd)
                    {
                        r.error = sub.LastError();
                    }
                    break;
                }
                r.hash = fnv;
            });
    }
    Check(WaitUntil([&started] { return started.load() == kViewers; }, 60000), "all 50 viewer sessions established");
    const int connected = started.load();
    Check(connected == kViewers, "all 50 viewers connected (kStartOk)");
    {
        int ok = 0;
        for (const ViewerResult& r : results)
        {
            ok += r.start_status == websrt::kStartOk ? 1 : 0;
        }
        Check(ok == kViewers, "no Start failure among the 50");
        if (ok != kViewers)
        {
            for (const ViewerResult& r : results)
            {
                if (r.start_status != websrt::kStartOk)
                {
                    std::fprintf(stderr,
                                 "concurrency_test: viewer start=%d error='%s'\n",
                                 static_cast<int>(r.start_status),
                                 r.error.c_str());
                }
            }
        }
    }
    Check(gateway.SnapshotStreams().front().viewers == static_cast<std::size_t>(kViewers),
          "the stream holds all 50 waiting viewers before the publisher joins");

    // ---- the publisher: ~2.7 Mbps for ~15 s ----
    websrt::PublisherConfig pcfg;
    pcfg.host            = "127.0.0.1";
    pcfg.port            = port;
    pcfg.stream_name     = "g8-load";
    pcfg.cert_sha256_hex = hash;
    if (!Check(pub.Start(pcfg) == websrt::kPublishOk, "publisher accepted on the 50-viewer stream"))
    {
        publish_done = true;
        for (std::thread& t : threads)
        {
            t.join();
        }
        return 1;
    }
    const auto  t_writes0 = std::chrono::steady_clock::now();
    std::size_t off       = 0;
    bool        wfail     = false;
    for (int tick = 0; tick < kTicks && !wfail; ++tick)
    {
        const auto next = std::chrono::steady_clock::now() + std::chrono::milliseconds{kTickMs};
        while (off < (static_cast<std::size_t>(tick) + 1) * kTickBytes)
        {
            const std::size_t len = ((static_cast<std::size_t>(tick) + 1) * kTickBytes) - off;
            const int         n   = pub.Write(pat.data() + off, len, 5000);
            if (n <= 0)
            {
                std::fprintf(stderr,
                             "concurrency_test: publisher Write failed at offset %zu: %s\n",
                             off,
                             pub.LastError().c_str());
                wfail = true;
                break;
            }
            off += static_cast<std::size_t>(n);
        }
        std::this_thread::sleep_until(next);
    }
    const auto t_writes1 = std::chrono::steady_clock::now();
    publish_done         = true;
    Check(pub.End(30000), "publisher ended gracefully after ~15 s");
    const auto        t_end1    = std::chrono::steady_clock::now();
    const std::size_t published = off;
    const auto        write_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(t_writes1 - t_writes0).count();
    std::fprintf(
        stderr,
        "concurrency_test: published %zu B in %lld ms of paced writes (~%llu kB/s), End() %lld ms\n",
        published,
        static_cast<long long>(write_ms),
        static_cast<unsigned long long>(write_ms > 0 ? published / static_cast<std::uint64_t>(write_ms) : 0),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t_end1 - t_writes1).count()));

    for (std::thread& t : threads)
    {
        t.join();
    }
    const auto t_reads_done = std::chrono::steady_clock::now();
    const auto rss_at_join  = RssKib();
    // The publisher's own event loop (epoll + eventfd pair) is still alive
    // here - stop it so the fd accounting below measures what the GATEWAY
    // and the 50 viewer sessions left behind, not the still-scoped client.
    pub.Stop();
    std::fprintf(
        stderr,
        "concurrency_test: phases: viewers %lld ms, writes %lld ms, End+drain %lld ms\n",
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t_writes0 - t_viewers0).count()),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t_writes1 - t_writes0).count()),
        static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t_reads_done - t_writes1).count()));

    // ---- the gate ----
    std::uint64_t min_bytes = UINT64_MAX;
    std::uint64_t max_bytes = 0;
    std::uint64_t sum_bytes = 0;
    int           clean_eof = 0;
    int           hash_ok   = 0;
    for (const ViewerResult& r : results)
    {
        min_bytes = std::min(min_bytes, r.bytes);
        max_bytes = std::max(max_bytes, r.bytes);
        sum_bytes += r.bytes;
        clean_eof += r.terminal == websrt::kReadEnd ? 1 : 0;
        hash_ok += r.bytes == published && r.hash == want_hash ? 1 : 0;
        if (r.terminal != websrt::kReadEnd)
        {
            std::fprintf(stderr,
                         "concurrency_test: viewer terminal=%d bytes=%llu error='%s'\n",
                         r.terminal,
                         static_cast<unsigned long long>(r.bytes),
                         r.error.c_str());
        }
    }
    const double avg_kib = static_cast<double>(sum_bytes) / kViewers / 1024.0;
    std::fprintf(stderr,
                 "concurrency_test: viewers bytes min=%llu avg=%.1f KiB max=%llu (published %zu B), "
                 "clean EOF %d/%d, hash-exact %d/%d\n",
                 static_cast<unsigned long long>(min_bytes),
                 avg_kib,
                 static_cast<unsigned long long>(max_bytes),
                 published,
                 clean_eof,
                 kViewers,
                 hash_ok,
                 kViewers);

    Check(clean_eof == kViewers, "every viewer ended with a clean EOF (no session errors)");
    Check(published == kTotalBytes, "the publisher wrote the full pattern");
    Check(min_bytes >= published - published / 100, "every viewer received >= 99% of the published bytes");
    Check(max_bytes - min_bytes <= published / 100, "viewer byte spread within 1% (zero viewer lag window)");
    Check(hash_ok == kViewers, "every viewer's bytes hash-match the published pattern (byte-exact)");

    // ---- ticker + teardown accounting ----
    const std::uint64_t tick_avg = gateway.TickAvgUs();
    const std::uint64_t tick_max = gateway.TickMaxUs();
    std::fprintf(stderr,
                 "concurrency_test: registry ticker avg %llu us, max %llu us over %llu ticks\n",
                 static_cast<unsigned long long>(tick_avg),
                 static_cast<unsigned long long>(tick_max),
                 static_cast<unsigned long long>(gateway.TickCount()));
    Check(tick_avg < 5000, "ticker avg < 5 ms");
    Check(gateway.Sessions().ActiveSessionCount() == 0 ||
              WaitUntil([&gateway] { return gateway.ActiveSessionCount() == 0; }, 10000),
          "every session reaped after publisher end");

    gateway.Shutdown();
    // 1.5 s settle: the srt fork destroys closed sockets on its ~1 s GC
    // tick, and the just-stopped publisher's virtual-transport eventfd is
    // reclaimed there (the 50 subscribers' ones always were, mid-run).
    std::this_thread::sleep_for(std::chrono::milliseconds{1500});
    const int  fds_after = CountFds();
    const auto rss_after = RssKib();
    // Sole tolerated leftover: ONE anon_inode:[eventfd] - the srt fork's
    // GC-pending virtual-transport wake channel of the last-stopped CLIENT
    // session (libwebsrt/srt-fork side, not the gateway). Anything else -
    // sockets, epoll instances, more fds - is a real leak and fails.
    bool extra_ok = true;
    if (fds_after > fds_before)
    {
        for (const std::string& t : FdTargets())
        {
            if (std::ranges::find(fd_base, t) == fd_base.end())
            {
                std::fprintf(stderr, "concurrency_test: fd left open: %s\n", t.c_str());
                extra_ok =
                    extra_ok && fds_after - fds_before == 1 && t.find("anon_inode:[eventfd]") != std::string::npos;
            }
        }
    }
    std::fprintf(stderr,
                 "concurrency_test: fds %d -> %d, RSS before %llu / at-join %llu / after %llu KiB, "
                 "server datagrams dropped %d\n",
                 fds_before,
                 fds_after,
                 rss_before ? static_cast<unsigned long long>(*rss_before) : 0ULL,
                 rss_at_join ? static_cast<unsigned long long>(*rss_at_join) : 0ULL,
                 rss_after ? static_cast<unsigned long long>(*rss_after) : 0ULL,
                 gateway.Server().DatagramsDropped());
    Check(fds_after <= fds_before || extra_ok,
          "fd count back to baseline (sole tolerated: the srt GC-pending client VT eventfd)");
    if (rss_at_join && rss_after)
    {
        Check(*rss_after <= *rss_at_join + 2048, "teardown does not grow memory (RSS after <= at-join + 2 MiB)");
    }

    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    if (!g_ok)
    {
        std::fprintf(stderr, "concurrency_test: FAILURES\n");
        return 1;
    }
    std::printf("concurrency_test: OK (%lld ms)\n", static_cast<long long>(elapsed_ms.count()));
    return 0;
}
