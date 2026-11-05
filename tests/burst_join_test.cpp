// G9: an unpaced (burst) WT publisher with a viewer joining mid-stream.
//
// The e2e suites push a small fixture (~65 KB) through a waiting viewer and
// so never exercise a publisher that outruns the consumer at line rate -
// the file-push shape (ffmpeg -i file.ts quicsrt://..., no -re), where the
// publisher blasts the whole stream as fast as the socket accepts it. A
// burst that outruns the datagram medium starves the reverse path (the
// SRT ACKs/keepalives back to the sender) - the publisher's peer-idle
// budget must ride that out (libquicsrt publisher.cpp kPeerIdleTimeoutMs;
// publisher_starve_test covers the budget at the srt level), and a viewer
// joining WHILE THE STREAM IS LIVE must receive data.
//
//   1. BURST PUBLISHER SURVIVES. A publisher writes 12 MB unpaced over
//      several seconds (write-as-fast-as-accepted with pacing between
//      bursts); the stream must stay publisher-live throughout.
//   2. MID-JOIN VIEWER RECEIVES DATA. A viewer attaching ~1.5 s into the
//      blast (the ring actively fed, the cursor primed at the live edge)
//      must receive bytes, not an empty 200.
//
// NOTE the live-gateway lesson this test is cut against: an unpaced ffmpeg
// push of a 12-s source finishes its OUTPUT within ~0.2 s and closes the
// session ~0.5 s in (ffmpeg itself lingers on its realtime-paced input) -
// a viewer joining seconds later subscribes to an already-ended stream and
// correctly receives nothing. Mid-join delivery is only meaningful while
// the publisher is actually publishing; hence the sustained blast here.
//
// Ports: 127.0.0.1:4437 with an ephemeral fallback.

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "quicsrt/publisher.hpp"
#include "quicsrt/subscriber.hpp"

namespace
{

using quicsrt::gateway::Gateway;
using quicsrt::gateway::GatewayConfig;
using quicsrt::gateway::StreamStats;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "burst_join_test: FAIL: %s\n", what);
    }
    return cond;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms, int slice_ms = 5)
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

StreamStats StreamNamed(const std::vector<StreamStats>& snapshot, const std::string& name)
{
    for (const StreamStats& s : snapshot)
    {
        if (s.name == name)
        {
            return s;
        }
    }
    return StreamStats{};
}

quicsrt::SubscriberConfig SubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    quicsrt::SubscriberConfig cfg;
    cfg.host             = "127.0.0.1";
    cfg.port             = port;
    cfg.stream_name      = stream;
    cfg.cert_sha256_hex  = hash;
    cfg.tsbpd_latency_ms = 120;
    return cfg;
}

quicsrt::PublisherConfig PubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    quicsrt::PublisherConfig cfg;
    cfg.host            = "127.0.0.1";
    cfg.port            = port;
    cfg.stream_name     = stream;
    cfg.cert_sha256_hex = hash;
    return cfg;
}

std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port             = htons(4437);
        const bool port4437_free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (port4437_free)
        {
            return 4437;
        }
    }
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_port = 0;
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "burst_join_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

} // namespace

int main()
{
    const auto                           t_total0 = std::chrono::steady_clock::now();
    const quicsrt::gateway::CertProvider cert;
    const std::uint16_t                  port = ChoosePort();

    const std::string config_text = std::string{"[server]\n"
                                                "wt_port = 4437\n"
                                                "max_viewers = 2\n"
                                                "broadcast_capacity = 4096\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g9-burst\"\n"};

    quicsrt::gateway::Config config;
    try
    {
        config = quicsrt::gateway::ParseConfig(config_text, "burst_join_test");
    }
    catch (const quicsrt::gateway::ConfigError& e)
    {
        std::fprintf(stderr, "burst_join_test: config error: %s\n", e.what());
        return 1;
    }
    config.server.wt_port = port;

    const auto policy = quicsrt::gateway::Chain(std::make_shared<quicsrt::gateway::PathPolicy>("/wt"),
                                                quicsrt::gateway::BuildAllowlistPolicy(config));

    Gateway gateway(cert, policy, GatewayConfig{.max_viewers = config.server.max_viewers,
                                                .broadcast_capacity = config.server.broadcast_capacity});
    if (!Check(gateway.Start("127.0.0.1", port), "gateway binds 127.0.0.1:4437 (or the ephemeral fallback)"))
    {
        return 1;
    }
    const std::string hash = cert.Sha256Hex();
    std::fprintf(stderr, "burst_join_test: gateway on 127.0.0.1:%u, hash %s\n", port, hash.c_str());

    quicsrt::Publisher pub;
    if (!Check(pub.Start(PubCfg(port, hash, "g9-burst")) == quicsrt::kPublishOk, "publisher accepted"))
    {
        gateway.Shutdown();
        return 1;
    }

    // The sustained burst: 12 MB in 128-KB bursts, one burst every ~40 ms
    // (~25 Mbps) for ~4 s - unpaced within each burst (the file-push
    // shape), sustained across the window so a mid-join viewer lands on a
    // live stream.
    constexpr std::size_t kBurstBytes = 128 * 1024;
    constexpr std::size_t kTotal      = 12 * 1024 * 1024;
    std::vector<std::uint8_t>  chunk(kBurstBytes);
    for (std::size_t i = 0; i < chunk.size(); ++i)
    {
        chunk[i] = static_cast<std::uint8_t>((i / 188) ^ (i % 251));
    }
    std::atomic<std::size_t> written{0};
    std::atomic<int>         write_error{0};
    std::thread              blast(
        [&]
        {
            while (written.load() < kTotal)
            {
                const int n = pub.Write(chunk.data(), chunk.size(), 5000);
                if (n <= 0)
                {
                    write_error.store(n);
                    return;
                }
                written.store(written.load() + static_cast<std::size_t>(n));
                std::this_thread::sleep_for(std::chrono::milliseconds{40});
            }
        });

    // The publisher must stay live across the window (a session reaped by
    // its own burst is the defect this guards).
    bool        publisher_died = false;
    std::size_t msgs_at_death  = 0;
    for (int ms = 0; ms <= 3000; ms += 50)
    {
        const StreamStats s = StreamNamed(gateway.SnapshotStreams(), "g9-burst");
        if (!s.name.empty() && !s.publisher_live && !publisher_died)
        {
            publisher_died     = true;
            msgs_at_death      = s.messages_sent;
        }
        if (ms % 500 == 0)
        {
            std::fprintf(stderr,
                         "burst_join_test: t=%4d ms alive=%d ring=%zu msgs=%llu viewers=%zu (wrote %zu B)\n",
                         ms,
                         s.name.empty() ? -1 : (s.publisher_live ? 1 : 0),
                         s.ring_size,
                         static_cast<unsigned long long>(s.messages_sent),
                         s.viewers,
                         written.load());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // The mid-join viewer: attaches while the blast is still running.
    std::size_t viewer_bytes = 0;
    {
        quicsrt::Subscriber sub;
        const auto          sub_status = sub.Start(SubCfg(port, hash, "g9-burst"));
        std::fprintf(stderr,
                     "burst_join_test: viewer status=%d ('%s')\n",
                     static_cast<int>(sub_status),
                     sub.LastError().c_str());
        if (Check(sub_status == quicsrt::kStartOk, "mid-join viewer accepted"))
        {
            char       buf[1128];
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
            while (std::chrono::steady_clock::now() < deadline && viewer_bytes == 0)
            {
                const int n = sub.Read(buf, sizeof buf, 200);
                if (n > 0)
                {
                    viewer_bytes += static_cast<std::size_t>(n);
                }
                else if (n == quicsrt::kReadEnd || n == quicsrt::kReadClosed)
                {
                    std::fprintf(stderr, "burst_join_test: viewer stream ended: '%s'\n", sub.LastError().c_str());
                    break;
                }
            }
        }
        sub.Stop();
    }

    blast.join();
    std::fprintf(stderr,
                 "burst_join_test: publisher wrote %zu B (error=%d), publisher_died=%d (msgs=%zu), viewer got %zu B\n",
                 written.load(),
                 write_error.load(),
                 publisher_died ? 1 : 0,
                 msgs_at_death,
                 viewer_bytes);

    Check(!publisher_died, "1: the burst publisher's session stayed live through the blast");
    Check(write_error.load() == 0, "1: no publisher write failed");
    Check(viewer_bytes > 0, "2: the mid-join viewer received data");

    pub.Stop();
    Check(WaitUntil(
              [&gateway]
              {
                  const StreamStats s = StreamNamed(gateway.SnapshotStreams(), "g9-burst");
                  return s.name.empty() || (!s.publisher_live && s.viewers == 0);
              },
              10000),
          "the ended stream is released");

    gateway.Shutdown();

    if (!g_ok)
    {
        std::fprintf(stderr, "burst_join_test: FAILURES\n");
        return 1;
    }
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_total0);
    std::printf("burst_join_test: OK (%lld ms)\n", static_cast<long long>(elapsed_ms.count()));
    return 0;
}
