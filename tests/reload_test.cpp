// P4.1 hot reload - the PLAN.md P4.1 Verify scenario against a real
// gateway core configured from a real config FILE (the reload re-parses
// it, so unlike gateway_e2e_test the config lives on disk):
//   1. One-stream-allowlist config (two streams, max_viewers = 1): a
//      viewer is allowed and streaming; the per-stream cap refuses a
//      second viewer (429).
//   2. Reload with one stream removed and another added, max_viewers
//      raised: a NEW CONNECT to the removed stream gets 404, to the added
//      stream is allowed, and a second viewer now fits on a stream whose
//      broadcaster was created under the old cap (the cap swap reaches
//      already-existing rings) - while the existing viewer of the removed
//      stream KEEPS STREAMING byte-for-byte (already-granted access).
//   3. Reload with an invalid config: the call fails with an error, the
//      old config stays active (the added stream still allowed) and the
//      gateway stays healthy (running, ticker advancing, cap unchanged).
//
// ReloadConfig IS the SIGHUP entry point; main.cpp only flips a
// sig_atomic_t flag in the handler and calls it from the poll loop (the
// handler must not parse files), so the signal plumbing itself is trivial
// and not exercised here.
//
// Ports: 127.0.0.1:4437 with an ephemeral fallback (the other tests'
// 4433-4436 are never touched). The gateway under test is a real Gateway;
// the clients are libwebsrt's public Subscriber/Publisher, each on its
// own engine.

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"
#include "gateway/reload.h"

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include "websrt/publisher.hpp"
#include "websrt/subscriber.hpp"

namespace
{

constexpr const char* kConfigPath = "/tmp/websrt-gateway-reload-test.conf";
constexpr int         kMaxPayload = 1128; // WebSRT constant: 6 x 188-byte TS packets

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "reload_test: FAIL: %s\n", what);
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

void WriteConfigFile(const std::string& text)
{
    std::ofstream out(kConfigPath, std::ios::out | std::ios::trunc);
    out << text;
}

/// Deterministic payload (no fixture dependency; the gateway must never
/// care where the bytes came from).
std::vector<std::uint8_t> PatternBytes(std::size_t n, std::uint32_t seed)
{
    std::vector<std::uint8_t> bytes(n);
    std::uint32_t             state = seed;
    for (std::uint8_t& byte : bytes)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<std::uint8_t>(state >> 24);
    }
    return bytes;
}

websrt::SubscriberConfig SubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    websrt::SubscriberConfig cfg;
    cfg.host             = "127.0.0.1";
    cfg.port             = port;
    cfg.stream_name      = stream;
    cfg.cert_sha256_hex  = hash;
    cfg.tsbpd_latency_ms = 120;
    return cfg;
}

websrt::PublisherConfig PubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    websrt::PublisherConfig cfg;
    cfg.host            = "127.0.0.1";
    cfg.port            = port;
    cfg.stream_name     = stream;
    cfg.cert_sha256_hex = hash;
    return cfg;
}

/// Push `bytes` through the publisher, resuming on partial accepts.
bool WriteAll(websrt::Publisher& pub, const std::vector<std::uint8_t>& bytes)
{
    std::size_t off = 0;
    while (off < bytes.size())
    {
        const int n = pub.Write(bytes.data() + off, bytes.size() - off, 5000);
        if (n <= 0)
        {
            std::fprintf(stderr, "reload_test: publisher Write failed at %zu: %s\n", off, pub.LastError().c_str());
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

/// Read until `want` bytes have arrived or the deadline passes.
std::vector<std::uint8_t> ReadBytes(websrt::Subscriber& sub, std::size_t want, int timeout_ms)
{
    std::vector<std::uint8_t> received;
    received.reserve(want);
    char       buf[kMaxPayload];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (received.size() < want)
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            break;
        }
        const int n = sub.Read(buf, sizeof buf, 200);
        if (n > 0)
        {
            received.insert(received.end(), buf, buf + n);
            continue;
        }
        if (n == websrt::kReadEnd || n == websrt::kReadClosed)
        {
            std::fprintf(stderr, "reload_test: stream ended after %zu/%zu bytes\n", received.size(), want);
            break;
        }
    }
    return received;
}

bool SameBytes(const std::vector<std::uint8_t>& got, const std::vector<std::uint8_t>& want)
{
    return got.size() == want.size() && std::memcmp(got.data(), want.data(), got.size()) == 0;
}

bool ErrorMentions(const std::string& haystack, const char* needle)
{
    return haystack.find(needle) != std::string::npos;
}

/// 127.0.0.1:4437 when free, else an ephemeral port (probe-bind :0, close,
/// hand the port over; the tiny TOCTOU window is acceptable for a test).
std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port              = htons(4437);
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
        std::fprintf(stderr, "reload_test: cannot probe any port\n");
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
    const websrt::gateway::CertProvider cert;
    const std::uint16_t                 port = ChoosePort();
    ::unlink(kConfigPath); // a stale file from an aborted run must not leak in

    // v1: the one-stream-allowlist start (two streams here so the viewer
    // cap has its own name), max_viewers = 1.
    WriteConfigFile("[server]\n"
                    "max_viewers = 1\n"
                    "\n"
                    "[[stream]]\n"
                    "name = \"rl-live\"\n"
                    "\n"
                    "[[stream]]\n"
                    "name = \"rl-cap\"\n");
    websrt::gateway::Config config = websrt::gateway::LoadConfig(kConfigPath);

    const auto               policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                               websrt::gateway::BuildAllowlistPolicy(config));
    websrt::gateway::Gateway gateway(
        cert, policy, websrt::gateway::GatewayConfig{.max_viewers = config.server.max_viewers});
    if (!Check(gateway.Start("127.0.0.1", port), "gateway binds 127.0.0.1:4437 (or the ephemeral fallback)"))
    {
        return 1;
    }
    const std::string hash = cert.Sha256Hex();
    std::fprintf(stderr, "reload_test: gateway on 127.0.0.1:%u, hash %s\n", port, hash.c_str());

    // The publisher and the viewer that must survive every reload below.
    websrt::Publisher pub;
    Check(pub.Start(PubCfg(port, hash, "rl-live")) == websrt::kPublishOk, "1: publisher accepted");
    websrt::Subscriber viewer;
    Check(viewer.Start(SubCfg(port, hash, "rl-live")) == websrt::kStartOk, "1: viewer allowed by the allowlist");

    const std::vector<std::uint8_t> chunk1 = PatternBytes(std::size_t{16} * kMaxPayload, 0x1234);
    Check(WriteAll(pub, chunk1), "1: published chunk 1");
    Check(SameBytes(ReadBytes(viewer, chunk1.size(), 20000), chunk1), "1: viewer streaming chunk 1 byte-for-byte");

    // The cap of one refuses a second viewer on rl-cap.
    websrt::Subscriber cap_first;
    Check(cap_first.Start(SubCfg(port, hash, "rl-cap")) == websrt::kStartOk, "1: first viewer of rl-cap accepted");
    websrt::Subscriber cap_second;
    const auto         cap_status = cap_second.Start(SubCfg(port, hash, "rl-cap"));
    Check(cap_status == websrt::kStartRejected, "1: second viewer refused at the cap");
    Check(ErrorMentions(cap_second.LastError(), "429"), "1: the cap refusal carries HTTP 429");

    // ---- 2. reload: "rl-live" removed, "rl-added" added, cap -> 2 ----
    WriteConfigFile("[server]\n"
                    "max_viewers = 2\n"
                    "log_level = \"error\"\n"
                    "\n"
                    "[[stream]]\n"
                    "name = \"rl-cap\"\n"
                    "\n"
                    "[[stream]]\n"
                    "name = \"rl-added\"\n");
    std::string reload_error;
    auto        reloaded = websrt::gateway::ReloadConfig(kConfigPath, gateway, config, &reload_error);
    Check(reloaded.has_value(), "2: reload succeeds");
    if (reloaded.has_value())
    {
        config                             = *reloaded;
        const std::size_t expected_streams = 2; // rl-live is gone
        Check(config.streams.size() == expected_streams, "2: the new config reports the new allowlist");
    }
    Check(gateway.MaxViewers() == 2, "2: max_viewers swapped (synchronously applied)");

    // A NEW CONNECT to the removed stream gets 404...
    websrt::Subscriber late;
    const auto         late_status = late.Start(SubCfg(port, hash, "rl-live"));
    Check(late_status == websrt::kStartRejected, "2: new CONNECT to the removed stream refused");
    Check(ErrorMentions(late.LastError(), "404"), "2: the refusal carries HTTP 404");
    // ...to the added stream is allowed (the NEW allowlist is really active)...
    websrt::Subscriber added;
    Check(added.Start(SubCfg(port, hash, "rl-added")) == websrt::kStartOk,
          "2: new CONNECT to the added stream allowed");
    // ...and the raised cap now admits a second viewer on a broadcaster
    // created under the OLD cap.
    websrt::Subscriber cap_second2;
    Check(cap_second2.Start(SubCfg(port, hash, "rl-cap")) == websrt::kStartOk,
          "2: raised max_viewers admits a second viewer on the existing stream");

    // The existing viewer of the removed stream keeps streaming.
    const std::vector<std::uint8_t> chunk2 = PatternBytes(std::size_t{16} * kMaxPayload, 0x5678);
    Check(WriteAll(pub, chunk2), "2: published chunk 2 through the reload");
    Check(SameBytes(ReadBytes(viewer, chunk2.size(), 20000), chunk2),
          "2: the existing viewer keeps streaming byte-for-byte");

    // ---- 3. reload with an invalid config: old config stays, healthy ----
    WriteConfigFile("[server]\nwt_port = \"banana\"\n");
    std::string bad_error;
    auto        bad = websrt::gateway::ReloadConfig(kConfigPath, gateway, config, &bad_error);
    Check(!bad.has_value(), "3: invalid config -> reload fails");
    Check(!bad_error.empty() && ErrorMentions(bad_error, "'wt_port'"), "3: the failure reports the config error");
    Check(gateway.MaxViewers() == 2, "3: the applied cap is untouched by the failed reload");
    Check(gateway.Running(), "3: the gateway is still running");

    // The OLD config is still active: the added stream is still allowed.
    websrt::Subscriber still;
    Check(still.Start(SubCfg(port, hash, "rl-added")) == websrt::kStartOk,
          "3: the old config stays active (rl-added still allowed)");

    // Healthy: the ticker keeps advancing.
    const std::uint64_t ticks_before = gateway.TickCount();
    Check(WaitUntil([&gateway, ticks_before] { return gateway.TickCount() > ticks_before; }, 5000),
          "3: the ticker keeps advancing");

    pub.End(15000); // clean end for the live stream's viewer
    gateway.Shutdown();
    ::unlink(kConfigPath);

    if (!g_ok)
    {
        std::fprintf(stderr, "reload_test: FAILURES\n");
        return 1;
    }
    std::printf("reload_test: OK\n");
    return 0;
}
