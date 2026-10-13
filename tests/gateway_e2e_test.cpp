// G5 end-to-end: the full gateway loop - accept, admission, per-session SRT
// initiators, the broadcaster ring and first-wins occupancy - driven by
// libwebsrt's public Subscriber/Publisher clients over WT loopback. C++ on
// both sides, no Rust gateway. The gateway under test is a real Gateway
// configured from a real TOML config (config -> StreamAllowlistPolicy ->
// Gateway), so the allowlist path is exercised too, not just the open mode.
//
//   1. HAPPY PATH, byte-for-byte. A Subscriber attaches FIRST (the waiting
//      viewer), the Publisher joins, and the whole WebSRT fixture
//      (fixtures/test.ts) comes back through the ring byte-for-byte in
//      order - the TS bytes are never modified server-side.
//   2. WAITING VIEWER. A subscriber of a configured stream with no
//      publisher is accepted (NOT 404), the stream exists as an idle
//      waiting stream, it receives nothing yet, and it starts receiving
//      when a publisher appears.
//   3. FIRST-WINS 403. A second publisher on a live name is refused at
//      admission: kPublishRejected, HTTP 403 in LastError.
//   4. VIEWER CAP. With max_viewers = 2 a third concurrent subscriber is
//      refused (429); closing one frees the slot for a new viewer.
//   5. PUBLISHER END. Publisher::End() closes every viewer of the stream
//      with a clean EOF (Read returns kReadEnd), and the name is released.
//   6. ALLOWLIST. An unconfigured publish name -> 403 at admission, an
//      unconfigured subscribe name -> 404, against this config-loaded
//      gateway.
//   7. TOKEN - NOT COVERED HERE (see the note at the bottom): libwebsrt's
//      client configs have no ?token= field, so a client cannot present a
//      token at all. The per-stream token decision is covered by
//      tests/policy_test.cpp against the very policy the gateway is built
//      with here.
//
// Ports: 127.0.0.1:4434 with an ephemeral fallback (probe-bind :0, read the
// port, close, hand it over) if 4434 is busy. The Rust gateway's
// 4433/9000 are never touched. Each Subscriber/Publisher owns its own
// EventLoop internally (G3: one engine per loop).

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#include "websrt/publisher.hpp"
#include "websrt/subscriber.hpp"

namespace
{

using websrt::gateway::Gateway;
using websrt::gateway::GatewayConfig;
using websrt::gateway::StreamStats;

constexpr const char* kFixture    = "/home/flibb/maxolgi/WebSRT/fixtures/test.ts";
constexpr int         kMaxPayload = 1128; // WebSRT constant: 6 x 188-byte TS packets
constexpr std::size_t kMaxViewers = 2;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "gateway_e2e_test: FAIL: %s\n", what);
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

/// One stream's snapshot entry, or a zeroed one when absent.
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

bool ErrorMentions(const std::string& haystack, const char* needle)
{
    return haystack.find(needle) != std::string::npos;
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
            std::fprintf(
                stderr, "gateway_e2e_test: publisher Write failed at offset %zu: %s\n", off, pub.LastError().c_str());
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
            std::fprintf(stderr, "gateway_e2e_test: stream ended after %zu/%zu bytes\n", received.size(), want);
            break;
        }
    }
    return received;
}

/// 127.0.0.1:4434 when free, else an ephemeral port (probe-bind :0, close,
/// hand the port over; the tiny TOCTOU window is acceptable for a test).
std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port              = htons(4434);
        const bool port4434_free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (port4434_free)
        {
            return 4434;
        }
    }
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_port = 0;
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "gateway_e2e_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

/// The fixture bytes, or a deterministic TS-pattern fallback when the file
/// is absent (the gateway must never care where the bytes came from).
std::vector<std::uint8_t> LoadPayload()
{
    std::ifstream in(kFixture, std::ios::in | std::ios::binary);
    if (in.is_open())
    {
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!bytes.empty())
        {
            std::fprintf(stderr, "gateway_e2e_test: payload: %zu bytes from %s\n", bytes.size(), kFixture);
            return bytes;
        }
    }
    // 58 x 1128: 188-aligned AND payload-sized. The TsChunker framing
    // (ingest FRAMING note, libwebsrt publisher.h) carries a sub-188
    // remainder until end-of-stream, so a fallback with a sub-188 tail
    // (64 KiB leaves 112 bytes) can never arrive mid-stream.
    constexpr std::size_t     kPatternBytes = std::size_t{58} * 1128;
    std::vector<std::uint8_t> bytes(kPatternBytes);
    std::uint32_t             state = 0x9E3779B9U;
    for (std::uint8_t& byte : bytes)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<std::uint8_t>(state >> 24);
    }
    std::fprintf(stderr,
                 "gateway_e2e_test: payload: %s absent, using %zu deterministic pattern bytes\n",
                 kFixture,
                 bytes.size());
    return bytes;
}

} // namespace

int main()
{
    const auto                          t_total0 = std::chrono::steady_clock::now();
    const std::vector<std::uint8_t>     payload  = LoadPayload();
    const websrt::gateway::CertProvider cert;

    const std::uint16_t port = ChoosePort();

    // A real config, parsed by the real parser: the allowlist the gateway
    // enforces below is the one this TOML describes.
    const std::string config_text = std::string{"[server]\n"
                                                "wt_port = 4434\n"
                                                "max_viewers = 2\n"
                                                "broadcast_capacity = 4096\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-happy\"\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-wait\"\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-firstwins\"\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-cap\"\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-end\"\n"
                                                "\n"
                                                "[[stream]]\n"
                                                "name = \"g5-token\"\n"
                                                "token = \"letmein\"\n"};

    websrt::gateway::Config config;
    try
    {
        config = websrt::gateway::ParseConfig(config_text, "gateway_e2e_test");
    }
    catch (const websrt::gateway::ConfigError& e)
    {
        std::fprintf(stderr, "gateway_e2e_test: config error: %s\n", e.what());
        return 1;
    }
    config.server.wt_port = port; // the CLI overrides file scalars

    const auto policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                               websrt::gateway::BuildAllowlistPolicy(config));

    Gateway gateway(cert,
                    policy,
                    GatewayConfig{.max_viewers        = config.server.max_viewers,
                                  .broadcast_capacity = config.server.broadcast_capacity});
    if (!Check(gateway.Start("127.0.0.1", port), "gateway binds 127.0.0.1:4434 (or the ephemeral fallback)"))
    {
        return 1;
    }
    const std::string hash = cert.Sha256Hex();
    std::fprintf(stderr,
                 "gateway_e2e_test: gateway on 127.0.0.1:%u, allowlist mode, %zu configured stream(s), hash %s\n",
                 port,
                 config.streams.size(),
                 hash.c_str());

    // ---- 1. happy path, byte-for-byte (subscriber first) ----
    {
        websrt::Subscriber sub;
        const auto         sub_status = sub.Start(SubCfg(port, hash, "g5-happy"));
        const bool sub_ok = Check(sub_status == websrt::kStartOk, "1: waiting Subscriber accepted (kStartOk, not 404)");
        std::fprintf(stderr,
                     "gateway_e2e_test: 1: subscriber status=%d ('%s')\n",
                     static_cast<int>(sub_status),
                     sub.LastError().c_str());

        websrt::Publisher pub;
        const auto        pub_status = pub.Start(PubCfg(port, hash, "g5-happy"));
        const bool        pub_ok     = Check(pub_status == websrt::kPublishOk, "1: Publisher accepted");
        std::fprintf(stderr,
                     "gateway_e2e_test: 1: publisher status=%d ('%s')\n",
                     static_cast<int>(pub_status),
                     pub.LastError().c_str());
        if (sub_ok && pub_ok)
        {
            Check(WriteAll(pub, payload), "1: published the whole payload");
            const std::vector<std::uint8_t> got = ReadBytes(sub, payload.size(), 20000);
            Check(got.size() == payload.size(), "1: subscriber received every byte");
            const bool identical =
                got.size() == payload.size() && std::memcmp(got.data(), payload.data(), got.size()) == 0;
            Check(identical, "1: bytes byte-for-byte in order");
            std::fprintf(stderr,
                         "gateway_e2e_test: 1: %zu/%zu bytes, identical=%d\n",
                         got.size(),
                         payload.size(),
                         identical ? 1 : 0);
        }
        const StreamStats after = StreamNamed(gateway.SnapshotStreams(), "g5-happy");
        std::fprintf(stderr,
                     "gateway_e2e_test: 1: stream alive=%d viewers=%zu ring=%zu sent=%llu drops=%llu\n",
                     after.publisher_live ? 1 : 0,
                     after.viewers,
                     after.ring_size,
                     static_cast<unsigned long long>(after.messages_sent),
                     static_cast<unsigned long long>(after.ring_drops));
        Check(after.messages_sent >= payload.size() / kMaxPayload, "1: the ring took every published message");
    }

    // ---- 2. waiting viewer on an idle stream ----
    {
        websrt::Subscriber sub;
        Check(sub.Start(SubCfg(port, hash, "g5-wait")) == websrt::kStartOk,
              "2: subscriber of an unpublished stream accepted (waiting, not 404)");

        // The stream exists as an idle waiting stream with this viewer.
        const StreamStats idle = StreamNamed(gateway.SnapshotStreams(), "g5-wait");
        Check(!idle.publisher_live, "2: the stream is idle (no publisher yet)");
        Check(idle.viewers == 1, "2: the waiting viewer is attached");
        Check(idle.messages_sent == 0, "2: nothing has been published yet");
        std::fprintf(stderr,
                     "gateway_e2e_test: 2: idle stream viewers=%zu sent=%llu\n",
                     idle.viewers,
                     static_cast<unsigned long long>(idle.messages_sent));

        // It receives nothing while waiting.
        char buf[kMaxPayload];
        Check(sub.Read(buf, sizeof buf, 300) == websrt::kReadTimeout, "2: the waiting viewer receives nothing yet");

        websrt::Publisher pub;
        Check(pub.Start(PubCfg(port, hash, "g5-wait")) == websrt::kPublishOk,
              "2: publisher attaches to the idle stream");
        const std::size_t want = std::min<std::size_t>(payload.size(), std::size_t{16} * kMaxPayload);
        Check(WriteAll(pub, std::vector<std::uint8_t>(payload.begin(), payload.begin() + static_cast<long>(want))),
              "2: published into the waiting stream");
        const std::vector<std::uint8_t> got = ReadBytes(sub, want, 20000);
        const bool identical = got.size() == want && std::memcmp(got.data(), payload.data(), got.size()) == 0;
        Check(identical, "2: the waiting viewer receives the publisher's bytes byte-for-byte");
        const StreamStats live = StreamNamed(gateway.SnapshotStreams(), "g5-wait");
        Check(live.publisher_live, "2: the stream is live once the publisher attached");
        std::fprintf(stderr,
                     "gateway_e2e_test: 2: got %zu/%zu bytes, identical=%d, ring=%zu\n",
                     got.size(),
                     want,
                     identical ? 1 : 0,
                     live.ring_size);
    }

    // ---- 3. first-wins occupancy: 403 at admission ----
    {
        websrt::Publisher first;
        Check(first.Start(PubCfg(port, hash, "g5-firstwins")) == websrt::kPublishOk,
              "3: the first publisher wins the name");

        websrt::Publisher second;
        const auto        status = second.Start(PubCfg(port, hash, "g5-firstwins"));
        Check(status == websrt::kPublishRejected, "3: the challenger is refused (kPublishRejected)");
        Check(ErrorMentions(second.LastError(), "403"), "3: the refusal carries HTTP 403");
        std::fprintf(stderr,
                     "gateway_e2e_test: 3: challenger status=%d last_error='%s'\n",
                     static_cast<int>(status),
                     second.LastError().c_str());

        // Once the incumbent is gone the name is free again.
        first.Stop();
        Check(WaitUntil([&gateway] { return !StreamNamed(gateway.SnapshotStreams(), "g5-firstwins").publisher_live; },
                        5000),
              "3: the name is released when the publisher goes away");
        websrt::Publisher third;
        Check(third.Start(PubCfg(port, hash, "g5-firstwins")) == websrt::kPublishOk,
              "3: a later publisher reclaims the name");
    }

    // ---- 4. per-stream viewer cap: 429 ----
    {
        websrt::Subscriber v1;
        websrt::Subscriber v2;
        websrt::Subscriber v3;
        Check(v1.Start(SubCfg(port, hash, "g5-cap")) == websrt::kStartOk, "4: viewer 1 accepted");
        Check(v2.Start(SubCfg(port, hash, "g5-cap")) == websrt::kStartOk, "4: viewer 2 accepted (at the cap)");

        const auto status = v3.Start(SubCfg(port, hash, "g5-cap"));
        Check(status == websrt::kStartRejected, "4: viewer 3 refused (kStartRejected)");
        Check(ErrorMentions(v3.LastError(), "429"), "4: the refusal carries HTTP 429");
        std::fprintf(stderr,
                     "gateway_e2e_test: 4: third viewer status=%d last_error='%s'\n",
                     static_cast<int>(status),
                     v3.LastError().c_str());

        const StreamStats capped = StreamNamed(gateway.SnapshotStreams(), "g5-cap");
        Check(capped.viewers == kMaxViewers, "4: exactly max_viewers viewers are attached");

        // Freeing a slot lets a new viewer in.
        v2.Stop();
        Check(WaitUntil([&gateway] { return StreamNamed(gateway.SnapshotStreams(), "g5-cap").viewers == 1; }, 5000),
              "4: the closed viewer's slot is released");
        websrt::Subscriber v4;
        Check(v4.Start(SubCfg(port, hash, "g5-cap")) == websrt::kStartOk, "4: a new viewer takes the freed slot");
        Check(StreamNamed(gateway.SnapshotStreams(), "g5-cap").viewers == kMaxViewers, "4: the cap holds again");
        v1.Stop();
        v4.Stop();
    }

    // ---- 5. publisher end closes the viewers (clean EOF) ----
    {
        websrt::Subscriber sub;
        Check(sub.Start(SubCfg(port, hash, "g5-end")) == websrt::kStartOk, "5: viewer attached before the publisher");

        websrt::Publisher pub;
        Check(pub.Start(PubCfg(port, hash, "g5-end")) == websrt::kPublishOk, "5: publisher attached");
        const std::size_t want = std::min<std::size_t>(payload.size(), std::size_t{8} * kMaxPayload);
        Check(WriteAll(pub, std::vector<std::uint8_t>(payload.begin(), payload.begin() + static_cast<long>(want))),
              "5: published a prefix");
        const std::vector<std::uint8_t> got = ReadBytes(sub, want, 20000);
        Check(got.size() == want && std::memcmp(got.data(), payload.data(), got.size()) == 0,
              "5: the viewer received the prefix byte-for-byte");

        Check(pub.End(15000), "5: the publisher ended the stream gracefully");
        // The gateway closes every viewer of the stream; the browser/libwebsrt
        // client observes that as a clean end-of-stream.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        int        eof      = 0;
        while (std::chrono::steady_clock::now() < deadline)
        {
            char      buf[kMaxPayload];
            const int n = sub.Read(buf, sizeof buf, 500);
            if (n == 0)
            {
                eof = websrt::kReadEnd;
                break;
            }
            if (n < 0)
            {
                eof = n;
                break;
            }
        }
        Check(eof == websrt::kReadEnd, "5: the viewer's Read returns a clean EOF (0)");
        std::fprintf(stderr,
                     "gateway_e2e_test: 5: viewer Read terminal=%d (kReadEnd=%d) last_error='%s'\n",
                     eof,
                     static_cast<int>(websrt::kReadEnd),
                     sub.LastError().c_str());
        Check(WaitUntil(
                  [&gateway]
                  {
                      const StreamStats s = StreamNamed(gateway.SnapshotStreams(), "g5-end");
                      return s.name.empty() || (!s.publisher_live && s.viewers == 0);
                  },
                  5000),
              "5: the ended stream is dropped (no publisher, no viewers)");
    }

    // ---- 6. allowlist: 403 publish, 404 subscribe ----
    {
        websrt::Publisher pub;
        const auto        pub_status = pub.Start(PubCfg(port, hash, "g5-denied"));
        Check(pub_status == websrt::kPublishRejected, "6: an unconfigured publish name is refused");
        Check(ErrorMentions(pub.LastError(), "403"), "6: the publish refusal carries HTTP 403");

        websrt::Subscriber sub;
        const auto         sub_status = sub.Start(SubCfg(port, hash, "g5-denied"));
        Check(sub_status == websrt::kStartRejected, "6: an unconfigured subscribe name is refused");
        Check(ErrorMentions(sub.LastError(), "404"), "6: the subscribe refusal carries HTTP 404");
        std::fprintf(stderr,
                     "gateway_e2e_test: 6: publish=%d ('%s') subscribe=%d ('%s')\n",
                     static_cast<int>(pub_status),
                     pub.LastError().c_str(),
                     static_cast<int>(sub_status),
                     sub.LastError().c_str());

        // ---- 7. per-stream token: the CLIENT cannot present one ----
        // libwebsrt's SubscriberConfig/PublisherConfig have no token field,
        // so no libwebsrt client can send ?token=. Sending one would be
        // refused for the wrong reason (a missing token), so the accept
        // half is asserted here and the DECISION half is covered by
        // tests/policy_test.cpp (same StreamAllowlistPolicy instance type).
        websrt::Subscriber tokened;
        Check(tokened.Start(SubCfg(port, hash, "g5-token")) == websrt::kStartRejected,
              "7: a token-protected stream refuses a client with no token");
        Check(ErrorMentions(tokened.LastError(), "403"), "7: the token refusal carries HTTP 403");
        std::fprintf(
            stderr, "gateway_e2e_test: 7: no-token subscribe refused with '%s'\n", tokened.LastError().c_str());
    }

    Check(gateway.ActiveSessionCount() == 0, "every session was reaped");

    std::fprintf(stderr,
                 "gateway_e2e_test: registry ticks %llu, max tick %llu us\n",
                 static_cast<unsigned long long>(gateway.TickCount()),
                 static_cast<unsigned long long>(gateway.TickMaxUs()));
    Check(gateway.TickCount() > 0, "the ~2 ms registry ticker ran");

    gateway.Shutdown();
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_total0);

    if (!g_ok)
    {
        std::fprintf(stderr, "gateway_e2e_test: FAILURES\n");
        return 1;
    }
    std::printf("gateway_e2e_test: OK (%lld ms)\n", static_cast<long long>(elapsed_ms.count()));
    return 0;
}