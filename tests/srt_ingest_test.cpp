// G6 tests: the SRT/UDP ingest, end to end against the REAL gateway core.
//
//   1. PUBLISH -> VIEWER, byte-for-byte. A stock-libsrt caller (plain
//      srt_create_socket/srt_connect/srt_sendmsg - no libwebsrt session
//      anywhere; the ingest is the only stock socket in the gateway) dials
//      the ingest with streamid=NAME and sends the WebSRT fixture; a
//      libwebsrt Subscriber attached to the same stream gets every byte
//      back, in order, unmodified. THIS IS THE P3 INGEST GATE.
//   2. EMPTY STREAMID rejected - a publisher with no streamid never gets a
//      stream and never delivers a byte.
//   3. FIRST-WINS - a second ingest publisher on a live name is refused;
//      the name frees when the incumbent disconnects and a later publisher
//      reclaims it.
//   4. ALLOWLIST - against a config-loaded allowlist, a streamid no
//      [[stream]] entry covers is refused at accept.
//   5. CHUNKING - a 64 KB burst in live-sized 1316-byte SRT messages
//      arrives as <= 1128-byte, 188-aligned messages, byte-exact, with the
//      leftover sub-188 tail flushed when the publisher hangs up (a fake
//      sink counts the sizes). A single 64 KB sendmsg is not expressible
//      over live-mode SRT - its congestion control refuses any message
//      above the negotiated payload - so the burst is what a real
//      1316-byte-per-message publisher sends.
//   6. SESSION CAP - with max_sessions = 2 the third concurrent publisher
//      is refused right at accept (counted as rejected_session_cap, no
//      stream slot claimed), and the slot frees when a publisher hangs
//      up.
//
// The gateway under test is the real Gateway built from a real TOML config
// (config -> StreamAllowlistPolicy -> Gateway) on a loopback port, and the
// ingest is the real SrtIngest wired exactly as src/main.cpp wires it.
// Ports: 127.0.0.1:9100 (ingest), :4436 (WebTransport), :9101 (the
// fake-sink ingest), :9102 (the capped fake-sink ingest), each with the
// probe-bind ephemeral fallback the G5 test uses. The Rust gateway's
// 4433/9000 are never touched. Deterministic: every wait is bounded and
// asserted.

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"
#include "gateway/ingest/srt_ingest.h"

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
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "websrt/subscriber.hpp"

namespace
{

using websrt::gateway::Gateway;
using websrt::gateway::GatewayConfig;
using websrt::gateway::StreamStats;

// WebSRT checkout fixture; override with WEBSRT_TEST_FIXTURE, default
// follows the workspace layout under $HOME.
std::string FixturePath()
{
    if (const char* env = std::getenv("WEBSRT_TEST_FIXTURE"))
        return env;
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/maxolgi/WebSRT/fixtures/test.ts" : std::string();
}
constexpr int         kMaxPayload = 1128; // WebSRT constant: 6 x 188-byte TS packets
constexpr std::size_t kTsPacket   = 188;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "srt_ingest_test: FAIL: %s\n", what);
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

/// The allowlist consult src/main.cpp wires into the ingest's publish_gate:
/// the SRT streamid reuses the WT publish decision verbatim, on a synthetic
/// ?publish= request.
bool PublishAllowed(const websrt::gateway::SessionPolicy& policy, const std::string& name)
{
    // Named string: SessionRequest::query is a string_view, so a temporary
    // spliced straight into it would dangle before Decide reads it.
    const std::string               query = "publish=" + websrt::gateway::PercentEncodeQueryValue(name);
    websrt::gateway::SessionRequest req;
    req.path  = "/wt";
    req.query = query;
    return policy.Decide(req) == websrt::gateway::Decision::Accept;
}

/// `preferred` when free, else an ephemeral port (probe-bind :0, read the
/// port back, close, hand it over; the tiny TOCTOU window is acceptable for
/// a test - the same tradeoff gateway_e2e_test makes).
std::uint16_t ChoosePort(std::uint16_t preferred)
{
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    sa.sin_port = htons(preferred);
    int fd      = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0)
    {
        const bool free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (free)
        {
            return preferred;
        }
    }

    sa.sin_port = 0;
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "srt_ingest_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

// ---------------------------------------------------------------------------
// The stock-libsrt publisher: a plain srt_* caller, like deps/srt's apps.
// ---------------------------------------------------------------------------

class SrtCaller
{
public:
    SrtCaller() = default;
    ~SrtCaller() { Close(); }

    SrtCaller(const SrtCaller&)            = delete;
    SrtCaller& operator=(const SrtCaller&) = delete;

    /// An empty `streamid` connects WITHOUT SRTO_STREAMID - that is the
    /// streamid-required test's caller.
    bool Connect(std::uint16_t port, const std::string& streamid, std::string* error)
    {
        sock_ = srt_create_socket();
        if (sock_ == SRT_INVALID_SOCK)
        {
            *error = std::string("srt_create_socket: ") + srt_getlasterror_str();
            return false;
        }
        const int live   = SRTT_LIVE;
        const int tmo    = 5000; // SRTO_CONNTIMEO, milliseconds
        const int sndbuf = 16 * 1024 * 1024;
        const int lat    = 120;
        auto opt_i = [this](SRT_SOCKOPT o, int v) { return srt_setsockopt(sock_, 0, o, &v, sizeof v) != SRT_ERROR; };
        opt_i(SRTO_TRANSTYPE, live);
        opt_i(SRTO_LATENCY, lat);
        opt_i(SRTO_CONNTIMEO, tmo);
        // A roomy send buffer: SRTT_LIVE drops a packet that would arrive
        // late rather than blocking, so a full buffer would silently lose
        // bytes the tests assert on.
        opt_i(SRTO_SNDBUF, sndbuf);
        if (!streamid.empty())
        {
            srt_setsockopt(sock_, 0, SRTO_STREAMID, streamid.data(), static_cast<int>(streamid.size()));
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        sa.sin_port = htons(port);
        if (srt_connect(sock_, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) == SRT_ERROR)
        {
            *error = std::string{"srt_connect: "} + srt_getlasterror_str();
            Close();
            return false;
        }
        return true;
    }

    bool Send(const void* data, std::size_t len) const
    {
        return srt_sendmsg(sock_, static_cast<const char*>(data), static_cast<int>(len), -1, -1) ==
               static_cast<int>(len);
    }

    [[nodiscard]] bool Connected() const
    {
        return sock_ != SRT_INVALID_SOCK && srt_getsockstate(sock_) == SRTS_CONNECTED;
    }

    void Close()
    {
        if (sock_ != SRT_INVALID_SOCK)
        {
            srt_close(sock_);
            sock_ = SRT_INVALID_SOCK;
        }
    }

private:
    SRTSOCKET sock_ = SRT_INVALID_SOCK;
};

// ---------------------------------------------------------------------------
// The fake sink: an injected gateway stand-in that records what the ingest
// publishes, so the chunking can be asserted with no viewer in the way. The
// callbacks run on whichever loop the ingest posts to.
// ---------------------------------------------------------------------------

struct FakeSink
{
    mutable std::mutex        mutex;
    std::vector<std::uint8_t> bytes;
    std::vector<std::size_t>  chunk_sizes;
    std::set<std::string>     held;
    int                       claims   = 0;
    int                       releases = 0;

    [[nodiscard]] std::size_t Total() const
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return bytes.size();
    }
};

websrt::gateway::SrtIngest::Sink MakeFakeSink(const std::shared_ptr<FakeSink>& state)
{
    websrt::gateway::SrtIngest::Sink sink;
    sink.publish_gate = [](const std::string&) { return true; };
    sink.claim        = [state](const std::string& stream)
    {
        const std::lock_guard<std::mutex> lock(state->mutex);
        if (!state->held.insert(stream).second)
        {
            return false;
        }
        ++state->claims;
        return true;
    };
    sink.publish = [state](const std::string&, const void* data, std::size_t len)
    {
        const auto*                       bytes = static_cast<const std::uint8_t*>(data);
        const std::lock_guard<std::mutex> lock(state->mutex);
        state->bytes.insert(state->bytes.end(), bytes, bytes + len);
        state->chunk_sizes.push_back(len);
    };
    sink.release = [state](const std::string& stream)
    {
        const std::lock_guard<std::mutex> lock(state->mutex);
        state->held.erase(stream);
        ++state->releases;
    };
    return sink;
}

std::vector<std::uint8_t> LoadPayload()
{
    std::ifstream in(FixturePath(), std::ios::in | std::ios::binary);
    if (in.is_open())
    {
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!bytes.empty())
        {
            std::fprintf(stderr, "srt_ingest_test: payload: %zu bytes from %s\n", bytes.size(), FixturePath().c_str());
            return bytes;
        }
    }
    // 58 x 1128: 188-aligned AND payload-sized. The TsChunker framing
    // (srt_ingest.h FRAMING note) carries a sub-188 remainder until
    // end-of-stream, so a fallback with a sub-188 tail (64 KiB leaves
    // 112 bytes) can never arrive mid-stream.
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
                 "srt_ingest_test: payload: %s absent, using %zu deterministic pattern bytes\n",
                 FixturePath().c_str(),
                 bytes.size());
    return bytes;
}

} // namespace

int main()
{
    const auto                          t_total0 = std::chrono::steady_clock::now();
    const std::vector<std::uint8_t>     payload  = LoadPayload();
    const websrt::gateway::CertProvider cert;

    const std::uint16_t wt_port     = ChoosePort(4436);
    const std::uint16_t ingest_port = ChoosePort(9100);
    const std::uint16_t fake_port   = ChoosePort(9101);
    const std::uint16_t cap_port    = ChoosePort(9102);

    const std::string config_text = std::string{"[server]\n"} + "wt_port = " + std::to_string(wt_port) + "\n" +
                                    "max_viewers = 4\n"
                                    "broadcast_capacity = 4096\n"
                                    "srt_ingest_port = " +
                                    std::to_string(ingest_port) +
                                    "\n"
                                    "srt_ingest_bind = \"127.0.0.1\"\n"
                                    "\n"
                                    "[[stream]]\n"
                                    "name = \"g6-happy\"\n"
                                    "\n"
                                    "[[stream]]\n"
                                    "name = \"g6-firstwins\"\n";

    websrt::gateway::Config config;
    try
    {
        config = websrt::gateway::ParseConfig(config_text, "srt_ingest_test");
    }
    catch (const websrt::gateway::ConfigError& e)
    {
        std::fprintf(stderr, "srt_ingest_test: config error: %s\n", e.what());
        return 1;
    }

    const auto policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                               websrt::gateway::BuildAllowlistPolicy(config));
    Gateway    gateway(cert,
                    policy,
                    GatewayConfig{.max_viewers        = config.server.max_viewers,
                                     .broadcast_capacity = config.server.broadcast_capacity});
    if (!Check(gateway.Start("127.0.0.1", wt_port), "gateway binds its WebTransport port"))
    {
        return 1;
    }
    const std::string hash = cert.Sha256Hex();

    // The real ingest, wired exactly as src/main.cpp wires it - including
    // the P4.3 webhook sink, whose events this test records (the recorder
    // is the "dispatcher" here: enqueue-only, on the ingest thread).
    websrt::gateway::SrtIngestConfig ingest_config;
    ingest_config.bind       = "127.0.0.1";
    ingest_config.port       = ingest_port;
    ingest_config.latency_ms = config.server.latency_ms;

    std::mutex                                 wh_mutex;
    std::vector<websrt::gateway::WebhookEvent> wh_events;

    websrt::gateway::SrtIngest::Sink sink;
    sink.publish_gate = [&policy](const std::string& name) { return PublishAllowed(*policy, name); };
    sink.claim        = [&gateway](const std::string& name) { return gateway.ClaimIngestPublish(name); };
    sink.publish      = [&gateway](const std::string& name, const void* data, std::size_t len)
    { gateway.PublishMedia(name, data, len); };
    sink.release = [&gateway](const std::string& name) { gateway.ReleaseIngestPublish(name); };
    sink.webhook = [&wh_mutex, &wh_events](const websrt::gateway::WebhookEvent& event)
    {
        const std::lock_guard<std::mutex> lock(wh_mutex);
        wh_events.push_back(event);
    };

    websrt::gateway::SrtIngest ingest(std::move(ingest_config), std::move(sink), gateway.Loop());
    std::string                ingest_error;
    if (!Check(ingest.Start(&ingest_error), "ingest binds its SRT/UDP port"))
    {
        std::fprintf(stderr, "srt_ingest_test: %s\n", ingest_error.c_str());
        return 1;
    }
    std::fprintf(stderr,
                 "srt_ingest_test: gateway wt=%u ingest=%u fake=%u cap=%u, allowlist mode, %zu stream(s)\n",
                 wt_port,
                 ingest_port,
                 fake_port,
                 cap_port,
                 config.streams.size());

    websrt::SubscriberConfig sub_cfg;
    sub_cfg.host             = "127.0.0.1";
    sub_cfg.port             = wt_port;
    sub_cfg.cert_sha256_hex  = hash;
    sub_cfg.tsbpd_latency_ms = 120;

    // ---- 1. PUBLISH -> VIEWER, byte-for-byte ----
    {
        sub_cfg.stream_name = "g6-happy";
        websrt::Subscriber sub;
        Check(sub.Start(sub_cfg) == websrt::kStartOk, "1: subscriber attaches before the publisher");

        SrtCaller   pub;
        std::string err;
        Check(pub.Connect(ingest_port, "g6-happy", &err), "1: stock-libsrt publisher connects with streamid=g6-happy");
        std::fprintf(stderr, "srt_ingest_test: 1: srt_connect -> %s\n", err.empty() ? "ok" : err.c_str());

        // The fixture in 1128-byte SRT messages - what a real publisher
        // (OBS/ffmpeg muxing one packet cluster) sends.
        std::size_t off   = 0;
        std::size_t sent  = 0;
        bool        wrote = true;
        while (off < payload.size())
        {
            const std::size_t n = std::min<std::size_t>(kMaxPayload, payload.size() - off);
            if (!pub.Send(payload.data() + off, n))
            {
                wrote = false;
                break;
            }
            off += n;
            ++sent;
        }
        Check(wrote, "1: every sendmsg was accepted");
        std::fprintf(stderr, "srt_ingest_test: 1: sent %zu message(s), %zu byte(s)\n", sent, off);

        std::vector<std::uint8_t> got;
        got.reserve(payload.size());
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        while (got.size() < payload.size() && std::chrono::steady_clock::now() < deadline)
        {
            char      buf[kMaxPayload];
            const int n = sub.Read(buf, sizeof buf, 300);
            if (n > 0)
            {
                got.insert(got.end(), buf, buf + n);
            }
            else if (n == websrt::kReadEnd || n == websrt::kReadClosed)
            {
                break;
            }
        }
        Check(got.size() == payload.size(), "1: the viewer received every byte");
        const bool identical = got.size() == payload.size() && std::memcmp(got.data(), payload.data(), got.size()) == 0;
        Check(identical, "1: bytes byte-for-byte in order");
        std::fprintf(stderr,
                     "srt_ingest_test: 1: got %zu/%zu bytes, identical=%d\n",
                     got.size(),
                     payload.size(),
                     identical ? 1 : 0);

        const websrt::gateway::SrtIngestStats st = ingest.Stats();
        std::fprintf(stderr,
                     "srt_ingest_test: 1: ingest accepted=%llu rejected=%llu msg_in=%llu bytes_in=%llu "
                     "chunks_out=%llu bytes_out=%llu\n",
                     static_cast<unsigned long long>(st.publishers_accepted),
                     static_cast<unsigned long long>(st.publishers_rejected),
                     static_cast<unsigned long long>(st.messages_in),
                     static_cast<unsigned long long>(st.bytes_in),
                     static_cast<unsigned long long>(st.chunks_out),
                     static_cast<unsigned long long>(st.bytes_out));
        Check(st.bytes_out == payload.size(), "1: the ingest forwarded every byte");
        Check(st.publishers_accepted == 1, "1: exactly one publisher was accepted");
        Check(StreamNamed(gateway.SnapshotStreams(), "g6-happy").publisher_live, "1: the stream is live");
    }

    // P4.3 webhook hooks (the recorder wired into the sink above): part
    // 1's publisher connected and hung up; both facts must carry the
    // connection's identity. (The stream-level publisher_end is the
    // gateway's event - webhook_test part B covers that hook.)
    {
        const auto has_event = [&wh_mutex, &wh_events](const char* event, const char* stream)
        {
            const std::lock_guard<std::mutex> lock(wh_mutex);
            for (const websrt::gateway::WebhookEvent& ev : wh_events)
            {
                if (ev.event == event && ev.stream == stream)
                {
                    return true;
                }
            }
            return false;
        };
        Check(WaitUntil([&] { return has_event("publisher_connect", "g6-happy"); }, 8000),
              "wh: publisher_connect fired for the ingest publisher");
        Check(WaitUntil([&] { return has_event("publisher_disconnect", "g6-happy"); }, 8000),
              "wh: publisher_disconnect fired when it hung up");
        const std::lock_guard<std::mutex> lock(wh_mutex);
        for (const websrt::gateway::WebhookEvent& ev : wh_events)
        {
            if (ev.stream == "g6-happy")
            {
                Check(ev.role == "publisher", "wh: ingest events carry the publisher role");
                Check(ev.remote.rfind("127.0.0.1:", 0) == 0, "wh: ingest events carry the peer ip:port");
                Check(ev.session_id > 0, "wh: ingest events carry a session id");
            }
        }
    }

    // ---- 2. empty streamid rejected ----
    {
        const websrt::gateway::SrtIngestStats before = ingest.Stats();
        SrtCaller                             anon;
        std::string                           err;
        const bool                            connected = anon.Connect(ingest_port, "", &err);
        // Whether the refusal lands during the handshake or immediately
        // after it, the caller must never end up with a usable publisher.
        bool dead = !connected;
        if (connected)
        {
            dead = WaitUntil([&anon] { return !anon.Connected(); }, 8000);
        }
        Check(dead, "2: a publisher with no streamid gets no usable connection");
        anon.Close();
        Check(WaitUntil([&ingest, before] { return ingest.Stats().rejected_no_streamid > before.rejected_no_streamid; },
                        5000),
              "2: the ingest counted a no-streamid rejection");
        const websrt::gateway::SrtIngestStats st = ingest.Stats();
        Check(st.bytes_in == before.bytes_in, "2: not a single byte came through the anonymous publisher");
        std::fprintf(stderr,
                     "srt_ingest_test: 2: connect=%s rejected_no_streamid=%llu bytes_in=%llu\n",
                     connected ? "ok-then-closed" : err.c_str(),
                     static_cast<unsigned long long>(st.rejected_no_streamid),
                     static_cast<unsigned long long>(st.bytes_in));
    }

    // ---- 3. first-wins occupancy ----
    {
        SrtCaller   first;
        std::string err;
        Check(first.Connect(ingest_port, "g6-firstwins", &err), "3: the first publisher wins the name");
        Check(WaitUntil([&ingest] { return ingest.Stats().connections.size() == 1; }, 5000),
              "3: the ingest holds the first publisher");

        SrtCaller   second;
        std::string err2;
        second.Connect(ingest_port, "g6-firstwins", &err2);
        bool refused = !second.Connected();
        if (second.Connected())
        {
            refused = WaitUntil([&second] { return !second.Connected(); }, 8000);
        }
        Check(refused, "3: the challenger is refused");
        second.Close();
        Check(WaitUntil([&ingest] { return ingest.Stats().rejected_occupied >= 1; }, 5000),
              "3: the ingest counted an occupancy rejection");
        Check(WaitUntil([&ingest] { return ingest.Stats().connections.size() == 1; }, 3000),
              "3: the refused challenger left no connection behind");

        first.Close();
        Check(WaitUntil([&gateway] { return !StreamNamed(gateway.SnapshotStreams(), "g6-firstwins").publisher_live; },
                        8000),
              "3: the name is released when the publisher disconnects");

        SrtCaller   third;
        std::string err3;
        Check(third.Connect(ingest_port, "g6-firstwins", &err3), "3: a later publisher reclaims the name");
        Check(WaitUntil([&ingest] { return ingest.Stats().connections.size() == 1; }, 5000),
              "3: the reclaiming publisher is the live connection");
        std::fprintf(stderr,
                     "srt_ingest_test: 3: rejected_occupied=%llu accepted=%llu\n",
                     static_cast<unsigned long long>(ingest.Stats().rejected_occupied),
                     static_cast<unsigned long long>(ingest.Stats().publishers_accepted));
        third.Close();
        Check(WaitUntil([&ingest] { return ingest.Stats().connections.empty(); }, 8000),
              "3: the reclaiming publisher is torn down cleanly");
    }

    // ---- 4. allowlist: an unconfigured streamid is refused at accept ----
    {
        const websrt::gateway::SrtIngestStats before = ingest.Stats();
        SrtCaller                             denied;
        std::string                           err;
        denied.Connect(ingest_port, "g6-denied", &err);
        bool refused = !denied.Connected();
        if (denied.Connected())
        {
            refused = WaitUntil([&denied] { return !denied.Connected(); }, 8000);
        }
        Check(refused, "4: an unconfigured streamid is refused");
        denied.Close();
        Check(WaitUntil([&ingest, before] { return ingest.Stats().rejected_not_allowed > before.rejected_not_allowed; },
                        5000),
              "4: the ingest counted an allowlist rejection");
        std::fprintf(stderr,
                     "srt_ingest_test: 4: rejected_not_allowed=%llu\n",
                     static_cast<unsigned long long>(ingest.Stats().rejected_not_allowed));
    }

    ingest.Stop();
    Check(gateway.ActiveSessionCount() == 0, "every session was reaped");

    // ---- 5. chunking: one 64 KB sendmsg -> <= 1128-byte 188-aligned messages ----
    {
        websrt::EventLoop fake_loop;
        fake_loop.Start();
        auto                             fake = std::make_shared<FakeSink>();
        websrt::gateway::SrtIngestConfig cfg;
        cfg.bind       = "127.0.0.1";
        cfg.port       = fake_port;
        cfg.latency_ms = 120;
        websrt::gateway::SrtIngest fake_ingest(cfg, MakeFakeSink(fake), fake_loop);
        std::string                fake_error;
        if (!Check(fake_ingest.Start(&fake_error), "5: the fake-sink ingest binds"))
        {
            std::fprintf(stderr, "srt_ingest_test: %s\n", fake_error.c_str());
            return 1;
        }

        constexpr std::size_t kBigBytes = std::size_t{64} * 1024;
        // A live-mode SRT connection CANNOT carry a 64 KB message: its
        // congestion control refuses anything above the negotiated payload
        // ("LiveCC: payload size: 65536 exceeds maximum allowed 1316").
        // 1316 B - the live default, and what OBS/ffmpeg actually send - is
        // already oversized for the 1128 B WebSRT ceiling, so the burst is
        // what the ingest has to re-frame.
        constexpr std::size_t     kLiveMsg = 1316;
        std::vector<std::uint8_t> big(kBigBytes);
        for (std::size_t i = 0; i < kBigBytes; ++i)
        {
            big[i] = static_cast<std::uint8_t>((i * 7) + 3);
        }

        SrtCaller   pub;
        std::string err;
        Check(pub.Connect(fake_port, "g6-chunk", &err), "5: the publisher connects to the fake-sink ingest");
        bool wrote = true;
        for (std::size_t off = 0; off < kBigBytes; off += kLiveMsg)
        {
            if (!pub.Send(big.data() + off, std::min(kLiveMsg, kBigBytes - off)))
            {
                wrote = false;
                break;
            }
        }
        Check(wrote, "5: the oversized burst was accepted");
        // Live mode drops what is still queued when the socket closes
        // (Linger is off), so wait for the burst to land BEFORE hanging up -
        // the close is only there to make the ingest flush the sub-188 tail.
        Check(WaitUntil([&fake_ingest] { return fake_ingest.Stats().bytes_in >= kBigBytes; }, 15000),
              "5: the ingest received the whole burst");
        pub.Close();
        Check(WaitUntil([&fake] { return fake->Total() >= kBigBytes; }, 15000), "5: every byte came through");
        std::this_thread::sleep_for(std::chrono::milliseconds{300}); // let the tail flush land

        std::vector<std::size_t> sizes;
        {
            const std::lock_guard<std::mutex> lock(fake->mutex);
            sizes = fake->chunk_sizes;
        }
        std::size_t total   = 0;
        std::size_t biggest = 0;
        for (const std::size_t n : sizes)
        {
            total += n;
            biggest = std::max(biggest, n);
        }
        // Every chunk but the last is a whole number of 188-byte TS packets
        // and at most the 1128-byte payload; the last is whatever sub-188
        // tail the ingest flushed on disconnect.
        bool aligned = !sizes.empty();
        bool full    = false;
        for (std::size_t i = 0; i < sizes.size(); ++i)
        {
            if (i + 1 == sizes.size())
            {
                aligned = sizes[i] < kTsPacket;
                continue;
            }
            if (sizes[i] % kTsPacket != 0)
            {
                aligned = false;
            }
            if (sizes[i] == kMaxPayload)
            {
                full = true;
            }
        }
        const std::size_t tail = sizes.empty() ? 0 : sizes.back();
        Check(total == kBigBytes, "5: the total is byte-exact");
        Check(biggest <= kMaxPayload, "5: no chunk exceeds the 1128-byte payload ceiling");
        Check(full, "5: chunks are cut at the payload ceiling, not merely under it");
        Check(aligned, "5: every chunk but the flushed tail is 188-aligned");
        Check(tail < kTsPacket, "5: the only short chunk is the flushed sub-188 tail");
        std::fprintf(stderr,
                     "srt_ingest_test: 5: %zu chunk(s), total %zu/%zu bytes, biggest=%zu, tail=%zu\n",
                     sizes.size(),
                     total,
                     kBigBytes,
                     biggest,
                     tail);

        fake_ingest.Stop();
        const std::lock_guard<std::mutex> lock(fake->mutex);
        Check(fake->claims == 1, "5: the fake sink claimed the publisher exactly once");
        Check(fake->releases == 1, "5: the fake sink released the publisher exactly once");
        fake_loop.Stop();
    }

    // ---- 6. session cap: the third concurrent publisher is refused ----
    {
        websrt::EventLoop cap_loop;
        cap_loop.Start();
        auto                             fake = std::make_shared<FakeSink>();
        websrt::gateway::SrtIngestConfig cfg;
        cfg.bind         = "127.0.0.1";
        cfg.port         = cap_port;
        cfg.latency_ms   = 120;
        cfg.max_sessions = 2;
        websrt::gateway::SrtIngest cap_ingest(cfg, MakeFakeSink(fake), cap_loop);
        std::string                cap_error;
        if (!Check(cap_ingest.Start(&cap_error), "6: the capped ingest binds"))
        {
            std::fprintf(stderr, "srt_ingest_test: %s\n", cap_error.c_str());
            return 1;
        }

        SrtCaller   a;
        std::string err;
        Check(a.Connect(cap_port, "cap-a", &err), "6: publisher one connects");
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().connections.size() == 1; }, 5000),
              "6: the capped ingest holds publisher one");
        SrtCaller b;
        Check(b.Connect(cap_port, "cap-b", &err), "6: publisher two connects");
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().connections.size() == 2; }, 5000),
              "6: the capped ingest holds publisher two");

        SrtCaller over;
        over.Connect(cap_port, "cap-over", &err);
        // The refusal must land whether the caller sees it in the handshake
        // or as an immediate close after it - and it must claim nothing.
        bool refused = !over.Connected();
        if (over.Connected())
        {
            refused = WaitUntil([&over] { return !over.Connected(); }, 8000);
        }
        Check(refused, "6: the third concurrent publisher is refused at the cap");
        over.Close();
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().rejected_session_cap >= 1; }, 5000),
              "6: the ingest counted a session-cap rejection");
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().connections.size() == 2; }, 3000),
              "6: the refused publisher left no connection behind");
        {
            const std::lock_guard<std::mutex> lock(fake->mutex);
            Check(fake->held.count("cap-over") == 0, "6: the refused publisher never claimed a stream slot");
        }

        a.Close();
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().connections.size() == 1; }, 8000),
              "6: hanging up frees the slot");
        SrtCaller   c;
        std::string err_c;
        Check(c.Connect(cap_port, "cap-c", &err_c), "6: a later publisher takes the freed slot");
        Check(WaitUntil([&cap_ingest] { return cap_ingest.Stats().connections.size() == 2; }, 5000),
              "6: the freed slot is live again");
        std::fprintf(stderr,
                     "srt_ingest_test: 6: rejected_session_cap=%llu accepted=%llu\n",
                     static_cast<unsigned long long>(cap_ingest.Stats().rejected_session_cap),
                     static_cast<unsigned long long>(cap_ingest.Stats().publishers_accepted));

        cap_ingest.Stop();
        cap_loop.Stop();
    }

    gateway.Shutdown();

    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_total0);
    if (!g_ok)
    {
        std::fprintf(stderr, "srt_ingest_test: FAILURES\n");
        return 1;
    }
    std::printf("srt_ingest_test: OK (%lld ms)\n", static_cast<long long>(elapsed_ms.count()));
    return 0;
}