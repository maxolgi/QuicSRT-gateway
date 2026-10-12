// G4 loopback: the per-session SRT initiator + session registry ticker,
// end-to-end over WT loopback against libwebsrt's own Subscriber (viewer
// direction) and Publisher (publisher direction) - full C++ on both sides,
// no Rust gateway. Gate criteria:
//   1. Viewer: session accepted -> initiator connects (caller,
//      skip-induction) -> Subscriber Start returns connected; N x 1128
//      deterministic messages fed through EnqueueForViewer are paced out
//      by the ~2 ms ticker and arrive byte-for-byte in order.
//   2. Credit behavior: a burst larger than the 256-msg/tick budget
//      completes in >= ceil(N/256) ticks (the budget actually paces) and
//      within ceil(N/256) + epsilon ticks (the ticker stays live); the
//      loop never blocks (total wall time sane).
//   3. Publisher: Publisher Start, K x 1128 deterministic Writes; the
//      ticker pumps ReceiveNext into the registry sink; collected bytes
//      byte-for-byte in order.
//   4. RTT seed: srt_bstats msRTT at the first connected observation
//      reflects the QUIC-RTT seed (well under srt's unseeded 100 ms
//      default), before any data flows.
//   5. drop_backlog: the first connected tick raises the marker
//      (PopBacklogDrop true exactly once).
//   6. Teardown: session close leaves no leaked srt sockets (fd-count
//      accounting, the M0 pattern) and the loop keeps running - a second
//      session after the first closed works.
//
// Client side: the public websrt::Subscriber and websrt::Publisher each
// own their EventLoop internally (G3: one engine per loop), so the two
// client engines run on two separate loops. Ports: 127.0.0.1:4435 with
// an ephemeral fallback; 4433/9000 (the Rust gateway) are never touched.

#include "gateway/cert.h"
#include "gateway/policy.h"
#include "gateway/session_registry.h"
#include "gateway/wt_server.h"

#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "websrt/publisher.hpp"
#include "websrt/subscriber.hpp"

namespace
{

using websrt::gateway::WtSessionHandle;

constexpr int         kPayloadSize = 1128; // WebSRT constant: 6 x 188-byte TS packets
constexpr int         kViewerMsgs  = 1000; // > 4 x the 256/tick credit budget
constexpr int         kPubMsgs     = 2000;
constexpr std::size_t kViewerBytes = std::size_t{kViewerMsgs} * kPayloadSize;
constexpr std::size_t kPubBytes    = std::size_t{kPubMsgs} * kPayloadSize;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "srt_initiator_test: FAIL: %s\n", what);
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

// Deterministic content: a xorshift32 stream seeded from the message
// index, regenerated identically on both sides (the M0 harness pattern).
void FillMessage(int index, std::uint8_t* bytes)
{
    std::uint32_t state = 0x9E3779B9U ^ (static_cast<std::uint32_t>(index) * 2654435761U);
    for (int i = 0; i < kPayloadSize; ++i)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bytes[i] = static_cast<std::uint8_t>(state >> 24);
    }
}

int CountSocketFds()
{
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr)
    {
        return -1;
    }
    int            count = 0;
    struct dirent* entry;
    char           link[64];
    while ((entry = readdir(dir)) != nullptr)
    {
        if (entry->d_name[0] == '.')
        {
            continue;
        }
        const std::string path  = std::string("/proc/self/fd/") + entry->d_name;
        const ssize_t     nread = readlink(path.c_str(), link, sizeof link - 1);
        if (nread <= 0)
        {
            continue;
        }
        link[nread] = 0;
        if (strncmp(link, "socket:", 7) == 0)
        {
            ++count;
        }
    }
    closedir(dir);
    return count;
}

/// Registry listener: records starts/ends and collects publisher media
/// (the G5 ring stand-in). Callbacks fire on the server loop thread.
class RigListener final : public websrt::gateway::SessionRegistryListener
{
public:
    void OnMedia(const std::string& stream_name, const std::uint8_t* data, std::size_t len) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        media_[stream_name].insert(media_[stream_name].end(), data, data + len);
    }

    void OnSessionStart(WtSessionHandle handle, const websrt::gateway::WtSessionStart& start) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        last_handle_     = handle;
        last_start_      = start;
        session_started_ = true;
    }

    void OnSessionEnded(WtSessionHandle /*handle*/, const std::string& reason) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        ++ended_count_;
        last_end_reason_ = reason;
    }

    [[nodiscard]] std::vector<std::uint8_t> MediaFor(const std::string& name) const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        const auto                        it = media_.find(name);
        return it == media_.end() ? std::vector<std::uint8_t>{} : it->second;
    }

    [[nodiscard]] WtSessionHandle LastHandle() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_handle_;
    }

    [[nodiscard]] bool WaitForStart(int timeout_ms) const
    {
        return WaitUntil([this] { return session_started_.load(); }, timeout_ms);
    }

    [[nodiscard]] int EndedCount() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return ended_count_;
    }

    [[nodiscard]] std::string LastEndReason() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_end_reason_;
    }

    void ResetSessionMarkers() { session_started_ = false; }

private:
    mutable std::mutex                               mutex_;
    std::map<std::string, std::vector<std::uint8_t>> media_;
    WtSessionHandle                                  last_handle_;
    websrt::gateway::WtSessionStart                  last_start_;
    std::string                                      last_end_reason_;
    int                                              ended_count_ = 0;
    std::atomic<bool>                                session_started_{false};
};

// 127.0.0.1:4435 when free, else an ephemeral port (probe-bind :0, close,
// hand the port over; the tiny TOCTOU window is acceptable for a test).
std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port              = htons(4435);
        const bool port4435_free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (port4435_free)
        {
            return 4435;
        }
    }
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_port = 0;
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "srt_initiator_test: cannot probe any port\n");
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
    using namespace websrt::gateway;
    using websrt::gateway::SessionInfo;

    const auto         t_total0 = std::chrono::steady_clock::now();
    const CertProvider cert;

    websrt::EventLoop server_loop;
    server_loop.Start();

    RigListener     rig_listener;
    SessionRegistry registry(server_loop, rig_listener);
    const auto      policy = std::make_shared<const AcceptAll>();
    WtServer        server(server_loop, cert, policy, registry);
    registry.AttachServer(server);
    const std::uint16_t port = ChoosePort();
    if (!Check(server.Bind("127.0.0.1", port), "server binds 127.0.0.1 (4435 or ephemeral fallback)"))
    {
        server_loop.Stop();
        return 1;
    }
    registry.Start();
    if (std::getenv("G4_SRT_DEBUG") != nullptr)
    {
        srt_setloglevel(4); // debug: handshake/shutdown tracing on both ends
    }
    std::fprintf(stderr, "srt_initiator_test: server on 127.0.0.1:%u (hash %s)\n", port, cert.Sha256Hex().c_str());

    // ---- 1+2+4+5. Viewer direction, RTT seed, drop_backlog, credit -----
    WtSessionHandle viewer_handle;
    {
        websrt::SubscriberConfig cfg;
        cfg.host             = "127.0.0.1";
        cfg.port             = port;
        cfg.stream_name      = "g4view";
        cfg.cert_sha256_hex  = cert.Sha256Hex();
        cfg.tsbpd_latency_ms = 120;

        websrt::Subscriber sub;
        const auto         connect_t0 = std::chrono::steady_clock::now();
        Check(sub.Start(cfg) == websrt::kStartOk, "viewer: Subscriber Start returns connected (initiator handshake)");
        const double connect_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - connect_t0).count();
        Check(rig_listener.WaitForStart(2000), "viewer: OnSessionStart fired");
        viewer_handle = rig_listener.LastHandle();
        Check(viewer_handle.IsValid(), "viewer: handle valid");
        Check(registry.ActiveSessionCount() == 1, "viewer: one live session");
        Check(WaitUntil([&registry, viewer_handle] { return registry.IsConnected(viewer_handle); }, 2000),
              "viewer: registry observed the SRT connection");

        // (5) drop_backlog raised on the first connected tick, once.
        Check(WaitUntil([&registry, viewer_handle] { return registry.PopBacklogDrop(viewer_handle); }, 2000),
              "drop_backlog: marker set on the first connected tick");
        Check(!registry.PopBacklogDrop(viewer_handle), "drop_backlog: marker consumes exactly once");

        // (4) RTT seed, before any data: the QUIC srtt seed clamps to
        // >= 1 ms; srt's unseeded default initial RTT is 100 ms.
        SRT_TRACEBSTATS stats;
        Check(registry.Stats(viewer_handle, &stats), "rtt seed: stats readable while connected");
        Check(stats.msRTT > 0.0 && stats.msRTT <= 50.0,
              "rtt seed: msRTT reflects the QUIC seed, not the 100 ms default");
        std::fprintf(stderr, "srt_initiator_test: rtt seed msRTT=%.1f (connect %.1f ms)\n", stats.msRTT, connect_ms);

        // (1+2) Feed N messages; the ticker paces them out at <= 256/tick.
        std::uint8_t        msg[kPayloadSize];
        const std::uint64_t ticks_before = registry.TickCount();
        const auto          send_t0      = std::chrono::steady_clock::now();
        for (int i = 0; i < kViewerMsgs; ++i)
        {
            FillMessage(i, msg);
            Check(registry.EnqueueForViewer(viewer_handle, msg, kPayloadSize), "viewer: enqueued");
        }
        // All N leave through the credit budget: at least ceil(N/256)
        // ticks, and not much more (writability + WT queue hiccups).
        constexpr std::uint64_t kMinTicks = (kViewerMsgs + 255) / 256;
        Check(WaitUntil(
                  [&registry, viewer_handle]
                  {
                      SessionInfo info;
                      return registry.SessionInfoFor(viewer_handle, &info) && info.messages_sent == kViewerMsgs;
                  },
                  10000),
              "credit: all messages sent");
        const std::uint64_t ticks_used = registry.TickCount() - ticks_before;
        const double        send_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - send_t0).count();
        Check(ticks_used >= kMinTicks, "credit: budget paced the burst (>= ceil(N/256) ticks)");
        Check(ticks_used <= kMinTicks + 200, "credit: ticker stayed live (<= ceil(N/256) + 200 ticks)");

        // Collect on the subscriber: byte-for-byte, in order (TSBPD adds
        // ~120 ms; loss on the loopback WT path is NAK-recovered).
        std::vector<std::uint8_t> received;
        received.reserve(kViewerBytes);
        char       buf[kPayloadSize];
        const auto read_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        for (int i = 0; i < kViewerMsgs;)
        {
            const int n = sub.Read(buf, sizeof buf, 500);
            if (n > 0)
            {
                received.insert(received.end(), buf, buf + n);
                ++i;
                continue;
            }
            if (n == websrt::kReadEnd || n == websrt::kReadClosed)
            {
                Check(false, "viewer: session ended before all messages arrived");
                break;
            }
            if (std::chrono::steady_clock::now() >= read_deadline)
            {
                Check(false, "viewer: Read timed out before all messages arrived");
                break;
            }
        }
        Check(received.size() == kViewerBytes, "viewer: every message arrived");
        bool content_ok = received.size() == kViewerBytes;
        for (int i = 0; content_ok && i < kViewerMsgs; ++i)
        {
            FillMessage(i, msg);
            if (std::memcmp(received.data() + (static_cast<std::size_t>(i) * kPayloadSize), msg, kPayloadSize) != 0)
            {
                content_ok = false;
            }
        }
        Check(content_ok, "viewer: bytes byte-for-byte in order");
        std::fprintf(stderr,
                     "srt_initiator_test: viewer %d x %d bytes, %llu ticks (min %llu), send %.1f ms\n",
                     kViewerMsgs,
                     kPayloadSize,
                     static_cast<unsigned long long>(ticks_used),
                     static_cast<unsigned long long>(kMinTicks),
                     send_ms);

        // (6) Teardown: client closes -> OnSessionClosed -> initiator
        // reaped; the loop keeps running (ticks keep coming).
        const std::uint64_t ticks_at_close = registry.TickCount();
        sub.Stop();
        Check(WaitUntil([&registry] { return registry.ActiveSessionCount() == 0; }, 5000),
              "teardown: session reaped after the client closed");
        Check(WaitUntil([&rig_listener] { return rig_listener.EndedCount() == 1; }, 5000),
              "teardown: OnSessionEnded notified");
        Check(registry.TickCount() > ticks_at_close, "teardown: the loop kept ticking");
    }

    // ---- 3. Publisher direction ----------------------------------------
    WtSessionHandle publisher_handle;
    {
        websrt::PublisherConfig cfg;
        cfg.host            = "127.0.0.1";
        cfg.port            = port;
        cfg.stream_name     = "g4pub";
        cfg.cert_sha256_hex = cert.Sha256Hex();

        websrt::Publisher pub;
        Check(pub.Start(cfg) == websrt::kPublishOk, "publisher: Publisher Start returns connected");
        Check(rig_listener.WaitForStart(2000), "publisher: OnSessionStart fired");
        publisher_handle = rig_listener.LastHandle();
        Check(WaitUntil([&registry, publisher_handle] { return registry.IsConnected(publisher_handle); }, 2000),
              "publisher: registry observed the SRT connection");

        std::uint8_t msg[kPayloadSize];
        for (int i = 0; i < kPubMsgs; ++i)
        {
            FillMessage(i, msg);
            int off = 0;
            while (off < kPayloadSize)
            {
                const int n = pub.Write(msg + off, kPayloadSize - off, 2000);
                if (n <= 0)
                {
                    Check(false, "publisher: Write failed mid-stream");
                    break;
                }
                off += n;
            }
            if (!g_ok)
            {
                break;
            }
        }

        // The ticker pumps released messages into the sink (TSBPD ~120 ms
        // behind the writer).
        Check(
            WaitUntil(
                [&rig_listener]
                { return rig_listener.MediaFor("g4pub").size() >= static_cast<std::size_t>(kPubMsgs) * kPayloadSize; },
                10000),
            "publisher: sink collected every message");

        const std::vector<std::uint8_t> media = rig_listener.MediaFor("g4pub");
        Check(media.size() == kPubBytes, "publisher: exact byte count");
        bool pub_ok = media.size() == kPubBytes;
        for (int i = 0; pub_ok && i < kPubMsgs; ++i)
        {
            FillMessage(i, msg);
            if (std::memcmp(media.data() + (static_cast<std::size_t>(i) * kPayloadSize), msg, kPayloadSize) != 0)
            {
                pub_ok = false;
            }
        }
        Check(pub_ok, "publisher: bytes byte-for-byte in order");
        std::fprintf(stderr, "srt_initiator_test: publisher %d x %d bytes collected\n", kPubMsgs, kPayloadSize);

        // Graceful end: the SRT shutdown rides the open WT session; the
        // registry's receive path reaps the session and closes the WT.
        // The budget must exceed the send-buffer average decay: End waits
        // for pktSndBuf AND byteSndBuf == 0, and byteSndBuf (srt_bstats,
        // no clear) is a ~1 s time-constant moving average that trails
        // the fully-ACKed burst by ~7-8 s - an srt accounting artifact,
        // not unACKed data (retx/nak counters stay zero).
        const bool pub_end_ok = pub.End(15000);
        {
            websrt::PublisherStats st;
            if (pub.Stats(&st) == websrt::kStatsOk)
            {
                std::fprintf(stderr,
                             "srt_initiator_test: pub stats: buffered=%d bytes_buffered=%d sent=%lld retx=%lld "
                             "acks=%lld naks=%lld rtt=%.1f tsbpd=%d\n",
                             st.packets_buffered,
                             st.bytes_buffered,
                             static_cast<long long>(st.packets_sent),
                             static_cast<long long>(st.packets_retransmitted),
                             static_cast<long long>(st.acks_received),
                             static_cast<long long>(st.naks_received),
                             st.rtt_ms,
                             st.ms_tsbpd_delay);
            }
        }
        std::fprintf(
            stderr, "srt_initiator_test: pub.End=%d last_error='%s'\n", pub_end_ok ? 1 : 0, pub.LastError().c_str());
        Check(pub_end_ok, "publisher: End completed the graceful stream end");
        Check(WaitUntil([&registry] { return registry.ActiveSessionCount() == 0; }, 5000),
              "publisher: session reaped after the stream ended");
    }

    // ---- 6. fd accounting + a second session after the first closed ----
    {
        const int fds_clean = CountSocketFds();
        Check(fds_clean >= 0, "fds: countable");

        websrt::SubscriberConfig cfg;
        cfg.host            = "127.0.0.1";
        cfg.port            = port;
        cfg.stream_name     = "g4view2";
        cfg.cert_sha256_hex = cert.Sha256Hex();

        websrt::Subscriber sub2;
        Check(sub2.Start(cfg) == websrt::kStartOk, "second: Subscriber Start after the first session closed");
        Check(rig_listener.WaitForStart(2000), "second: OnSessionStart fired");
        const WtSessionHandle second_handle = rig_listener.LastHandle();
        Check(WaitUntil([&registry, second_handle] { return registry.PopBacklogDrop(second_handle); }, 2000),
              "second: drop_backlog marker set");

        // One message each way to prove the data plane, then close.
        std::uint8_t msg[kPayloadSize];
        FillMessage(4242, msg);
        Check(registry.EnqueueForViewer(second_handle, msg, kPayloadSize), "second: enqueued");
        char buf[kPayloadSize];
        Check(WaitUntil(
                  [&sub2, &buf, msg]
                  {
                      const int n = sub2.Read(buf, sizeof buf, 100);
                      return n == kPayloadSize && std::memcmp(buf, msg, kPayloadSize) == 0;
                  },
                  5000),
              "second: message delivered byte-exact");

        sub2.Stop();
        Check(WaitUntil([&registry] { return registry.ActiveSessionCount() == 0; }, 5000), "second: session reaped");
        Check(WaitUntil([&fds_clean] { return CountSocketFds() == fds_clean; }, 5000),
              "fds: no leaked sockets after both sessions (initiator sockets are virtual: zero OS fds)");
        std::fprintf(stderr, "srt_initiator_test: fds %d stable after teardown\n", fds_clean);
    }

    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_total0);
    std::fprintf(stderr,
                 "srt_initiator_test: max tick %llu us over %llu ticks\n",
                 static_cast<unsigned long long>(registry.TickMaxUs()),
                 static_cast<unsigned long long>(registry.TickCount()));

    server_loop.Stop(); // joins; WtServer + registry teardown follow in reverse order

    if (!g_ok)
    {
        std::fprintf(stderr, "srt_initiator_test: FAILURES\n");
        return 1;
    }
    std::printf("srt_initiator_test: OK (%lld ms)\n", static_cast<long long>(elapsed_ms.count()));
    return 0;
}
