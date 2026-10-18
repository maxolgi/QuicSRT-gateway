// P4.3 webhook tests (PLAN.md P4.3 Verify), two layers:
//
//   A. The dispatcher against a tiny local HTTP receiver (a plain socket
//      listener, no web server involved):
//        1. delivery + payload shape - the JSON body carries every field
//           (event, stream, role, remote, session_id, timestamp_ms) and
//           survives hostile bytes in string fields.
//        2. retry exactly once - a receiver that closes the first
//           connection without answering still gets the event delivered
//           on the second attempt.
//        3. bounded-queue drop counting - a receiver that never answers
//           pins the worker; 300 enqueues overflow the 256 bound and the
//           overflow is counted, while the enqueues themselves return
//           immediately (delivery NEVER blocks the notifier).
//        4. settings swap + off - the SIGHUP-reload semantics at the unit
//           level: events after a SetSettings swap go to the new URL;
//           an empty URL queues nothing and drops nothing.
//   B. A live gateway core over WT loopback (127.0.0.1:4438, ephemeral
//      fallback) with webhooks pointed at the receiver: the full session
//      lifecycle (viewer waiting-attach, publisher publish, clean end)
//      must deliver all five event kinds with correct fields, the media
//      path must stay byte-exact, and the loop must not feel it: the
//      enqueue of 200 extra events returns immediately and the ticker's
//      max tick is unchanged afterwards (the hooks live on the accept and
//      close paths, never on the tick).

#include "gateway/cert.h"
#include "gateway/gateway.h"
#include "gateway/webhooks.h"

#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <poll.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "quicsrt/publisher.hpp"
#include "quicsrt/subscriber.hpp"

namespace
{

using quicsrt::gateway::WebhookDispatcher;
using quicsrt::gateway::WebhookEvent;
using quicsrt::gateway::WebhookSettings;
using quicsrt::gateway::WebhookSnapshot;

constexpr int kMaxPayload = 1128; // WebSRT constant: 6 x 188-byte TS packets

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "webhook_test: FAIL: %s\n", what);
    }
    return cond;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms, int slice_ms = 10)
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

// ---------------------------------------------------------------------------
// The local receiver: one accept thread, one request per connection
// (Connection: close), three answering modes.
// ---------------------------------------------------------------------------

class Receiver
{
public:
    enum class Mode
    {
        kOk,    ///< answer 200 to everything
        kHang,  ///< read the request, never answer (pins the worker on its recv timeout)
        kFlaky, ///< close the FIRST connection without answering, 200 after that
    };

    explicit Receiver(Mode mode)
        : mode_(mode)
    {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        sa.sin_port   = htons(0);
        const int yes = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        if (::bind(listen_fd_, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0 ||
            ::listen(listen_fd_, 128) != 0)
        {
            std::fprintf(stderr, "webhook_test: receiver cannot bind\n");
            std::exit(1);
        }
        socklen_t len = sizeof sa;
        ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&sa), &len);
        port_   = ntohs(sa.sin_port);
        thread_ = std::thread([this] { Run(); });
    }

    ~Receiver() { Stop(); }

    Receiver(const Receiver&)            = delete;
    Receiver& operator=(const Receiver&) = delete;

    [[nodiscard]] std::uint16_t Port() const { return port_; }
    [[nodiscard]] std::string   Url() const { return "http://127.0.0.1:" + std::to_string(port_) + "/hook"; }

    [[nodiscard]] std::vector<std::string> Bodies() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return bodies_;
    }

    [[nodiscard]] std::size_t Connections() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return connections_;
    }

    /// Received bodies that carry `"event":"<name>"`.
    [[nodiscard]] std::vector<std::string> BodiesOf(const std::string& event) const
    {
        std::vector<std::string> out;
        for (const std::string& body : Bodies())
        {
            if (body.find("\"event\":\"" + event + "\"") != std::string::npos)
            {
                out.push_back(body);
            }
        }
        return out;
    }

    void Stop()
    {
        if (stopped_.exchange(true))
        {
            return;
        }
        if (thread_.joinable())
        {
            thread_.join();
        }
        for (const int fd : parked_)
        {
            ::close(fd);
        }
        parked_.clear();
        if (listen_fd_ >= 0)
        {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }

private:
    void Run()
    {
        while (!stopped_.load())
        {
            pollfd p{.fd = listen_fd_, .events = POLLIN, .revents = 0};
            if (::poll(&p, 1, 20) != 1)
            {
                continue;
            }
            const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (fd < 0)
            {
                continue;
            }
            HandleConn(fd);
        }
    }

    /// One request: headers + Content-Length body (bounded read).
    void HandleConn(int fd)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            ++connections_;
        }
        const timeval tv{.tv_sec = 2, .tv_usec = 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        std::string raw;
        char        buf[2048];
        for (;;)
        {
            const std::size_t header_end = raw.find("\r\n\r\n");
            if (header_end != std::string::npos)
            {
                const std::size_t content_length =
                    raw.find("Content-Length:") == std::string::npos
                        ? 0
                        : std::strtoull(raw.c_str() + raw.find("Content-Length:") + 15, nullptr, 10);
                if (raw.size() >= header_end + 4 + content_length)
                {
                    break; // the full body is in
                }
            }
            const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
            if (n <= 0)
            {
                break;
            }
            raw.append(buf, buf + n);
        }

        const std::size_t header_end = raw.find("\r\n\r\n");
        if (header_end != std::string::npos)
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            bodies_.push_back(raw.substr(header_end + 4));
        }

        bool keep = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            if (mode_ == Mode::kHang)
            {
                keep = true; // never answer
            }
            else if (mode_ == Mode::kFlaky && connections_ == 1)
            {
                keep = false; // drop the first caller on the floor
            }
        }
        if (keep)
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            parked_.push_back(fd);
            return;
        }
        if (mode_ != Mode::kFlaky || connections() > 1)
        {
            const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            ssize_t           off      = 0;
            while (off < static_cast<ssize_t>(response.size()))
            {
                const ssize_t n = ::send(fd, response.data() + off, response.size() - off, MSG_NOSIGNAL);
                if (n <= 0)
                {
                    break;
                }
                off += n;
            }
        }
        ::close(fd);
    }

    [[nodiscard]] std::size_t connections() const
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return connections_;
    }

    Mode                     mode_;
    int                      listen_fd_ = -1;
    std::uint16_t            port_      = 0;
    std::thread              thread_;
    std::atomic<bool>        stopped_{false};
    mutable std::mutex       mutex_;
    std::vector<std::string> bodies_;
    std::size_t              connections_ = 0; ///< mutex_-guarded
    std::vector<int>         parked_;          ///< kHang fds, closed by Stop
};

WebhookEvent MakeEvent(
    const char* event, const std::string& stream, const char* role, const std::string& remote, std::uint64_t session_id)
{
    return WebhookEvent{.event = event, .stream = stream, .role = role, .remote = remote, .session_id = session_id};
}

/// Numeric JSON field (the serializer emits no spaces).
std::uint64_t NumField(const std::string& body, const char* key)
{
    const std::string needle = std::string{"\""} + key + "\":";
    const auto        at     = body.find(needle);
    return at == std::string::npos ? 0 : std::strtoull(body.c_str() + at + needle.size(), nullptr, 10);
}

// ---------------------------------------------------------------------------
// A. dispatcher units
// ---------------------------------------------------------------------------

void TestDeliveryAndShape()
{
    Receiver              receiver(Receiver::Mode::kOk);
    const WebhookSettings settings{.url = receiver.Url(), .timeout = std::chrono::milliseconds{2000}};
    WebhookDispatcher     dispatcher(settings);

    // Hostile bytes in a string field: the body must escape them.
    dispatcher.Notify(MakeEvent("viewer_connect", "we\"ird\\name", "viewer", "127.0.0.1:1234", 7));
    Check(WaitUntil(
              [&]
              {
                  const WebhookSnapshot s = dispatcher.Snapshot();
                  return s.delivered == 1 && receiver.Bodies().size() == 1;
              },
              5000),
          "A.1: the event is delivered to the local receiver");
    const std::string body = receiver.Bodies().front();
    Check(body.find("\"event\":\"viewer_connect\"") != std::string::npos, "A.1: body names the event");
    Check(body.find("\"stream\":\"we\\\"ird\\\\name\"") != std::string::npos, "A.1: stream escaped JSON-correctly");
    Check(body.find("\"role\":\"viewer\"") != std::string::npos, "A.1: body names the role");
    Check(body.find("\"remote\":\"127.0.0.1:1234\"") != std::string::npos, "A.1: body carries remote ip:port");
    Check(NumField(body, "session_id") == 7, "A.1: body carries the session id");
    Check(NumField(body, "timestamp_ms") > 0, "A.1: Notify stamped a timestamp");
}

void TestRetryOnce()
{
    Receiver              receiver(Receiver::Mode::kFlaky);
    const WebhookSettings settings{.url = receiver.Url(), .timeout = std::chrono::milliseconds{2000}};
    WebhookDispatcher     dispatcher(settings);

    dispatcher.Notify(MakeEvent("viewer_disconnect", "flaky", "viewer", "127.0.0.1:99", 1));
    Check(WaitUntil(
              [&]
              {
                  const WebhookSnapshot s = dispatcher.Snapshot();
                  return s.delivered == 1 && receiver.Connections() == 2 && receiver.Bodies().size() == 2;
              },
              10000),
          "A.2: a failed first POST is retried exactly once and then delivered");
    Check(receiver.Bodies()[0] == receiver.Bodies()[1], "A.2: both attempts carry the same body");
    Check(dispatcher.Snapshot().failed == 0, "A.2: the successful retry is not a failure");
}

void TestDropCounting()
{
    Receiver              receiver(Receiver::Mode::kHang);
    const WebhookSettings settings{.url = receiver.Url(), .timeout = std::chrono::milliseconds{300}};
    WebhookDispatcher     dispatcher(settings);

    const auto t0 = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < 300; ++i)
    {
        dispatcher.Notify(MakeEvent("viewer_connect", "flood", "viewer", "127.0.0.1:1", i + 1));
    }
    const auto enqueue_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    // The worker holds one popped event and blocks on the hanging
    // receiver; the queue takes 256, so 43-44 of the 300 drop.
    const WebhookSnapshot s = dispatcher.Snapshot();
    Check(s.dropped >= 43 && s.dropped <= 44, "A.3: the bounded queue counts the overflow as drops");
    Check(s.delivered == 0, "A.3: nothing was delivered while the receiver hangs");
    Check(enqueue_ms < 500, "A.3: 300 enqueues against a stuck receiver return immediately");
}

void TestSettingsSwapAndOff()
{
    Receiver a(Receiver::Mode::kOk);
    Receiver b(Receiver::Mode::kOk);

    const WebhookSettings on_a{.url = a.Url(), .timeout = std::chrono::milliseconds{2000}};
    WebhookDispatcher     dispatcher(on_a);
    dispatcher.Notify(MakeEvent("publisher_connect", "swap", "publisher", "127.0.0.1:2", 1));
    Check(WaitUntil([&] { return dispatcher.Snapshot().delivered == 1; }, 5000), "A.4: first URL receives");

    // The reload swap: events after it go to the new URL only.
    dispatcher.SetSettings(WebhookSettings{.url = b.Url(), .timeout = std::chrono::milliseconds{2000}});
    dispatcher.Notify(MakeEvent("publisher_disconnect", "swap", "publisher", "127.0.0.1:2", 1));
    Check(WaitUntil(
              [&]
              {
                  const WebhookSnapshot s = dispatcher.Snapshot();
                  return s.delivered == 2 && b.Bodies().size() == 1 && a.Bodies().size() == 1;
              },
              5000),
          "A.4: after the swap only the new URL receives");

    // Off (the reload on<->off direction): queue nothing, drop nothing.
    dispatcher.SetSettings(WebhookSettings{});
    dispatcher.Notify(MakeEvent("viewer_connect", "swap", "viewer", "127.0.0.1:3", 2));
    std::this_thread::sleep_for(std::chrono::milliseconds{150});
    const WebhookSnapshot s = dispatcher.Snapshot();
    Check(s.delivered == 2 && s.dropped == 0 && !s.enabled, "A.4: an empty URL is off - no queue, no drops");
}

// ---------------------------------------------------------------------------
// B. the live gateway
// ---------------------------------------------------------------------------

std::uint16_t ChoosePort()
{
    int         fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd >= 0)
    {
        sa.sin_port              = htons(4438);
        const bool port4438_free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (port4438_free)
        {
            return 4438;
        }
    }
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    sa.sin_port = 0;
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "webhook_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

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

void TestGatewayLifecycle()
{
    const quicsrt::gateway::CertProvider cert;
    const std::uint16_t                  port = ChoosePort();
    Receiver                             receiver(Receiver::Mode::kOk);

    const auto policy = quicsrt::gateway::Chain(
        std::make_shared<quicsrt::gateway::PathPolicy>("/wt"),
        std::make_shared<quicsrt::gateway::StreamAllowlistPolicy>(std::vector<quicsrt::gateway::StreamAclEntry>{
            quicsrt::gateway::StreamAclEntry{.name_pattern = "wh-live", .token = std::nullopt}}));
    quicsrt::gateway::Gateway gateway(
        cert,
        policy,
        quicsrt::gateway::GatewayConfig{
            .max_viewers = 4,
            .webhooks    = WebhookSettings{.url = receiver.Url(), .timeout = std::chrono::milliseconds{2000}}});
    if (!Check(gateway.Start("127.0.0.1", port), "B: gateway binds 127.0.0.1:4438 (or the ephemeral fallback)"))
    {
        return;
    }
    const std::string hash = cert.Sha256Hex();
    std::fprintf(stderr, "webhook_test: gateway on 127.0.0.1:%u, receiver %s\n", port, receiver.Url().c_str());

    quicsrt::SubscriberConfig sub_cfg;
    sub_cfg.host             = "127.0.0.1";
    sub_cfg.port             = port;
    sub_cfg.stream_name      = "wh-live";
    sub_cfg.cert_sha256_hex  = hash;
    sub_cfg.tsbpd_latency_ms = 120;

    quicsrt::PublisherConfig pub_cfg;
    pub_cfg.host            = "127.0.0.1";
    pub_cfg.port            = port;
    pub_cfg.stream_name     = "wh-live";
    pub_cfg.cert_sha256_hex = hash;

    // Waiting viewer first, then the publisher: both connect events fire.
    quicsrt::Subscriber viewer;
    Check(viewer.Start(sub_cfg) == quicsrt::kStartOk, "B: viewer attaches (waiting)");
    quicsrt::Publisher pub;
    Check(pub.Start(pub_cfg) == quicsrt::kPublishOk, "B: publisher accepted");

    const std::vector<std::uint8_t> chunk = PatternBytes(std::size_t{16} * kMaxPayload, 0xC0FFEE);
    std::size_t                     off   = 0;
    bool                            wrote = true;
    while (off < chunk.size())
    {
        const int n = pub.Write(chunk.data() + off, chunk.size() - off, 5000);
        if (n <= 0)
        {
            wrote = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    Check(wrote, "B: published the chunk");

    std::vector<std::uint8_t> got;
    got.reserve(chunk.size());
    while (got.size() < chunk.size())
    {
        char      buf[kMaxPayload];
        const int n = viewer.Read(buf, sizeof buf, 500);
        if (n > 0)
        {
            got.insert(got.end(), buf, buf + n);
        }
    }
    Check(got.size() == chunk.size() && std::memcmp(got.data(), chunk.data(), got.size()) == 0,
          "B: the media path stays byte-exact with webhooks on");

    pub.End(15000);
    char      buf[kMaxPayload];
    const int end = viewer.Read(buf, sizeof buf, 5000);
    Check(end == quicsrt::kReadEnd || end == quicsrt::kReadClosed, "B: the viewer observes a clean EOF");

    // All five lifecycle events must land, with the right fields.
    const char* events[] = {
        "viewer_connect", "publisher_connect", "publisher_end", "viewer_disconnect", "publisher_disconnect"};
    Check(WaitUntil(
              [&]
              {
                  for (const char* event : events)
                  {
                      if (receiver.BodiesOf(event).empty())
                      {
                          return false;
                      }
                  }
                  return true;
              },
              30000),
          "B: all five lifecycle events were delivered");
    for (const char* event : events)
    {
        const std::string body = receiver.BodiesOf(event).front();
        Check(body.find("\"stream\":\"wh-live\"") != std::string::npos, "B: event bodies name the stream");
        const bool publisher_event = std::strncmp(event, "publisher", 9) == 0;
        Check(body.find(publisher_event ? "\"role\":\"publisher\"" : "\"role\":\"viewer\"") != std::string::npos,
              "B: event bodies name the role");
        if (std::strcmp(event, "publisher_end") == 0)
        {
            Check(NumField(body, "session_id") == 0 && body.find("\"remote\":\"\"") != std::string::npos,
                  "B: publisher_end is stream-level (no session identity)");
        }
        else
        {
            Check(body.find("\"remote\":\"127.0.0.1:") != std::string::npos, "B: event bodies carry the peer ip:port");
            Check(NumField(body, "session_id") > 0, "B: event bodies carry a session id");
        }
    }
    Check(receiver.Bodies().front().find("\"event\":\"viewer_connect\"") != std::string::npos,
          "B: the waiting viewer's connect arrived first");

    // The loop must not feel the webhooks: enqueueing 200 events more
    // returns immediately (delivery is the worker's problem), the ticker's
    // max tick is unchanged, and the events still drain.
    const std::uint64_t tick_max_before = gateway.TickMaxUs();
    const auto          t0              = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < 200; ++i)
    {
        gateway.NotifyWebhook(MakeEvent("viewer_connect", "churn", "viewer", "127.0.0.1:9", i + 1));
    }
    const auto churn_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    Check(churn_ms < 100, "B: 200 enqueues return immediately (never the event loop's problem)");
    Check(WaitUntil(
              [&]
              {
                  const WebhookSnapshot s = gateway.WebhookStats();
                  return s.delivered >= 205 && s.dropped == 0 && s.enabled;
              },
              20000),
          "B: the churn drained to the receiver (nothing dropped)");
    Check(WaitUntil([&gateway, tick_max_before] { return gateway.TickCount() > 0; }, 5000), "B: ticks advance");
    std::this_thread::sleep_for(std::chrono::milliseconds{200});
    Check(gateway.TickMaxUs() == tick_max_before, "B: the max tick is unchanged by webhook traffic");
    Check(gateway.TickAvgUs() < 5000, "B: the tick average stays under the 5 ms gate");

    gateway.Shutdown();
}

} // namespace

int main()
{
    TestDeliveryAndShape();
    TestRetryOnce();
    TestDropCounting();
    TestSettingsSwapAndOff();
    TestGatewayLifecycle();

    if (!g_ok)
    {
        std::fprintf(stderr, "webhook_test: FAILURES\n");
        return 1;
    }
    std::printf("webhook_test: OK\n");
    return 0;
}
