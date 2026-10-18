// WtServer end-to-end over the loopback: libquicsrt's WTClient drives the
// gateway's WebTransport server. Asserts the accept path plus the two
// deliberate fixes:
//   1. Accept: CONNECT /wt?stream=test -> 200, OnWtSession with the right
//      name/role, client session ready.
//   2. Policy rejections are DELIVERABLE: a publish the allowlist forbids
//      yields HTTP 403 and an unknown stream yields HTTP 404 - the client
//      must observe the status (the 404-reset fix), not a transport error.
//   3. Datagrams both directions with payload equality.
//   4. Concurrency (the accept-stall regression): 5 WTClient sessions
//      connecting within the same second all reach ready quickly, then all
//      exchange datagrams simultaneously.
//   5. Clean close: server Close() -> every client sees OnSessionClosed;
//      loop Stop() joins.
//
// Ports: 127.0.0.1:4434 with an ephemeral fallback (bind a :0 probe socket,
// read its port, close, then bind that) if 4434 is busy. Ports
// 4433/9000 are never touched. Each WTClient owns its own EventLoop (an
// EventLoop hosts at most one engine); the server has its own loop too.

#include "gateway/policy.h"
#include "gateway/wt_server.h"

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
#include <utility>
#include <vector>

#include "core/event_loop.h"
#include "wt/client.h"

namespace
{

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "wt_server_test: FAIL: %s\n", what);
    }
    return cond;
}

// Polls `pred` until true or the deadline; returns false on timeout.
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

/// One libquicsrt WTClient on its own EventLoop (one engine per loop).
class TestClient : public quicsrt::WTClientListener
{
public:
    explicit TestClient(std::uint16_t port, const std::string& cert_hash)
        : client_(loop_, *this)
    {
        loop_.Start();
        target_.host          = "127.0.0.1";
        target_.port          = port;
        target_.cert_hash_hex = cert_hash;
    }

    ~TestClient() override { loop_.Stop(); }

    bool Connect(const std::string& path)
    {
        target_.path  = path;
        const auto t0 = std::chrono::steady_clock::now();
        if (!client_.Connect(target_))
        {
            return false;
        }
        connect_started_ = t0;
        return true;
    }

    [[nodiscard]] bool WaitReady(int timeout_ms)
    {
        return WaitUntil([this] { return ready() || closed(); }, timeout_ms) && ready();
    }

    // Milliseconds from Connect() to OnSessionReady (valid after WaitReady).
    [[nodiscard]] double ReadyMs() const
    {
        return std::chrono::duration<double, std::milli>(ready_at_ - connect_started_).count();
    }

    [[nodiscard]] int  HttpStatus() const { return client_.HttpStatus(); }
    [[nodiscard]] bool SendDatagram(const void* data, std::size_t size) { return client_.SendDatagram(data, size); }

    /// Datagrams received (payload copies), guarded (callback on the loop thread).
    [[nodiscard]] std::vector<std::string> Datagrams() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return datagrams_;
    }

    [[nodiscard]] bool        ready() const { return ready_; }
    [[nodiscard]] bool        closed() const { return closed_; }
    [[nodiscard]] std::string close_reason() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return close_reason_;
    }

private:
    void OnSessionReady() override
    {
        ready_at_ = std::chrono::steady_clock::now();
        ready_    = true;
    }
    void OnSessionClosed(const std::string& reason) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        close_reason_ = reason;
        closed_       = true;
    }
    void OnDatagram(const std::uint8_t* data, std::size_t size) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        datagrams_.emplace_back(reinterpret_cast<const char*>(data), size);
    }

    mutable std::mutex                    mutex_;
    std::vector<std::string>              datagrams_;
    std::string                           close_reason_;
    std::atomic<bool>                     ready_{false};
    std::atomic<bool>                     closed_{false};
    std::chrono::steady_clock::time_point connect_started_;
    std::chrono::steady_clock::time_point ready_at_;

    quicsrt::EventLoop        loop_;
    quicsrt::WTClient::Target target_{};
    quicsrt::WTClient         client_;
};

/// The gateway side: one WtServer + recorded listener events. Datagrams
/// are echoed back (SendDatagram from OnDatagram - a listener callback on
/// the loop thread may call back into WtServer).
class TestServer : public quicsrt::gateway::WtServerListener
{
public:
    TestServer(quicsrt::EventLoop&                                    loop,
               const quicsrt::gateway::CertProvider&                  cert,
               std::shared_ptr<const quicsrt::gateway::SessionPolicy> policy)
        : server_(loop, cert, std::move(policy), *this)
    {
    }

    [[nodiscard]] bool Bind(std::uint16_t port) { return server_.Bind("127.0.0.1", port); }
    void               Close() { server_.Close(); }
    [[nodiscard]] bool SendDatagram(quicsrt::gateway::WtSessionHandle h, const void* data, std::size_t size)
    {
        return server_.SendDatagram(h, data, size);
    }
    [[nodiscard]] int SessionsAccepted() const { return server_.SessionsAccepted(); }

    [[nodiscard]] quicsrt::gateway::WtSessionHandle LastHandle() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_handle_;
    }
    [[nodiscard]] std::string LastSubscribeName() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_subscribe_name_;
    }
    [[nodiscard]] std::string LastPublishName() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_publish_name_;
    }
    [[nodiscard]] int SessionClosedCount() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return session_closed_count_;
    }
    /// (handle, payload) pairs in arrival order.
    [[nodiscard]] std::vector<std::pair<quicsrt::gateway::WtSessionHandle, std::string>> Datagrams() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return datagrams_;
    }

private:
    void OnWtSession(quicsrt::gateway::WtSessionHandle handle, const quicsrt::gateway::WtSessionStart& start) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        last_handle_         = handle;
        last_subscribe_name_ = start.subscribe_name.value_or("");
        last_publish_name_   = start.publish_name.value_or("");
    }
    void OnSessionClosed(quicsrt::gateway::WtSessionHandle /*handle*/, const std::string& /*reason*/) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        ++session_closed_count_;
    }
    void OnDatagram(quicsrt::gateway::WtSessionHandle handle, const std::uint8_t* data, std::size_t size) override
    {
        {
            const std::lock_guard<std::mutex> lock{mutex_};
            datagrams_.emplace_back(handle, std::string(reinterpret_cast<const char*>(data), size));
        }
        server_.SendDatagram(handle, data, size); // echo back
    }

    mutable std::mutex                                                     mutex_;
    quicsrt::gateway::WtSessionHandle                                      last_handle_;
    std::string                                                            last_subscribe_name_;
    std::string                                                            last_publish_name_;
    int                                                                    session_closed_count_ = 0;
    std::vector<std::pair<quicsrt::gateway::WtSessionHandle, std::string>> datagrams_;

    quicsrt::gateway::WtServer server_;
};

// 127.0.0.1:4434 when free, else an ephemeral port (probe-bind :0, close,
// hand the port to the server; the tiny TOCTOU window is acceptable for a
// test and 4433/9000 are never touched).
std::uint16_t ChoosePort(const quicsrt::gateway::CertProvider& /*cert*/)
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
        std::fprintf(stderr, "wt_server_test: cannot probe any port\n");
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
    using namespace quicsrt::gateway;
    if (std::getenv("WT_TEST_LSQUIC_DEBUG") != nullptr)
    {
        quicsrt::SetLsquicLogLevel("debug");
    }

    const CertProvider cert;
    auto               policy = std::make_shared<const StreamAllowlistPolicy>(std::vector<StreamAclEntry>{
        StreamAclEntry{.name_pattern = "test", .allow_publish = false, .allow_subscribe = true, .token = std::nullopt},
    });

    quicsrt::EventLoop server_loop;
    server_loop.Start();
    TestServer          server(server_loop, cert, policy);
    const std::uint16_t port = ChoosePort(cert);
    Check(server.Bind(port), "server binds 127.0.0.1 (4434 or ephemeral fallback)");
    if (!g_ok)
    {
        server_loop.Stop();
        return 1;
    }
    std::fprintf(stderr, "wt_server_test: server on 127.0.0.1:%u (hash %s)\n", port, cert.Sha256Hex().c_str());

    // ---- 1. Accept ----------------------------------------------------
    {
        TestClient client{port, cert.Sha256Hex()};
        Check(client.Connect("/wt?stream=test"), "accept: Connect starts");
        Check(WaitUntil([&server] { return server.SessionsAccepted() == 1; }, 5000), "accept: server saw the session");
        Check(server.LastSubscribeName() == "test", "accept: subscribe name is 'test'");
        Check(server.LastPublishName().empty(), "accept: no publish name");
        Check(server.LastHandle().IsValid(), "accept: handle is valid");
        Check(client.WaitReady(5000), "accept: client session ready");
        Check(client.HttpStatus() == 200, "accept: client saw HTTP 200");
    }

    // ---- 2. Policy rejections deliverable (the 404-reset fix) ---------
    {
        TestClient pub{port, cert.Sha256Hex()};
        Check(pub.Connect("/wt?publish=test"), "403: Connect starts");
        Check(!pub.WaitReady(3000), "403: publish session not ready");
        Check(pub.HttpStatus() == 403, "403: client OBSERVES HTTP 403 (not a transport error)");
        Check(pub.closed(), "403: session closed");
        Check(pub.close_reason().find("403") != std::string::npos, "403: close reason carries the status");

        TestClient unknown{port, cert.Sha256Hex()};
        Check(unknown.Connect("/wt?stream=missing"), "404: Connect starts");
        Check(!unknown.WaitReady(3000), "404: unknown-stream session not ready");
        Check(unknown.HttpStatus() == 404, "404: client OBSERVES HTTP 404 (not a transport error)");
        Check(unknown.closed(), "404: session closed");
        Check(unknown.close_reason().find("404") != std::string::npos, "404: close reason carries the status");
    }
    Check(server.SessionsAccepted() == 1, "rejections: still exactly one accepted session");

    // ---- 3. Datagrams both directions ---------------------------------
    {
        TestClient client{port, cert.Sha256Hex()};
        Check(client.Connect("/wt?stream=test"), "datagram: Connect starts");
        Check(client.WaitReady(5000), "datagram: client session ready");
        const auto handle = server.LastHandle();

        static const char kPing[] = "ping-from-client";
        Check(client.SendDatagram(kPing, sizeof kPing - 1), "datagram: client sends");
        Check(WaitUntil(
                  [&server, handle]
                  {
                      for (const auto& [h, payload] : server.Datagrams())
                      {
                          if (h == handle && payload == kPing)
                          {
                              return true;
                          }
                      }
                      return false;
                  },
                  5000),
              "datagram: server received the payload on the right handle");

        // The server echoes; the echo must come back to this client.
        Check(WaitUntil(
                  [&client]
                  {
                      for (const std::string& got : client.Datagrams())
                      {
                          if (got == kPing)
                          {
                              return true;
                          }
                      }
                      return false;
                  },
                  5000),
              "datagram: echo returned to the client");

        // Server-initiated datagram (posted SendDatagram from this thread).
        static const char kPong[] = "server-push";
        Check(server.SendDatagram(handle, kPong, sizeof kPong - 1), "datagram: server-initiated send accepted");
        Check(WaitUntil(
                  [&client]
                  {
                      for (const std::string& got : client.Datagrams())
                      {
                          if (got == kPong)
                          {
                              return true;
                          }
                      }
                      return false;
                  },
                  5000),
              "datagram: server push reached the client");
    }

    // ---- 4. Concurrency (the accept-stall regression) ------------------
    std::vector<std::unique_ptr<TestClient>> fleet;
    {
        constexpr int kFleet = 5;
        const auto    t0     = std::chrono::steady_clock::now();
        for (int i = 0; i < kFleet; ++i)
        {
            fleet.push_back(std::make_unique<TestClient>(port, cert.Sha256Hex()));
        }
        for (int i = 0; i < kFleet; ++i)
        {
            Check(fleet[static_cast<std::size_t>(i)]->Connect("/wt?stream=test"), "concurrency: Connect starts");
        }
        double slowest_ms = 0;
        for (int i = 0; i < kFleet; ++i)
        {
            auto& c = fleet[static_cast<std::size_t>(i)];
            Check(c->WaitReady(3000), "concurrency: every session ready under the bound");
            slowest_ms = c->ReadyMs() > slowest_ms ? c->ReadyMs() : slowest_ms;
        }
        const double total_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        std::fprintf(stderr,
                     "wt_server_test: %d concurrent connects: slowest %.1f ms, total %.1f ms\n",
                     kFleet,
                     slowest_ms,
                     total_ms);
        Check(slowest_ms < 3000.0, "concurrency: slowest individual connect < 3 s");
        Check(total_ms < 5000.0, "concurrency: total < 5 s");
        Check(server.SessionsAccepted() == 2 + kFleet, "concurrency: server accepted every session");

        // All five exchange datagrams simultaneously: 3 each, echoed back.
        constexpr int kPerClient = 3;
        for (int i = 0; i < kFleet; ++i)
        {
            for (int j = 0; j < kPerClient; ++j)
            {
                const std::string blob = "c" + std::to_string(i) + "-d" + std::to_string(j);
                Check(fleet[static_cast<std::size_t>(i)]->SendDatagram(blob.data(), blob.size()),
                      "concurrency: datagram queued");
            }
        }
        Check(WaitUntil([&server, kFleet, kPerClient]
                        { return static_cast<int>(server.Datagrams().size()) >= kFleet * kPerClient; },
                        5000),
              "concurrency: all datagrams reached the server");
        for (int i = 0; i < kFleet; ++i)
        {
            const std::string tag = "c" + std::to_string(i) + "-d";
            Check(WaitUntil(
                      [&fleet, i, kPerClient, tag]
                      {
                          int hits = 0;
                          for (const std::string& got : fleet[static_cast<std::size_t>(i)]->Datagrams())
                          {
                              if (got.starts_with(tag))
                              {
                                  ++hits;
                              }
                          }
                          return hits >= kPerClient;
                      },
                      5000),
                  "concurrency: every echo returned");
        }
    }

    // ---- 5. Clean close ------------------------------------------------
    {
        server.Close();
        for (const auto& client : fleet)
        {
            Check(WaitUntil([&client] { return client->closed(); }, 5000), "close: client observed OnSessionClosed");
            Check(client->close_reason().find("connection closed") != std::string::npos,
                  "close: reason is a clean connection close");
        }
        Check(WaitUntil([&server] { return server.SessionClosedCount() >= 5; }, 5000),
              "close: server reaped every session");
    }

    fleet.clear();      // destroy clients after their OnSessionClosed fired
    server_loop.Stop(); // joins; the WtServer teardown follows at destruction

    if (!g_ok)
    {
        std::fprintf(stderr, "wt_server_test: FAILURES\n");
        return 1;
    }
    std::printf("wt_server_test: OK\n");
    return 0;
}
