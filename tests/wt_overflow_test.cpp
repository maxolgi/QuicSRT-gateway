// Adversarial session-stream framing against the WT server: a client that
// CONNECTs successfully, then streams a capsule header claiming an
// enormous length without completing it - the one-client OOM vector the
// bounded capsule parser (libquicsrt) and the gateway's kill rule close.
// Proves:
//   1. A truncated capsule header alone does NOT kill the session (a
//      partial tail is legitimate framing; the parser buffers it boundedly).
//   2. Completing the header to claim 64 MiB (>> the parser's 1 MiB
//      pending ceiling) kills the session PROMPTLY: the terminal
//      OnSessionClosed fires with an overflow reason and the raw client
//      observes the session-stream FIN, both within CI-safe budgets.
//   3. Post-kill garbage on the FIN'd stream is inert, and a subsequent
//      well-formed session (real WTClient) still connects and exchanges
//      an echoed datagram - the server is healthy after the kill.
//
// Level: libquicsrt's WTClient only sends protocol-shaped bytes, so the
// attack rides RawClient below - WTClient's proven engine recipe (deps/
// libquicsrt src/wt/client.cpp) with one addition, a public raw write on
// the session stream. That makes the raw level practical here, so the
// kill is proven end-to-end over real QUIC, not at a synthetic seam.

#include "gateway/policy.h"
#include "gateway/wt_server.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <lsxpack_header.h>
#include <lsquic.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
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
#include "wt/capsule.h"
#include "wt/client.h"

namespace
{

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "wt_overflow_test: FAIL: %s\n", what);
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

constexpr std::size_t kRecvBufSize = 16384;

bool ParseHashHex(const std::string& hex, std::uint8_t out[32])
{
    if (hex.size() != 64)
    {
        return false;
    }
    const auto nib = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f')
        {
            return c - 'a' + 10;
        }
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i)
    {
        const int hi = nib(hex[2 * i]);
        const int lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// Raw WT session-stream client: WTClient's engine recipe (LSENG_HTTP,
/// QUIC v1, datagrams advertised, cert pinned by SHA-256-of-DER) minus the
/// protocol layer - the session stream is WRITABLE with arbitrary bytes,
/// which is exactly what the adversarial flow needs and WTClient cannot
/// express. Owns its EventLoop (one engine per loop).
class RawClient : private quicsrt::EngineHost
{
public:
    RawClient(std::uint16_t port, std::string path, const std::string& cert_hash_hex)
        : path_(std::move(path))
    {
        static std::once_flag global_init_once;
        std::call_once(global_init_once,
                       []
                       {
                           if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
                           {
                               std::fprintf(stderr, "wt_overflow_test: lsquic_global_init failed\n");
                           }
                       });

        if (!ParseHashHex(cert_hash_hex, expected_hash_))
        {
            std::fprintf(stderr, "wt_overflow_test: bad cert hash\n");
            return;
        }

        peer_sa_.sin_family = AF_INET;
        peer_sa_.sin_port   = htons(port);
        if (::inet_pton(AF_INET, "127.0.0.1", &peer_sa_.sin_addr) != 1)
        {
            return;
        }
        fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd_ < 0 || ::connect(fd_, reinterpret_cast<sockaddr*>(&peer_sa_), sizeof peer_sa_) != 0)
        {
            return;
        }
        socklen_t len = sizeof local_sa_;
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&local_sa_), &len) != 0)
        {
            return;
        }
        loop_.AddFd(fd_, EPOLLIN, [this](int, std::uint32_t) { HandleUdpReadable(); });

        struct lsquic_engine_settings settings;
        lsquic_engine_init_settings(&settings, LSENG_HTTP);
        settings.es_versions  = 1U << LSQVER_I001; // the server speaks QUIC v1 + h3
        settings.es_datagrams = 1;                 // the server closes conns without a >=1200B frame size
        char err_buf[256];
        if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP, err_buf, sizeof err_buf))
        {
            std::fprintf(stderr, "wt_overflow_test: engine settings rejected: %s\n", err_buf);
            return;
        }

        struct lsquic_engine_api api{};
        api.ea_settings        = &settings;
        api.ea_packets_out     = PacketsOut;
        api.ea_packets_out_ctx = this;
        api.ea_stream_if       = &kStreamIf;
        api.ea_stream_if_ctx   = this;
        api.ea_verify_cert     = VerifyCertPinned;
        api.ea_verify_ctx      = this;
        engine_                = lsquic_engine_new(LSENG_HTTP, &api);
        if (engine_ == nullptr)
        {
            return;
        }
        loop_.SetEngineHost(this);
        conn_      = lsquic_engine_connect(engine_,
                                      N_LSQVER,
                                      reinterpret_cast<sockaddr*>(&local_sa_),
                                      reinterpret_cast<sockaddr*>(&peer_sa_),
                                      nullptr,
                                      nullptr,
                                      "127.0.0.1",
                                      0,
                                      nullptr,
                                      0,
                                      nullptr,
                                      0);
        connected_ = conn_ != nullptr;
        loop_.Start();
    }

    ~RawClient() override
    {
        loop_.Stop(); // joins; teardown then runs with the loop halted
        loop_.SetEngineHost(nullptr);
        if (fd_registered_)
        {
            loop_.DelFd(fd_);
            fd_registered_ = false;
        }
        if (fd_ >= 0)
        {
            ::close(fd_);
            fd_ = -1;
        }
        if (engine_ != nullptr)
        {
            lsquic_engine_destroy(engine_); // fires remaining callbacks; they only touch flags
            engine_ = nullptr;
        }
    }

    RawClient(const RawClient&)            = delete;
    RawClient& operator=(const RawClient&) = delete;

    [[nodiscard]] bool        connected() const { return connected_; }
    [[nodiscard]] bool        fin_seen() const { return fin_seen_; }
    [[nodiscard]] bool        conn_closed() const { return conn_closed_; }
    [[nodiscard]] std::size_t BytesWritten() const { return bytes_written_.load(); }

    /// Thread-safe. Writes arbitrary bytes on the session stream (after the
    /// CONNECT headers). Returns false when the loop rejected the post.
    bool WriteRaw(const std::uint8_t* data, std::size_t size)
    {
        return loop_.Post(
            [this, bytes = std::vector<std::uint8_t>(data, data + size)]() mutable
            {
                if (stream_ == nullptr || !headers_sent_)
                {
                    return;
                }
                const ssize_t n = lsquic_stream_write(stream_, bytes.data(), bytes.size());
                lsquic_stream_flush(stream_);
                if (n > 0)
                {
                    bytes_written_.fetch_add(static_cast<std::size_t>(n));
                }
            });
    }

    /// Thread-safe. Graceful CONNECTION_CLOSE (the server reaps the conn).
    void Close()
    {
        (void)loop_.Post(
            [this]
            {
                if (conn_ != nullptr)
                {
                    lsquic_conn_close(conn_);
                }
            });
    }

private:
    // EngineHost: loop-thread engine driving (WTClient's recipe).
    bool NextTick(std::chrono::microseconds& diff) override
    {
        if (engine_ == nullptr)
        {
            return false;
        }
        int diff_us = 0;
        if (lsquic_engine_earliest_adv_tick(engine_, &diff_us) != 0)
        {
            diff = std::chrono::microseconds{diff_us};
            return true;
        }
        return false;
    }

    void Pump() override
    {
        if (engine_ == nullptr)
        {
            return;
        }
        int diff_us = 0;
        if (lsquic_engine_earliest_adv_tick(engine_, &diff_us) != 0 && diff_us <= 0)
        {
            lsquic_engine_process_conns(engine_);
        }
        if (lsquic_engine_has_unsent_packets(engine_) != 0)
        {
            lsquic_engine_send_unsent_packets(engine_);
        }
    }

    void HandleUdpReadable()
    {
        if (engine_ == nullptr)
        {
            return;
        }
        std::uint8_t buf[kRecvBufSize];
        for (;;)
        {
            const ssize_t n = ::recv(fd_, buf, sizeof buf, MSG_DONTWAIT);
            if (n > 0)
            {
                lsquic_engine_packet_in(engine_,
                                        buf,
                                        static_cast<std::size_t>(n),
                                        reinterpret_cast<sockaddr*>(&local_sa_),
                                        reinterpret_cast<sockaddr*>(&peer_sa_),
                                        nullptr,
                                        0);
                continue;
            }
            return; // EAGAIN or an ICMP error; nothing to feed
        }
    }

    // wtransport's extended-CONNECT set (client.cpp SendConnectHeaders).
    void SendConnectHeaders(lsquic_stream_t* stream)
    {
        const std::string authority = std::string{"127.0.0.1"} + ":" + std::to_string(ntohs(peer_sa_.sin_port));
        const struct
        {
            const char* name;
            const char* val;
        } pairs[] = {
            {.name = ":method", .val = "CONNECT"},
            {.name = ":scheme", .val = "https"},
            {.name = ":protocol", .val = "webtransport"},
            {.name = ":authority", .val = authority.c_str()},
            {.name = ":path", .val = path_.c_str()},
            {.name = "user-agent", .val = "wt-overflow-test"},
        };
        lsxpack_header headers[std::size(pairs)];
        char           storage[1024];
        std::size_t    off = 0;
        for (std::size_t i = 0; i < std::size(pairs); ++i)
        {
            const std::size_t name_len = std::strlen(pairs[i].name);
            const std::size_t val_len  = std::strlen(pairs[i].val);
            std::memcpy(storage + off, pairs[i].name, name_len);
            std::memcpy(storage + off + name_len, pairs[i].val, val_len);
            lsxpack_header_set_offset2(&headers[i], storage + off, 0, name_len, name_len, val_len);
            off += name_len + val_len;
        }
        lsquic_http_headers_t hdrs{};
        hdrs.count   = std::size(pairs);
        hdrs.headers = headers;
        if (0 == lsquic_stream_send_headers(stream, &hdrs, 0))
        {
            lsquic_stream_flush(stream); // eos=0: the block only reaches the wire flushed
            headers_sent_ = true;
        }
    }

    // lsquic callback shims; flags only, so engine destroy is safe.
    static RawClient* FromConn(lsquic_conn_t* conn) { return reinterpret_cast<RawClient*>(lsquic_conn_get_ctx(conn)); }

    static lsquic_conn_ctx_t* OnNewConn(void* ctx, lsquic_conn_t* conn)
    {
        auto* c  = static_cast<RawClient*>(ctx);
        c->conn_ = conn;
        return reinterpret_cast<lsquic_conn_ctx_t*>(c);
    }

    static void OnConnClosed(lsquic_conn_t* conn)
    {
        auto* c = FromConn(conn);
        if (c == nullptr)
        {
            return;
        }
        c->conn_        = nullptr;
        c->conn_closed_ = true;
    }

    static void OnHskDone(lsquic_conn_t* conn, enum lsquic_hsk_status status)
    {
        if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK)
        {
            lsquic_conn_make_stream(conn);
        }
    }

    static lsquic_stream_ctx_t* OnNewStream(void* ctx, lsquic_stream_t* stream)
    {
        auto* c    = static_cast<RawClient*>(ctx);
        c->stream_ = stream;
        lsquic_stream_wantread(stream, 1);
        lsquic_stream_wantwrite(stream, 1);
        return reinterpret_cast<lsquic_stream_ctx_t*>(c);
    }

    static void OnRead(lsquic_stream_t* stream, lsquic_stream_ctx_t* /*h*/)
    {
        auto*        c = reinterpret_cast<RawClient*>(lsquic_stream_get_ctx(stream));
        std::uint8_t buf[kRecvBufSize];
        for (;;)
        {
            const ssize_t n = lsquic_stream_read(stream, buf, sizeof buf);
            if (n > 0)
            {
                continue; // response head etc.: drained and discarded
            }
            if (n == 0)
            {
                // The server FIN'd the session stream - the observable end
                // of a TerminateSession kill.
                c->fin_seen_ = true;
                lsquic_stream_wantread(stream, 0);
                return;
            }
            return; // EAGAIN or error
        }
    }

    static void OnWrite(lsquic_stream_t* stream, lsquic_stream_ctx_t* /*h*/)
    {
        auto* c = reinterpret_cast<RawClient*>(lsquic_stream_get_ctx(stream));
        if (!c->headers_sent_)
        {
            c->SendConnectHeaders(stream);
            lsquic_stream_wantwrite(stream, 0);
        }
    }

    static void OnClose(lsquic_stream_t* /*stream*/, lsquic_stream_ctx_t* /*h*/) {}

    static void OnDatagram(lsquic_conn_t* /*conn*/, const void* /*buf*/, std::size_t /*size*/) {}

    static ssize_t OnDgWrite(lsquic_conn_t* conn, void* /*buf*/, std::size_t /*size*/)
    {
        lsquic_conn_want_datagram_write(conn, 0); // nothing to send
        return 0;
    }

    static int VerifyCertPinned(void* ctx, struct stack_st_X509* chain)
    {
        auto* c    = static_cast<RawClient*>(ctx);
        X509* leaf = sk_X509_value(chain, 0);
        if (leaf == nullptr)
        {
            return -1;
        }
        unsigned char* der     = nullptr;
        const int      der_len = i2d_X509(leaf, &der);
        if (der_len <= 0 || der == nullptr)
        {
            return -1;
        }
        std::uint8_t md[SHA256_DIGEST_LENGTH];
        SHA256(der, static_cast<std::size_t>(der_len), md);
        OPENSSL_free(der);
        return std::memcmp(md, c->expected_hash_, sizeof md) == 0 ? 0 : -1;
    }

    static int PacketsOut(void* ctx, const struct lsquic_out_spec* specs, unsigned count)
    {
        auto* c    = static_cast<RawClient*>(ctx);
        int   sent = 0;
        for (unsigned i = 0; i < count; ++i)
        {
            const ssize_t n = ::send(c->fd_, specs[i].iov->iov_base, specs[i].iov->iov_len, 0);
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                return sent > 0 ? sent : -1;
            }
            ++sent;
        }
        return sent;
    }

    static const struct lsquic_stream_if kStreamIf;

    quicsrt::EventLoop loop_;
    std::string        path_;
    std::uint8_t       expected_hash_[SHA256_DIGEST_LENGTH] = {};

    lsquic_engine* engine_        = nullptr;
    lsquic_conn*   conn_          = nullptr;
    lsquic_stream* stream_        = nullptr;
    int            fd_            = -1;
    bool           fd_registered_ = true; // registered in the constructor
    sockaddr_in    local_sa_{};
    sockaddr_in    peer_sa_{};

    bool headers_sent_ = false;
    bool connected_    = false;

    std::atomic<bool>        fin_seen_{false};
    std::atomic<bool>        conn_closed_{false};
    std::atomic<std::size_t> bytes_written_{0};
};

const struct lsquic_stream_if RawClient::kStreamIf = {
    .on_new_conn                = RawClient::OnNewConn,
    .on_goaway_received         = nullptr,
    .on_conn_closed             = RawClient::OnConnClosed,
    .on_new_stream              = RawClient::OnNewStream,
    .on_read                    = RawClient::OnRead,
    .on_write                   = RawClient::OnWrite,
    .on_close                   = RawClient::OnClose,
    .on_dg_write                = RawClient::OnDgWrite,
    .on_datagram                = RawClient::OnDatagram,
    .on_hsk_done                = RawClient::OnHskDone,
    .on_new_token               = nullptr,
    .on_sess_resume_info        = nullptr,
    .on_reset                   = nullptr,
    .on_conncloseframe_received = nullptr,
    .on_hset_in                 = nullptr,
};

/// The gateway side: one WtServer + recorded listener events; datagrams
/// are echoed back (wt_server_test's TestServer, trimmed).
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
    [[nodiscard]] int SessionClosedCount() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return session_closed_count_;
    }
    [[nodiscard]] std::string LastCloseReason() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return last_close_reason_;
    }
    [[nodiscard]] std::vector<std::pair<quicsrt::gateway::WtSessionHandle, std::string>> Datagrams() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return datagrams_;
    }

private:
    void OnWtSession(quicsrt::gateway::WtSessionHandle handle,
                     const quicsrt::gateway::WtSessionStart& /*start*/) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        last_handle_ = handle;
    }
    void OnSessionClosed(quicsrt::gateway::WtSessionHandle /*handle*/, const std::string& reason) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        ++session_closed_count_;
        last_close_reason_ = reason;
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
    int                                                                    session_closed_count_ = 0;
    std::string                                                            last_close_reason_;
    std::vector<std::pair<quicsrt::gateway::WtSessionHandle, std::string>> datagrams_;

    quicsrt::gateway::WtServer server_;
};

/// A well-formed session: libquicsrt's WTClient exactly as production
/// clients behave (wt_server_test's TestClient, trimmed).
class WellFormedClient : public quicsrt::WTClientListener
{
public:
    WellFormedClient(std::uint16_t port, const std::string& cert_hash)
        : client_(loop_, *this)
    {
        loop_.Start();
        target_.host          = "127.0.0.1";
        target_.port          = port;
        target_.cert_hash_hex = cert_hash;
    }

    ~WellFormedClient() override { loop_.Stop(); }

    bool Connect(const std::string& path)
    {
        target_.path = path;
        return client_.Connect(target_);
    }
    [[nodiscard]] bool WaitReady(int timeout_ms)
    {
        return WaitUntil([this] { return ready() || closed(); }, timeout_ms) && ready();
    }
    [[nodiscard]] bool SendDatagram(const void* data, std::size_t size) { return client_.SendDatagram(data, size); }
    [[nodiscard]] std::vector<std::string> Datagrams() const
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        return datagrams_;
    }
    [[nodiscard]] bool ready() const { return ready_; }
    [[nodiscard]] bool closed() const { return closed_; }

private:
    void OnSessionReady() override { ready_ = true; }
    void OnSessionClosed(const std::string& /*reason*/) override { closed_ = true; }
    void OnDatagram(const std::uint8_t* data, std::size_t size) override
    {
        const std::lock_guard<std::mutex> lock{mutex_};
        datagrams_.emplace_back(reinterpret_cast<const char*>(data), size);
    }

    mutable std::mutex       mutex_;
    std::vector<std::string> datagrams_;
    std::atomic<bool>        ready_{false};
    std::atomic<bool>        closed_{false};

    quicsrt::EventLoop        loop_;
    quicsrt::WTClient::Target target_{};
    quicsrt::WTClient         client_;
};

// 127.0.0.1:4436 when free, else an ephemeral port (wt_server_test's
// ChoosePort pattern; 4433/4434/9000 belong to other tests and services).
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
        std::fprintf(stderr, "wt_overflow_test: cannot probe any port\n");
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
    const std::uint16_t port = ChoosePort();
    Check(server.Bind(port), "server binds 127.0.0.1 (4436 or ephemeral fallback)");
    if (!g_ok)
    {
        server_loop.Stop();
        return 1;
    }
    std::fprintf(stderr, "wt_overflow_test: server on 127.0.0.1:%u\n", port);

    // ---- 1. The attack: truncated huge-length header, then completion --
    {
        RawClient attacker{port, "/wt?stream=test", cert.Sha256Hex()};
        Check(attacker.connected(), "attack: raw client engine connected");
        Check(WaitUntil([&server] { return server.SessionsAccepted() == 1; }, 5000),
              "attack: CONNECT accepted (200) server-side");
        if (!g_ok)
        {
            server_loop.Stop();
            return 1;
        }

        // Capsule type 0 (skippable) + a length varint claiming 64 MiB,
        // >> WtCapsuleParser::kMaxPendingBytes (1 MiB).
        constexpr std::uint64_t kClaim = 64ULL << 20;
        std::uint8_t            len_varint[8];
        const std::size_t       len_len = quicsrt::VarintPut(len_varint, kClaim);

        // First write: the type byte and the length varint's first byte -
        // an incomplete header, exactly the attacker's streaming shape.
        // Legitimate framing: the session must survive it.
        std::vector<std::uint8_t> truncated;
        truncated.push_back(0x00);
        truncated.push_back(len_varint[0]);
        Check(attacker.WriteRaw(truncated.data(), truncated.size()), "attack: truncated-header write posted");
        std::this_thread::sleep_for(std::chrono::milliseconds{300});
        Check(server.SessionClosedCount() == 0, "attack: an incomplete capsule header does NOT kill the session");

        // Second write: the rest of the varint (the demand becomes known:
        // 64 MiB > the 1 MiB ceiling) plus the first payload bytes.
        std::vector<std::uint8_t> completion(len_varint + 1, len_varint + len_len);
        completion.insert(completion.end(), 8, 0xAA);
        const auto t0 = std::chrono::steady_clock::now();
        Check(attacker.WriteRaw(completion.data(), completion.size()), "attack: completion write posted");
        Check(WaitUntil([&server] { return server.SessionClosedCount() == 1; }, 5000),
              "attack: overflow killed the session within the budget");
        const double kill_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        std::fprintf(stderr, "wt_overflow_test: kill observed after %.1f ms\n", kill_ms);
        Check(kill_ms < 1000.0, "attack: kill is prompt (< 1 s; budget 5 s)");
        Check(server.LastCloseReason().find("overflow") != std::string::npos,
              "attack: close reason names the capsule overflow");
        Check(WaitUntil([&attacker] { return attacker.fin_seen(); }, 5000),
              "attack: raw client observed the session-stream FIN");

        // Post-kill garbage on the FIN'd stream is inert: reads were
        // disarmed and the session (with its parser) is gone, so nothing
        // reassembles it.
        std::vector<std::uint8_t> garbage(4096, 0x55);
        for (int i = 0; i < 16; ++i)
        {
            (void)attacker.WriteRaw(garbage.data(), garbage.size()); // 64 KiB total
        }
        attacker.Close();
        (void)WaitUntil([&attacker] { return attacker.conn_closed(); }, 2000);
    }

    // ---- 2. A subsequent well-formed session still works ---------------
    {
        WellFormedClient client{port, cert.Sha256Hex()};
        Check(client.Connect("/wt?stream=test"), "health: well-formed Connect starts");
        Check(client.WaitReady(5000), "health: well-formed session ready");
        const auto handle = server.LastHandle();

        static const char kPing[] = "still-alive";
        Check(client.SendDatagram(kPing, sizeof kPing - 1), "health: datagram sent");
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
              "health: server received the datagram on the right handle");
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
              "health: echo returned to the client");
    }

    // ---- 3. Clean close -------------------------------------------------
    server.Close();
    server_loop.Stop(); // joins; the WtServer teardown follows at destruction

    if (!g_ok)
    {
        std::fprintf(stderr, "wt_overflow_test: FAILURES\n");
        return 1;
    }
    std::printf("wt_overflow_test: OK\n");
    return 0;
}
