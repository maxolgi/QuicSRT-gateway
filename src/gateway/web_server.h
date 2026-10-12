// The gateway's own web server (P3 step 6): the browser player, the
// health/stats endpoint, and the runtime cert-hash.js - the C++ port of
// the Rust oracle's crates/websrt-gateway/src/web_server.rs (axum +
// axum-server + rust-embed) and of the /health router wired in its
// main.rs. The oracle embeds web/dist at compile time; the C++ gateway
// NEVER builds the player, so the assets are read from a configured
// web_root instead (the Rust gateway's own --web-root escape hatch).
//
// WHAT IT SERVES. Two roles, one class, so the endpoint paths and JSON
// shapes are literally the same code in both:
//   - the WEB server (cert set): HTTPS on web_port, serving web_root
//     (/, /index.html, /stream.html, /cert-hash.js, /assets/*.wasm...).
//     HTTPS is the default, but it is the CLI's choice ([server].web_tls):
//     the closed-network deployment serves the page over plain HTTP, which
//     is still a secure context for a browser on 127.0.0.1 or the LAN, and
//     the WebTransport handshake stays TLS (pinned via cert-hash.js) either
//     way.
//   - the HEALTH server (no cert): plain HTTP on health_port, serving
//     /health and /stats. This is the oracle's shape exactly - its
//     health listener is axum::serve on a raw TcpListener (main.rs:490),
//     i.e. plain HTTP on a separate port from the HTTPS web server, with
//     a startup warning when the bind is not loopback.
//
// TLS comes from the SAME CertProvider instance the WebTransport server
// uses (NewServerSslCtx), so one cert-hash.js hash pins both listeners.
//
// JSON SHAPE. /health reproduces the oracle's health_handler key for
// key (websrt-gateway/src/main.rs:690-704) - status, streams,
// alive_streams, viewers, max_viewers, per_stream, per_session, ticker,
// ingester - plus two additive keys the C++ gateway adds (uptime_ms,
// active_sessions), so a parity diff over the oracle's keys still
// matches. /stats is the C++ addition (P4's "HTTP stats page" in the
// oracle's terms): the same evidence with the stream/session/ingest
// detail the oracle's GatewayStats struct carries but does not expose.
//
// THREAD MODEL. One accept thread (poll on the listener, so Stop() never
// has to interrupt a blocking accept) plus thread-per-connection, capped
// at WebServerConfig::max_connections - a static/health server has no
// reason for a pool, and the cap bounds what a hostile client can spend.
// Past the cap a connection is closed immediately (logged, not queued).
// Each worker serves its connection to completion (keep-alive included,
// with a 10 s idle timeout) and is reaped by the accept thread. The cap
// is comfortable for the player: browsers open 6 connections per origin
// and keep them alive, so the served assets never queue behind each
// other.
//
// LIFETIME. `cert`, `gateway` and `ingest` are BORROWED and must outlive
// the server. Stop() closes the listener, shuts down every live
// connection and joins every thread; it is callable while the gateway
// loop still runs (the CLI stops the web/health servers BEFORE
// gateway.Shutdown(), because the stats snapshot rides a Post onto that
// loop).

#ifndef WEBSRT_GATEWAY_WEB_SERVER_H
#define WEBSRT_GATEWAY_WEB_SERVER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/ssl.h>

#include "gateway/cert.h"

namespace websrt::gateway
{

class Gateway;
class SrtIngest;

/// One WebServer instance. Port 0 asks the kernel for a free port (tests).
struct WebServerConfig
{
    /// Bind address; resolved with getaddrinfo, so a hostname works too.
    std::string   bind = "127.0.0.1";
    std::uint16_t port = 0;

    /// HTTPS with this identity (the web server role, [server].web_tls =
    /// true); nullptr = plain HTTP (the health server role, the oracle's
    /// shape, and the closed-network web server).
    const CertProvider* cert = nullptr;

    /// Directory the static files are read from. EMPTY = no static
    /// serving at all (/health and /stats only), which is the default:
    /// the gateway ships no web app of its own.
    std::string web_root;

    /// Live stats sources, both optional (nullptr reports zeros). The
    /// gateway is only read through its thread-safe snapshot API, so any
    /// worker thread may call it.
    const Gateway*   gateway = nullptr;
    const SrtIngest* ingest  = nullptr;

    /// Concurrent connections served at once; one more is closed on
    /// arrival. 16 is generous for the player (6 per browser origin).
    std::size_t max_connections = 16;
};

class WebServer final
{
public:
    explicit WebServer(WebServerConfig config);
    ~WebServer();

    WebServer(const WebServer&)            = delete;
    WebServer& operator=(const WebServer&) = delete;

    /// Binds, resolves and validates web_root (a web_root that is not an
    /// existing directory fails HERE rather than turning every asset into
    /// a 404 at runtime), then starts the accept thread. On failure
    /// *error explains why and the server stays inert.
    bool Start(std::string* error);

    /// Idempotent: stops accepting, closes the listener, shuts down every
    /// live connection, joins the accept thread and every worker.
    void Stop();

    [[nodiscard]] bool Running() const { return running_; }

    /// The bound port - the real one when the config asked for 0.
    [[nodiscard]] std::uint16_t Port() const { return port_; }

private:
    /// A connection in transit: the fd plus the TLS session wrapping it
    /// (null TLS = the plain-HTTP health server).
    struct Wire;

    /// One worker thread plus the flag the accept thread reaps it on.
    /// The flag is shared_ptr'd because the thread outlives the vector
    /// slot it was pushed into (Stop() may join workers in any order).
    struct Worker
    {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    /// One worker thread: the whole connection (TLS handshake, then every
    /// request on it) until close, error or idle timeout.
    void Serve(int fd, const std::shared_ptr<std::atomic<bool>>& done);
    /// The accept thread.
    void AcceptLoop();
    /// Join the workers that have finished (the accept thread's reaper).
    void ReapWorkers();
    /// Route + render one request; false closes the connection after the
    /// response was written.
    bool Handle(Wire& wire, const std::string& method, const std::string& target, const std::string& if_none_match);

    static void SendJson(Wire& wire, const std::string& body, bool head);
    static void SendSimple(Wire&                                                   wire,
                           int                                                     status,
                           const char*                                             reason,
                           const char*                                             content_type,
                           const std::string&                                      body,
                           bool                                                    head,
                           const std::vector<std::pair<std::string, std::string>>& extra      = {},
                           bool                                                    keep_alive = true);

    /// /health - the oracle's shape (see the file header).
    [[nodiscard]] std::string HealthJson() const;
    /// /stats - the C++ addition: the same evidence, untruncated.
    [[nodiscard]] std::string StatsJson() const;

    WebServerConfig                       config_;
    int                                   listen_fd_ = -1;
    std::uint16_t                         port_      = 0;
    std::string                           root_;              ///< canonicalized config_.web_root
    SSL_CTX*                              ssl_ctx_ = nullptr; ///< null = plain HTTP
    std::thread                           accept_thread_;
    std::atomic<bool>                     running_{false};
    std::atomic<bool>                     stopping_{false};
    std::chrono::steady_clock::time_point started_;
    std::chrono::steady_clock::time_point last_drop_log_; ///< accept thread only

    /// Live connections, so Stop() can shut them down out from under a
    /// worker blocked in read.
    std::mutex          conns_mutex_;
    std::set<int>       conns_;
    std::mutex          workers_mutex_;
    std::vector<Worker> workers_;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_WEB_SERVER_H