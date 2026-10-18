// The gateway's own web server (P3 step 6): the browser player, the
// health/stats endpoint, and the runtime cert-hash.js. web/dist is
// embedded at compile time (the table generated from web/dist by CMake -
// see embedded_player.h), with a [server].web_root override for serving
// some other tree from disk (the dev/ops escape hatch). cert-hash.js is
// served DYNAMICALLY in both modes - never written to disk ("served
// dynamically, changes every boot").
//
// WHAT IT SERVES. Two roles, one class, so the endpoint paths and JSON
// shapes are literally the same code in both:
//   - the WEB server (cert set): HTTPS on web_port, serving the embedded
//     player (/, /index.html, /stream.html, /cert-hash.js,
//     /assets/*.wasm...) or the web_root override.
//     HTTPS is the default, but it is the CLI's choice ([server].web_tls):
//     the closed-network deployment serves the page over plain HTTP, which
//     is still a secure context for a browser on 127.0.0.1 or the LAN, and
//     the WebTransport handshake stays TLS (pinned via cert-hash.js) either
//     way.
//   - the HEALTH server (no cert): plain HTTP on health_port, serving
//     /health and /stats - i.e. plain HTTP on a separate port from the
//     HTTPS web server, with
//     a startup warning when the bind is not loopback.
//
// TLS comes from the SAME CertProvider instance the WebTransport server
// uses (NewServerSslCtx), so one cert-hash.js hash pins both listeners.
//
// JSON SHAPE. /health keys: status, streams,
// alive_streams, viewers, max_viewers, per_stream, per_session, ticker,
// ingester, uptime_ms, active_sessions. /stats is the richer view: the
// same evidence with the stream/session/ingest detail /health omits.
// Since P4 step 2 the same /stats also renders as HTML when the
// request's Accept names text/html (the SLS-parity stats page:
// server-side-rendered tables, auto-refresh meta, same data as the
// JSON); every other client - curl's */*, a script's
// application/json, a missing header - keeps the JSON, whose shape
// never changes for it.
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

namespace quicsrt::gateway
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
    /// true); nullptr = plain HTTP (the health server role and the
    /// closed-network web server).
    const CertProvider* cert = nullptr;

    /// Directory the static files are read from, overriding the embedded
    /// player (a dev/ops escape hatch; unset = serve the embedded
    /// web/dist). Must exist when set - Start() fails otherwise.
    std::string web_root;

    /// The body of the dynamic /cert-hash.js route (built by CertProvider
    /// at boot: pinned hash + WT_PORT; the hash changes every boot in
    /// self mode, so the route is Cache-Control: no-store). Empty = no
    /// route (404).
    std::string cert_hash_js;

    /// Serve the player (the embedded web/dist, or the web_root override)
    /// on this server - the WEB role. False = /health and /stats only
    /// (the health server's shape).
    bool serve_player = false;

    /// Live stats sources, both optional (nullptr reports zeros). The
    /// gateway is only read through its thread-safe snapshot API, so any
    /// worker thread may call it.
    const Gateway*   gateway = nullptr;
    const SrtIngest* ingest  = nullptr;

    /// Concurrent connections served at once; one more is closed on
    /// arrival. 16 is generous for the player (6 per browser origin).
    std::size_t max_connections = 16;

    /// TOTAL budget for receiving one request's headers, per request
    /// (both server roles; each keep-alive request gets a fresh one).
    /// The per-read socket timeout stays the idle cutoff - a client
    /// that trickles a byte every few seconds never trips it, so on
    /// budget exhaustion the server answers 408 and closes. Wired from
    /// [server].request_header_timeout_s (1..600) by the CLI.
    int header_timeout_s = 30;
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
    bool Handle(Wire&              wire,
                const std::string& method,
                const std::string& target,
                const std::string& if_none_match,
                const std::string& accept);

    static void SendJson(Wire& wire, const std::string& body, bool head);
    static void SendSimple(Wire&                                                   wire,
                           int                                                     status,
                           const char*                                             reason,
                           const char*                                             content_type,
                           const std::string&                                      body,
                           bool                                                    head,
                           const std::vector<std::pair<std::string, std::string>>& extra      = {},
                           bool                                                    keep_alive = true);

    /// /health (see the file header).
    [[nodiscard]] std::string HealthJson() const;
    /// /stats - the C++ addition: the same evidence, untruncated.
    [[nodiscard]] std::string StatsJson() const;
    /// /stats for a browser Accept - the same evidence as StatsJson,
    /// server-side rendered as auto-refreshing HTML (P4 step 2).
    [[nodiscard]] std::string StatsHtml() const;

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

} // namespace quicsrt::gateway

#endif // WEBSRT_GATEWAY_WEB_SERVER_H