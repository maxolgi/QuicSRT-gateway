// websrt-gateway: CLI-parity C++ replacement of the Rust WebSRT gateway.
// Thin CLI over the websrtgw core library (refinement item 1): argument
// wiring, TOML config, signal handling and the run-until-signalled loop live
// here; the accept loop, per-session SRT initiators and the broadcaster
// ring live in src/gateway/. --selftest is the ctest smoke entry (the
// consumer gate); --config FILE loads the stream-allowlist TOML
// (refinement item 2).
//
// P3 step 4: the WebTransport accept path, the ring and first-wins occupancy
// are live. P3 step 5: so is the SRT/UDP ingest (a stock libsrt listener that
// publishes into the same ring). P3 step 6: the HTTPS web server (the
// browser player + the runtime cert-hash.js) and the plain-HTTP health/stats
// endpoint are wired here too.

#include <atomic>
#include <sys/stat.h>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/embedded_example_conf.h"
#include "gateway/gateway.h"
#include "gateway/ingest/srt_ingest.h"
#include "gateway/policy.h"
#include "gateway/reload.h"
#include "gateway/selftest.h"
#include "gateway/web_server.h"
#include "wt/client.h"

namespace
{

// Set from the signal handlers; the run loop polls them. sig_atomic_t is
// the only type a handler may portably touch.
volatile std::sig_atomic_t g_stop   = 0;
volatile std::sig_atomic_t g_reload = 0;

extern "C" void OnSignal(int /*signo*/)
{
    g_stop = 1;
}

// SIGHUP only flips the flag: the handler must not parse the config
// (malloc/iostreams are off limits there); the run loop does the work.
extern "C" void OnReloadSignal(int /*signo*/)
{
    g_reload = 1;
}

/// A bare run (no --config) drops the fully commented example config as
/// ./gateway.conf when it does not exist yet - the release artifact is a
/// lone binary, so the first run leaves the operator something to edit.
/// Never called when --config is given: an explicit path is the
/// operator's decision, and a missing file there is a hard error.
void WriteExampleConfigIfAbsent()
{
    constexpr const char* kDefaultPath = "gateway.conf";
    struct stat           st{};
    if (::stat(kDefaultPath, &st) == 0)
    {
        return; // already here - never overwrite
    }
    const std::string_view body = websrt::gateway::EmbeddedExampleConf();
    std::ofstream          out(kDefaultPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open() || !(out.write(body.data(), static_cast<std::streamsize>(body.size()))))
    {
        std::fprintf(stderr, "websrt-gateway: note: cannot write the example config to %s\n", kDefaultPath);
        return;
    }
    out.close();
    if (!out)
    {
        std::remove(kDefaultPath);
        std::fprintf(stderr, "websrt-gateway: note: cannot write the example config to %s\n", kDefaultPath);
        return;
    }
    std::printf("websrt-gateway: wrote %s (a fully commented example configuration; edit and run with --config %s)\n",
                kDefaultPath,
                kDefaultPath);
    std::fflush(stdout);
}

int Run(const std::optional<std::string>& config_path, const std::optional<std::string>& log_level)
{
    // lsquic's own diagnostic logging, routed to stderr by libwebsrt.
    // Must happen before any engine exists: the logger is process-wide
    // and installed once, so this is the first thing Run does. Off
    // (absent flag) leaves lsquic's default level untouched.
    if (log_level.has_value())
    {
        websrt::SetLsquicLogLevel(log_level->c_str());
        std::printf("websrt-gateway: lsquic log level: %s\n", log_level->c_str());
        std::fflush(stdout);
    }
    // Cert mode comes from the config when present, self mode otherwise
    // (the Rust gateway's default). Self mode ALWAYS generates a fresh
    // cert on every boot - nothing is persisted to disk, so the hash
    // changes per restart and viewers must reload the page.
    std::string                                     cert_mode = "self";
    std::optional<std::string>                      cert_pem;
    std::optional<std::string>                      key_pem;
    std::shared_ptr<websrt::gateway::SessionPolicy> policy;
    websrt::gateway::GatewayConfig                  gateway_config;
    std::uint16_t                                   wt_bind_port      = 4433;
    std::string                                     wt_bind           = "127.0.0.1";
    std::uint16_t                                   ingest_port       = 0;
    std::string                                     ingest_bind       = "127.0.0.1";
    std::uint64_t                                   ingest_latency_ms = 120;
    std::optional<std::string>                      ingest_passphrase;
    std::uint16_t                                   health_port = 0;
    std::string                                     health_bind = "127.0.0.1";
    std::uint16_t                                   web_port    = 0;
    std::string                                     web_bind    = "127.0.0.1";
    std::optional<std::string>                      web_root;
    bool                                            web_tls = true;
    // The applied config, diff base and fallback of every SIGHUP reload.
    websrt::gateway::Config live_config;

    if (config_path.has_value())
    {
        websrt::gateway::Config config;
        try
        {
            config = websrt::gateway::LoadConfig(*config_path);
        }
        catch (const websrt::gateway::ConfigError& e)
        {
            std::fprintf(stderr, "websrt-gateway: config error: %s\n", e.what());
            return 1;
        }
        policy    = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                        websrt::gateway::BuildAllowlistPolicy(config));
        cert_mode = config.server.cert_mode;
        cert_pem  = config.server.cert_pem;
        key_pem   = config.server.key_pem;
        const websrt::gateway::ServerConfig& s = config.server;
        gateway_config.max_viewers             = s.max_viewers;
        gateway_config.broadcast_capacity      = s.broadcast_capacity;
        gateway_config.webhooks                = websrt::gateway::WebhookSettings{
                           .url = config.webhooks.on_event_url, .timeout = std::chrono::milliseconds{config.webhooks.timeout_ms}};
        wt_bind_port      = s.wt_port;
        wt_bind           = s.wt_bind;
        ingest_port       = s.srt_ingest_port;
        ingest_bind       = s.srt_ingest_bind;
        ingest_latency_ms = s.latency_ms;
        ingest_passphrase = s.srt_passphrase;
        health_port       = s.health_port;
        health_bind       = s.health_bind;
        web_port          = s.web_port;
        web_bind          = s.web_bind;
        web_root          = s.web_root;
        web_tls           = s.web_tls;
        // The file may carry its own lsquic level (P4.1 reload swaps it);
        // the CLI flag wins at boot. Still before any engine exists.
        if (!log_level.has_value() && s.log_level.has_value())
        {
            websrt::SetLsquicLogLevel(s.log_level->c_str());
            std::printf("websrt-gateway: lsquic log level: %s (config)\n", s.log_level->c_str());
        }
        if (config.streams.empty())
        {
            // Same exposure as a bare run's open mode - say so loudly.
            std::fprintf(stderr,
                         "websrt-gateway: WARNING: no [[stream]] entries in %s - any stream name accepted\n",
                         config_path->c_str());
        }
        std::printf("websrt-gateway: config: %zu stream(s), %s "
                    "(wt %s:%u, srt ingest %s:%u, health %s:%u, web %s:%u, max_viewers %u, "
                    "broadcast_capacity %u)\n",
                    config.streams.size(),
                    config.streams.empty() ? "open mode (no [[stream]] entries)" : "allowlist mode",
                    s.wt_bind.c_str(),
                    s.wt_port,
                    s.srt_ingest_bind.c_str(),
                    s.srt_ingest_port,
                    s.health_bind.c_str(),
                    s.health_port,
                    s.web_bind.c_str(),
                    s.web_port,
                    s.max_viewers,
                    s.broadcast_capacity);
        if (!config.webhooks.on_event_url.empty())
        {
            std::printf("websrt-gateway: webhooks on: POST session events to %s (timeout %llu ms)\n",
                        config.webhooks.on_event_url.c_str(),
                        static_cast<unsigned long long>(config.webhooks.timeout_ms));
        }
        live_config = std::move(config);
    }
    else
    {
        // No config: open mode (Rust-oracle parity for dev/tests) with a
        // loud warning. Any stream name is accepted; only the fixed /wt
        // path is enforced. First run also drops ./gateway.conf.
        WriteExampleConfigIfAbsent();
        std::fprintf(stderr,
                     "websrt-gateway: WARNING: open mode: no allowlist configured - any stream name accepted\n");
        policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                        std::make_shared<websrt::gateway::AcceptAll>());
        std::printf("websrt-gateway: config: 0 stream(s), open mode\n");
        // web_port/health_port stay 0 without a config file: no reason to
        // serve the player or expose metrics in open mode. Both are
        // [server] keys (defaults 5173 / 0; with a config, web_port alone
        // turns the web server on - the player is embedded in the binary).
    }
    std::fflush(stdout);

    websrt::gateway::CertProvider cert;
    try
    {
        if (cert_mode == "mkcert")
        {
            // Config validation already rejects mkcert without PEMs; the
            // guard keeps the deref honest for any other caller of Run().
            if (!cert_pem.has_value() || !key_pem.has_value())
            {
                std::fprintf(stderr,
                             "websrt-gateway: cert error: cert_mode = \"mkcert\" requires both cert_pem and key_pem\n");
                return 1;
            }
            cert = websrt::gateway::CertProvider(*cert_pem, *key_pem);
            std::printf("websrt-gateway: mkcert identity loaded; browser uses normal PKI\n");
        }
        else
        {
            cert = websrt::gateway::CertProvider();
            std::printf("websrt-gateway: WebTransport cert DER SHA-256: %s\n", cert.Sha256Hex().c_str());
        }
    }
    catch (const websrt::gateway::CertError& e)
    {
        std::fprintf(stderr, "websrt-gateway: cert error: %s\n", e.what());
        return 1;
    }
    std::fflush(stdout);

    // Per-session TSBPD latency stays at the registry's 10 ms floor (the
    // Rust SrtConfig default, srt_sender.rs:58-59): a client couples with
    // the gateway, not with the publisher. [server].latency_ms is the
    // SRT/UDP ingest knob only.
    websrt::gateway::Gateway gateway(cert, policy, gateway_config);
    if (!gateway.Start(wt_bind, wt_bind_port))
    {
        std::fprintf(stderr, "websrt-gateway: cannot serve WebTransport on %s:%u\n", wt_bind.c_str(), wt_bind_port);
        return 1;
    }
    // One line per bound service at boot, so a startup log answers "what
    // is this process actually listening on?" without reading the config.
    std::printf("websrt-gateway: WebTransport on %s:%u\n", wt_bind.c_str(), wt_bind_port);
    std::fflush(stdout);

    // SRT/UDP ingest (P3 step 5). The ingest owns an ordinary stock libsrt
    // socket on a real UDP port and feeds the SAME broadcaster ring as a WT
    // publisher; it posts every framed message onto the gateway loop and
    // claims/releases the publisher slot there, so first-wins occupancy is
    // shared with WT publishers. It is owned by a scope that ends BEFORE
    // gateway.Shutdown(): its posts ride that loop.
    std::optional<websrt::gateway::SrtIngest> ingest;
    if (ingest_port != 0)
    {
        websrt::gateway::SrtIngestConfig ingest_config;
        ingest_config.bind       = ingest_bind;
        ingest_config.port       = ingest_port;
        ingest_config.latency_ms = ingest_latency_ms;
        ingest_config.passphrase = ingest_passphrase;

        websrt::gateway::SrtIngest::Sink sink;
        // Publish gate = the policy half of the WT accept path: the gateway
        // consults the CURRENT policy (hot-reloadable, P4.1) through a
        // synthetic ?publish= request - an unconfigured name, publish=false,
        // or a token-protected entry the streamid cannot present refuses
        // the connection.
        sink.publish_gate = [&gateway](const std::string& name) { return gateway.PublishAllowed(name); };
        // Admission + media + teardown all run on the gateway loop.
        sink.claim   = [&gateway](const std::string& name) { return gateway.ClaimIngestPublish(name); };
        sink.publish = [&gateway](const std::string& name, const void* data, std::size_t len)
        { gateway.PublishMedia(name, data, len); };
        sink.release = [&gateway](const std::string& name) { gateway.ReleaseIngestPublish(name); };
        // P4.3: the ingest's publisher_connect/disconnect ride the SAME
        // dispatcher the WT session lifecycle notifies through.
        sink.webhook = [&gateway](const websrt::gateway::WebhookEvent& event) { gateway.NotifyWebhook(event); };

        ingest.emplace(std::move(ingest_config), std::move(sink), gateway.Loop());
        std::string ingest_error;
        if (!ingest->Start(&ingest_error))
        {
            std::fprintf(stderr, "websrt-gateway: SRT ingest error: %s\n", ingest_error.c_str());
            gateway.Shutdown();
            return 1;
        }
        std::printf("websrt-gateway: SRT/UDP ingest on %s:%u (passphrase: %s, latency %llu ms)\n",
                    ingest_bind.c_str(),
                    ingest_port,
                    ingest_passphrase.has_value() ? "set" : "none",
                    static_cast<unsigned long long>(ingest_latency_ms));
        std::fflush(stdout);
    }

    // cert-hash.js, served DYNAMICALLY by the web server (never written
    // to disk, the oracle's shape): the page reads window.CERT_HASH +
    // window.WT_PORT from it, and in self mode the hash changes every
    // boot, so viewers must reload the page after a restart.
    const std::string cert_hash_js = cert.BuildCertHashJs(wt_bind_port);

    // The web server (the player) and the health endpoint. Both borrow the
    // gateway and the ingest, so they are torn down BEFORE gateway.Shutdown():
    // their stats snapshot rides a Post onto the gateway loop.
    std::optional<websrt::gateway::WebServer> web;
    std::optional<websrt::gateway::WebServer> health;
    const websrt::gateway::Gateway*           gateway_ptr = &gateway;
    const websrt::gateway::SrtIngest*         ingest_ptr  = ingest.has_value() ? &*ingest : nullptr;

    if (web_port != 0)
    {
        // web_root is an override; unset serves the embedded player.
        const std::string served_root = web_root.value_or(std::string("<embedded player>"));
        web.emplace(websrt::gateway::WebServerConfig{.bind            = web_bind,
                                                     .port            = web_port,
                                                     .cert            = web_tls ? &cert : nullptr,
                                                     .web_root        = web_root.value_or(std::string()),
                                                     .cert_hash_js    = cert_hash_js,
                                                     .serve_player    = true,
                                                     .gateway         = gateway_ptr,
                                                     .ingest          = ingest_ptr,
                                                     .max_connections = 16});
        std::string web_error;
        if (!web->Start(&web_error))
        {
            std::fprintf(stderr, "websrt-gateway: web server error: %s\n", web_error.c_str());
            if (ingest.has_value())
            {
                ingest->Stop();
            }
            gateway.Shutdown();
            return 1;
        }
        std::printf("websrt-gateway: cert-hash.js served at /cert-hash.js (%s)\n",
                    cert.PinnedHash() ? "pinned hash" : "null (PKI)");
        if (web_tls)
        {
            std::printf("websrt-gateway: web server (HTTPS) on %s:%u, root %s\n",
                        web_bind.c_str(),
                        web->Port(),
                        served_root.c_str());
        }
        else
        {
            // Closed-network mode: the page goes out over plain HTTP (a
            // browser treats http://127.0.0.1 and LAN pages as secure
            // contexts). Only the page port is affected - the WebTransport
            // listener above is still TLS, pinned via cert-hash.js.
            std::printf("websrt-gateway: web server (HTTP, closed-network) on %s:%u, root %s\n",
                        web_bind.c_str(),
                        web->Port(),
                        served_root.c_str());
        }
        std::fflush(stdout);
    }

    if (web_port == 0)
    {
        // Said explicitly so the boot log answers "is the player being
        // served?" without cross-referencing the config.
        std::printf("websrt-gateway: web server off (no [server].web_root; the C++ gateway builds no player)\n");
        std::fflush(stdout);
    }

    if (health_port != 0)
    {
        // The Rust gateway warns when metrics are bound off loopback
        // (main.rs:466-471); the same exposure applies here.
        if (health_bind != "127.0.0.1" && health_bind != "localhost" && health_bind != "::1")
        {
            std::fprintf(stderr,
                         "websrt-gateway: WARNING: health server bound to %s; metrics will be visible on the "
                         "network\n",
                         health_bind.c_str());
        }
        health.emplace(websrt::gateway::WebServerConfig{.bind            = health_bind,
                                                        .port            = health_port,
                                                        .cert            = nullptr,
                                                        .web_root        = {},
                                                        .gateway         = gateway_ptr,
                                                        .ingest          = ingest_ptr,
                                                        .max_connections = 16});
        std::string health_error;
        if (!health->Start(&health_error))
        {
            std::fprintf(stderr, "websrt-gateway: health server error: %s\n", health_error.c_str());
            if (web.has_value())
            {
                web->Stop();
            }
            if (ingest.has_value())
            {
                ingest->Stop();
            }
            gateway.Shutdown();
            return 1;
        }
        std::printf(
            "websrt-gateway: health/stats (HTTP) on %s:%u (/health, /stats)\n", health_bind.c_str(), health->Port());
        std::fflush(stdout);
    }

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    std::signal(SIGHUP, OnReloadSignal);
    while (g_stop == 0)
    {
        if (g_reload != 0)
        {
            g_reload = 0;
            if (config_path.has_value())
            {
                // P4.1 hot reload. ReloadConfig re-parses and validates
                // BEFORE swapping; on failure the old config stays active
                // and the gateway stays healthy.
                std::string reload_error;
                if (const auto reloaded =
                        websrt::gateway::ReloadConfig(*config_path, gateway, live_config, &reload_error))
                {
                    live_config = std::move(*reloaded);
                }
            }
            else
            {
                std::fprintf(stderr, "websrt-gateway: SIGHUP ignored: no config file (open mode)\n");
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    std::fprintf(stderr, "websrt-gateway: signal received, draining\n");
    if (ingest.has_value())
    {
        ingest->Stop(); // closes the publishers, releases their claims
    }
    // The HTTP endpoints go down with the ingest and BEFORE the gateway
    // loop: a /health answered mid-shutdown would ride a Post onto a loop
    // that is on its way out. Stopping them here also means a drained
    // gateway has already stopped answering metrics, which is what an
    // operator watching /health during a restart expects.
    if (health.has_value())
    {
        health->Stop();
    }
    if (web.has_value())
    {
        web->Stop();
    }
    gateway.Shutdown();
    return 0;
}

void Usage()
{
    std::fprintf(stderr,
                 "usage: websrt-gateway [--selftest] [--config FILE] [--log-level LEVEL]\n"
                 "\n"
                 "  --log-level LEVEL  lsquic diagnostic logging on stderr (e.g. debug, info,\n"
                 "                     warn, error, none). Off when omitted.\n");
}

} // namespace

int main(int argc, char** argv)
{
    bool                       selftest = false;
    std::optional<std::string> config_path;
    std::optional<std::string> log_level;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--selftest") == 0)
        {
            selftest = true;
        }
        else if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc)
        {
            config_path = argv[++i];
        }
        else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
        {
            log_level = argv[++i];
        }
        else
        {
            Usage();
            return 2;
        }
    }

    if (selftest)
    {
        return websrt::gateway::RunSelftest();
    }
    return Run(config_path, log_level);
}