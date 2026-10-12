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
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"
#include "gateway/ingest/srt_ingest.h"
#include "gateway/policy.h"
#include "gateway/selftest.h"
#include "gateway/web_server.h"

namespace
{

// Set from the signal handler; the run loop polls it. sig_atomic_t is the
// only type a handler may portably touch.
volatile std::sig_atomic_t g_stop = 0;

extern "C" void OnSignal(int /*signo*/)
{
    g_stop = 1;
}

int Run(const std::optional<std::string>& config_path)
{
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
        wt_bind_port                           = s.wt_port;
        wt_bind                                = s.wt_bind;
        ingest_port                            = s.srt_ingest_port;
        ingest_bind                            = s.srt_ingest_bind;
        ingest_latency_ms                      = s.latency_ms;
        ingest_passphrase                      = s.srt_passphrase;
        health_port                            = s.health_port;
        health_bind                            = s.health_bind;
        web_port                               = s.web_port;
        web_bind                               = s.web_bind;
        web_root                               = s.web_root;
        std::printf("websrt-gateway: config: %zu stream(s), allowlist mode "
                    "(wt %s:%u, srt ingest %s:%u, health %s:%u, web %s:%u, max_viewers %u, "
                    "broadcast_capacity %u)\n",
                    config.streams.size(),
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
    }
    else
    {
        // No config: open mode (Rust-oracle parity for dev/tests) with a
        // loud warning. Any stream name is accepted; only the fixed /wt
        // path is enforced.
        std::fprintf(stderr,
                     "websrt-gateway: WARNING: open mode: no allowlist configured - any stream name accepted\n");
        policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                        std::make_shared<websrt::gateway::AcceptAll>());
        std::printf("websrt-gateway: config: 0 stream(s), open mode\n");
        // web_port/health_port stay 0 without a config file: there is no
        // web_root to serve and no reason to expose metrics. Both are
        // [server] keys (defaults 5173 / 0, and web_port is forced to 0
        // whenever web_root is absent - the root is what turns it on).
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
        // Publish gate = the policy half of the WT accept path: ask the very
        // policy the WebTransport publisher is judged by whether this
        // streamid may publish at all (a synthetic ?publish= request; an
        // unconfigured name, publish=false, or a token-protected entry the
        // streamid cannot present refuses the connection).
        sink.publish_gate = [policy](const std::string& name)
        {
            // Named string: SessionRequest::query is a string_view, so a
            // temporary spliced straight into it would dangle before Decide
            // reads it.
            const std::string               query = "publish=" + websrt::gateway::PercentEncodeQueryValue(name);
            websrt::gateway::SessionRequest req;
            req.path  = "/wt";
            req.query = query;
            return policy->Decide(req) == websrt::gateway::Decision::Accept;
        };
        // Admission + media + teardown all run on the gateway loop.
        sink.claim   = [&gateway](const std::string& name) { return gateway.ClaimIngestPublish(name); };
        sink.publish = [&gateway](const std::string& name, const void* data, std::size_t len)
        { gateway.PublishMedia(name, data, len); };
        sink.release = [&gateway](const std::string& name) { gateway.ReleaseIngestPublish(name); };

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

    // cert-hash.js, written into the served root BEFORE the web server
    // starts, exactly as the Rust gateway does (main.rs:361-400): the page
    // reads window.CERT_HASH + window.WT_PORT from it, and in self mode the
    // hash changes every boot, so viewers must reload the page after a
    // restart. Regenerated unconditionally - the file is runtime state,
    // never committed, and the certificates themselves are never written.
    if (web_port != 0 && web_root.has_value())
    {
        const std::string hash_path = *web_root + "/cert-hash.js";
        try
        {
            cert.WriteCertHashJs(hash_path, wt_bind_port);
        }
        catch (const websrt::gateway::CertError& e)
        {
            std::fprintf(stderr, "websrt-gateway: %s\n", e.what());
            gateway.Shutdown();
            return 1;
        }
        std::printf("websrt-gateway: cert-hash.js -> %s (%s)\n",
                    hash_path.c_str(),
                    cert.PinnedHash() ? "pinned hash" : "null (PKI)");
        std::fflush(stdout);
    }

    // The web server (the player) and the health endpoint. Both borrow the
    // gateway and the ingest, so they are torn down BEFORE gateway.Shutdown():
    // their stats snapshot rides a Post onto the gateway loop.
    std::optional<websrt::gateway::WebServer> web;
    std::optional<websrt::gateway::WebServer> health;
    const websrt::gateway::Gateway*           gateway_ptr = &gateway;
    const websrt::gateway::SrtIngest*         ingest_ptr  = ingest.has_value() ? &*ingest : nullptr;

    if (web_port != 0 && web_root.has_value())
    {
        web.emplace(websrt::gateway::WebServerConfig{.bind            = web_bind,
                                                     .port            = web_port,
                                                     .cert            = &cert,
                                                     .web_root        = *web_root,
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
        std::printf(
            "websrt-gateway: web server (HTTPS) on %s:%u, root %s\n", web_bind.c_str(), web->Port(), web_root->c_str());
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
    while (g_stop == 0)
    {
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
    std::fprintf(stderr, "usage: websrt-gateway [--selftest] [--config FILE]\n");
}

} // namespace

int main(int argc, char** argv)
{
    bool                       selftest = false;
    std::optional<std::string> config_path;
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
    return Run(config_path);
}