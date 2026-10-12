// websrt-gateway: CLI-parity C++ replacement of the Rust WebSRT gateway.
// Thin CLI over the websrtgw core library (refinement item 1): argument
// wiring, TOML config, signal handling and the run-until-signalled loop live
// here; the accept loop, per-session SRT initiators and the broadcaster
// ring live in src/gateway/. --selftest is the ctest smoke entry (the
// consumer gate); --config FILE loads the stream-allowlist TOML
// (refinement item 2).
//
// P3 step 4: the WebTransport accept path, the ring and first-wins occupancy
// are live. NOT YET WIRED (later P3 steps, logged at startup when their
// config port is set): the SRT/UDP ingest (G6), the health/stats endpoint and
// the static web server (G7), and the cert-hash.js emission next to web/dist.

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
#include "gateway/policy.h"
#include "gateway/selftest.h"

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
    std::uint16_t                                   wt_bind_port = 4433;
    std::string                                     wt_bind      = "127.0.0.1";
    std::uint16_t                                   ingest_port  = 0;
    std::uint16_t                                   health_port  = 0;
    std::uint16_t                                   web_port     = 0;

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
        health_port                            = s.health_port;
        web_port                               = s.web_port;
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
    }
    std::fflush(stdout);

    if (ingest_port != 0)
    {
        std::fprintf(stderr,
                     "websrt-gateway: NOT YET IMPLEMENTED: the SRT/UDP ingest on port %u "
                     "(P3 step 5) is configured but will not listen\n",
                     ingest_port);
    }
    if (health_port != 0)
    {
        std::fprintf(stderr,
                     "websrt-gateway: NOT YET IMPLEMENTED: the health/stats endpoint on port %u "
                     "(P3 step 6) is configured but will not listen\n",
                     health_port);
    }
    if (web_port != 0)
    {
        std::fprintf(stderr,
                     "websrt-gateway: NOT YET IMPLEMENTED: the static web server on port %u "
                     "(P3 step 6) is configured but will not listen; no cert-hash.js is written\n",
                     web_port);
    }
    std::fflush(stderr);

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

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    while (g_stop == 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    std::fprintf(stderr, "websrt-gateway: signal received, draining\n");
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