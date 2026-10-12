// websrt-gateway: CLI-parity C++ replacement of the Rust WebSRT gateway.
// Thin CLI over the websrtgw core library (refinement item 1): argument
// wiring lives here, gateway machinery lives in src/gateway/. --selftest is
// the ctest smoke entry (the consumer gate); --config FILE loads the
// stream-allowlist TOML (refinement item 2).
//
// P3 IN PROGRESS: startup beyond config + cert handling is not implemented
// yet (the accept loop arrives with later P3 steps) - main() deliberately
// binds nothing, writes no cert-hash.js, and exits 0 after logging the
// cert line.

#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/policy.h"
#include "gateway/selftest.h"

namespace
{

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
        std::printf("websrt-gateway: config: %zu stream(s), allowlist mode "
                    "(wt %s:%u, srt ingest %s:%u, health %s:%u, web %s:%u, max_viewers %u)\n",
                    config.streams.size(),
                    s.wt_bind.c_str(),
                    s.wt_port,
                    s.srt_ingest_bind.c_str(),
                    s.srt_ingest_port,
                    s.health_bind.c_str(),
                    s.health_port,
                    s.web_bind.c_str(),
                    s.web_port,
                    s.max_viewers);
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
        std::fflush(stdout);
    }

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

    (void)policy; // handed to the accept loop when P3 wires it in
    (void)cert;   // handed to the WT server/web server when P3 wires them in

    std::fprintf(stderr, "websrt-gateway: server startup not implemented yet (P3 in progress); exiting\n");
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
