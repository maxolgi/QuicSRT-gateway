// websrt-gateway: CLI-parity C++ replacement of the Rust WebSRT gateway.
// Thin CLI over the websrtgw core library (refinement item 1): argument
// wiring lives here, gateway machinery lives in src/gateway/. --selftest is
// the ctest smoke entry (the consumer gate); --config FILE loads the
// stream-allowlist TOML (refinement item 2).
//
// P3 IN PROGRESS: startup beyond config handling is not implemented yet
// (the accept loop arrives with later P3 steps) - main() deliberately
// binds nothing and exits 0 after config handling.

#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>

#include "gateway/config.h"
#include "gateway/policy.h"
#include "gateway/selftest.h"

namespace
{

int Run(const std::optional<std::string>& config_path)
{
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
        policy = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                        websrt::gateway::BuildAllowlistPolicy(config));
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
    (void)policy; // handed to the accept loop when P3 wires it in

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
