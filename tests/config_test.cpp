// Config units: strict TOML parsing of [server] + [[stream]] into Config,
// the StreamAllowlistPolicy built from it, and the error discipline
// (unknown keys, missing/bogus fields, validation ranges). Plain checks
// (not assert) so Release stays meaningful, following libwebsrt's style.

#include "gateway/config.h"

#include <cstdio>
#include <optional>
#include <string>

namespace
{

using websrt::gateway::BuildAllowlistPolicy;
using websrt::gateway::Config;
using websrt::gateway::ConfigError;
using websrt::gateway::Decision;
using websrt::gateway::LoadConfig;
using websrt::gateway::ParseConfig;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "config_test: FAIL: %s\n", what);
    }
    return cond;
}

websrt::gateway::SessionRequest Req(std::string_view query)
{
    websrt::gateway::SessionRequest req;
    req.path      = "/wt";
    req.query     = query;
    req.authority = "localhost:4433";
    return req;
}

/// Parse must throw; optionally the message must contain `needle`.
bool CheckThrows(const std::string& text, const char* what, const char* needle = nullptr)
{
    try
    {
        const Config ignored = ParseConfig(text, "test.conf");
        (void)ignored;
    }
    catch (const ConfigError& e)
    {
        if (needle != nullptr)
        {
            return Check(std::string(e.what()).find(needle) != std::string::npos, what);
        }
        return true;
    }
    return Check(false, what);
}

bool TestValidFullParse()
{
    const Config c = ParseConfig(R"toml(
[server]
wt_port = 8443
wt_bind = "0.0.0.0"
srt_ingest_port = 19000
srt_ingest_bind = "10.0.0.1"
latency_ms = 60
max_bandwidth_kbps = 250000
health_port = 9091
health_bind = "127.0.0.2"
web_port = 8080
web_bind = "0.0.0.0"
max_viewers = 50
cert_mode = "mkcert"
cert_pem = "cert.pem"
key_pem = "key.pem"
srt_passphrase = "0123456789"
log_level = "debug"

[[stream]]
name = "test"

[[stream]]
name = "priv-*"
publish = true
subscribe = true
token = "s3cret"

[[stream]]
name = "viewonly"
publish = false

[[stream]]
name = "cam?"
subscribe = false
)toml",
                                 "test.conf");
    Check(c.server.wt_port == 8443, "wt_port parsed");
    Check(c.server.wt_bind == "0.0.0.0", "wt_bind parsed");
    Check(c.server.srt_ingest_port == 19000, "srt_ingest_port parsed");
    Check(c.server.srt_ingest_bind == "10.0.0.1", "srt_ingest_bind parsed");
    Check(c.server.latency_ms == 60, "latency_ms parsed");
    Check(c.server.max_bandwidth_kbps == 250000, "max_bandwidth_kbps parsed");
    Check(c.server.health_port == 9091, "health_port parsed");
    Check(c.server.health_bind == "127.0.0.2", "health_bind parsed");
    Check(c.server.web_port == 8080, "web_port parsed");
    Check(c.server.web_bind == "0.0.0.0", "web_bind parsed");
    Check(c.server.max_viewers == 50, "max_viewers parsed");
    Check(c.server.cert_mode == "mkcert", "cert_mode parsed");
    Check(c.server.cert_pem == std::optional<std::string>("cert.pem"), "cert_pem parsed");
    Check(c.server.key_pem == std::optional<std::string>("key.pem"), "key_pem parsed");
    Check(c.server.srt_passphrase == std::optional<std::string>("0123456789"), "srt_passphrase parsed");
    Check(c.server.log_level == std::optional<std::string>("debug"), "log_level parsed");
    Check(c.streams.size() == 4, "stream count");
    Check(c.streams[0].name == "test" && c.streams[0].publish && c.streams[0].subscribe &&
              !c.streams[0].token.has_value(),
          "stream defaults (publish/subscribe true, no token)");
    Check(c.streams[1].token == std::optional<std::string>("s3cret"), "stream token parsed");
    Check(!c.streams[2].publish && c.streams[2].subscribe, "stream publish=false parsed");
    Check(c.streams[3].publish && !c.streams[3].subscribe, "stream subscribe=false parsed");
    Check(c.streams[3].name == "cam?", "glob name preserved verbatim");
    return true;
}

bool TestDefaults()
{
    const Config c = ParseConfig("", "test.conf");
    Check(c.server.wt_port == 4433, "default wt_port");
    Check(c.server.wt_bind == "127.0.0.1", "default wt_bind");
    Check(c.server.srt_ingest_port == 9000, "default srt_ingest_port");
    Check(c.server.latency_ms == 120, "default latency_ms");
    Check(c.server.max_bandwidth_kbps == 0, "default max_bandwidth_kbps");
    Check(c.server.health_port == 0, "default health_port");
    Check(c.server.web_port == 5173, "default web_port");
    Check(c.server.max_viewers == 16, "default max_viewers");
    Check(c.server.cert_mode == "self" && !c.server.cert_pem.has_value() && !c.server.key_pem.has_value(),
          "default cert mode");
    Check(!c.server.log_level.has_value(), "default: no log_level");
    Check(c.streams.empty(), "no streams by default");
    return true;
}

bool TestBuildPolicy()
{
    const Config c = ParseConfig(R"toml(
[[stream]]
name = "test"

[[stream]]
name = "priv-*"
token = "tok"

[[stream]]
name = "viewonly"
publish = false
)toml",
                                 "test.conf");
    const auto   p = BuildAllowlistPolicy(c);
    Check(p->Decide(Req("publish=test")) == Decision::Accept, "config policy publish allowed");
    Check(p->Decide(Req("publish=viewonly")) == Decision::Forbidden, "config policy publish role denied");
    Check(p->Decide(Req("publish=nope")) == Decision::Forbidden, "config policy publish no match");
    Check(p->Decide(Req("stream=test")) == Decision::Accept, "config policy subscribe allowed");
    Check(p->Decide(Req("stream=nope")) == Decision::Reject, "config policy subscribe no match");
    Check(p->Decide(Req("stream=priv-9&token=tok")) == Decision::Accept, "config policy subscribe token ok");
    Check(p->Decide(Req("stream=priv-9")) == Decision::Forbidden, "config policy subscribe token missing");
    return true;
}

bool TestInvalidToml()
{
    return CheckThrows("[server\nwt_port = 1\n", "invalid TOML -> clear error", "test.conf");
}

bool TestUnknownKeys()
{
    CheckThrows("[server]\nwt_prot = 4433\n", "unknown [server] key lists key+table", "unknown key 'wt_prot'");
    CheckThrows(
        "[[stream]]\nname = \"x\"\ntoken2 = \"y\"\n", "unknown [[stream]] key lists key+table", "unknown key 'token2'");
    CheckThrows("[bogus]\nx = 1\n", "unknown top-level table reported", "unknown key 'bogus'");
    return true;
}

bool TestMissingAndInvalidFields()
{
    CheckThrows("[[stream]]\npublish = true\n", "missing stream name", "'name' is required");
    CheckThrows("[[stream]]\nname = \"\"\n", "empty stream name", "must not be empty");
    CheckThrows("[[stream]]\nname = \"x\"\ntoken = \"\"\n", "empty stream token", "must not be empty");
    CheckThrows("[[stream]]\nname = \"x\"\nname2 = 1\n", "unknown stream key", "unknown key 'name2'");
    CheckThrows("[server]\nwt_port = \"x\"\n", "wt_port wrong type", "must be an integer");
    CheckThrows("[server]\nwt_port = 70000\n", "wt_port out of range", "between 1 and 65535");
    CheckThrows("[server]\nlatency_ms = 5\n", "latency below floor", "between 10 and 60000");
    CheckThrows("[server]\nmax_viewers = 0\n", "max_viewers zero", "between 1 and 1000000");
    CheckThrows(R"([server]
cert_mode = "magic"
)",
                "bad cert_mode",
                R"("self" or "mkcert")");
    CheckThrows("[server]\ncert_mode = \"mkcert\"\n", "mkcert without pems", "requires both cert_pem and key_pem");
    CheckThrows("[server]\nsrt_passphrase = \"short\"\n", "short passphrase", "10-79 characters");
    CheckThrows("[server]\nlog_level = \"chatty\"\n", "bad log_level lists valid values", "'log_level' must be one of");
    CheckThrows("[server]\nwt_bind = \"\"\n", "empty bind", "must not be empty");
    CheckThrows("stream = 3\n", "stream not array of tables", "array of tables");
    CheckThrows("[[stream]]\nname = \"x\"\n\n[[stream]]\nname = \"x\"\n",
                "duplicate stream name",
                "duplicate [[stream]] name 'x'");
    return true;
}

bool TestLoadConfigFile()
{
    try
    {
        const Config ignored = LoadConfig("definitely-missing-file.conf");
        (void)ignored;
    }
    catch (const ConfigError& e)
    {
        return Check(std::string(e.what()).find("cannot open") != std::string::npos, "missing file -> ConfigError");
    }
    return Check(false, "missing file -> ConfigError");
}

bool TestOpenModeDefault()
{
    // Documented CLI behavior: without --config main() builds
    // Chain(PathPolicy("/wt"), AcceptAll) - open mode accepts any stream
    // name. (The full composition matrix lives in policy_test's open-mode
    // section; this pins the config-side default that no file = no
    // allowlist.)
    const auto open = websrt::gateway::Chain(std::make_shared<websrt::gateway::PathPolicy>("/wt"),
                                             std::make_shared<websrt::gateway::AcceptAll>());
    Check(open->Decide(Req("stream=anything")) == Decision::Accept, "open mode accepts any stream name");
    return true;
}

} // namespace

int main()
{
    struct Section
    {
        const char* name;
        bool (*fn)();
    };

    const Section sections[] = {
        {.name = "valid-full-parse", .fn = TestValidFullParse},
        {.name = "defaults", .fn = TestDefaults},
        {.name = "build-policy", .fn = TestBuildPolicy},
        {.name = "invalid-toml", .fn = TestInvalidToml},
        {.name = "unknown-keys", .fn = TestUnknownKeys},
        {.name = "missing-invalid-fields", .fn = TestMissingAndInvalidFields},
        {.name = "load-config-file", .fn = TestLoadConfigFile},
        {.name = "open-mode-default", .fn = TestOpenModeDefault},
    };

    bool ok = true;
    for (const Section& section : sections)
    {
        ok = section.fn() && ok;
    }
    if (!ok)
    {
        return 1;
    }
    std::printf("config_test: all sections passed\n");
    return 0;
}
