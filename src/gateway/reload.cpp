// SIGHUP hot-reload implementation (P4.1). The signal handler itself only
// flips a sig_atomic_t flag (main.cpp); this function is everything behind
// it, so tests drive it directly. The swappable state rides ONE
// Gateway::ApplyRuntimeConfig post - no CONNECT can observe a half-applied
// reload. Since P4 step 3 the webhook settings ([webhooks], previously
// deferred) ride the same post.

#include "gateway/reload.h"

#include <cstdio>

#include "wt/client.h"

namespace websrt::gateway
{

namespace
{

/// Log one restart-required setting that changed. Everything a reload
/// cannot apply is bound into a socket, a TLS identity or a live ring at
/// Start() time - restart is the only way to pick the new value up.
void LogRestartRequired(const ServerConfig& old_s, const ServerConfig& new_s)
{
    const auto changed = [](const char* key, const std::string& was, const std::string& now)
    {
        if (was != now)
        {
            std::fprintf(stderr,
                         "websrt-gateway: reload: [server].%s changed %s -> %s; requires restart\n",
                         key,
                         was.c_str(),
                         now.c_str());
        }
    };
    const auto optstr = [](const std::optional<std::string>& v) { return v.value_or("(unset)"); };

    // WT listener: bound once at Start.
    changed("wt_port", std::to_string(old_s.wt_port), std::to_string(new_s.wt_port));
    changed("wt_bind", old_s.wt_bind, new_s.wt_bind);
    // SRT/UDP ingest: the listener socket, its latency-scaled buffers, its
    // passphrase and its admission cap ride the config copy taken at Start.
    changed("srt_ingest_port", std::to_string(old_s.srt_ingest_port), std::to_string(new_s.srt_ingest_port));
    changed("srt_ingest_bind", old_s.srt_ingest_bind, new_s.srt_ingest_bind);
    changed("latency_ms", std::to_string(old_s.latency_ms), std::to_string(new_s.latency_ms));
    changed("srt_passphrase", optstr(old_s.srt_passphrase), optstr(new_s.srt_passphrase));
    changed(
        "max_ingest_sessions", std::to_string(old_s.max_ingest_sessions), std::to_string(new_s.max_ingest_sessions));
    // TLS identity: built once at boot (self mode regenerates per boot,
    // mkcert loads the PEMs); a live engine keeps its SSL_CTX, and the
    // served cert-hash.js pins the identity the browsers already hold.
    changed("cert_mode", old_s.cert_mode, new_s.cert_mode);
    changed("cert_pem", optstr(old_s.cert_pem), optstr(new_s.cert_pem));
    changed("key_pem", optstr(old_s.key_pem), optstr(new_s.key_pem));
    // HTTP servers: bound (and cert-hash.js's dynamic route installed) at
    // Start; the WT listener's TLS pinning depends on that pairing.
    changed("health_port", std::to_string(old_s.health_port), std::to_string(new_s.health_port));
    changed("health_bind", old_s.health_bind, new_s.health_bind);
    changed("web_port", std::to_string(old_s.web_port), std::to_string(new_s.web_port));
    changed("web_bind", old_s.web_bind, new_s.web_bind);
    changed("web_root", optstr(old_s.web_root), optstr(new_s.web_root));
    changed("web_tls", old_s.web_tls ? "true" : "false", new_s.web_tls ? "true" : "false");
    // Broadcaster rings: the depth and the byte budget are fixed per
    // stream at creation; only a restart rebuilds every ring at one depth
    // and one budget.
    changed("broadcast_capacity", std::to_string(old_s.broadcast_capacity), std::to_string(new_s.broadcast_capacity));
    changed("broadcast_byte_budget",
            std::to_string(old_s.broadcast_byte_budget),
            std::to_string(new_s.broadcast_byte_budget));
    // WT admission limits + engine timeouts: the engine settings are built
    // once at Start and the tracker seeds at construction.
    changed(
        "max_sessions_per_ip", std::to_string(old_s.max_sessions_per_ip), std::to_string(new_s.max_sessions_per_ip));
    changed("max_sessions", std::to_string(old_s.max_sessions), std::to_string(new_s.max_sessions));
    changed("wt_idle_timeout_s", std::to_string(old_s.wt_idle_timeout_s), std::to_string(new_s.wt_idle_timeout_s));
    changed("wt_handshake_timeout_s",
            std::to_string(old_s.wt_handshake_timeout_s),
            std::to_string(new_s.wt_handshake_timeout_s));
    // max_bandwidth_kbps is deliberately absent: it is not wired into any
    // runtime path at boot either, so "requires restart" would be false -
    // a restart changes nothing about it.
}

} // namespace

std::optional<Config> ReloadConfig(const std::string& path, Gateway& gateway, const Config& current, std::string* error)
{
    Config next;
    try
    {
        next = LoadConfig(path);
    }
    catch (const ConfigError& e)
    {
        // The old config stays active; the gateway is healthy. Parse and
        // validation happen entirely BEFORE any swap, so a bad file cannot
        // leave the gateway half-reconfigured.
        if (error != nullptr)
        {
            *error = e.what();
        }
        std::fprintf(stderr, "websrt-gateway: reload failed, keeping the current config: %s\n", e.what());
        return std::nullopt;
    }

    // The swappable set. Policy + viewer cap + webhook settings land
    // atomically on the loop; the log level is process-wide state, applied
    // here.
    gateway.ApplyRuntimeConfig(Chain(std::make_shared<PathPolicy>("/wt"), BuildAllowlistPolicy(next)),
                               next.server.max_viewers,
                               WebhookSettings{.url     = next.webhooks.on_event_url,
                                               .timeout = std::chrono::milliseconds{next.webhooks.timeout_ms}});
    if (next.webhooks.on_event_url != current.webhooks.on_event_url)
    {
        std::fprintf(stderr,
                     "websrt-gateway: reload: webhooks -> %s\n",
                     next.webhooks.on_event_url.empty() ? "off" : next.webhooks.on_event_url.c_str());
    }
    if (next.server.log_level != current.server.log_level)
    {
        if (next.server.log_level.has_value())
        {
            websrt::SetLsquicLogLevel(next.server.log_level->c_str());
            std::fprintf(stderr, "websrt-gateway: reload: log level -> %s\n", next.server.log_level->c_str());
        }
        else
        {
            // No queryable "boot default" exists to revert to; the current
            // level stays until the next boot.
            std::fprintf(stderr,
                         "websrt-gateway: reload: log_level removed; keeping the current level "
                         "(restart to revert to the boot default)\n");
        }
    }
    LogRestartRequired(current.server, next.server);
    std::fprintf(stderr,
                 "websrt-gateway: config reloaded: %zu stream(s) (%s), max_viewers %u\n",
                 next.streams.size(),
                 next.streams.empty() ? "open mode, any name accepted" : "allowlist mode",
                 next.server.max_viewers);
    return next;
}

} // namespace websrt::gateway
