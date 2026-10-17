// TOML configuration for the gateway CLI (refinement item 2): [server]
// scalars + [[stream]] allowlist entries, parsed strictly (unknown keys are
// errors) into a Config that can build a StreamAllowlistPolicy.
//
// This is a gateway-BINARY-side dependency by design: TOML parsing and
// --config live only in the CLI; embedded consumers of the websrtgw core
// library supply a SessionPolicy in code and never link toml++.

#ifndef WEBSRT_GATEWAY_CONFIG_H
#define WEBSRT_GATEWAY_CONFIG_H

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "gateway/policy.h"

namespace websrt::gateway
{

/// Parse/validation failure with context (file, table, key, line when
/// known). Thrown by ParseConfig/LoadConfig.
class ConfigError : public std::runtime_error
{
public:
    explicit ConfigError(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

/// [server] scalar knobs. Defaults mirror the Rust gateway CLI
/// (crates/websrt-gateway/src/main.rs). Rust CLI knobs deliberately
/// deferred (documented):
///   - no_gui / no_web                 binary-side flags; the C++ gateway
///                                     is CLI-only
///   - input / fixture*                Rust dev file-source; the C++ gateway
///                                      sources are SRT ingest + WT publish
///   - srt_mode / srt_call / srt_streamid  ingest here is always
///                                      listener-mode UDP; streamid comes
///                                      from the allowlist
///   - sim_loss / sim_seed             sim-loss feature not ported
///   - auth_token / allowed_origins    superseded by [[stream]] tokens; an
///                                      origin knob returns with its own key
///                                      when needed
struct ServerConfig
{
    std::uint16_t wt_port         = 4433;
    std::string   wt_bind         = "127.0.0.1";
    std::uint16_t srt_ingest_port = 9000;
    std::string   srt_ingest_bind = "127.0.0.1";
    std::uint64_t latency_ms =
        120; ///< SRT/UDP ingest TSBPD latency; per-session viewer latency is the fixed 10 ms floor (srt_sender.rs)
    std::uint64_t max_bandwidth_kbps     = 0;    ///< 0 = unlimited
    int           max_sessions_per_ip    = 10;   ///< WT sessions per peer IP, 0 = unlimited (Rust GatewayLimits)
    int           max_sessions           = 1000; ///< total WT sessions, 0 = unlimited
    int           wt_idle_timeout_s      = 10;   ///< WT idle timeout in seconds (1..600)
    int           wt_handshake_timeout_s = 10;   ///< QUIC/WT handshake budget in seconds (1..60)
    std::uint16_t health_port            = 0;    ///< 0 = disabled
    std::string   health_bind            = "127.0.0.1";
    std::uint16_t web_port               = 5173; ///< static web server, 0 disables
    std::string   web_bind               = "127.0.0.1";
    std::optional<std::string> web_root; ///< disk override of the embedded player; unset => embedded
    /// TLS on the static web server. false serves the player page over
    /// plain HTTP for the closed-network deployment, where a browser
    /// treats http://127.0.0.1 and LAN pages as secure contexts anyway.
    /// The WebTransport handshake is UNAFFECTED: it stays TLS and is
    /// pinned through the dynamically served cert-hash.js either way.
    bool                       web_tls            = true;
    std::uint32_t              max_viewers        = 16;     ///< per-stream viewer cap
    std::uint32_t              broadcast_capacity = 32768;  ///< per-stream broadcaster ring depth in messages
    std::string                cert_mode          = "self"; ///< "self" | "mkcert"
    std::optional<std::string> cert_pem;                    ///< mkcert mode: required
    std::optional<std::string> key_pem;                     ///< mkcert mode: required
    std::optional<std::string> srt_passphrase;              ///< SRT PBKEYLEN passphrase (10-79 chars)
    /// lsquic diagnostic log level, lsquic's own set ("emerg".."debug").
    /// Absent leaves the process default; the CLI --log-level flag
    /// overrides the file at boot. Runtime-swappable on SIGHUP reload
    /// (P4.1) - one of the reload-swappable settings besides the
    /// [[stream]] allowlist, max_viewers and [webhooks] (P4 step 3).
    std::optional<std::string> log_level;
};

/// One [[stream]] entry. `name` is an exact name or a glob ('*' any chars,
/// '?' one char) - matched against the percent-decoded stream name.
struct StreamConfig
{
    std::string                name;
    bool                       publish   = true;
    bool                       subscribe = true;
    std::optional<std::string> token; ///< optional per-stream ?token=
};

/// [webhooks] (P4 step 3, SLS names): on_event_url + timeout. Absent
/// table => empty url => the feature is off.
struct WebhooksConfig
{
    std::string   on_event_url;      ///< "http://host[:port][/path]"; empty = off
    std::uint64_t timeout_ms = 2000; ///< per-attempt POST timeout
};

/// Parsed configuration: server scalars + ordered stream allowlist + the
/// webhook knobs.
struct Config
{
    ServerConfig              server;
    std::vector<StreamConfig> streams;
    WebhooksConfig            webhooks;
};

/// Parse TOML text (source names errors). Throws ConfigError on invalid
/// TOML, unknown keys (reported with key and table), wrong types, and
/// validation failures (port ranges, latency floor, cert requirements,
/// non-empty name/token, passphrase length, duplicate names).
[[nodiscard]] Config ParseConfig(std::string_view text, const std::string& source);

/// Read + parse a config file. Throws ConfigError (including unreadable
/// file).
[[nodiscard]] Config LoadConfig(const std::string& path);

/// Build the StreamAllowlistPolicy from the config's [[stream]] entries,
/// in file order (first matching entry wins at decide time). A config with
/// no [[stream]] entries yields the empty policy, which allows every name.
[[nodiscard]] std::shared_ptr<StreamAllowlistPolicy> BuildAllowlistPolicy(const Config& config);

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_CONFIG_H
