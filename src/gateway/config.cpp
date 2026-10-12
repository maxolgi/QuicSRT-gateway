// TOML configuration parsing (toml++ v3.4.0, deps/tomlplusplus). Strict by
// design: unknown keys are errors listing key and table; validation errors
// carry the table/key context (libwebsrt validate() discipline).

#include "gateway/config.h"

#include <fstream>
#include <ios>
#include <iterator>
#include <set>

#include <toml++/toml.hpp>

namespace websrt::gateway
{

namespace
{

using Table = const toml::table;

[[nodiscard]] std::string At(const toml::node& node)
{
    const toml::source_position p = node.source().begin;
    return " (line " + std::to_string(p.line) + ")";
}

/// Require a non-empty string.
std::string ReqString(Table& table, const char* key, const std::string& ctx)
{
    const toml::node* node = table.get(key);
    if (node == nullptr)
    {
        throw ConfigError(ctx + ": '" + key + "' is required");
    }
    if (!node->is_string())
    {
        throw ConfigError(ctx + ": '" + key + "' must be a string" + At(*node));
    }
    std::string v = node->as_string()->get();
    if (v.empty())
    {
        throw ConfigError(ctx + ": '" + key + "' must not be empty" + At(*node));
    }
    return v;
}

/// Optional string (null/absent -> nullopt); must be non-empty when present.
std::optional<std::string> OptString(Table& table, const char* key, const std::string& ctx)
{
    const toml::node* node = table.get(key);
    if (node == nullptr)
    {
        return std::nullopt;
    }
    if (!node->is_string())
    {
        throw ConfigError(ctx + ": '" + key + "' must be a string" + At(*node));
    }
    std::string v = node->as_string()->get();
    if (v.empty())
    {
        throw ConfigError(ctx + ": '" + key + "' must not be empty when present" + At(*node));
    }
    return v;
}

/// Optional integer within [min, max].
std::uint64_t OptInt(
    Table& table, const char* key, const std::string& ctx, std::uint64_t fallback, std::uint64_t min, std::uint64_t max)
{
    const toml::node* node = table.get(key);
    if (node == nullptr)
    {
        return fallback;
    }
    if (!node->is_integer())
    {
        throw ConfigError(ctx + ": '" + key + "' must be an integer" + At(*node));
    }
    const std::int64_t v = node->as_integer()->get();
    if (v < static_cast<std::int64_t>(min) || v > static_cast<std::int64_t>(max))
    {
        throw ConfigError(ctx + ": '" + key + "' must be between " + std::to_string(min) + " and " +
                          std::to_string(max) + ", got " + std::to_string(v));
    }
    return static_cast<std::uint64_t>(v);
}

/// Optional boolean (null/absent -> fallback).
bool OptBool(Table& table, const char* key, const std::string& ctx, bool fallback)
{
    const toml::node* node = table.get(key);
    if (node == nullptr)
    {
        return fallback;
    }
    if (!node->is_boolean())
    {
        throw ConfigError(ctx + ": '" + key + "' must be a boolean" + At(*node));
    }
    return node->as_boolean()->get();
}

std::string JoinKnown(const std::set<std::string>& known)
{
    std::string out;
    for (auto it = known.begin(); it != known.end(); ++it)
    {
        if (it != known.begin())
        {
            out += ", ";
        }
        out += *it;
    }
    return out;
}

/// Every key in `table` must be in `known`, else ConfigError naming key and
/// table (strict parsing).
void CheckKnownKeys(Table& table, const std::set<std::string>& known, const std::string& ctx)
{
    for (auto&& [key, value] : table)
    {
        if (known.find(std::string(key.str())) == known.end())
        {
            throw ConfigError(ctx + ": unknown key '" + std::string(key.str()) + "'" + At(value) +
                              " (known keys: " + JoinKnown(known) + ")");
        }
    }
}

ServerConfig ParseServer(Table& table)
{
    static const std::set<std::string> kKnown = {"wt_port",
                                                 "wt_bind",
                                                 "srt_ingest_port",
                                                 "srt_ingest_bind",
                                                 "latency_ms",
                                                 "max_bandwidth_kbps",
                                                 "health_port",
                                                 "health_bind",
                                                 "web_port",
                                                 "web_bind",
                                                 "web_root",
                                                 "web_tls",
                                                 "max_viewers",
                                                 "broadcast_capacity",
                                                 "cert_mode",
                                                 "cert_pem",
                                                 "key_pem",
                                                 "srt_passphrase",
                                                 "log_level"};
    CheckKnownKeys(table, kKnown, "[server]");

    ServerConfig s;
    s.wt_port = static_cast<std::uint16_t>(OptInt(table, "wt_port", "[server]", s.wt_port, 1, 65535));
    s.wt_bind = OptString(table, "wt_bind", "[server]").value_or(s.wt_bind);
    s.srt_ingest_port =
        static_cast<std::uint16_t>(OptInt(table, "srt_ingest_port", "[server]", s.srt_ingest_port, 1, 65535));
    s.srt_ingest_bind = OptString(table, "srt_ingest_bind", "[server]").value_or(s.srt_ingest_bind);
    // PLAN.md: gateway-side TSBPD floor is 10 ms.
    s.latency_ms         = OptInt(table, "latency_ms", "[server]", s.latency_ms, 10, 60000);
    s.max_bandwidth_kbps = OptInt(table, "max_bandwidth_kbps", "[server]", s.max_bandwidth_kbps, 0, 1'000'000'000ULL);
    s.health_port = static_cast<std::uint16_t>(OptInt(table, "health_port", "[server]", s.health_port, 0, 65535));
    s.health_bind = OptString(table, "health_bind", "[server]").value_or(s.health_bind);
    s.web_port    = static_cast<std::uint16_t>(OptInt(table, "web_port", "[server]", s.web_port, 0, 65535));
    s.web_bind    = OptString(table, "web_bind", "[server]").value_or(s.web_bind);
    // The static root the web server serves. Absent = no static serving
    // at all: the gateway builds no web app, so there is nothing to serve
    // until an operator points it at a built web/dist.
    s.web_root = OptString(table, "web_root", "[server]");
    if (!s.web_root.has_value())
    {
        // The root is what turns the knob on: with no web_root there is
        // nothing to serve, so web_port goes off (the Rust binary embeds
        // web/dist at compile time and never faces the question). Setting
        // web_port alone therefore just means "off", which the CLI's boot
        // log reports explicitly - it is not a startup error.
        s.web_port = 0;
    }
    // Plain-HTTP page serving is the closed-network deployment mode: the
    // WT listener keeps its TLS either way, so nothing about the handshake
    // depends on this.
    s.web_tls     = OptBool(table, "web_tls", "[server]", s.web_tls);
    s.max_viewers = static_cast<std::uint32_t>(OptInt(table, "max_viewers", "[server]", s.max_viewers, 1, 1'000'000));
    s.broadcast_capacity = static_cast<std::uint32_t>(
        OptInt(table, "broadcast_capacity", "[server]", s.broadcast_capacity, 1, 10'000'000));
    s.cert_mode = OptString(table, "cert_mode", "[server]").value_or(s.cert_mode);
    if (s.cert_mode != "self" && s.cert_mode != "mkcert")
    {
        throw ConfigError(R"([server]: 'cert_mode' must be "self" or "mkcert", got ")" + s.cert_mode + "\"");
    }
    s.cert_pem       = OptString(table, "cert_pem", "[server]");
    s.key_pem        = OptString(table, "key_pem", "[server]");
    s.srt_passphrase = OptString(table, "srt_passphrase", "[server]");
    if (s.cert_mode == "mkcert" && (!s.cert_pem.has_value() || !s.key_pem.has_value()))
    {
        throw ConfigError("[server]: cert_mode = \"mkcert\" requires both cert_pem and key_pem");
    }
    if (s.srt_passphrase.has_value())
    {
        const std::size_t len = s.srt_passphrase->size();
        if (len < 10 || len > 79)
        {
            throw ConfigError("[server]: 'srt_passphrase' must be 10-79 characters, got " + std::to_string(len));
        }
    }
    s.log_level = OptString(table, "log_level", "[server]");
    if (s.log_level.has_value())
    {
        // The exact set lsquic_set_log_level understands (lsquic_logger.c
        // lsquic_str_to_log_level); a typo must fail the parse, not silently
        // leave the level unchanged (lsquic_set_log_level returns -1).
        static const std::set<std::string> kLevels = {
            "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug"};
        if (kLevels.find(*s.log_level) == kLevels.end())
        {
            throw ConfigError("[server]: 'log_level' must be one of emerg, alert, crit, error, warn, notice, "
                              "info, debug, got \"" +
                              *s.log_level + "\"");
        }
    }
    return s;
}

StreamConfig ParseStream(Table& table, std::size_t index)
{
    const std::string                  ctx    = "[[stream]] #" + std::to_string(index + 1);
    static const std::set<std::string> kKnown = {"name", "publish", "subscribe", "token"};
    CheckKnownKeys(table, kKnown, ctx);

    StreamConfig st;
    st.name      = ReqString(table, "name", ctx);
    st.publish   = OptBool(table, "publish", ctx, true);
    st.subscribe = OptBool(table, "subscribe", ctx, true);
    st.token     = OptString(table, "token", ctx);
    return st;
}

} // namespace

Config ParseConfig(std::string_view text, const std::string& source)
{
    toml::table root;
    try
    {
        root = toml::parse(text, source);
    }
    catch (const toml::parse_error& e)
    {
        throw ConfigError(source + ": " + e.what() + " (line " + std::to_string(e.source().begin.line) + ")");
    }

    Config config;
    for (auto&& [key, value] : root)
    {
        if (key.str() == "server")
        {
            if (!value.is_table())
            {
                throw ConfigError("'server' must be a table ([server])" + At(value));
            }
            config.server = ParseServer(*value.as_table());
        }
        else if (key.str() == "stream")
        {
            if (!value.is_array_of_tables())
            {
                throw ConfigError("'stream' must be an array of tables ([[stream]])" + At(value));
            }
            std::size_t index = 0;
            for (auto&& entry : *value.as_array())
            {
                config.streams.push_back(ParseStream(*entry.as_table(), index++));
            }
        }
        else
        {
            throw ConfigError("unknown key '" + std::string(key.str()) + "'" + At(value) +
                              " at top level (expected [server] or [[stream]])");
        }
    }

    std::set<std::string> seen;
    for (const StreamConfig& st : config.streams)
    {
        if (!seen.insert(st.name).second)
        {
            throw ConfigError("duplicate [[stream]] name '" + st.name +
                              "' (globs may overlap; exact duplicates are bugs)");
        }
    }
    return config;
}

Config LoadConfig(const std::string& path)
{
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        throw ConfigError("cannot open config file '" + path + "'");
    }
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return ParseConfig(text, path);
}

std::shared_ptr<StreamAllowlistPolicy> BuildAllowlistPolicy(const Config& config)
{
    std::vector<StreamAclEntry> entries;
    entries.reserve(config.streams.size());
    for (const StreamConfig& st : config.streams)
    {
        entries.push_back(StreamAclEntry{
            .name_pattern = st.name, .allow_publish = st.publish, .allow_subscribe = st.subscribe, .token = st.token});
    }
    return std::make_shared<StreamAllowlistPolicy>(std::move(entries));
}

} // namespace websrt::gateway
