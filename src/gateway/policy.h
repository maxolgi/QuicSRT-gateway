// Session-acceptance policy seam for the gateway - a faithful port of the
// Rust oracle's crates/websrt/src/hooks.rs (P3 step 2, refinement items 1+2).
//
// Each incoming WebTransport session is shown to a SessionPolicy, which
// decides whether to accept or reject it. The library ships the four
// built-in policies from the oracle (PathPolicy, OriginAllowlistPolicy,
// AuthTokenPolicy, AcceptAll) composable via Chain(), plus the
// StreamAllowlistPolicy from refinement item 2 (exact+glob stream names,
// publish/subscribe roles, per-stream token).
//
// Thread-safety: Decide() is const and implementations are immutable after
// construction - built once at startup and consulted from the accept loop.
// Implementations must not block.

#ifndef WEBSRT_GATEWAY_POLICY_H
#define WEBSRT_GATEWAY_POLICY_H

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace quicsrt::gateway
{

/// Decision returned by SessionPolicy::Decide(). The rejection variants map
/// onto the WebTransport CONNECT responses the Rust oracle sends:
///   Reject          -> 404 Not Found        (unknown paths or missing streams)
///   Forbidden       -> 403 Forbidden        (failed auth, disallowed origin/role)
///   TooManyRequests -> 429 Too Many Requests (rate limits, connection caps)
enum class Decision : std::uint8_t
{
    Accept,
    Reject,
    Forbidden,
    TooManyRequests
};

/// Remote peer socket address (the Rust oracle carries std::net::SocketAddr).
struct SocketAddress
{
    std::string_view host;
    std::uint16_t    port = 0;
};

/// Information about an incoming WebTransport session request. Built by the
/// gateway from the lsquic/WT handshake and passed to SessionPolicy::Decide.
/// All strings are borrowed - the request outlives the Decide() call only.
struct SessionRequest
{
    /// Path portion of the URL (everything before '?').
    std::string_view path;
    /// Query string (everything after '?'; empty if no '?').
    std::string_view query;
    /// Origin header value if the client sent one.
    std::optional<std::string_view> origin;
    /// Authority (HTTP/3 ':authority' pseudo-header; comparable to Host).
    std::string_view authority;
    /// User-Agent header value if the client sent one.
    std::optional<std::string_view> user_agent;
    /// All HTTP/3 request headers as a string multimap (repeatable header
    /// names); null when the caller has not populated headers. Policies must
    /// not require it - the built-ins use only the fields above.
    const std::multimap<std::string, std::string>* headers = nullptr;
    /// Remote peer socket address.
    SocketAddress remote_address{};

    /// Extract a percent-decoded query parameter value. Nullopt if absent.
    [[nodiscard]] std::optional<std::string> QueryParam(std::string_view key) const;
};

/// Extract a percent-decoded query parameter value from a `key=value&...`
/// query string. Port of hooks.rs parse_query_param: the value is
/// percent-decoded (invalid `%xx` escapes pass through literally, `+` is
/// NOT a space) and then UTF-8 lossy-decoded (invalid sequences become
/// U+FFFD). Returns nullopt if the key is absent; a bare `key` with no `=`
/// yields the empty string.
[[nodiscard]] std::optional<std::string> ParseQueryParam(std::string_view query, std::string_view key);

/// Percent-encode `value` so that ParseQueryParam returns it back unchanged
/// when it is spliced into `key=value`. '%', '&', '=', '#', '+', '?' and
/// every byte outside printable ASCII become %XX. The SRT/UDP ingest uses it
/// to reuse the WT publish decision on a synthetic request (its streamid
/// arrives out-of-band, not in a query).
[[nodiscard]] std::string PercentEncodeQueryValue(std::string_view value);

/// Constant-time string equality: the accumulation has no data-dependent
/// branch or early exit, so token validation leaks no timing side-channel
/// (the C++ counterpart of subtle::ConstantTimeEq in AuthTokenPolicy).
/// Runtime scales with the longer input - length is not treated as secret.
[[nodiscard]] bool ConstantTimeEquals(std::string_view a, std::string_view b) noexcept;

/// Glob match used by StreamAllowlistPolicy name patterns: `*` matches any
/// sequence of characters (including empty), `?` matches exactly one
/// character, everything else matches literally. Case-sensitive; patterns
/// are matched against the raw (percent-decoded) stream name.
[[nodiscard]] bool GlobMatch(std::string_view pattern, std::string_view name) noexcept;

/// Pluggable session-acceptance policy (the Rust oracle's `trait
/// SessionPolicy`; Decide is synchronous here because the accept loop calls
/// it inline). Type-erased composition happens through shared_ptr + Chain().
class SessionPolicy
{
public:
    virtual ~SessionPolicy() = default;

    /// Inspect `req` and return the Decision for it.
    [[nodiscard]] virtual Decision Decide(const SessionRequest& req) const = 0;
};

/// Compose two type-erased policies: accepts only if both accept; short-
/// circuits on the first rejection, propagating its variant (the oracle's
/// `chain`). The Rust generic Chain<A, B> maps onto shared_ptr erasure here
/// so the CLI can build chains at runtime from config.
[[nodiscard]] std::shared_ptr<SessionPolicy> Chain(std::shared_ptr<SessionPolicy> first,
                                                   std::shared_ptr<SessionPolicy> second);

/// Policy that accepts only if `req.path` equals the expected path (the
/// fixed `/wt` in this gateway). Mismatch -> Reject (404).
class PathPolicy final : public SessionPolicy
{
public:
    explicit PathPolicy(std::string expected);

    [[nodiscard]] Decision Decide(const SessionRequest& req) const override;

private:
    std::string m_expected;
};

/// Policy that accepts only if `req.origin` matches one of the allowed
/// origins. Requests with no Origin header are rejected (Forbidden).
class OriginAllowlistPolicy final : public SessionPolicy
{
public:
    explicit OriginAllowlistPolicy(std::vector<std::string> allowed);

    [[nodiscard]] Decision Decide(const SessionRequest& req) const override;

private:
    std::vector<std::string> m_allowed;
};

/// Policy that accepts only if `req.query` carries `?token=<expected>`.
/// The comparison is ConstantTimeEquals - no timing side-channel.
class AuthTokenPolicy final : public SessionPolicy
{
public:
    explicit AuthTokenPolicy(std::string expected);

    [[nodiscard]] Decision Decide(const SessionRequest& req) const override;

private:
    std::string m_expected;
};

/// Always-accept policy. Useful as the open-mode default (no --config) and
/// for testing.
class AcceptAll final : public SessionPolicy
{
public:
    [[nodiscard]] Decision Decide(const SessionRequest& req) const override;
};

/// One [[stream]] allowlist rule (refinement item 2). `name_pattern` is an
/// exact name or a glob ('*' any chars, '?' one char). Immutable after
/// construction - StreamAllowlistPolicy is built once at startup.
struct StreamAclEntry
{
    std::string                name_pattern;
    bool                       allow_publish   = true;
    bool                       allow_subscribe = true;
    std::optional<std::string> token; ///< optional per-stream ?token= (constant-time compare)
};

/// Stream access control: deny-by-default while entries are configured;
/// with NO entries every stream name is allowed, publish and subscribe
/// alike (a config file with no [[stream]] sections behaves like open
/// mode, but with the file's [server] settings). Routing mirrors the Rust
/// gateway's query shapes (`/wt?publish=NAME`, `/wt?stream=NAME` or
/// `/wt?subscribe=NAME`, optional `&token=`):
///   - publish request (`?publish=NAME`): no matching entry, an entry with
///     publish=false, or a token set on the entry and absent/mismatched in
///     the query -> Forbidden (403); otherwise Accept.
///   - subscribe request (`?stream=NAME`, else `?subscribe=NAME`): no
///     matching entry or subscribe=false -> Reject (404, unknown stream);
///     token rules likewise -> Forbidden (403); otherwise Accept.
///   - neither publish nor stream/subscribe present -> Reject.
///   - combined `?publish=X&stream=Y`: both legs are checked; the first
///     failure is returned.
/// The first entry whose pattern matches the (percent-decoded) name wins.
class StreamAllowlistPolicy final : public SessionPolicy
{
public:
    explicit StreamAllowlistPolicy(std::vector<StreamAclEntry> entries);

    [[nodiscard]] Decision Decide(const SessionRequest& req) const override;

private:
    [[nodiscard]] Decision DecidePublish(std::string_view name, const SessionRequest& req) const;
    [[nodiscard]] Decision DecideSubscribe(std::string_view name, const SessionRequest& req) const;

    std::vector<StreamAclEntry> m_entries;
};

} // namespace quicsrt::gateway

#endif // WEBSRT_GATEWAY_POLICY_H
