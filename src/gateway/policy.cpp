// Session policy seam: implementation - see policy.h for the surface docs.

#include "gateway/policy.h"

#include <algorithm>

namespace quicsrt::gateway
{

namespace
{

/// Hex digit value or -1.
int HexVal(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

/// Append `bytes` to `out` as UTF-8 with lossy replacement (U+FFFD) - the
/// WHATWG decode_utf8_lossy semantics: each maximal ill-formed
/// subpart becomes exactly one replacement character. Valid sequences
/// (the table below rejects overlong forms, surrogates, > U+10FFFF and
/// stray continuations) are copied verbatim.
void AppendUtf8Lossy(std::string& out, const unsigned char* bytes, std::size_t n)
{
    constexpr const char* kReplacement = "\xEF\xBF\xBD";
    std::size_t           i            = 0;
    while (i < n)
    {
        const unsigned char lead = bytes[i];
        if (lead < 0x80)
        {
            out.push_back(static_cast<char>(lead));
            ++i;
            continue;
        }
        // Continuation bytes expected after the lead, and the allowed range
        // of the first continuation for leads whose range is restricted
        // (WHATWG UTF-8 decoder table). cont < 0 marks an invalid lead.
        int      cont = -1;
        unsigned lo   = 0x80;
        unsigned hi   = 0xBF;
        if (lead >= 0xC2 && lead <= 0xDF)
        {
            cont = 1;
        }
        else if (lead == 0xE0)
        {
            cont = 2;
            lo   = 0xA0;
        }
        else if ((lead >= 0xE1 && lead <= 0xEC) || lead == 0xEE || lead == 0xEF)
        {
            cont = 2;
        }
        else if (lead == 0xED)
        {
            cont = 2;
            hi   = 0x9F;
        }
        else if (lead == 0xF0)
        {
            cont = 3;
            lo   = 0x90;
        }
        else if (lead >= 0xF1 && lead <= 0xF3)
        {
            cont = 3;
        }
        else if (lead == 0xF4)
        {
            cont = 3;
            hi   = 0x8F;
        }
        if (cont < 0)
        {
            out.append(kReplacement);
            ++i;
            continue;
        }
        // Confirm the continuation bytes; lo/hi applies to the first one,
        // 80-BF to the rest. Truncation at end of input counts like an
        // invalid continuation (the subpart stays maximal).
        std::size_t valid = 0;
        if (i + 1 < n && bytes[i + 1] >= lo && bytes[i + 1] <= hi)
        {
            valid = 1;
            while (valid < static_cast<std::size_t>(cont) && i + valid + 1 < n && bytes[i + valid + 1] >= 0x80 &&
                   bytes[i + valid + 1] <= 0xBF)
            {
                ++valid;
            }
        }
        if (valid == static_cast<std::size_t>(cont))
        {
            for (std::size_t k = 0; k <= valid; ++k)
            {
                out.push_back(static_cast<char>(bytes[i + k]));
            }
            i += valid + 1;
        }
        else
        {
            // One replacement for the whole maximal subpart (lead + `valid`
            // continuations); the offending byte is re-examined fresh.
            out.append(kReplacement);
            i += valid + 1;
        }
    }
}

} // namespace

std::optional<std::string> ParseQueryParam(std::string_view query, std::string_view key)
{
    std::size_t pos = 0;
    while (pos <= query.size())
    {
        std::size_t end = query.find('&', pos);
        if (end == std::string_view::npos)
        {
            end = query.size();
        }
        const std::string_view kv = query.substr(pos, end - pos);
        const std::size_t      eq = kv.find('=');
        const std::string_view k  = eq == std::string_view::npos ? kv : kv.substr(0, eq);
        if (k == key)
        {
            const std::string_view val = eq == std::string_view::npos ? std::string_view{} : kv.substr(eq + 1);
            // Percent-decode into raw bytes (invalid escapes pass through
            // literally, '+' is NOT a space), then UTF-8 lossy-decode.
            std::string raw;
            raw.reserve(val.size());
            for (std::size_t i = 0; i < val.size(); ++i)
            {
                if (val[i] == '%' && i + 2 < val.size() && HexVal(val[i + 1]) >= 0 && HexVal(val[i + 2]) >= 0)
                {
                    raw.push_back(static_cast<char>((HexVal(val[i + 1]) << 4) | HexVal(val[i + 2])));
                    i += 2;
                    continue;
                }
                raw.push_back(val[i]);
            }
            std::string out;
            AppendUtf8Lossy(out, reinterpret_cast<const unsigned char*>(raw.data()), raw.size());
            return out;
        }
        pos = end + 1;
    }
    return std::nullopt;
}

std::string PercentEncodeQueryValue(std::string_view value)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string           out;
    out.reserve(value.size());
    for (const char c : value)
    {
        const auto byte       = static_cast<unsigned char>(c);
        const bool unreserved = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                                (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' ||
                                byte == '~';
        if (unreserved)
        {
            out.push_back(c);
            continue;
        }
        out.push_back('%');
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0F]);
    }
    return out;
}

bool ConstantTimeEquals(std::string_view a, std::string_view b) noexcept
{
    // Length difference folds into the accumulator; every byte position of
    // the longer input is mixed in unconditionally - no early exit, so the
    // comparison time carries no information about matching prefixes.
    std::size_t       diff = a.size() ^ b.size();
    const std::size_t n    = std::max(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i)
    {
        const unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<std::size_t>(ca ^ cb);
    }
    return diff == 0;
}

bool GlobMatch(std::string_view pattern, std::string_view name) noexcept
{
    // Classic backtracking matcher: remember the last '*' position and,
    // on mismatch, retry with one more consumed name character.
    std::size_t p      = 0;
    std::size_t n      = 0;
    std::size_t star_p = std::string_view::npos;
    std::size_t star_n = 0;
    while (n < name.size())
    {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == name[n]))
        {
            ++p;
            ++n;
        }
        else if (p < pattern.size() && pattern[p] == '*')
        {
            star_p = p++;
            star_n = n;
        }
        else if (star_p != std::string_view::npos)
        {
            p = star_p + 1;
            n = ++star_n;
        }
        else
        {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*')
    {
        ++p;
    }
    return p == pattern.size();
}

std::optional<std::string> SessionRequest::QueryParam(std::string_view key) const
{
    return ParseQueryParam(query, key);
}

// ---------------------------------------------------------------------------
// Chain + built-ins.
// ---------------------------------------------------------------------------

namespace
{

class ChainPolicy final : public SessionPolicy
{
public:
    ChainPolicy(std::shared_ptr<SessionPolicy> first, std::shared_ptr<SessionPolicy> second)
        : m_first(std::move(first))
        , m_second(std::move(second))
    {
    }

    [[nodiscard]] Decision Decide(const SessionRequest& req) const override
    {
        const Decision first = m_first->Decide(req);
        if (first != Decision::Accept)
        {
            return first;
        }
        return m_second->Decide(req);
    }

private:
    std::shared_ptr<SessionPolicy> m_first;
    std::shared_ptr<SessionPolicy> m_second;
};

} // namespace

std::shared_ptr<SessionPolicy> Chain(std::shared_ptr<SessionPolicy> first, std::shared_ptr<SessionPolicy> second)
{
    return std::make_shared<ChainPolicy>(std::move(first), std::move(second));
}

PathPolicy::PathPolicy(std::string expected)
    : m_expected(std::move(expected))
{
}

Decision PathPolicy::Decide(const SessionRequest& req) const
{
    return req.path == m_expected ? Decision::Accept : Decision::Reject;
}

OriginAllowlistPolicy::OriginAllowlistPolicy(std::vector<std::string> allowed)
    : m_allowed(std::move(allowed))
{
}

Decision OriginAllowlistPolicy::Decide(const SessionRequest& req) const
{
    if (!req.origin.has_value())
    {
        return Decision::Forbidden;
    }
    for (const std::string& a : m_allowed)
    {
        if (a == *req.origin)
        {
            return Decision::Accept;
        }
    }
    return Decision::Forbidden;
}

AuthTokenPolicy::AuthTokenPolicy(std::string expected)
    : m_expected(std::move(expected))
{
}

Decision AuthTokenPolicy::Decide(const SessionRequest& req) const
{
    const std::optional<std::string> token = ParseQueryParam(req.query, "token");
    if (token.has_value() && ConstantTimeEquals(*token, m_expected))
    {
        return Decision::Accept;
    }
    return Decision::Forbidden;
}

Decision AcceptAll::Decide(const SessionRequest& /*req*/) const
{
    return Decision::Accept;
}

// ---------------------------------------------------------------------------
// StreamAllowlistPolicy.
// ---------------------------------------------------------------------------

namespace
{

/// Token check shared by both roles: an entry with a token requires a query
/// token that matches (constant-time). Nullopt = check passed.
std::optional<Decision> CheckEntryToken(const StreamAclEntry& entry, const SessionRequest& req)
{
    if (!entry.token.has_value())
    {
        return std::nullopt;
    }
    const std::optional<std::string> got = ParseQueryParam(req.query, "token");
    if (got.has_value() && ConstantTimeEquals(*got, *entry.token))
    {
        return std::nullopt;
    }
    return Decision::Forbidden;
}

} // namespace

StreamAllowlistPolicy::StreamAllowlistPolicy(std::vector<StreamAclEntry> entries)
    : m_entries(std::move(entries))
{
}

Decision StreamAllowlistPolicy::DecidePublish(std::string_view name, const SessionRequest& req) const
{
    for (const StreamAclEntry& entry : m_entries)
    {
        if (!GlobMatch(entry.name_pattern, name))
        {
            continue;
        }
        if (!entry.allow_publish)
        {
            return Decision::Forbidden;
        }
        if (const std::optional<Decision> rejected = CheckEntryToken(entry, req))
        {
            return *rejected;
        }
        return Decision::Accept;
    }
    return Decision::Forbidden;
}

Decision StreamAllowlistPolicy::DecideSubscribe(std::string_view name, const SessionRequest& req) const
{
    for (const StreamAclEntry& entry : m_entries)
    {
        if (!GlobMatch(entry.name_pattern, name))
        {
            continue;
        }
        if (!entry.allow_subscribe)
        {
            return Decision::Reject;
        }
        if (const std::optional<Decision> rejected = CheckEntryToken(entry, req))
        {
            return *rejected;
        }
        return Decision::Accept;
    }
    return Decision::Reject;
}

Decision StreamAllowlistPolicy::Decide(const SessionRequest& req) const
{
    const std::optional<std::string> publish_name   = ParseQueryParam(req.query, "publish");
    const std::optional<std::string> stream_name    = ParseQueryParam(req.query, "stream");
    const std::optional<std::string> subscribe_name = ParseQueryParam(req.query, "subscribe");

    // No entries configured = no stream-name restrictions: every NAMED
    // publish/subscribe request is allowed (a nameless CONNECT falls
    // through to the Reject below). The usual Chain's PathPolicy and the
    // gateway's admission checks still apply either way.
    if (m_entries.empty() && (publish_name.has_value() || stream_name.has_value() || subscribe_name.has_value()))
    {
        return Decision::Accept;
    }

    if (publish_name.has_value())
    {
        const Decision d = DecidePublish(*publish_name, req);
        if (d != Decision::Accept)
        {
            return d;
        }
    }
    // `stream` wins over `subscribe` - the routing order.
    if (stream_name.has_value())
    {
        const Decision d = DecideSubscribe(*stream_name, req);
        if (d != Decision::Accept)
        {
            return d;
        }
    }
    else if (subscribe_name.has_value())
    {
        const Decision d = DecideSubscribe(*subscribe_name, req);
        if (d != Decision::Accept)
        {
            return d;
        }
    }
    if (!publish_name.has_value() && !stream_name.has_value() && !subscribe_name.has_value())
    {
        return Decision::Reject;
    }
    return Decision::Accept;
}

} // namespace quicsrt::gateway
