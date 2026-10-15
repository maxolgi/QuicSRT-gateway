// Policy seam units: the hooks.rs test matrix ported from the Rust oracle
// (crates/websrt/src/hooks.rs) plus the glob matcher, the StreamAllowlist
// role/token matrix and chain short-circuiting. Plain checks (not assert)
// so Release stays meaningful, following libwebsrt's test style.

#include "gateway/policy.h"

#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using websrt::gateway::AcceptAll;
using websrt::gateway::AuthTokenPolicy;
using websrt::gateway::Chain;
using websrt::gateway::Decision;
using websrt::gateway::OriginAllowlistPolicy;
using websrt::gateway::ParseQueryParam;
using websrt::gateway::PathPolicy;
using websrt::gateway::SessionPolicy;
using websrt::gateway::SessionRequest;
using websrt::gateway::StreamAclEntry;
using websrt::gateway::StreamAllowlistPolicy;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "policy_test: FAIL: %s\n", what);
    }
    return cond;
}

// Mirrors hooks.rs's req() test helper (empty static headers).
SessionRequest Req(std::string_view path, std::string_view query, std::optional<std::string_view> origin = std::nullopt)
{
    static const std::multimap<std::string, std::string> kEmptyHeaders;
    SessionRequest                                       req;
    req.path           = path;
    req.query          = query;
    req.origin         = origin;
    req.authority      = "localhost:4433";
    req.headers        = &kEmptyHeaders;
    req.remote_address = {.host = "127.0.0.1", .port = 0};
    return req;
}

// ---------------------------------------------------------------------------
// parse_query_param (hooks.rs matrix)
// ---------------------------------------------------------------------------

bool TestParseQueryParam()
{
    Check(ParseQueryParam("stream=foo&token=abc", "stream") == std::optional<std::string>("foo"),
          "parse_query_param basic: stream");
    Check(ParseQueryParam("stream=foo&token=abc", "token") == std::optional<std::string>("abc"),
          "parse_query_param basic: token");
    Check(!ParseQueryParam("stream=foo&token=abc", "missing").has_value(), "parse_query_param basic: missing");
    Check(!ParseQueryParam("", "stream").has_value(), "parse_query_param empty query");
    Check(ParseQueryParam("stream=foo%20bar", "stream") == std::optional<std::string>("foo bar"),
          "parse_query_param percent-decodes");
    Check(ParseQueryParam("publish", "publish") == std::optional<std::string>(""),
          "parse_query_param key without value");
    // C++-side extras locking the ported decoder semantics.
    Check(ParseQueryParam("stream=foo%FFbar", "stream") == std::optional<std::string>("foo\xEF\xBF\xBD"
                                                                                      "bar"),
          "parse_query_param invalid utf-8 -> U+FFFD");
    Check(ParseQueryParam("stream=%ED%A0%80", "stream") ==
              std::optional<std::string>("\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD"),
          "parse_query_param surrogate -> three U+FFFD");
    Check(ParseQueryParam("stream=%C3%A9", "stream") == std::optional<std::string>("\xc3\xa9"),
          "parse_query_param valid 2-byte utf-8 passes through");
    Check(ParseQueryParam("stream=a%2", "stream") == std::optional<std::string>("a%2"),
          "parse_query_param truncated escape stays literal");
    Check(ParseQueryParam("stream=a+b", "stream") == std::optional<std::string>("a+b"),
          "parse_query_param '+' is not a space");
    Check(ParseQueryParam("stream=a%2Gb", "stream") == std::optional<std::string>("a%2Gb"),
          "parse_query_param invalid hex stays literal");
    Check(ParseQueryParam("token=a=b", "token") == std::optional<std::string>("a=b"),
          "parse_query_param value may contain '='");
    const SessionRequest req = Req("/wt", "stream=x", std::nullopt);
    Check(req.QueryParam("stream") == std::optional<std::string>("x"), "SessionRequest::QueryParam");
    return true;
}

// ---------------------------------------------------------------------------
// GlobMatch
// ---------------------------------------------------------------------------

bool TestGlobMatch()
{
    Check(websrt::gateway::GlobMatch("test", "test"), "glob exact match");
    Check(!websrt::gateway::GlobMatch("test", "Test"), "glob is case-sensitive");
    Check(websrt::gateway::GlobMatch("test-*", "test-abc"), "glob '*' tail");
    Check(websrt::gateway::GlobMatch("test-*", "test-"), "glob '*' matches empty");
    Check(websrt::gateway::GlobMatch("*", ""), "glob lone '*' matches empty name");
    Check(websrt::gateway::GlobMatch("*", "anything"), "glob lone '*' matches anything");
    Check(websrt::gateway::GlobMatch("a*c", "ac"), "glob '*' interior empty");
    Check(websrt::gateway::GlobMatch("a*c", "abbbc"), "glob '*' interior");
    Check(websrt::gateway::GlobMatch("a**b", "axb"), "glob consecutive stars");
    Check(websrt::gateway::GlobMatch("*x*y*", "axbyc"), "glob multiple stars");
    Check(websrt::gateway::GlobMatch("a?c", "abc"), "glob '?' single char");
    Check(!websrt::gateway::GlobMatch("a?c", "ac"), "glob '?' needs a char");
    Check(!websrt::gateway::GlobMatch("a?c", "abbc"), "glob '?' is exactly one char");
    Check(!websrt::gateway::GlobMatch("a?c", "a?c/x"), "glob '?' is not a path separator");
    Check(!websrt::gateway::GlobMatch("abcd", "abc"), "glob pattern longer than name");
    Check(!websrt::gateway::GlobMatch("abc", "abcd"), "glob name longer than pattern");
    Check(websrt::gateway::GlobMatch("foo bar", "foo bar"), "glob literal space (decoded name)");
    return true;
}

// ---------------------------------------------------------------------------
// ConstantTimeEquals
// ---------------------------------------------------------------------------

bool TestConstantTimeEquals()
{
    Check(websrt::gateway::ConstantTimeEquals("s3cret", "s3cret"), "ct equals");
    Check(!websrt::gateway::ConstantTimeEquals("s3cret", "s3creu"), "ct differs in last byte");
    Check(!websrt::gateway::ConstantTimeEquals("s3cret", "s3cre"), "ct shorter");
    Check(!websrt::gateway::ConstantTimeEquals("s3cre", "s3cret"), "ct longer");
    Check(!websrt::gateway::ConstantTimeEquals("", "x"), "ct empty vs non-empty");
    Check(websrt::gateway::ConstantTimeEquals("", ""), "ct empty vs empty");
    Check(!websrt::gateway::ConstantTimeEquals("s3cret pass", "s3cret pasS"), "ct with space");
    return true;
}

// ---------------------------------------------------------------------------
// PathPolicy (hooks.rs matrix)
// ---------------------------------------------------------------------------

bool TestPathPolicy()
{
    const auto p = std::make_shared<PathPolicy>("/wt");
    Check(p->Decide(Req("/wt", "", std::nullopt)) == Decision::Accept, "path policy matches exact path");
    Check(p->Decide(Req("/other", "", std::nullopt)) == Decision::Reject, "path policy rejects different path");
    Check(p->Decide(Req("/wt", "stream=foo", std::nullopt)) == Decision::Accept,
          "path policy does not match query string");
    return true;
}

// ---------------------------------------------------------------------------
// OriginAllowlistPolicy (hooks.rs matrix)
// ---------------------------------------------------------------------------

bool TestOriginAllowlistPolicy()
{
    const auto p = std::make_shared<OriginAllowlistPolicy>(std::vector<std::string>{"https://example.com"});
    Check(p->Decide(Req("/wt", "", "https://example.com")) == Decision::Accept,
          "origin allowlist matches allowed origin");
    Check(p->Decide(Req("/wt", "", "https://evil.test")) == Decision::Forbidden,
          "origin allowlist rejects unlisted origin");
    Check(p->Decide(Req("/wt", "", std::nullopt)) == Decision::Forbidden, "origin allowlist rejects missing origin");
    const auto empty = std::make_shared<OriginAllowlistPolicy>(std::vector<std::string>{});
    Check(empty->Decide(Req("/wt", "", "https://example.com")) == Decision::Forbidden,
          "origin allowlist empty list rejects everything");
    return true;
}

// ---------------------------------------------------------------------------
// AuthTokenPolicy (hooks.rs matrix)
// ---------------------------------------------------------------------------

bool TestAuthTokenPolicy()
{
    const auto p = std::make_shared<AuthTokenPolicy>("s3cret");
    Check(p->Decide(Req("/wt", "token=s3cret", std::nullopt)) == Decision::Accept, "auth token accepts correct token");
    Check(p->Decide(Req("/wt", "stream=foo&token=s3cret&other=bar", std::nullopt)) == Decision::Accept,
          "auth token accepts with other params");
    Check(p->Decide(Req("/wt", "token=wrong", std::nullopt)) == Decision::Forbidden, "auth token rejects wrong token");
    Check(p->Decide(Req("/wt", "stream=foo", std::nullopt)) == Decision::Forbidden, "auth token rejects missing token");
    Check(p->Decide(Req("/wt", "", std::nullopt)) == Decision::Forbidden, "auth token rejects empty query");
    const auto spaced = std::make_shared<AuthTokenPolicy>("s3cret pass");
    Check(spaced->Decide(Req("/wt", "token=s3cret%20pass", std::nullopt)) == Decision::Accept,
          "auth token percent-decodes value");
    return true;
}

// ---------------------------------------------------------------------------
// Chain (hooks.rs matrix)
// ---------------------------------------------------------------------------

namespace
{

class RateLimitPolicy final : public SessionPolicy
{
public:
    [[nodiscard]] Decision Decide(const SessionRequest& /*req*/) const override { return Decision::TooManyRequests; }
};

} // namespace

bool TestChain()
{
    const auto chain = Chain(std::make_shared<PathPolicy>("/wt"), std::make_shared<AuthTokenPolicy>("t"));
    Check(chain->Decide(Req("/wt", "token=t", std::nullopt)) == Decision::Accept, "chain accepts when both accept");
    Check(chain->Decide(Req("/other", "token=t", std::nullopt)) == Decision::Reject,
          "chain rejects when first rejects");
    Check(chain->Decide(Req("/wt", "token=wrong", std::nullopt)) == Decision::Forbidden,
          "chain rejects when second rejects");
    // Triple-chain to verify associativity (hooks.rs chain_short_circuits...).
    const auto triple = Chain(std::make_shared<PathPolicy>("/wt"),
                              Chain(std::make_shared<OriginAllowlistPolicy>(std::vector<std::string>{"https://x.test"}),
                                    std::make_shared<AuthTokenPolicy>("t")));
    Check(triple->Decide(Req("/other", "token=t", "https://x.test")) == Decision::Reject,
          "chain short-circuits on first reject");
    const auto originFirst = Chain(std::make_shared<OriginAllowlistPolicy>(std::vector<std::string>{"https://x.test"}),
                                   std::make_shared<AuthTokenPolicy>("t"));
    Check(originFirst->Decide(Req("/wt", "token=t", "https://evil.test")) == Decision::Forbidden,
          "chain propagates Forbidden from first");
    const auto rateLimited = Chain(std::make_shared<PathPolicy>("/wt"), std::make_shared<RateLimitPolicy>());
    Check(rateLimited->Decide(Req("/wt", "", std::nullopt)) == Decision::TooManyRequests,
          "chain propagates TooManyRequests from second");
    // hooks.rs arc_dyn_policy_satisfies_trait: a type-erased policy chains.
    const std::shared_ptr<SessionPolicy> inner = std::make_shared<PathPolicy>("/wt");
    const auto                           outer = Chain(inner, std::make_shared<AcceptAll>());
    Check(outer->Decide(Req("/wt", "", std::nullopt)) == Decision::Accept, "erased policy chains (accept)");
    Check(outer->Decide(Req("/other", "", std::nullopt)) == Decision::Reject, "erased policy chains (reject)");
    return true;
}

// ---------------------------------------------------------------------------
// AcceptAll (hooks.rs matrix)
// ---------------------------------------------------------------------------

bool TestAcceptAll()
{
    const auto p = std::make_shared<AcceptAll>();
    Check(p->Decide(Req("/anything", "", std::nullopt)) == Decision::Accept, "accept all always accepts");
    return true;
}

// ---------------------------------------------------------------------------
// StreamAllowlistPolicy (refinement item 2 matrix)
// ---------------------------------------------------------------------------

std::shared_ptr<StreamAllowlistPolicy> SampleAcl()
{
    std::vector<StreamAclEntry> entries = {
        {.name_pattern = "test", .allow_publish = true, .allow_subscribe = true, .token = std::nullopt},
        {.name_pattern = "viewonly", .allow_publish = false, .allow_subscribe = true, .token = std::nullopt},
        {.name_pattern = "priv-*", .allow_publish = true, .allow_subscribe = true, .token = std::string("tok")},
        {.name_pattern = "nosub", .allow_publish = true, .allow_subscribe = false, .token = std::nullopt},
        {.name_pattern = "foo bar", .allow_publish = true, .allow_subscribe = true, .token = std::nullopt},
    };
    return std::make_shared<StreamAllowlistPolicy>(std::move(entries));
}

bool TestStreamAllowlistPublish()
{
    const auto p = SampleAcl();
    Check(p->Decide(Req("/wt", "publish=test", std::nullopt)) == Decision::Accept, "allowlist publish allowed");
    Check(p->Decide(Req("/wt", "publish=nope", std::nullopt)) == Decision::Forbidden, "allowlist publish no match");
    Check(p->Decide(Req("/wt", "publish=viewonly", std::nullopt)) == Decision::Forbidden,
          "allowlist publish role denied");
    Check(p->Decide(Req("/wt", "publish=priv-1&token=tok", std::nullopt)) == Decision::Accept,
          "allowlist publish token ok");
    Check(p->Decide(Req("/wt", "publish=priv-1", std::nullopt)) == Decision::Forbidden,
          "allowlist publish token missing");
    Check(p->Decide(Req("/wt", "publish=priv-1&token=bad", std::nullopt)) == Decision::Forbidden,
          "allowlist publish token wrong");
    Check(p->Decide(Req("/wt", "publish=priv-1&token=tok%20x", std::nullopt)) == Decision::Forbidden,
          "allowlist publish token percent-decoded mismatch");
    Check(p->Decide(Req("/wt", "publish", std::nullopt)) == Decision::Forbidden,
          "allowlist bare publish key counts as publish request");
    return true;
}

bool TestStreamAllowlistSubscribe()
{
    const auto p = SampleAcl();
    Check(p->Decide(Req("/wt", "stream=test", std::nullopt)) == Decision::Accept, "allowlist subscribe allowed");
    Check(p->Decide(Req("/wt", "subscribe=test", std::nullopt)) == Decision::Accept,
          "allowlist subscribe via ?subscribe=");
    Check(p->Decide(Req("/wt", "stream=nope", std::nullopt)) == Decision::Reject, "allowlist subscribe no match");
    Check(p->Decide(Req("/wt", "stream=nosub", std::nullopt)) == Decision::Reject, "allowlist subscribe role denied");
    Check(p->Decide(Req("/wt", "stream=priv-1&token=tok", std::nullopt)) == Decision::Accept,
          "allowlist subscribe token ok");
    Check(p->Decide(Req("/wt", "stream=priv-1&token=bad", std::nullopt)) == Decision::Forbidden,
          "allowlist subscribe token wrong");
    Check(p->Decide(Req("/wt", "stream=priv-1", std::nullopt)) == Decision::Forbidden,
          "allowlist subscribe token missing");
    Check(p->Decide(Req("/wt", "stream=/&subscribe=test", std::nullopt)) == Decision::Reject,
          "allowlist stream= wins over subscribe=");
    Check(p->Decide(Req("/wt", "stream=foo%20bar", std::nullopt)) == Decision::Accept,
          "allowlist matches percent-decoded name");
    return true;
}

bool TestStreamAllowlistShapes()
{
    const auto p = SampleAcl();
    Check(p->Decide(Req("/wt", "", std::nullopt)) == Decision::Reject, "allowlist empty query -> Reject");
    Check(p->Decide(Req("/wt", "foo=bar", std::nullopt)) == Decision::Reject,
          "allowlist unknown shape (neither publish nor stream) -> Reject");
    Check(p->Decide(Req("/wt", "publish=test&stream=test", std::nullopt)) == Decision::Accept,
          "allowlist combined both ok");
    Check(p->Decide(Req("/wt", "publish=test&stream=nope", std::nullopt)) == Decision::Reject,
          "allowlist combined: bad stream -> Reject");
    Check(p->Decide(Req("/wt", "publish=nope&stream=test", std::nullopt)) == Decision::Forbidden,
          "allowlist combined: bad publish -> Forbidden");
    // First matching entry wins.
    const std::vector<StreamAclEntry> ordered = {
        {.name_pattern = "*", .allow_publish = false, .allow_subscribe = true, .token = std::nullopt},
        {.name_pattern = "x", .allow_publish = true, .allow_subscribe = true, .token = std::nullopt},
    };
    const auto firstWins = std::make_shared<StreamAllowlistPolicy>(ordered);
    Check(firstWins->Decide(Req("/wt", "publish=x", std::nullopt)) == Decision::Forbidden,
          "allowlist first match wins (deny)");
    Check(firstWins->Decide(Req("/wt", "stream=x", std::nullopt)) == Decision::Accept,
          "allowlist first match wins (allow)");
    // Empty allowlist allows every name (config-present open mode); only
    // the request shape (a name must be present) is still enforced.
    const auto empty = std::make_shared<StreamAllowlistPolicy>(std::vector<StreamAclEntry>{});
    Check(empty->Decide(Req("/wt", "publish=x", std::nullopt)) == Decision::Accept, "empty allowlist publish");
    Check(empty->Decide(Req("/wt", "stream=x", std::nullopt)) == Decision::Accept, "empty allowlist subscribe");
    Check(empty->Decide(Req("/wt", "subscribe=y", std::nullopt)) == Decision::Accept,
          "empty allowlist subscribe param");
    Check(empty->Decide(Req("/wt", "publish=a&stream=b", std::nullopt)) == Decision::Accept,
          "empty allowlist combined");
    Check(empty->Decide(Req("/wt", "", std::nullopt)) == Decision::Reject, "empty allowlist nameless -> Reject");
    return true;
}

// ---------------------------------------------------------------------------
// Open-mode composition (what the CLI builds without --config).
// ---------------------------------------------------------------------------

bool TestOpenModeComposition()
{
    const auto p = Chain(std::make_shared<PathPolicy>("/wt"), std::make_shared<AcceptAll>());
    Check(p->Decide(Req("/wt", "stream=anything-at-all", std::nullopt)) == Decision::Accept,
          "open mode accepts any stream name");
    Check(p->Decide(Req("/wt", "publish=whatever", std::nullopt)) == Decision::Accept,
          "open mode accepts any publish name");
    Check(p->Decide(Req("/other", "stream=x", std::nullopt)) == Decision::Reject,
          "open mode still enforces the path policy");
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
        {.name = "parse-query-param", .fn = TestParseQueryParam},
        {.name = "glob", .fn = TestGlobMatch},
        {.name = "constant-time-equals", .fn = TestConstantTimeEquals},
        {.name = "path-policy", .fn = TestPathPolicy},
        {.name = "origin-allowlist", .fn = TestOriginAllowlistPolicy},
        {.name = "auth-token", .fn = TestAuthTokenPolicy},
        {.name = "chain", .fn = TestChain},
        {.name = "accept-all", .fn = TestAcceptAll},
        {.name = "allowlist-publish", .fn = TestStreamAllowlistPublish},
        {.name = "allowlist-subscribe", .fn = TestStreamAllowlistSubscribe},
        {.name = "allowlist-shapes", .fn = TestStreamAllowlistShapes},
        {.name = "open-mode", .fn = TestOpenModeComposition},
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
    std::printf("policy_test: all sections passed\n");
    return 0;
}
