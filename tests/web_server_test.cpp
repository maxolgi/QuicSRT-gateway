// G7 end-to-end: the web server over real TLS with a real gateway behind it.
// Four groups, in the order they fail:
//
//   1. STATIC SERVING (HTTPS, self-signed; the client is BoringSSL with
//      verification off). index.html and its Content-Type, a .wasm asset
//      as application/wasm (a MIME the browser must NOT be allowed to
//      second-guess), HEAD, a 304 on If-None-Match, directory -> index
//      resolution, ".." and encoded traversal refused, an unknown path 404,
//      a POST 405, and nosniff on every response.
//   2. /health SHAPE against the Rust oracle (websrt-gateway/src/main.rs
//      health_handler): every key the oracle emits must be here, with the
//      same meaning - a parity diff between the two gateways is meant to
//      come back empty on the oracle's own keys.
//   3. /stats and /health against LIVE state: a real libwebsrt publisher
//      and subscriber through the gateway core, so the stream and session
//      rows exist and the registry ticker is demonstrably advancing; the
//      SRT/UDP ingest runs beside it, so its counters appear too.
//   4. cert-hash.js as the boot writes it: the live hash in self mode and
//      null in mkcert mode, served from the web root - plus the
//      closed-network mode ([server].web_tls = false), where the same tree
//      goes out over plain HTTP and the page still pins the WT cert.
//   5. the TOTAL request-header deadline: a client that trickles header
//      bytes slower than any single read ever times out (the per-read
//      idle cutoff is 10 s) must be cut by the budget alone - the
//      slowloris that would otherwise hold every worker - while a
//      promptly-sent request under the same short budget is unaffected.
//
// Ports: ephemeral everywhere (the config asks for 0 and the test reads
// Port() back), plus ChoosePort for the gateway and the ingest, so no
// production port is ever touched and three runs cannot collide.

#include "srt.h"

#include "gateway/cert.h"
#include "gateway/config.h"
#include "gateway/gateway.h"
#include "gateway/ingest/srt_ingest.h"
#include "gateway/policy.h"
#include "gateway/web_server.h"

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <openssl/ssl.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <map>
#include <ranges>
#include <string>
#include <thread>
#include <vector>

#include "websrt/publisher.hpp"
#include "websrt/subscriber.hpp"

namespace
{

using websrt::gateway::CertProvider;
using websrt::gateway::Gateway;
using websrt::gateway::GatewayConfig;
using websrt::gateway::WebServer;
using websrt::gateway::WebServerConfig;

namespace fs = std::filesystem;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "web_server_test: FAIL: %s\n", what);
    }
    return cond;
}

bool WaitUntil(const std::function<bool()>& pred, int timeout_ms, int slice_ms = 5)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (!pred())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{slice_ms});
    }
    return true;
}

std::uint16_t ChoosePort(std::uint16_t preferred)
{
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    sa.sin_port = htons(preferred);
    int fd      = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0)
    {
        const bool free = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
        ::close(fd);
        if (free)
        {
            return preferred;
        }
    }

    sa.sin_port = 0;
    fd          = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        std::fprintf(stderr, "web_server_test: cannot probe any port\n");
        std::exit(1);
    }
    socklen_t len = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len);
    ::close(fd);
    return ntohs(sa.sin_port);
}

void WriteFile(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// ---- the HTTP client ----

struct HttpResponse
{
    int                                status = 0;
    std::map<std::string, std::string> headers; // lowercased names
    std::string                        body;

    [[nodiscard]] std::string Header(const std::string& name) const
    {
        const auto it = headers.find(name);
        return it == headers.end() ? std::string() : it->second;
    }
    [[nodiscard]] bool Has(const std::string& name) const { return headers.contains(name); }
};

/// One connection, reused across requests (the keep-alive path). With
/// tls=false it speaks plain HTTP - that is the health server's mode.
class HttpClient
{
public:
    ~HttpClient()
    {
        if (ssl_ != nullptr)
        {
            SSL_free(ssl_);
        }
        if (fd_ >= 0)
        {
            ::close(fd_);
        }
    }

    bool Connect(std::uint16_t port, bool tls)
    {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0)
        {
            return false;
        }
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        sa.sin_port = htons(port);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
        {
            return false;
        }
        if (!tls)
        {
            return true;
        }
        // Verification off: the gateway serves a self-signed cert whose
        // hash the browser pins via cert-hash.js, which this client has no
        // business checking.
        ssl_ = SSL_new(ClientCtx());
        return ssl_ != nullptr && SSL_set_fd(ssl_, fd_) == 1 && SSL_connect(ssl_) == 1;
    }

    bool Raw(const std::string& data)
    {
        std::size_t off = 0;
        while (off < data.size())
        {
            const long n = ssl_ != nullptr ? SSL_write(ssl_, data.data() + off, static_cast<int>(data.size() - off))
                                           : ::send(fd_, data.data() + off, data.size() - off, MSG_NOSIGNAL);
            if (n <= 0)
            {
                return false;
            }
            off += static_cast<std::size_t>(n);
        }
        return true;
    }

    /// One request line + headers, one parsed response.
    bool Exchange(const std::string& target, HttpResponse* out, const std::string& extra_headers = {})
    {
        return ExchangeRaw("GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n" + extra_headers + "\r\n", out, true);
    }

    /// A HEAD response advertises a length but carries no body - asking
    /// for one would hang the read.
    bool ExchangeHead(const std::string& target, HttpResponse* out)
    {
        return ExchangeRaw("HEAD " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", out, false);
    }

    bool ExchangeRaw(const std::string& request, HttpResponse* out, bool expect_body = true)
    {
        // A keep-alive connection reuses this object, so the previous
        // response's headers must not leak into the next one (a stale
        // content-length would hang the body read below).
        *out = HttpResponse{};
        if (!Raw(request))
        {
            return false;
        }

        std::string buffer;
        char        buf[4096];
        std::size_t header_end = std::string::npos;
        while ((header_end = buffer.find("\r\n\r\n")) == std::string::npos)
        {
            const long n = ssl_ != nullptr ? SSL_read(ssl_, buf, sizeof buf) : ::recv(fd_, buf, sizeof buf, 0);
            if (n <= 0)
            {
                return false;
            }
            buffer.append(buf, static_cast<std::size_t>(n));
        }

        const std::size_t first_eol = buffer.find("\r\n");
        const std::string line      = buffer.substr(0, first_eol);
        const std::size_t sp1       = line.find(' ');
        const std::size_t sp2       = line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos)
        {
            return false;
        }
        out->status = std::atoi(line.substr(sp1 + 1, sp2 - sp1 - 1).c_str());

        std::size_t pos = first_eol + 2;
        while (pos < header_end)
        {
            const std::size_t eol    = buffer.find("\r\n", pos);
            const std::string header = buffer.substr(pos, eol - pos);
            const std::size_t colon  = header.find(':');
            if (colon != std::string::npos)
            {
                std::string name  = header.substr(0, colon);
                std::string value = header.substr(colon + 1);
                std::ranges::transform(
                    name, name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                const std::size_t first = value.find_first_not_of(" \t");
                value                   = first == std::string::npos ? std::string() : value.substr(first);
                out->headers[name]      = value;
            }
            pos = eol + 2;
        }

        std::size_t length = 0;
        const auto  it     = out->headers.find("content-length");
        if (expect_body && it != out->headers.end())
        {
            length = static_cast<std::size_t>(std::strtoul(it->second.c_str(), nullptr, 10));
        }
        out->body = buffer.substr(header_end + 4);
        while (out->body.size() < length)
        {
            const long n = ssl_ != nullptr ? SSL_read(ssl_, buf, sizeof buf) : ::recv(fd_, buf, sizeof buf, 0);
            if (n <= 0)
            {
                break;
            }
            out->body.append(buf, static_cast<std::size_t>(n));
        }
        return true;
    }

private:
    static SSL_CTX* ClientCtx()
    {
        static SSL_CTX* ctx = nullptr;
        if (ctx == nullptr)
        {
            ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        }
        return ctx;
    }

    int  fd_  = -1;
    SSL* ssl_ = nullptr;
};

/// A raw request/response pair on a throwaway connection - the only way to
/// send a target no client library would let through ("/../secret.txt").
bool OneShot(std::uint16_t port, const std::string& request, HttpResponse* out)
{
    HttpClient client;
    if (!client.Connect(port, true))
    {
        return false;
    }
    return client.ExchangeRaw(request, out);
}

// ---- a stock-libsrt publisher, for the ingest counters ----

class SrtPublisher
{
public:
    bool Connect(std::uint16_t port, const std::string& streamid, std::string* error)
    {
        sock_ = srt_create_socket();
        if (sock_ == SRT_INVALID_SOCK)
        {
            *error = "srt_create_socket failed";
            return false;
        }
        int yes = 1;
        srt_setsockflag(sock_, SRTO_SNDSYN, &yes, sizeof yes);
        if (!streamid.empty())
        {
            srt_setsockopt(sock_, 0, SRTO_STREAMID, streamid.data(), static_cast<int>(streamid.size()));
        }
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        sa.sin_port = htons(port);
        if (srt_connect(sock_, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) == SRT_ERROR)
        {
            *error = std::string{"srt_connect: "} + srt_getlasterror_str();
            return false;
        }
        return true;
    }

    bool Send(const char* data, int len) const { return srt_sendmsg(sock_, data, len, -1, 1) == len; }

    ~SrtPublisher()
    {
        if (sock_ != SRT_INVALID_SOCK)
        {
            srt_close(sock_);
        }
    }

private:
    SRTSOCKET sock_ = SRT_INVALID_SOCK;
};

websrt::PublisherConfig PubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    websrt::PublisherConfig cfg;
    cfg.host            = "127.0.0.1";
    cfg.port            = port;
    cfg.stream_name     = stream;
    cfg.cert_sha256_hex = hash;
    return cfg;
}

websrt::SubscriberConfig SubCfg(std::uint16_t port, const std::string& hash, const std::string& stream)
{
    websrt::SubscriberConfig cfg;
    cfg.host             = "127.0.0.1";
    cfg.port             = port;
    cfg.stream_name      = stream;
    cfg.cert_sha256_hex  = hash;
    cfg.tsbpd_latency_ms = 120;
    return cfg;
}

/// `"key"` - the JSON-quoted form, so the assertions below read like the
/// documents they match.
std::string Q(const std::string& key)
{
    return "\"" + key + "\"";
}

/// A JSON key at the top level of `body`: `"key":` anywhere is close
/// enough for these fixed, server-generated documents.
bool HasKey(const std::string& body, const std::string& key)
{
    return body.find(Q(key) + ":") != std::string::npos;
}

void CheckKeys(const std::string& body, const std::vector<std::string>& keys, const char* what)
{
    for (const std::string& key : keys)
    {
        Check(HasKey(body, key), (std::string(what) + ": missing key " + key).c_str());
    }
}

/// A number-valued key, read out of the document (0 when absent).
std::uint64_t NumberAfter(const std::string& body, const std::string& key)
{
    const std::size_t at = body.find(Q(key) + ":");
    if (at == std::string::npos)
    {
        return 0;
    }
    return std::strtoull(body.c_str() + at + key.size() + 3, nullptr, 10);
}

/// The number in the stats page's `<th>key</th><td>N</td>` row - the
/// HTML twin of NumberAfter, so the two representations of /stats can be
/// compared key by key.
std::uint64_t HtmlNumberAfter(const std::string& body, const std::string& key)
{
    const std::string marker = "<th>" + key + "</th><td>";
    const std::size_t at     = body.find(marker);
    if (at == std::string::npos)
    {
        return 0;
    }
    return std::strtoull(body.c_str() + at + marker.size(), nullptr, 10);
}

/// A 1128-byte chunk of 6 well-formed TS packets (one PID, afc=0b01,
/// sequential continuity counters starting at start_cc, mod 16) - real
/// continuity, so the ingest's TS probe counts checks without gaps.
std::vector<std::uint8_t> MakeTsChunk(std::uint8_t start_cc)
{
    std::vector<std::uint8_t> chunk(1128);
    for (std::size_t pkt = 0; pkt < 6; ++pkt)
    {
        const std::size_t off = pkt * 188;
        chunk[off + 0]        = 0x47;
        chunk[off + 1]        = 0x01; // PID 0x0100
        chunk[off + 2]        = 0x00;
        chunk[off + 3]        = static_cast<std::uint8_t>((0b01 << 4) | ((start_cc + pkt) & 0x0F));
    }
    return chunk;
}

} // namespace

int main()
{
    // ---- the web root: a small stand-in for web/dist ----
    char        root_template[] = "/tmp/websrt-web-test-XXXXXX";
    const char* root_dir        = ::mkdtemp(root_template);
    if (root_dir == nullptr)
    {
        std::fprintf(stderr, "web_server_test: cannot create a temp dir\n");
        return 1;
    }
    const fs::path root(root_dir);
    const fs::path secret = root.parent_path() / (root.filename().string() + "-secret.txt");

    const std::string index_html = "<!doctype html><title>player</title>\n";
    WriteFile(root / "index.html", index_html);
    WriteFile(root / "app.js", "export const x = 1;\n");
    WriteFile(root / "mod.wasm", std::string("\0asm\x01\x00\x00\x00", 8));
    WriteFile(root / "favicon.ico", "icon");
    WriteFile(root / "assets" / "index-abc.js", "console.log('hi')\n");
    WriteFile(root / "sub" / "index.html", "<!doctype html><title>sub</title>\n");
    WriteFile(secret, "TOP SECRET\n");
    // A symlink out of the root: canonicalization must refuse it too.
    std::error_code ec;
    fs::create_symlink(secret, root / "escape.txt", ec);

    // ---- the gateway, its cert and the servers ----
    const std::uint16_t wt_port     = ChoosePort(4437);
    const std::uint16_t ingest_port = ChoosePort(9102);
    const CertProvider  cert;
    const std::string   hash = cert.Sha256Hex();

    // main.cpp's boot step, in the test: the dynamic /cert-hash.js body.
    const std::string cert_hash_js = cert.BuildCertHashJs(wt_port);

    Gateway gateway(cert, std::make_shared<websrt::gateway::AcceptAll>(), GatewayConfig{.max_viewers = 8});
    if (!Check(gateway.Start("127.0.0.1", wt_port), "the gateway binds its WebTransport port"))
    {
        return 1;
    }

    websrt::gateway::SrtIngest::Sink sink;
    sink.claim   = [&gateway](const std::string& name) { return gateway.ClaimIngestPublish(name); };
    sink.publish = [&gateway](const std::string& name, const void* data, std::size_t len)
    { gateway.PublishMedia(name, data, len); };
    sink.release = [&gateway](const std::string& name) { gateway.ReleaseIngestPublish(name); };

    websrt::gateway::SrtIngestConfig ingest_config;
    ingest_config.bind = "127.0.0.1";
    ingest_config.port = ingest_port;
    websrt::gateway::SrtIngest ingest(ingest_config, sink, gateway.Loop());
    std::string                ingest_error;
    if (!Check(ingest.Start(&ingest_error), "the SRT/UDP ingest binds its port"))
    {
        std::fprintf(stderr, "web_server_test: %s\n", ingest_error.c_str());
        gateway.Shutdown();
        return 1;
    }

    WebServer   web(WebServerConfig{.bind            = "127.0.0.1",
                                    .port            = 0,
                                    .cert            = &cert,
                                    .web_root        = root.string(),
                                    .cert_hash_js    = cert_hash_js,
                                    .serve_player    = true,
                                    .gateway         = &gateway,
                                    .ingest          = &ingest,
                                    .max_connections = 16});
    std::string error;
    if (!Check(web.Start(&error), "the HTTPS web server binds an ephemeral port"))
    {
        std::fprintf(stderr, "web_server_test: %s\n", error.c_str());
        ingest.Stop();
        gateway.Shutdown();
        return 1;
    }
    const std::uint16_t web_port = web.Port();

    // The health server: the oracle's plain HTTP on its own port.
    WebServer health(
        WebServerConfig{.bind = "127.0.0.1", .port = 0, .web_root = {}, .gateway = &gateway, .ingest = &ingest});
    if (!Check(health.Start(&error), "the plain-HTTP health server binds an ephemeral port"))
    {
        std::fprintf(stderr, "web_server_test: %s\n", error.c_str());
        web.Stop();
        ingest.Stop();
        gateway.Shutdown();
        return 1;
    }
    const std::uint16_t health_port = health.Port();
    std::fprintf(stderr,
                 "web_server_test: web (HTTPS) on %u, health (HTTP) on %u, wt %u, ingest %u, root %s\n",
                 web_port,
                 health_port,
                 wt_port,
                 ingest_port,
                 root_dir);

    // ---- 1. static serving over HTTPS ----
    {
        HttpClient client;
        Check(client.Connect(web_port, true), "1: TLS handshake with the self-signed cert");

        HttpResponse response;
        Check(client.Exchange("/", &response), "1: GET / answered");
        Check(response.status == 200, "1: GET / is 200");
        Check(response.Header("content-type") == "text/html; charset=utf-8", "1: index.html Content-Type");
        Check(response.body == index_html, "1: index.html body byte-for-byte");
        Check(response.Header("x-content-type-options") == "nosniff", "1: nosniff on every response");

        Check(client.Exchange("/app.js", &response), "1: GET /app.js answered");
        Check(response.status == 200 && response.Header("content-type") == "text/javascript; charset=utf-8",
              "1: js Content-Type");

        Check(client.Exchange("/mod.wasm", &response), "1: GET /mod.wasm answered");
        Check(response.status == 200 && response.Header("content-type") == "application/wasm",
              "1: wasm is application/wasm (instantiateStreaming depends on it)");

        Check(client.Exchange("/assets/index-abc.js", &response), "1: GET /assets/index-abc.js answered");
        Check(response.status == 200 && response.body == "console.log('hi')\n", "1: nested asset served");

        Check(client.Exchange("/favicon.ico", &response), "1: GET /favicon.ico answered");
        Check(response.status == 200 && response.Header("content-type") == "image/x-icon", "1: ico Content-Type");

        Check(client.Exchange("/sub/", &response), "1: GET /sub/ answered");
        Check(response.status == 200 && response.body.find("<title>sub</title>") != std::string::npos,
              "1: a directory resolves to its index.html");

        // Keep-alive: this is the third request on one connection.
        Check(client.Exchange("/app.js", &response), "1: the connection is kept alive across requests");

        const std::string etag = response.Header("etag");
        Check(!etag.empty(), "1: responses carry an ETag");

        Check(client.Exchange("/app.js", &response, "If-None-Match: " + etag + "\r\n"), "1: conditional GET answered");
        Check(response.status == 304, "1: a matching If-None-Match gets a 304");
        Check(response.body.empty(), "1: a 304 carries no body");
        Check(response.Header("etag") == etag, "1: the 304 repeats the ETag");

        Check(client.ExchangeHead("/index.html", &response), "1: HEAD answered");
        Check(response.status == 200, "1: HEAD is 200");
        Check(response.body.empty(), "1: HEAD carries no body");
        Check(response.Header("content-length") == std::to_string(index_html.size()), "1: HEAD reports Content-Length");

        Check(client.Exchange("/nope.html", &response), "1: GET /nope.html answered");
        Check(response.status == 404, "1: an unknown path is 404");

        Check(client.ExchangeRaw("POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n", &response),
              "1: POST answered");
        Check(response.status == 405, "1: POST is 405");
        Check(response.Header("allow") == "GET, HEAD", "1: the 405 advertises Allow");
    }

    // Traversal: raw targets, because a client library would normalize them.
    {
        const std::string target = "../" + secret.filename().string();
        HttpResponse      response;
        Check(OneShot(web_port, "GET /" + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &response),
              "1: a ../ request is answered");
        Check(response.status == 403 || response.status == 404, "1: ../ is refused");
        Check(response.body.find("TOP SECRET") == std::string::npos, "1: ../ never leaks the file");

        Check(OneShot(web_port, "GET /..%2f" + target.substr(3) + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &response),
              "1: an encoded traversal is answered");
        Check(response.status == 403 || response.status == 404, "1: an encoded traversal is refused");
        Check(response.body.find("TOP SECRET") == std::string::npos, "1: the encoded traversal never leaks it");

        Check(OneShot(web_port, "GET /escape.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &response),
              "1: a symlink out of the root is answered");
        Check(response.status == 403 || response.status == 404, "1: a symlink out of the root is refused");
        Check(response.body.find("TOP SECRET") == std::string::npos, "1: the symlink never leaks the file");

        Check(OneShot(web_port, "GET /../../../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", &response),
              "1: a deep traversal is answered");
        Check(response.status == 403 || response.status == 404, "1: a deep traversal is refused");
    }

    // ---- 2. /health against the Rust oracle's shape ----
    {
        HttpClient   client;
        HttpResponse response;
        Check(client.Connect(web_port, true), "2: connected");
        Check(client.Exchange("/health", &response), "2: GET /health answered");
        Check(response.status == 200, "2: /health is 200");
        Check(response.Header("content-type") == "application/json", "2: /health is JSON");

        // Every key websrt-gateway/src/main.rs:690-704 emits.
        CheckKeys(response.body,
                  {"status",
                   "streams",
                   "alive_streams",
                   "viewers",
                   "max_viewers",
                   "per_stream",
                   "per_session",
                   "ticker",
                   "ingester",
                   // the C++ addition (see web_server.h)
                   "uptime_ms",
                   "active_sessions"},
                  "2: /health");
        // And inside the two arrays.
        Check(response.body.find(Q("per_stream") + ":[]") != std::string::npos, "2: per_stream is an array");
        Check(response.body.find(Q("per_session") + ":[]") != std::string::npos, "2: per_session is an array");
        Check(response.body.find(Q("status") + ":\"no_source\"") != std::string::npos,
              "2: an idle gateway reports no_source");
        Check(NumberAfter(response.body, "max_viewers") == 8, "2: max_viewers is the configured cap");
        Check(HasKey(response.body, "uptime_ms"), "2: uptime_ms is a number");

        // The per-row keys, once rows exist (checked against live state
        // in group 3).
        Check(client.Exchange("/stats", &response), "3: GET /stats answered");
        Check(response.status == 200 && response.Header("content-type") == "application/json", "3: /stats is JSON");
        CheckKeys(response.body,
                  {"uptime_ms",
                   "stream_count",
                   "alive_streams",
                   "viewers",
                   "max_viewers",
                   "active_sessions",
                   "ticker",
                   "server",
                   "streams",
                   "sessions",
                   "ingest"},
                  "3: /stats");
        CheckKeys(response.body, {"sessions_accepted", "datagrams_received", "datagrams_dropped"}, "3: /stats server");
        Check(response.body.find(Q("count") + ":") != std::string::npos, "3: /stats reports the ticker count");

        // P4 step 2: /stats negotiation. JSON stays the default - curl's
        // Accept is */*, scripts send none or application/json - and the
        // HTML rendering goes only to a client that names text/html (a
        // browser navigation).
        Check(client.Exchange("/stats", &response, "Accept: */*\r\n"), "2: /stats with curl's Accept answered");
        Check(response.status == 200 && response.Header("content-type") == "application/json",
              "2: curl's */* Accept keeps the JSON");
        Check(client.Exchange("/stats", &response, "Accept: application/json\r\n"),
              "2: /stats with a script's Accept answered");
        Check(response.Header("content-type") == "application/json", "2: application/json keeps the JSON");
        Check(client.Exchange("/stats", &response), "2: /stats with no Accept answered");
        Check(response.Header("content-type") == "application/json", "2: no Accept header keeps the JSON");
        Check(client.Exchange(
                  "/stats", &response, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"),
              "2: /stats with a browser's Accept answered");
        Check(response.status == 200 && response.Header("content-type") == "text/html; charset=utf-8",
              "2: a browser's Accept gets the HTML page");
        Check(response.body.find("<meta http-equiv=\"refresh\"") != std::string::npos,
              "2: the HTML page auto-refreshes");
        Check(response.body.find(">none<") != std::string::npos, "2: the idle page renders empty tables as none");
    }

    // ---- 3. live state: a real publisher + subscriber through the core ----
    {
        websrt::Subscriber sub;
        Check(sub.Start(SubCfg(wt_port, hash, "g7-live")) == websrt::kStartOk, "3: the subscriber attached");

        websrt::Publisher pub;
        Check(pub.Start(PubCfg(wt_port, hash, "g7-live")) == websrt::kPublishOk, "3: the publisher attached");
        const std::vector<std::uint8_t> chunk = MakeTsChunk(0);
        bool                            sent  = false;
        for (int i = 0; i < 200 && !sent; ++i)
        {
            sent = pub.Write(chunk.data(), static_cast<int>(chunk.size()), 200) == static_cast<int>(chunk.size());
        }
        Check(sent, "3: the publisher pushed media");

        HttpClient   client;
        HttpResponse response;
        Check(client.Connect(web_port, true), "3: connected for the live poll");

        Check(WaitUntil(
                  [&client, &response]
                  {
                      if (!client.Exchange("/health", &response))
                      {
                          return false;
                      }
                      return response.body.find(Q("name") + ":\"g7-live\"") != std::string::npos &&
                             NumberAfter(response.body, "alive_streams") == 1 &&
                             response.body.find(Q("per_session") + ":[{") != std::string::npos;
                  },
                  10000),
              "3: /health shows the live stream and its sessions");

        // The per_stream / per_session rows carry the oracle's row keys.
        Check(response.body.find(Q("alive") + ":true") != std::string::npos, "3: the stream row is alive");
        CheckKeys(response.body,
                  {"messages_sent",
                   "send_failures",
                   "session_id",
                   "stream",
                   "tx_data",
                   "tx_buffered",
                   "tx_retransmit",
                   "tx_loss",
                   "rtt_ms",
                   "messages_pushed",
                   "viewer_lag",
                   "buffer_lag"},
                  "3: /health rows");
        Check(NumberAfter(response.body, "viewers") == 1, "3: the subscriber is counted as a viewer");

        // The ticker is running, and it advances between two reads.
        const std::uint64_t ticks_before = NumberAfter(response.body, "count");
        Check(ticks_before > 0, "3: the registry ticker is running");
        Check(WaitUntil(
                  [&client, &response, ticks_before]
                  {
                      if (!client.Exchange("/health", &response))
                      {
                          return false;
                      }
                      return NumberAfter(response.body, "count") > ticks_before;
                  },
                  5000),
              "3: the ticker count advances between two /health reads");
        std::fprintf(stderr,
                     "web_server_test: 3: stream alive, sessions live, ticker %llu -> %llu us max\n",
                     static_cast<unsigned long long>(ticks_before),
                     static_cast<unsigned long long>(NumberAfter(response.body, "max_us")));

        Check(client.Exchange("/stats", &response), "3: /stats over the live gateway");
        CheckKeys(response.body,
                  {"ring_size",
                   "ring_drops",
                   "oversize_drops",
                   "publisher",
                   "connected",
                   "max_payload",
                   "messages_sent",
                   "messages_received",
                   "backlog_size"},
                  "3: /stats rows");
        Check(response.body.find(Q("stream") + ":\"g7-live\"") != std::string::npos,
              "3: /stats names the session's stream");

        // The ingest side: a stock-libsrt publisher lands, and both
        // endpoints show its counters.
        std::string  ingest_err;
        SrtPublisher srt_pub;
        Check(srt_pub.Connect(ingest_port, "g7-ingest", &ingest_err), "3: the ingest publisher connected");
        for (int i = 0; i < 8; ++i)
        {
            // Sequential CC across sends (6 packets each, mod 16): the
            // probe must count checks and find zero gaps.
            const std::vector<std::uint8_t> media = MakeTsChunk(static_cast<std::uint8_t>((i * 6) & 0x0F));
            srt_pub.Send(reinterpret_cast<const char*>(media.data()), static_cast<int>(media.size()));
        }
        Check(WaitUntil(
                  [&client, &response]
                  {
                      return client.Exchange("/health", &response) &&
                             response.body.find(Q("ingester") + ":{\"g7-ingest\":") != std::string::npos &&
                             NumberAfter(response.body, "cc_checks") > 0;
                  },
                  10000),
              "3: /health reports the ingest's continuity probe");
        Check(NumberAfter(response.body, "cc_gaps") == 0, "3: the clean ingest stream has no CC gaps");
        Check(response.body.find(Q("name") + ":\"g7-ingest\"") != std::string::npos,
              "3: the ingest's stream is live in the registry");

        Check(client.Exchange("/stats", &response), "3: /stats with the ingest attached");
        CheckKeys(response.body,
                  {"rejected_no_streamid",
                   "rejected_not_allowed",
                   "rejected_occupied",
                   "messages_in",
                   "bytes_in",
                   "chunks_out",
                   "cc_checks",
                   "cc_gaps",
                   "messages_seen",
                   "connections"},
                  "3: /stats ingest");
        Check(response.body.find(Q("stream") + ":\"g7-ingest\"") != std::string::npos,
              "3: the ingest connection is listed");

        // P4 step 2: both representations of /stats from the same live
        // state - the JSON and the HTML are read back to back with the
        // sessions held, and the stable fields must agree (only the
        // fields a live gateway advances - uptime, the ticker, the byte
        // counters - may move between the two reads).
        HttpResponse json_view;
        Check(client.Exchange("/stats", &json_view, "Accept: application/json\r\n"), "3: /stats JSON view answered");
        HttpResponse html_view;
        Check(client.Exchange("/stats", &html_view, "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"),
              "3: /stats HTML view answered");
        Check(json_view.Header("content-type") == "application/json" &&
                  html_view.Header("content-type") == "text/html; charset=utf-8",
              "3: the two views negotiate to their content types");
        Check(json_view.body.find(Q("name") + ":\"g7-live\"") != std::string::npos &&
                  html_view.body.find("g7-live") != std::string::npos &&
                  json_view.body.find(Q("name") + ":\"g7-ingest\"") != std::string::npos &&
                  html_view.body.find("g7-ingest") != std::string::npos,
              "3: both views name both live streams");
        for (const char* key : {"stream_count", "alive_streams", "viewers", "active_sessions", "publishers_accepted"})
        {
            Check(HtmlNumberAfter(html_view.body, key) == NumberAfter(json_view.body, key),
                  (std::string("3: both views agree on ") + key).c_str());
        }
        Check(NumberAfter(json_view.body, "stream_count") == 2, "3: two live streams are reported");
        Check(NumberAfter(json_view.body, "active_sessions") == 2,
              "3: the publisher and subscriber sessions are reported");
        Check(NumberAfter(json_view.body, "count") > 0 &&
                  HtmlNumberAfter(html_view.body, "count") >= NumberAfter(json_view.body, "count"),
              "3: both views carry the advancing ticker");
        Check(html_view.body.find("<meta http-equiv=\"refresh\"") != std::string::npos,
              "3: the live page auto-refreshes");
        // And the JSON shape is unchanged by the HTML addition.
        CheckKeys(json_view.body,
                  {"uptime_ms",
                   "stream_count",
                   "alive_streams",
                   "viewers",
                   "max_viewers",
                   "active_sessions",
                   "ticker",
                   "server",
                   "streams",
                   "sessions",
                   "ingest"},
                  "3: /stats JSON shape unchanged");

        // The HTML escapes what it interpolates: a stream name is caller
        // data (this one arrives as an ingest streamid), and it must never
        // reach the page as markup.
        std::string  esc_err;
        SrtPublisher esc_pub;
        Check(esc_pub.Connect(ingest_port, "g7-<&>\"", &esc_err), "3: the markup-named ingest publisher connected");
        for (int i = 0; i < 8; ++i)
        {
            esc_pub.Send(reinterpret_cast<const char*>(chunk.data()), static_cast<int>(chunk.size()));
        }
        Check(WaitUntil(
                  [&client, &html_view]
                  {
                      return client.Exchange("/stats", &html_view, "Accept: text/html\r\n") &&
                             html_view.body.find("g7-&lt;&amp;&gt;&quot;") != std::string::npos;
                  },
                  10000),
              "3: the HTML view escapes the stream name");
        Check(html_view.body.find("g7-<&>") == std::string::npos, "3: raw markup never reaches the page");
        Check(client.Exchange("/stats", &json_view, "Accept: application/json\r\n"),
              "3: the JSON view of the markup name answered");
        Check(json_view.body.find("g7-<&>") != std::string::npos, "3: the JSON carries the stream name raw, as before");

        pub.Stop();
        sub.Stop();
        Check(WaitUntil([&] { return gateway.ActiveSessionCount() == 0; }, 10000), "3: both sessions were reaped");
    }

    // ---- 4. cert-hash.js, and the health server's plain HTTP ----
    {
        HttpClient   client;
        HttpResponse response;
        Check(client.Connect(web_port, true), "4: connected");
        Check(client.Exchange("/cert-hash.js", &response), "4: GET /cert-hash.js answered");
        Check(response.status == 200, "4: cert-hash.js is 200");
        Check(response.Header("content-type") == "text/javascript; charset=utf-8", "4: cert-hash.js is a script");
        Check(response.body ==
                  "window.CERT_HASH = \"" + hash + "\";\nwindow.WT_PORT = " + std::to_string(wt_port) + ";",
              "4: cert-hash.js carries the live hash and the WT port");
        std::fprintf(stderr, "web_server_test: 4: served cert-hash.js\n%s\n", response.body.c_str());

        // Plain HTTP, the health port's mode - and no static root there.
        HttpClient plain;
        Check(plain.Connect(health_port, false), "4: plain-HTTP connect to the health server");
        Check(plain.Exchange("/health", &response), "4: /health over plain HTTP");
        Check(response.status == 200 && response.Header("content-type") == "application/json",
              "4: /health works over plain HTTP too");
        Check(plain.Exchange("/index.html", &response), "4: a static path on the health server");
        Check(response.status == 404, "4: the health server serves no static files");
    }

    // The closed-network web server ([server].web_tls = false): the same
    // web_root without a cert - plain HTTP for the page, unchanged for the
    // WT handshake.
    {
        WebServer   http_web(WebServerConfig{.bind            = "127.0.0.1",
                                             .port            = 0,
                                             .cert            = nullptr,
                                             .web_root        = root.string(),
                                             .cert_hash_js    = cert_hash_js,
                                             .serve_player    = true,
                                             .gateway         = &gateway,
                                             .ingest          = &ingest,
                                             .max_connections = 16});
        std::string http_error;
        Check(http_web.Start(&http_error), "4: the plain-HTTP web server binds");
        if (http_web.Running())
        {
            HttpClient   client;
            HttpResponse response;
            Check(client.Connect(http_web.Port(), false), "4: plain-HTTP connect to the web server");
            Check(client.Exchange("/", &response), "4: GET / over plain HTTP answered");
            Check(response.status == 200 && response.body == index_html,
                  "4: the player page is served over plain HTTP");
            Check(response.Header("x-content-type-options") == "nosniff", "4: nosniff over plain HTTP too");

            Check(client.Exchange("/cert-hash.js", &response), "4: cert-hash.js over plain HTTP answered");
            Check(response.status == 200 && response.body == "window.CERT_HASH = \"" + hash + "\";\nwindow.WT_PORT = " +
                                                                 std::to_string(wt_port) + ";",
                  "4: plain HTTP still publishes the live hash - the WT pinning path is unaffected");
            http_web.Stop();
        }
    }

    // ---- mkcert mode: the hash is null, the file says so ----
    {
        const fs::path pem_dir = root.parent_path() / (root.filename().string() + "-pem");
        fs::create_directories(pem_dir);
        {
            std::ofstream cert_pem(pem_dir / "cert.pem", std::ios::binary);
            cert_pem << cert.CertPem();
            std::ofstream key_pem(pem_dir / "key.pem", std::ios::binary);
            key_pem << cert.KeyPem();
        }
        const CertProvider mkcert((pem_dir / "cert.pem").string(), (pem_dir / "key.pem").string());

        WebServer   mkcert_web(WebServerConfig{.bind         = "127.0.0.1",
                                               .port         = 0,
                                               .cert         = &mkcert,
                                               .web_root     = pem_dir.string(),
                                               .cert_hash_js = mkcert.BuildCertHashJs(wt_port),
                                               .serve_player = true,
                                               .gateway      = nullptr,
                                               .ingest       = nullptr});
        std::string mkcert_error;
        Check(mkcert_web.Start(&mkcert_error), "4: the mkcert-mode web server binds");
        if (mkcert_web.Running())
        {
            HttpClient   client;
            HttpResponse response;
            Check(client.Connect(mkcert_web.Port(), true), "4: TLS handshake on the mkcert identity");
            Check(client.Exchange("/cert-hash.js", &response), "4: mkcert cert-hash.js answered");
            Check(response.body == "window.CERT_HASH = null;\nwindow.WT_PORT = " + std::to_string(wt_port) + ";",
                  "4: mkcert mode advertises null (normal PKI validation)");
            mkcert_web.Stop();
        }
        fs::remove_all(pem_dir);
    }

    // ---- the embedded player: no web_root, serve straight from the
    // binary (the default deployment, rust-embed parity) ----
    {
        WebServer embedded(
            WebServerConfig{.bind = "127.0.0.1", .port = 0, .cert_hash_js = cert_hash_js, .serve_player = true});
        std::string embedded_error;
        Check(embedded.Start(&embedded_error), "4: the embedded-player web server binds");
        if (embedded.Running())
        {
            HttpClient   client;
            HttpResponse response;
            Check(client.Connect(embedded.Port(), false), "4: connect to the embedded-player server");
            Check(client.Exchange("/", &response), "4: GET / answered from the embedded table");
            Check(response.status == 200 && response.Header("content-type") == "text/html; charset=utf-8" &&
                      response.body.rfind("<!doctype html>", 0) == 0,
                  "4: / serves the embedded player's index.html");
            const std::string etag = response.Header("etag");
            Check(!etag.empty(), "4: embedded assets carry an ETag");
            // A 304 carries no body, so the reader must not expect one.
            Check(
                client.ExchangeRaw("GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nIf-None-Match: " + etag + "\r\n\r\n",
                                   &response,
                                   false),
                "4: conditional re-GET answered");
            Check(response.status == 304, "4: the ETag yields a 304 (immutable per binary)");
            Check(client.Exchange("/no-such-asset.js", &response), "4: unknown asset answered");
            Check(response.status == 404, "4: unknown asset is a 404");
            Check(client.Exchange("/cert-hash.js", &response), "4: dynamic cert-hash.js on the embedded server");
            Check(response.status == 200 && response.body == cert_hash_js,
                  "4: the dynamic route serves the boot-built body");
            embedded.Stop();
        }
    }

    // ---- 5. the total request-header deadline (the slowloris cut) ----
    {
        // A short budget on a standalone plain-HTTP server. The trickler
        // below feeds one byte every 250 ms - no per-read timeout (10 s)
        // can ever fire - so ONLY the total budget can end it, which is
        // exactly the attack the budget exists for.
        WebServer   slow(WebServerConfig{.bind = "127.0.0.1", .port = 0, .header_timeout_s = 2});
        std::string slow_error;
        Check(slow.Start(&slow_error), "5: the short-header-budget server binds");
        if (slow.Running())
        {
            // A prompt request is untouched by the same short budget.
            HttpClient   client;
            HttpResponse response;
            Check(client.Connect(slow.Port(), false), "5: connected for a prompt request");
            Check(client.Exchange("/health", &response), "5: a prompt request is answered");
            Check(response.status == 200, "5: a prompt request succeeds under the 2 s budget");

            // The trickler: raw socket, one byte at a time, watching for
            // the cut between sends. Never a "\r\n\r\n".
            int         fd = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
            sa.sin_port = htons(slow.Port());
            Check(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0, "5: the trickler connected");

            const std::string dribble = "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: 0123456789";
            const auto        t0      = std::chrono::steady_clock::now();
            bool              closed  = false;
            std::string       received;
            std::size_t       sent = 0;
            while (!closed && std::chrono::steady_clock::now() - t0 < std::chrono::seconds{10})
            {
                if (::send(fd, dribble.data() + sent, 1, MSG_NOSIGNAL) != 1)
                {
                    closed = true; // the write failed: the server cut us off
                    break;
                }
                ++sent;
                struct pollfd pfd{};
                pfd.fd     = fd;
                pfd.events = POLLIN;
                if (::poll(&pfd, 1, 250) > 0)
                {
                    char buf[512];
                    for (;;)
                    {
                        const long n = ::recv(fd, buf, sizeof buf, MSG_DONTWAIT);
                        if (n > 0)
                        {
                            received.append(buf, static_cast<std::size_t>(n));
                            continue;
                        }
                        // 0 = orderly FIN; a reset racing the 408 out the
                        // door is the same verdict. EAGAIN just means the
                        // readable moment passed.
                        closed = n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
                        break;
                    }
                }
            }
            const auto elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            Check(closed, "5: the trickling connection was cut");
            Check(elapsed_ms < 8000, "5: the cut came from the 2 s budget, not from going silent");
            if (!received.empty())
            {
                Check(received.rfind("HTTP/1.1 408", 0) == 0, "5: the cut is a 408 Request Timeout");
            }
            std::fprintf(stderr,
                         "web_server_test: 5: trickler cut after %lld ms (%zu bytes sent, %s)\n",
                         static_cast<long long>(elapsed_ms),
                         sent,
                         received.empty() ? "no response bytes reached us" : "408 received");
            ::close(fd);
            slow.Stop();
        }
    }

    // ---- shutdown with a live keep-alive connection ----
    {
        HttpClient idle;
        Check(idle.Connect(web_port, true), "6: an idle keep-alive connection is open");
        HttpResponse response;
        Check(idle.Exchange("/index.html", &response), "6: the idle connection served a request");

        const auto t0 = std::chrono::steady_clock::now();
        web.Stop();
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        std::fprintf(
            stderr, "web_server_test: 6: Stop() with a live connection took %lld ms\n", static_cast<long long>(ms));
        Check(ms < 5000, "6: Stop() does not wait for the idle connection to time out");
        Check(!web.Running(), "6: the web server is stopped");

        health.Stop();
        ingest.Stop();
        gateway.Shutdown();
    }

    fs::remove_all(root);
    fs::remove(secret, ec);

    if (!g_ok)
    {
        std::fprintf(stderr, "web_server_test: FAILURES\n");
        return 1;
    }
    std::printf("web_server_test: OK\n");
    return 0;
}