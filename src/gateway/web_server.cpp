// WebServer implementation (see web_server.h for the port map and the
// threading contract). Direct BoringSSL + plain sockets: an HTTP/1.1
// server for a static page and two JSON endpoints needs no framework,
// and this way the only TLS identity in the process is the one
// CertProvider owns.
//
// MECHANICS worth knowing before changing anything:
//   - Sockets are BLOCKING with a 10 s SO_RCVTIMEO/SO_SNDTIMEO. That
//     timeout is the keep-alive idle cutoff and the only thing that ever
//     ends a wedged read, which is what lets Stop() join a worker
//     without a poll loop per connection.
//   - Keep-alive is on by default (HTTP/1.1). The player opens 6
//     connections per origin and reuses them; without it every asset
//     would take a fresh TCP+TLS handshake and could exhaust the
//     connection cap on one page load.
//   - The request is read to the first "\r\n\r\n" (bounded). No request
//     body is ever read: a POST with a body is answered 405 and the
//     connection closes, so the unread body cannot desynchronize us.
//   - One request's headers have a TOTAL budget
//     (WebServerConfig::header_timeout_s, 30 s default): a client that
//     trickles a byte every few seconds never trips the 10 s per-read
//     timeout, so on budget exhaustion it is answered 408 and closed.
//     Without it, max_connections tricklers wedge every worker - and
//     with them the player, /health and /stats alike.
//   - Static paths are canonicalized with realpath() and then required
//     to sit under the canonicalized root, which rejects "..", symlinks
//     pointing outside the root, and absolute targets alike.

#include "gateway/web_server.h"

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <iterator>
#include <ranges>
#include <utility>

#include <openssl/ssl.h>

#include "gateway/embedded_player.h"
#include "gateway/gateway.h"
#include "gateway/ingest/srt_ingest.h"

namespace quicsrt::gateway
{

namespace
{

/// A request line plus headers must fit here; anything larger is a 431.
constexpr std::size_t kMaxHeaderBytes = std::size_t{16} * 1024;

/// Refuse to buffer an absurd asset rather than the OOM it would cause.
/// The player's largest file (a wasm module) is a few MB.
constexpr long kMaxFileBytes = 64L * 1024L * 1024L;

/// Accept-loop poll slice: bounds how long Stop() waits for the thread.
constexpr int kPollSliceMs = 100;

/// Read/write idle cutoff; also the keep-alive lifetime.
constexpr int kIoTimeoutSeconds = 10;

void Log(const char* fmt, ...)
{
    std::fputs("web-server: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

const char* ReasonPhrase(int status)
{
    switch (status)
    {
    case 200:
        return "OK";
    case 304:
        return "Not Modified";
    case 400:
        return "Bad Request";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 413:
        return "Content Too Large";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 503:
        return "Service Unavailable";
    default:
        return "Error";
    }
}

/// Content-Type by extension. The wasm mapping is load-bearing: a
/// WebAssembly module the browser sniffs wrongly fails
/// instantiateStreaming with a MIME error. Everything unrecognized is
/// application/octet-stream, which X-Content-Type-Options: nosniff keeps
/// the browser from second-guessing.
const char* ContentType(const std::string& path)
{
    const std::size_t dot = path.find_last_of('.');
    const std::string ext_name =
        (dot == std::string::npos || path.find('/', dot) != std::string::npos) ? std::string() : path.substr(dot + 1);

    if (ext_name == "html" || ext_name == "htm")
    {
        return "text/html; charset=utf-8";
    }
    if (ext_name == "js" || ext_name == "mjs")
    {
        return "text/javascript; charset=utf-8";
    }
    if (ext_name == "wasm")
    {
        return "application/wasm";
    }
    if (ext_name == "css")
    {
        return "text/css; charset=utf-8";
    }
    if (ext_name == "json")
    {
        return "application/json";
    }
    if (ext_name == "map")
    {
        return "application/json";
    }
    if (ext_name == "png")
    {
        return "image/png";
    }
    if (ext_name == "svg")
    {
        return "image/svg+xml";
    }
    if (ext_name == "ico")
    {
        return "image/x-icon";
    }
    if (ext_name == "txt")
    {
        return "text/plain; charset=utf-8";
    }
    return "application/octet-stream";
}

/// The player responses' extra headers. COOP+COEP make the document
/// cross-origin isolated, which the emcc pthreads engine needs for its
/// SharedArrayBuffer; both player paths (the web_root disk override and
/// the embedded table) build their set here, 304s included. Harmless for
/// the single-threaded dist: every player subresource is same-origin, so
/// require-corp excludes nothing the page loads.
std::vector<std::pair<std::string, std::string>> PlayerHeaders(const std::string& etag)
{
    return {{"ETag", etag},
            {"Cross-Origin-Opener-Policy", "same-origin"},
            {"Cross-Origin-Embedder-Policy", "require-corp"}};
}

/// RFC 9110 percent-decoding, in place over `path`. The player links
/// plain ASCII assets, but a hand-typed URL may carry escapes.
void PercentDecode(std::string& path)
{
    std::string out;
    out.reserve(path.size());
    for (std::size_t i = 0; i < path.size(); ++i)
    {
        if (path[i] == '%' && i + 2 < path.size())
        {
            const auto hex = [](char c) -> int
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
            };
            const int hi = hex(path[i + 1]);
            const int lo = hex(path[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(path[i]);
    }
    path = std::move(out);
}

void Lower(std::string& value)
{
    std::ranges::transform(value, value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
}

/// The path portion of a request target (query and fragment dropped).
std::string PathOf(const std::string& target)
{
    std::string path = target.substr(0, target.find_first_of("?#"));
    PercentDecode(path);
    return path;
}

// ---- JSON ----
// A hand-rolled writer: the gateway has no JSON dependency, and the two
// documents are fixed shapes built in one place each.

void AppendJsonString(std::string& out, const std::string& value)
{
    out.push_back('"');
    for (const char c : value)
    {
        switch (c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                char esc[7];
                std::snprintf(esc, sizeof esc, "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
                out += esc;
            }
            else
            {
                out.push_back(c);
            }
        }
    }
    out.push_back('"');
}

void AppendKey(std::string& out, const char* key)
{
    out.push_back('"');
    out += key;
    out += "\":";
}

/// `"key":<number>` with the comma already appended by the caller.
void AppendNum(std::string& out, const char* key, std::uint64_t value)
{
    AppendKey(out, key);
    out += std::to_string(value);
}

void AppendBool(std::string& out, const char* key, bool value)
{
    AppendKey(out, key);
    out += value ? "true" : "false";
}

void AppendString(std::string& out, const char* key, const std::string& value)
{
    AppendKey(out, key);
    AppendJsonString(out, value);
}

// ---- HTML ----

/// /stats content negotiation, deliberately q-value-free: HTML exactly
/// when the Accept header names text/html - every browser navigation
/// does, and nothing in play ever sends text/html;q=0. curl's */*, a
/// script's application/json and a missing header all keep the JSON.
bool PrefersHtml(const std::string& accept)
{
    std::string lowered = accept;
    Lower(lowered);
    return lowered.find("text/html") != std::string::npos;
}

/// The one rule the stats page needs beyond string building: whatever a
/// client chose (stream names, remotes) is interpolated into the page
/// and must not carry markup into it.
void AppendHtmlEscaped(std::string& out, const std::string& value)
{
    for (const char c : value)
    {
        switch (c)
        {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        default:
            out.push_back(c);
        }
    }
}

} // namespace

// ---- Wire ----

struct WebServer::Wire
{
    explicit Wire(int fd, SSL* ssl)
        : fd(fd)
        , ssl(ssl)
    {
    }

    /// >0 bytes, 0 = the peer closed, <0 = error or the idle timeout.
    long Read(void* buf, std::size_t len) const
    {
        return ssl != nullptr ? SSL_read(ssl, buf, static_cast<int>(len)) : ::recv(fd, buf, len, 0);
    }

    /// Writes everything or reports failure; a short write on a socket is
    /// a slow peer, never a reason to truncate a response silently.
    bool Write(const void* buf, std::size_t len) const
    {
        const auto* bytes  = static_cast<const char*>(buf);
        std::size_t offset = 0;
        while (offset < len)
        {
            const long n = ssl != nullptr ? SSL_write(ssl, bytes + offset, static_cast<int>(len - offset))
                                          : ::send(fd, bytes + offset, len - offset, MSG_NOSIGNAL);
            if (n <= 0)
            {
                return false;
            }
            offset += static_cast<std::size_t>(n);
        }
        return true;
    }

    int  fd;
    SSL* ssl;
};

WebServer::WebServer(WebServerConfig config)
    : config_(std::move(config))
    , started_(std::chrono::steady_clock::now())
{
}

WebServer::~WebServer()
{
    Stop();
}

bool WebServer::Start(std::string* error)
{
    if (running_)
    {
        if (error != nullptr)
        {
            *error = "web server already started";
        }
        return false;
    }

    // A peer that resets a connection must not kill the process: the
    // plain-socket path can ask for MSG_NOSIGNAL per send, but TLS has no
    // equivalent (BoringSSL's SSL_write raises SIGPIPE on a reset), so the
    // process opts out once, here - the same thing every TLS server does.
    ::signal(SIGPIPE, SIG_IGN);

    // The web root is validated here, not per request: a typo in the
    // config must not look like a player that lost its assets.
    if (!config_.web_root.empty())
    {
        char resolved[PATH_MAX];
        if (realpath(config_.web_root.c_str(), resolved) == nullptr)
        {
            if (error != nullptr)
            {
                *error = "web_root '" + config_.web_root + "' does not exist";
            }
            return false;
        }
        struct stat st{};
        if (::stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            if (error != nullptr)
            {
                *error = "web_root '" + config_.web_root + "' is not a directory";
            }
            return false;
        }
        root_ = resolved;
    }

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo*  addrs   = nullptr;
    const std::string service = std::to_string(config_.port);
    const int         rc      = ::getaddrinfo(config_.bind.c_str(), service.c_str(), &hints, &addrs);
    if (rc != 0)
    {
        if (error != nullptr)
        {
            *error = std::string("cannot resolve bind address: ") + gai_strerror(rc);
        }
        return false;
    }

    for (struct addrinfo* ai = addrs; ai != nullptr; ai = ai->ai_next)
    {
        const int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        if (::bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && ::listen(fd, SOMAXCONN) == 0)
        {
            listen_fd_ = fd;
            break;
        }
        ::close(fd);
    }
    ::freeaddrinfo(addrs);

    if (listen_fd_ < 0)
    {
        if (error != nullptr)
        {
            *error = "cannot bind " + config_.bind + ":" + service;
        }
        return false;
    }

    struct sockaddr_storage bound{};
    socklen_t               bound_len = sizeof bound;
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0 && bound.ss_family == AF_INET)
    {
        port_ = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
    }
    else
    {
        port_ = config_.port;
    }

    if (config_.cert != nullptr)
    {
        ssl_ctx_ = NewServerSslCtx(*config_.cert);
        if (ssl_ctx_ == nullptr)
        {
            if (error != nullptr)
            {
                *error = "cannot build the server TLS context";
            }
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
    }

    started_       = std::chrono::steady_clock::now();
    running_       = true;
    stopping_      = false;
    accept_thread_ = std::thread(&WebServer::AcceptLoop, this);
    return true;
}

void WebServer::Stop()
{
    stopping_ = true;

    if (accept_thread_.joinable())
    {
        accept_thread_.join(); // exits within one poll slice
    }
    if (listen_fd_ >= 0)
    {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }

    // Moved out under the lock, acted on outside it: a worker needs the
    // same mutex to report that it finished, so joining while holding it
    // would deadlock.
    std::set<int> conns;
    {
        const std::lock_guard<std::mutex> lock(conns_mutex_);
        conns.swap(conns_);
    }
    for (const int fd : conns)
    {
        ::shutdown(fd, SHUT_RDWR); // unblocks a worker parked in read
    }

    std::vector<Worker> workers;
    {
        const std::lock_guard<std::mutex> lock(workers_mutex_);
        workers.swap(workers_);
    }
    for (Worker& worker : workers)
    {
        if (worker.thread.joinable())
        {
            worker.thread.join();
        }
    }

    if (ssl_ctx_ != nullptr)
    {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    running_ = false;
}

void WebServer::AcceptLoop()
{
    while (!stopping_)
    {
        struct pollfd pfd{};
        pfd.fd     = listen_fd_;
        pfd.events = POLLIN;
        if (::poll(&pfd, 1, kPollSliceMs) <= 0)
        {
            ReapWorkers();
            continue;
        }

        const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0)
        {
            continue;
        }

        {
            const std::lock_guard<std::mutex> lock(conns_mutex_);
            if (conns_.size() >= config_.max_connections)
            {
                // Past the cap: refuse immediately rather than queue, so
                // one client cannot spend the whole budget.
                ::close(fd);
                const auto now = std::chrono::steady_clock::now();
                if (now - last_drop_log_ >= std::chrono::seconds{1})
                {
                    last_drop_log_ = now;
                    Log("connection cap of %zu reached; connection refused", config_.max_connections);
                }
                continue;
            }
            conns_.insert(fd);
        }

        Worker worker;
        worker.done   = std::make_shared<std::atomic<bool>>(false);
        worker.thread = std::thread(&WebServer::Serve, this, fd, worker.done);
        const std::lock_guard<std::mutex> lock(workers_mutex_);
        workers_.push_back(std::move(worker));
    }
    ReapWorkers();
}

void WebServer::ReapWorkers()
{
    const std::lock_guard<std::mutex> lock(workers_mutex_);
    for (auto it = workers_.begin(); it != workers_.end();)
    {
        if (it->done->load(std::memory_order_relaxed))
        {
            if (it->thread.joinable())
            {
                it->thread.join();
            }
            it = workers_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void WebServer::Serve(int fd, const std::shared_ptr<std::atomic<bool>>& done)
{
    struct timeval timeout{};
    timeout.tv_sec  = kIoTimeoutSeconds;
    timeout.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);

    SSL* ssl = nullptr;
    if (ssl_ctx_ != nullptr)
    {
        ssl = SSL_new(ssl_ctx_);
        if (ssl == nullptr || SSL_set_fd(ssl, fd) != 1 || SSL_accept(ssl) != 1)
        {
            if (ssl != nullptr)
            {
                SSL_free(ssl);
            }
            ::close(fd);
            {
                const std::lock_guard<std::mutex> lock(conns_mutex_);
                conns_.erase(fd);
            }
            done->store(true, std::memory_order_relaxed);
            return;
        }
    }

    Wire wire(fd, ssl);
    bool keep_going = true;
    while (keep_going && !stopping_)
    {
        // Read to the end of the header block (bounded). No body is ever
        // read - a request that carries one is refused with 405 and the
        // connection closes.
        std::string request;
        char        buf[4096];
        // The header block's TOTAL budget, from the request's first
        // byte (a request that never sends one included - though a
        // fully silent peer is already ended by the per-read timeout
        // below). Checked after each read, so a read already parked
        // when the budget runs out still ends on the per-read timeout:
        // the deadline bounds the trickler, the timeout the silent peer.
        const auto header_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{config_.header_timeout_s};
        while (request.find("\r\n\r\n") == std::string::npos)
        {
            const long n = wire.Read(buf, sizeof buf);
            if (n <= 0)
            {
                break; // closed, timed out or errored
            }
            request.append(buf, static_cast<std::size_t>(n));
            if (request.size() > kMaxHeaderBytes)
            {
                SendSimple(
                    wire, 431, ReasonPhrase(431), "text/plain; charset=utf-8", "request headers too large\n", false);
                request.clear();
                break;
            }
            if (std::chrono::steady_clock::now() >= header_deadline)
            {
                SendSimple(
                    wire, 408, ReasonPhrase(408), "text/plain; charset=utf-8", "request header timeout\n", false);
                request.clear();
                break;
            }
        }
        if (request.empty() || request.find("\r\n\r\n") == std::string::npos)
        {
            break;
        }

        const std::size_t first_eol = request.find("\r\n");
        const std::string line      = request.substr(0, first_eol);
        const std::string headers   = request.substr(first_eol + 2, request.find("\r\n\r\n") - first_eol - 2);

        // Request line: METHOD SP TARGET SP VERSION.
        const std::size_t sp1 = line.find(' ');
        const std::size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos)
        {
            SendSimple(wire, 400, ReasonPhrase(400), "text/plain; charset=utf-8", "malformed request line\n", false);
            break;
        }
        const std::string method  = line.substr(0, sp1);
        const std::string target  = line.substr(sp1 + 1, sp2 - sp1 - 1);
        const std::string version = line.substr(sp2 + 1);
        if (version != "HTTP/1.1" && version != "HTTP/1.0")
        {
            SendSimple(wire, 400, ReasonPhrase(400), "text/plain; charset=utf-8", "unsupported HTTP version\n", false);
            break;
        }

        std::string if_none_match;
        std::string accept;
        bool        client_close = false;
        std::size_t pos          = 0;
        while (pos < headers.size())
        {
            const std::size_t eol    = headers.find("\r\n", pos);
            const std::string header = headers.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            const std::size_t colon  = header.find(':');
            if (colon != std::string::npos)
            {
                std::string name  = header.substr(0, colon);
                std::string value = header.substr(colon + 1);
                while (!name.empty() && name.back() == ' ')
                {
                    name.pop_back();
                }
                const std::size_t first = value.find_first_not_of(" \t");
                value                   = first == std::string::npos ? std::string() : value.substr(first);
                Lower(name);
                if (name == "if-none-match")
                {
                    if_none_match = value;
                }
                else if (name == "accept")
                {
                    accept = value;
                }
                else if (name == "connection")
                {
                    Lower(value);
                    client_close = value.find("close") != std::string::npos;
                }
            }
            if (eol == std::string::npos)
            {
                break;
            }
            pos = eol + 2;
        }

        keep_going = Handle(wire, method, target, if_none_match, accept);
        if (!keep_going || client_close)
        {
            break;
        }
    }

    if (ssl != nullptr)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    ::close(fd);
    {
        const std::lock_guard<std::mutex> lock(conns_mutex_);
        conns_.erase(fd);
    }
    done->store(true, std::memory_order_relaxed);
}

bool WebServer::Handle(Wire&              wire,
                       const std::string& method,
                       const std::string& target,
                       const std::string& if_none_match,
                       const std::string& accept)
{
    if (method != "GET" && method != "HEAD")
    {
        SendSimple(wire,
                   405,
                   ReasonPhrase(405),
                   "text/plain; charset=utf-8",
                   "only GET and HEAD are served\n",
                   false,
                   {{"Allow", "GET, HEAD"}},
                   false); // no body was read, so the stream is at EOF: close
        return false;
    }
    const bool head = method == "HEAD";

    const std::string path = PathOf(target);

    if (path == "/health")
    {
        SendJson(wire, HealthJson(), head);
        return true;
    }
    if (path == "/stats")
    {
        if (PrefersHtml(accept))
        {
            SendSimple(wire,
                       200,
                       ReasonPhrase(200),
                       "text/html; charset=utf-8",
                       StatsHtml(),
                       head,
                       {{"Cache-Control", "no-store"}});
        }
        else
        {
            SendJson(wire, StatsJson(), head);
        }
        return true;
    }

    if (!config_.cert_hash_js.empty() && path == "/cert-hash.js")
    {
        // Dynamic on purpose (the oracle serves it the same way): in self
        // mode the pinned hash changes every boot, so the file must never
        // be cached across restarts.
        SendSimple(wire,
                   200,
                   ReasonPhrase(200),
                   "text/javascript; charset=utf-8",
                   config_.cert_hash_js,
                   head,
                   {{"Cache-Control", "no-store"}});
        return true;
    }

    // Static file. Directory-ish targets resolve to their index.html, as
    // the oracle's fallback does for "/".
    std::string relative = path.empty() || path.front() != '/' ? "/" + path : path;
    if (relative.back() == '/' || relative == "/")
    {
        relative += "index.html";
    }

    if (config_.serve_player && !root_.empty())
    {
        // Disk override (web_root): canonicalized, contained, mtime+size
        // ETag'd file serving.
        char resolved[PATH_MAX];
        if (realpath((root_ + relative).c_str(), resolved) == nullptr)
        {
            SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
            return true;
        }
        std::string full = resolved;
        struct stat st{};
        if (::stat(full.c_str(), &st) != 0)
        {
            SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
            return true;
        }
        if (S_ISDIR(st.st_mode))
        {
            const std::string index = full + "/index.html";
            if (realpath(index.c_str(), resolved) == nullptr)
            {
                SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
                return true;
            }
            full = resolved;
            if (::stat(full.c_str(), &st) != 0)
            {
                SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
                return true;
            }
        }

        // The containment check, AFTER canonicalization: this is what rejects
        // "../..", an encoded traversal and any symlink pointing outside the
        // root, because realpath has already resolved all three.
        if (full != root_ && full.compare(0, root_.size() + 1, root_ + "/") != 0)
        {
            SendSimple(wire, 403, ReasonPhrase(403), "text/plain; charset=utf-8", "forbidden\n", head);
            return true;
        }

        std::ifstream in(full, std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
            return true;
        }
        const std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (body.size() > static_cast<std::size_t>(kMaxFileBytes))
        {
            SendSimple(wire, 413, ReasonPhrase(413), "text/plain; charset=utf-8", "asset too large\n", head);
            return true;
        }

        // ETag over size and mtime seconds: changes whenever the file is
        // rewritten or replaced, and unlike Last-Modified it cannot be
        // fooled by a sub-second edit (or by a clock skew on a deployment
        // that only rewrote the mtime).
        char etag[64];
        std::snprintf(etag,
                      sizeof etag,
                      "\"%lld-%lld\"",
                      static_cast<long long>(st.st_mtime),
                      static_cast<long long>(st.st_size));

        if (!if_none_match.empty() && if_none_match.find(etag) != std::string::npos)
        {
            SendSimple(wire, 304, ReasonPhrase(304), ContentType(full), {}, head, PlayerHeaders(etag));
            return true;
        }

        SendSimple(wire, 200, ReasonPhrase(200), ContentType(full), body, head, PlayerHeaders(etag));
        return true;
    }

    // Embedded player (the default when serve_player is set and no
    // web_root override is, rust-embed parity): the table is immutable
    // for the life of the binary, so the ETag is just the size - it
    // changes exactly when the binary does.
    if (config_.serve_player)
    {
        for (const EmbeddedAsset& asset : EmbeddedPlayerFiles())
        {
            if (asset.path != relative)
            {
                continue;
            }
            const std::string body(asset.bytes);
            const std::string etag = "\"bin-" + std::to_string(body.size()) + "\"";
            if (!if_none_match.empty() && if_none_match.find(etag) != std::string::npos)
            {
                SendSimple(wire, 304, ReasonPhrase(304), ContentType(relative), {}, head, PlayerHeaders(etag));
                return true;
            }
            SendSimple(wire, 200, ReasonPhrase(200), ContentType(relative), body, head, PlayerHeaders(etag));
            return true;
        }
    }

    SendSimple(wire, 404, ReasonPhrase(404), "text/plain; charset=utf-8", "not found\n", head);
    return true;
}

void WebServer::SendJson(Wire& wire, const std::string& body, bool head)
{
    SendSimple(wire, 200, ReasonPhrase(200), "application/json", body, head, {{"Cache-Control", "no-store"}});
}

void WebServer::SendSimple(Wire&                                                   wire,
                           int                                                     status,
                           const char*                                             reason,
                           const char*                                             content_type,
                           const std::string&                                      body,
                           bool                                                    head,
                           const std::vector<std::pair<std::string, std::string>>& extra,
                           bool                                                    keep_alive)
{
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    if (status != 304) // a 304 carries neither a body nor a Content-Type (RFC 9110 §15.4.5)
    {
        out += "Content-Type: ";
        out += content_type;
        out += "\r\nContent-Length: ";
        out += std::to_string(body.size());
        out += "\r\n";
    }
    for (const auto& [name, value] : extra)
    {
        out += name;
        out += ": ";
        out += value;
        out += "\r\n";
    }
    out += "X-Content-Type-Options: nosniff\r\n";
    out += keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    out += "\r\n";

    if (!wire.Write(out.data(), out.size()))
    {
        return;
    }
    if (!head && status != 304 && !body.empty())
    {
        wire.Write(body.data(), body.size());
    }
}

std::string WebServer::HealthJson() const
{
    const std::vector<StreamStats> streams =
        config_.gateway != nullptr ? config_.gateway->SnapshotStreams() : std::vector<StreamStats>{};
    const std::vector<SessionSnapshot> sessions =
        config_.gateway != nullptr ? config_.gateway->Sessions().SnapshotSessions() : std::vector<SessionSnapshot>{};

    std::size_t alive   = 0;
    std::size_t viewers = 0;
    for (const StreamStats& stream : streams)
    {
        alive += stream.publisher_live ? 1 : 0;
        viewers += stream.viewers;
    }

    std::string out = "{";
    AppendString(out, "status", alive > 0 ? "ok" : "no_source");
    out += ",";
    AppendNum(out,
              "uptime_ms",
              static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_)
                      .count()));
    out += ",";
    AppendNum(out, "streams", streams.size());
    out += ",";
    AppendNum(out, "alive_streams", alive);
    out += ",";
    AppendNum(out, "viewers", viewers);
    out += ",";
    AppendNum(out, "max_viewers", config_.gateway != nullptr ? config_.gateway->MaxViewers() : 0);
    out += ",";
    AppendNum(out, "active_sessions", sessions.size());

    out += ",\"per_stream\":[";
    for (std::size_t i = 0; i < streams.size(); ++i)
    {
        const StreamStats& stream = streams[i];
        if (i > 0)
        {
            out += ",";
        }
        out += "{";
        AppendString(out, "name", stream.name);
        out += ",";
        AppendBool(out, "alive", stream.publisher_live);
        out += ",";
        AppendNum(out, "viewers", stream.viewers);
        out += ",";
        AppendNum(out, "messages_sent", stream.messages_sent);
        out += ",";
        AppendNum(out, "send_failures", stream.send_failures);
        out += "}";
    }

    out += "],\"per_session\":[";
    for (std::size_t i = 0; i < sessions.size(); ++i)
    {
        const SessionSnapshot& session = sessions[i];
        if (i > 0)
        {
            out += ",";
        }
        out += "{";
        AppendNum(out, "session_id", session.session_id);
        out += ",";
        AppendString(out, "stream", session.info.stream_name);
        out += ",";
        AppendNum(out, "tx_data", static_cast<std::uint64_t>(session.srt.pktSentTotal));
        out += ",";
        AppendNum(out, "tx_buffered", static_cast<std::uint64_t>(session.srt.pktSndBuf));
        out += ",";
        AppendNum(out, "tx_retransmit", static_cast<std::uint64_t>(session.srt.pktRetransTotal));
        out += ",";
        AppendNum(out, "tx_loss", static_cast<std::uint64_t>(session.srt.pktSndLossTotal));
        out += ",";
        AppendNum(out, "rtt_ms", static_cast<std::uint64_t>(session.srt.msRTT));
        out += ",";
        AppendNum(out,
                  "messages_pushed",
                  session.info.publisher_role ? session.info.messages_received : session.info.messages_sent);
        out += ",";
        // The oracle counts lagged messages; here the drop-oldest counter
        // at the send backlog bound is the same event seen from the
        // session side (the ring has its own ring_drops in /stats).
        AppendNum(out, "viewer_lag", session.info.backlog_overflow_drops);
        out += ",";
        AppendNum(out, "buffer_lag", session.info.backlog_size);
        out += "}";
    }

    out += "],\"ticker\":{";
    const std::uint64_t count = config_.gateway != nullptr ? config_.gateway->TickCount() : 0;
    const std::uint64_t avg   = config_.gateway != nullptr ? config_.gateway->Sessions().TickAvgUs() : 0;
    const std::uint64_t max   = config_.gateway != nullptr ? config_.gateway->TickMaxUs() : 0;
    AppendNum(out, "count", count);
    out += ",";
    AppendNum(out, "avg_us", avg);
    out += ",";
    AppendNum(out, "max_us", max);
    out += "}";

    // The oracle's ingester slot (websrt-gateway main.rs:669-689): a map
    // keyed by stream name, each entry that publisher connection's
    // TS-continuity probe (cc_checks / cc_gaps / messages_seen), null
    // while no publisher has ever connected. An entry appears when a
    // publisher claims the name, persists after the connection ends
    // (frozen at its final counters) and starts fresh when the name is
    // claimed again. The aggregate counters live in /stats only.
    const SrtIngestStats ingest_stats = config_.ingest != nullptr ? config_.ingest->Stats() : SrtIngestStats{};
    out += ",\"ingester\":";
    if (ingest_stats.streams.empty())
    {
        out += "null";
    }
    else
    {
        out += "{";
        bool first = true;
        for (const auto& [name, cc] : ingest_stats.streams)
        {
            if (!first)
            {
                out += ",";
            }
            first = false;
            AppendJsonString(out, name);
            out += ":{";
            AppendNum(out, "cc_checks", cc.cc_checks);
            out += ",";
            AppendNum(out, "cc_gaps", cc.cc_gaps);
            out += ",";
            AppendNum(out, "messages_seen", cc.messages_seen);
            out += "}";
        }
        out += "}";
    }

    out += "}\n";
    return out;
}

std::string WebServer::StatsJson() const
{
    const std::vector<StreamStats> streams =
        config_.gateway != nullptr ? config_.gateway->SnapshotStreams() : std::vector<StreamStats>{};
    const std::vector<SessionSnapshot> sessions =
        config_.gateway != nullptr ? config_.gateway->Sessions().SnapshotSessions() : std::vector<SessionSnapshot>{};

    std::size_t alive   = 0;
    std::size_t viewers = 0;
    for (const StreamStats& stream : streams)
    {
        alive += stream.publisher_live ? 1 : 0;
        viewers += stream.viewers;
    }

    std::string out = "{";
    AppendNum(out,
              "uptime_ms",
              static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_)
                      .count()));
    out += ",";
    AppendNum(out, "stream_count", streams.size());
    out += ",";
    AppendNum(out, "alive_streams", alive);
    out += ",";
    AppendNum(out, "viewers", viewers);
    out += ",";
    AppendNum(out, "max_viewers", config_.gateway != nullptr ? config_.gateway->MaxViewers() : 0);
    out += ",";
    AppendNum(out, "active_sessions", sessions.size());

    out += ",\"ticker\":{";
    const std::uint64_t count = config_.gateway != nullptr ? config_.gateway->TickCount() : 0;
    const std::uint64_t avg   = config_.gateway != nullptr ? config_.gateway->Sessions().TickAvgUs() : 0;
    const std::uint64_t max   = config_.gateway != nullptr ? config_.gateway->TickMaxUs() : 0;
    AppendNum(out, "count", count);
    out += ",";
    AppendNum(out, "avg_us", avg);
    out += ",";
    AppendNum(out, "max_us", max);
    out += "}";

    // The WT server's own counters (the oracle keeps these in its GUI
    // only; here they are the other half of "is the accept path healthy").
    out += ",\"server\":{";
    if (config_.gateway != nullptr)
    {
        const WtServer& server = config_.gateway->Server();
        AppendNum(out, "sessions_accepted", static_cast<std::uint64_t>(server.SessionsAccepted()));
        out += ",";
        AppendNum(out, "sessions_rejected", static_cast<std::uint64_t>(server.SessionsRejected()));
        out += ",";
        AppendNum(out, "datagrams_received", static_cast<std::uint64_t>(server.DatagramsReceived()));
        out += ",";
        AppendNum(out, "datagrams_written", static_cast<std::uint64_t>(server.DatagramsWritten()));
        out += ",";
        AppendNum(out, "datagrams_dropped", static_cast<std::uint64_t>(server.DatagramsDropped()));
    }
    else
    {
        AppendNum(out, "sessions_accepted", 0);
        out += ",";
        AppendNum(out, "sessions_rejected", 0);
        out += ",";
        AppendNum(out, "datagrams_received", 0);
        out += ",";
        AppendNum(out, "datagrams_written", 0);
        out += ",";
        AppendNum(out, "datagrams_dropped", 0);
    }
    out += "}";

    // P4.3 webhook evidence: the dropped counter is the one an operator
    // watching a stuck receiver needs first.
    out += ",\"webhooks\":{";
    {
        const WebhookSnapshot webhooks =
            config_.gateway != nullptr ? config_.gateway->WebhookStats() : WebhookSnapshot{};
        AppendBool(out, "enabled", webhooks.enabled);
        out += ",";
        AppendNum(out, "delivered", webhooks.delivered);
        out += ",";
        AppendNum(out, "dropped", webhooks.dropped);
        out += ",";
        AppendNum(out, "failed", webhooks.failed);
    }
    out += "}";

    out += ",\"streams\":[";
    for (std::size_t i = 0; i < streams.size(); ++i)
    {
        const StreamStats& stream = streams[i];
        if (i > 0)
        {
            out += ",";
        }
        out += "{";
        AppendString(out, "name", stream.name);
        out += ",";
        AppendBool(out, "alive", stream.publisher_live);
        out += ",";
        AppendNum(out, "viewers", stream.viewers);
        out += ",";
        AppendNum(out, "ring_size", stream.ring_size);
        out += ",";
        AppendNum(out, "messages_sent", stream.messages_sent);
        out += ",";
        AppendNum(out, "send_failures", stream.send_failures);
        out += ",";
        AppendNum(out, "ring_drops", stream.ring_drops);
        out += ",";
        AppendNum(out, "oversize_drops", stream.oversize_drops);
        out += "}";
    }

    out += "],\"sessions\":[";
    for (std::size_t i = 0; i < sessions.size(); ++i)
    {
        const SessionSnapshot& session = sessions[i];
        if (i > 0)
        {
            out += ",";
        }
        out += "{";
        AppendNum(out, "session_id", session.session_id);
        out += ",";
        AppendString(out, "stream", session.info.stream_name);
        out += ",";
        AppendBool(out, "publisher", session.info.publisher_role);
        out += ",";
        AppendBool(out, "connected", session.info.connected);
        out += ",";
        AppendNum(out, "max_payload", static_cast<std::uint64_t>(session.info.max_payload));
        out += ",";
        AppendNum(out, "messages_sent", session.info.messages_sent);
        out += ",";
        AppendNum(out, "messages_received", session.info.messages_received);
        out += ",";
        AppendNum(out, "backlog_size", session.info.backlog_size);
        out += ",";
        AppendNum(out, "backlog_start_drops", session.info.backlog_start_drops);
        out += ",";
        AppendNum(out, "backlog_overflow_drops", session.info.backlog_overflow_drops);
        out += ",";
        AppendNum(out, "tx_data", static_cast<std::uint64_t>(session.srt.pktSentTotal));
        out += ",";
        AppendNum(out, "tx_retransmit", static_cast<std::uint64_t>(session.srt.pktRetransTotal));
        out += ",";
        AppendNum(out, "tx_loss", static_cast<std::uint64_t>(session.srt.pktSndLossTotal));
        out += ",";
        AppendNum(out, "tx_buffered", static_cast<std::uint64_t>(session.srt.pktSndBuf));
        out += ",";
        AppendNum(out, "rtt_ms", static_cast<std::uint64_t>(session.srt.msRTT));
        out += ",";
        AppendNum(out, "rx_mbps_x1000", static_cast<std::uint64_t>(session.srt.mbpsRecvRate * 1000.0));
        out += ",";
        AppendNum(
            out, "rx_pkts", static_cast<std::uint64_t>(session.srt.pktRecvTotal > 0 ? session.srt.pktRecvTotal : 0));
        out += ",";
        AppendNum(out,
                  "rx_drop",
                  static_cast<std::uint64_t>(session.srt.pktRcvDropTotal > 0 ? session.srt.pktRcvDropTotal : 0));
        out += ",";
        AppendNum(out,
                  "rx_loss",
                  static_cast<std::uint64_t>(session.srt.pktRcvLossTotal > 0 ? session.srt.pktRcvLossTotal : 0));
        out += ",";
        AppendNum(out,
                  "rx_belated",
                  static_cast<std::uint64_t>(session.srt.pktRcvBelated > 0 ? session.srt.pktRcvBelated : 0));
        out += "}";
    }

    out += "],\"ingest\":";
    if (config_.ingest == nullptr)
    {
        out += "null";
    }
    else
    {
        const SrtIngestStats stats = config_.ingest->Stats();
        out += "{";
        AppendNum(out, "publishers_accepted", stats.publishers_accepted);
        out += ",";
        AppendNum(out, "publishers_rejected", stats.publishers_rejected);
        out += ",";
        AppendNum(out, "rejected_no_streamid", stats.rejected_no_streamid);
        out += ",";
        AppendNum(out, "rejected_not_allowed", stats.rejected_not_allowed);
        out += ",";
        AppendNum(out, "rejected_occupied", stats.rejected_occupied);
        out += ",";
        AppendNum(out, "rejected_session_cap", stats.rejected_session_cap);
        out += ",";
        AppendNum(out, "publishers_ended", stats.publishers_ended);
        out += ",";
        AppendNum(out, "messages_in", stats.messages_in);
        out += ",";
        AppendNum(out, "bytes_in", stats.bytes_in);
        out += ",";
        AppendNum(out, "chunks_out", stats.chunks_out);
        out += ",";
        AppendNum(out, "bytes_out", stats.bytes_out);
        out += ",";
        AppendNum(out, "tail_flushes", stats.tail_flushes);
        out += ",\"connections\":[";
        for (std::size_t i = 0; i < stats.connections.size(); ++i)
        {
            const SrtConnectionStats& conn = stats.connections[i];
            if (i > 0)
            {
                out += ",";
            }
            out += "{";
            AppendString(out, "stream", conn.stream);
            out += ",";
            AppendString(out, "remote", conn.remote);
            out += ",";
            AppendNum(out, "bytes_in", conn.bytes_in);
            out += ",";
            AppendNum(out, "messages_in", conn.messages_in);
            out += ",";
            AppendNum(out, "chunks_out", conn.chunks_out);
            out += ",";
            AppendNum(out, "tail_bytes", conn.tail_bytes);
            out += ",";
            AppendNum(out, "cc_checks", conn.cc.cc_checks);
            out += ",";
            AppendNum(out, "cc_gaps", conn.cc.cc_gaps);
            out += ",";
            AppendNum(out, "messages_seen", conn.cc.messages_seen);
            out += "}";
        }
        out += "]}";
    }

    out += "}\n";
    return out;
}

std::string WebServer::StatsHtml() const
{
    const std::vector<StreamStats> streams =
        config_.gateway != nullptr ? config_.gateway->SnapshotStreams() : std::vector<StreamStats>{};
    const std::vector<SessionSnapshot> sessions =
        config_.gateway != nullptr ? config_.gateway->Sessions().SnapshotSessions() : std::vector<SessionSnapshot>{};

    std::size_t alive   = 0;
    std::size_t viewers = 0;
    for (const StreamStats& stream : streams)
    {
        alive += stream.publisher_live ? 1 : 0;
        viewers += stream.viewers;
    }

    std::string out = "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
                      // The page is its own dashboard; the refresh keeps the tables live.
                      "<meta http-equiv=\"refresh\" content=\"5\">\n"
                      "<title>QuicSRT-gateway stats</title>\n"
                      "<style>\n"
                      "body{font-family:sans-serif;margin:1em}\n"
                      "table{border-collapse:collapse;margin:0 0 1em}\n"
                      "th,td{border:1px solid #999;padding:2px 8px;text-align:left}\n"
                      "caption{caption-side:top;text-align:left;font-weight:bold;padding:4px 0}\n"
                      "</style>\n</head>\n<body>\n<h1>QuicSRT-gateway stats</h1>\n";

    // A label/value row of a two-column table (summary, ticker, server,
    // ingest) - the HTML counterpart of the JSON's flat number keys.
    const auto kv = [&out](const char* key, std::uint64_t value)
    {
        out += "<tr><th>";
        out += key;
        out += "</th><td>";
        out += std::to_string(value);
        out += "</td></tr>\n";
    };
    const auto td = [&out](const std::string& cell)
    {
        out += "<td>";
        out += cell;
        out += "</td>";
    };
    const auto yes_no = [](bool value) { return value ? "yes" : "no"; };

    out += "<table>\n";
    kv("uptime_ms",
       static_cast<std::uint64_t>(
           std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_).count()));
    kv("stream_count", streams.size());
    kv("alive_streams", alive);
    kv("viewers", viewers);
    kv("max_viewers", config_.gateway != nullptr ? config_.gateway->MaxViewers() : 0);
    kv("active_sessions", sessions.size());
    out += "</table>\n";

    out += "<table>\n<caption>ticker</caption>\n";
    kv("count", config_.gateway != nullptr ? config_.gateway->TickCount() : 0);
    kv("avg_us", config_.gateway != nullptr ? config_.gateway->Sessions().TickAvgUs() : 0);
    kv("max_us", config_.gateway != nullptr ? config_.gateway->TickMaxUs() : 0);
    out += "</table>\n";

    out += "<table>\n<caption>server</caption>\n";
    if (config_.gateway != nullptr)
    {
        const WtServer& server = config_.gateway->Server();
        kv("sessions_accepted", static_cast<std::uint64_t>(server.SessionsAccepted()));
        kv("sessions_rejected", static_cast<std::uint64_t>(server.SessionsRejected()));
        kv("datagrams_received", static_cast<std::uint64_t>(server.DatagramsReceived()));
        kv("datagrams_written", static_cast<std::uint64_t>(server.DatagramsWritten()));
        kv("datagrams_dropped", static_cast<std::uint64_t>(server.DatagramsDropped()));
    }
    else
    {
        kv("sessions_accepted", 0);
        kv("sessions_rejected", 0);
        kv("datagrams_received", 0);
        kv("datagrams_written", 0);
        kv("datagrams_dropped", 0);
    }
    out += "</table>\n";

    // P4.3 webhooks - same evidence as the JSON's webhooks object.
    out += "<table>\n<caption>webhooks</caption>\n";
    {
        const WebhookSnapshot webhooks =
            config_.gateway != nullptr ? config_.gateway->WebhookStats() : WebhookSnapshot{};
        kv("enabled", webhooks.enabled ? 1 : 0);
        kv("delivered", webhooks.delivered);
        kv("dropped", webhooks.dropped);
        kv("failed", webhooks.failed);
    }
    out += "</table>\n";

    out += "<table>\n<caption>streams</caption>\n"
           "<tr><th>name</th><th>alive</th><th>viewers</th><th>ring_size</th><th>messages_sent</th>"
           "<th>send_failures</th><th>ring_drops</th><th>oversize_drops</th></tr>\n";
    for (const StreamStats& stream : streams)
    {
        out += "<tr>";
        out += "<td>";
        AppendHtmlEscaped(out, stream.name);
        out += "</td>";
        td(yes_no(stream.publisher_live));
        td(std::to_string(stream.viewers));
        td(std::to_string(stream.ring_size));
        td(std::to_string(stream.messages_sent));
        td(std::to_string(stream.send_failures));
        td(std::to_string(stream.ring_drops));
        td(std::to_string(stream.oversize_drops));
        out += "</tr>\n";
    }
    if (streams.empty())
    {
        out += "<tr><td colspan=\"8\">none</td></tr>\n";
    }
    out += "</table>\n";

    out += "<table>\n<caption>sessions</caption>\n"
           "<tr><th>session_id</th><th>stream</th><th>publisher</th><th>connected</th><th>max_payload</th>"
           "<th>messages_sent</th><th>messages_received</th><th>backlog_size</th><th>backlog_start_drops</th>"
           "<th>backlog_overflow_drops</th><th>tx_data</th><th>tx_retransmit</th><th>tx_loss</th>"
           "<th>tx_buffered</th><th>rtt_ms</th></tr>\n";
    for (const SessionSnapshot& session : sessions)
    {
        out += "<tr>";
        td(std::to_string(session.session_id));
        out += "<td>";
        AppendHtmlEscaped(out, session.info.stream_name);
        out += "</td>";
        td(yes_no(session.info.publisher_role));
        td(yes_no(session.info.connected));
        td(std::to_string(session.info.max_payload));
        td(std::to_string(session.info.messages_sent));
        td(std::to_string(session.info.messages_received));
        td(std::to_string(session.info.backlog_size));
        td(std::to_string(session.info.backlog_start_drops));
        td(std::to_string(session.info.backlog_overflow_drops));
        td(std::to_string(static_cast<std::uint64_t>(session.srt.pktSentTotal)));
        td(std::to_string(static_cast<std::uint64_t>(session.srt.pktRetransTotal)));
        td(std::to_string(static_cast<std::uint64_t>(session.srt.pktSndLossTotal)));
        td(std::to_string(static_cast<std::uint64_t>(session.srt.pktSndBuf)));
        td(std::to_string(static_cast<std::uint64_t>(session.srt.msRTT)));
        out += "</tr>\n";
    }
    if (sessions.empty())
    {
        out += "<tr><td colspan=\"15\">none</td></tr>\n";
    }
    out += "</table>\n";

    if (config_.ingest == nullptr)
    {
        out += "<table>\n<caption>ingest</caption>\n<tr><td>inactive</td></tr>\n</table>\n";
    }
    else
    {
        const SrtIngestStats stats = config_.ingest->Stats();
        out += "<table>\n<caption>ingest</caption>\n";
        kv("publishers_accepted", stats.publishers_accepted);
        kv("publishers_rejected", stats.publishers_rejected);
        kv("rejected_no_streamid", stats.rejected_no_streamid);
        kv("rejected_not_allowed", stats.rejected_not_allowed);
        kv("rejected_occupied", stats.rejected_occupied);
        kv("rejected_session_cap", stats.rejected_session_cap);
        kv("publishers_ended", stats.publishers_ended);
        kv("messages_in", stats.messages_in);
        kv("bytes_in", stats.bytes_in);
        kv("chunks_out", stats.chunks_out);
        kv("bytes_out", stats.bytes_out);
        kv("tail_flushes", stats.tail_flushes);
        out += "</table>\n";

        out += "<table>\n<caption>ingest connections</caption>\n"
               "<tr><th>stream</th><th>remote</th><th>bytes_in</th><th>messages_in</th><th>chunks_out</th>"
               "<th>tail_bytes</th><th>cc_checks</th><th>cc_gaps</th><th>messages_seen</th></tr>\n";
        for (const SrtConnectionStats& conn : stats.connections)
        {
            out += "<tr>";
            out += "<td>";
            AppendHtmlEscaped(out, conn.stream);
            out += "</td>";
            out += "<td>";
            AppendHtmlEscaped(out, conn.remote);
            out += "</td>";
            td(std::to_string(conn.bytes_in));
            td(std::to_string(conn.messages_in));
            td(std::to_string(conn.chunks_out));
            td(std::to_string(conn.tail_bytes));
            td(std::to_string(conn.cc.cc_checks));
            td(std::to_string(conn.cc.cc_gaps));
            td(std::to_string(conn.cc.messages_seen));
            out += "</tr>\n";
        }
        if (stats.connections.empty())
        {
            out += "<tr><td colspan=\"9\">none</td></tr>\n";
        }
        out += "</table>\n";
    }

    out += "</body>\n</html>\n";
    return out;
}

} // namespace quicsrt::gateway