// Webhook delivery (P4 step 3). The HTTP client is deliberately
// dependency-free: a blocking plain-socket HTTP/1.1 POST with
// Connection: close, run ONLY on the worker thread. Socket timeouts
// (SO_SNDTIMEO/SO_RCVTIMEO, set before connect so the connect itself is
// bounded too) enforce the configured per-attempt timeout without any
// event loop involvement.

#include "gateway/webhooks.h"

#include <netdb.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <utility>

namespace quicsrt::gateway
{

namespace
{

std::int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Minimal JSON string escaping: quotes, backslash and the control range
/// (as \u00XX, RFC 8259 s.7). Stream names are operator input, so the
/// body must survive any byte sequence.
void AppendJsonString(std::string& out, const std::string& value)
{
    out += '"';
    for (const char c : value)
    {
        const auto uc = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\')
        {
            out += '\\';
            out += c;
        }
        else if (uc < 0x20)
        {
            char buf[7];
            std::snprintf(buf, sizeof buf, "\\u%04x", uc);
            out += buf;
        }
        else
        {
            out += c;
        }
    }
    out += '"';
}

std::string ToJson(const WebhookEvent& e)
{
    std::string out = "{\"event\":";
    AppendJsonString(out, e.event);
    out += ",\"stream\":";
    AppendJsonString(out, e.stream);
    out += ",\"role\":";
    AppendJsonString(out, e.role);
    out += ",\"remote\":";
    AppendJsonString(out, e.remote);
    out += ",\"session_id\":";
    out += std::to_string(e.session_id);
    out += ",\"timestamp_ms\":";
    out += std::to_string(e.timestamp_ms);
    out += "}";
    return out;
}

/// "http://host[:port][/path]" -> host, port (default 80), path
/// (default "/"). False on any other shape (config rejects those at parse
/// time; a runtime failure just counts the delivery as failed).
bool ParseUrl(const std::string& url, std::string& host, std::uint16_t& port, std::string& path)
{
    const std::string            prefix = "http://";
    const std::string::size_type after  = url.find(prefix);
    if (after != 0)
    {
        return false;
    }
    const std::string rest      = url.substr(prefix.size());
    const auto        slash     = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    path                        = slash == std::string::npos ? "/" : rest.substr(slash);
    const auto        colon     = authority.find(':');
    const std::string hostpart  = colon == std::string::npos ? authority : authority.substr(0, colon);
    if (hostpart.empty())
    {
        return false;
    }
    port = 80;
    if (colon != std::string::npos)
    {
        const std::string portpart = authority.substr(colon + 1);
        if (portpart.empty() || portpart.find_first_not_of("0123456789") != std::string::npos)
        {
            return false;
        }
        const unsigned long v = std::stoul(portpart);
        if (v == 0 || v > 65535)
        {
            return false;
        }
        port = static_cast<std::uint16_t>(v);
    }
    host = hostpart;
    return true;
}

bool SendAll(int fd, const std::string& bytes)
{
    std::size_t off = 0;
    while (off < bytes.size())
    {
        const ssize_t n = ::send(fd, bytes.data() + off, bytes.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
        {
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

} // namespace

WebhookDispatcher::WebhookDispatcher(WebhookSettings settings)
    : settings_(std::move(settings))
    , worker_([this] { Run(); })
{
}

WebhookDispatcher::~WebhookDispatcher()
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    worker_.join();
}

void WebhookDispatcher::SetSettings(const WebhookSettings& settings)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    settings_ = settings;
}

void WebhookDispatcher::Notify(WebhookEvent event)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if (settings_.url.empty())
    {
        return; // feature off: no queue, no drop count
    }
    if (queue_.size() >= kQueueBound)
    {
        ++dropped_;
        return;
    }
    event.timestamp_ms = NowMs();
    queue_.push_back(std::move(event));
    cv_.notify_one();
}

WebhookSnapshot WebhookDispatcher::Snapshot() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return WebhookSnapshot{
        .enabled = !settings_.url.empty(), .delivered = delivered_, .dropped = dropped_, .failed = failed_};
}

void WebhookDispatcher::Run()
{
    for (;;)
    {
        WebhookEvent    event;
        WebhookSettings settings;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (stop_)
            {
                // Shutdown: drop what is left, deterministically and
                // counted (the destructor must not drain a full queue
                // through timeout-bounded POSTs).
                dropped_ += queue_.size();
                queue_.clear();
                return;
            }
            event = queue_.front();
            queue_.pop_front();
            settings = settings_;
        }
        if (settings.url.empty())
        {
            // Turned off with events still queued: drain by dropping,
            // counted (a reload's "old or new settings" is exactly this
            // branch - the old URL is not remembered).
            const std::lock_guard<std::mutex> lock(mutex_);
            ++dropped_;
            continue;
        }
        const std::string body = ToJson(event);
        // Retry exactly once on failure.
        const bool                        ok = PostOnce(settings, body) || PostOnce(settings, body);
        const std::lock_guard<std::mutex> lock(mutex_);
        ok ? ++delivered_ : ++failed_;
    }
}

bool WebhookDispatcher::PostOnce(const WebhookSettings& settings, const std::string& body)
{
    std::string   host;
    std::string   path;
    std::uint16_t port = 0;
    if (!ParseUrl(settings.url, host, port, path))
    {
        return false;
    }

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res     = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || res == nullptr)
    {
        return false;
    }
    const int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
    {
        ::freeaddrinfo(res);
        return false;
    }
    // One timeout for the whole attempt: connect, send and receive are
    // each bounded by it (blocking connect honors SO_SNDTIMEO on Linux).
    const auto ms = static_cast<long>(settings.timeout.count());
    timeval    tv{.tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000};
    const auto set_timeout = [&fd, &tv]
    {
        return ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) == 0 &&
               ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0;
    };
    bool ok = set_timeout() && ::connect(fd, res->ai_addr, res->ai_addrlen) == 0;
    ::freeaddrinfo(res);

    if (ok)
    {
        std::string request;
        request.reserve(body.size() + 128);
        request += "POST " + path + " HTTP/1.1\r\n";
        request += "Host: " + host + ":" + std::to_string(port) + "\r\n";
        request += "Content-Type: application/json\r\n";
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        request += "Connection: close\r\n\r\n";
        request += body;
        ok = SendAll(fd, request);
    }
    if (ok)
    {
        // Only the status line matters: Connection: close means the body
        // is never read (the receiver closes or we do).
        char buf[512];
        bool have_line = false;
        int  status    = 0;
        while (!have_line)
        {
            const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
            if (n <= 0)
            {
                break; // EOF or error before a parseable status line
            }
            buf[sizeof buf - 1] = '\0';
            if (std::sscanf(buf, "HTTP/%*d.%*d %d", &status) == 1)
            {
                have_line = true;
            }
        }
        ok = have_line && status >= 200 && status < 300;
    }
    ::close(fd);
    return ok;
}

} // namespace quicsrt::gateway
