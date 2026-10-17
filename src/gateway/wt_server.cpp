// WebTransport server over lsquic (P3 step 3). Server-side mechanics, all
// verified in the vendored lsquic tree (deps/lsquic):
//
// - A WT CONNECT arrives as an ordinary HTTP/3 request stream: lsquic
//   decodes the client's extended-CONNECT header set with the engine's
//   header-set interface and queues it on the stream; on_read then fires
//   and the app claims the set with lsquic_stream_get_hset() BEFORE any
//   lsquic_stream_read() (include/lsquic.h:1798-1810). We supply a custom
//   ea_hsi_if (WtHsetIf below) instead of the built-in HTTP/1.x one
//   because the built-in converter rejects the `:protocol` pseudo-header
//   of an extended CONNECT as unknown (src/liblsquic/lsquic_http1x_if.c,
//   add_pseudo_header: only :method/:scheme/:status/:authority/:path are
//   known) - which would abort the connection with a QPACK error.
// - Accepting: write `:status 200` via lsquic_stream_send_headers + an
//   explicit flush, then mark the stream as the WT session stream
//   (lsquic_stream_set_webtransport_session,
//   src/liblsquic/lsquic_stream.c:4394-4424). Everything after the header
//   block on that stream is the WT capsule stream (RFC 9599).
// - WT client-initiated bidirectional substreams open with stream type
//   0x41 followed by the owning session's stream id; when
//   es_webtransport_server is on, lsquic parses that itself
//   (src/liblsquic/lsquic_stream.c:4964-4979) and the app can ask
//   lsquic_stream_is_webtransport_client_bidi_stream() /
//   lsquic_stream_get_webtransport_session_stream_id().
// - WT datagrams (RFC 9599) carry a quarter-stream-id context varint
//   prefix; session id = CONNECT stream id >> 2, in both directions. The
//   engine hands incoming frames to on_datagram and pulls outgoing ones
//   via on_dg_write armed by lsquic_conn_want_datagram_write() - the same
//   framing WTClient uses client-side.

#include "gateway/wt_server.h"
#include "wt/capsule.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <lsxpack_header.h>
#include <lsquic.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <optional>
#include <utility>

namespace websrt::gateway
{

namespace
{

constexpr std::size_t kRecvBufSize = 16384;

// QUIC minimum MTU (RFC 9000 s.14.2) - the datagram floor the Rust
// oracle demands post-accept (gateway.rs:525-543).
constexpr std::size_t kPmtuFloorBytes = 1200;

void Log(const char* fmt, ...)
{
    std::fputs("wt-server: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

// Decision-to-status mapping shared by the policy and non-WT paths
// (policy.h's Decision documentation).
constexpr const char* StatusForDecision(Decision d)
{
    switch (d)
    {
    case Decision::Accept:
        return "200";
    case Decision::Forbidden:
        return "403";
    case Decision::TooManyRequests:
        return "429";
    case Decision::Reject:
        break;
    }
    return "404";
}

// h3 ALPN selection on the server SSL_CTX. lsquic verifies the negotiated
// result itself (src/liblsquic/lsquic_enc_sess_ietf.c:3014-3028) but the
// TLS-level select callback is the application's job - the
// bin/test_cert.c select_alpn pattern. QUIC v1's ALPN is "h3".
int SelectAlpn(SSL* /*ssl*/,
               const unsigned char** out,
               unsigned char*        outlen,
               const unsigned char*  in,
               unsigned int          inlen,
               void* /*arg*/)
{
    static const unsigned char kH3[] = {0x02, 'h', '3'}; // length-prefixed
    if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, in, inlen, kH3, sizeof kH3) ==
        OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

} // namespace

// The header set WtHsetIf builds: pseudo and regular headers copied out of
// lsqpack's decode buffer one lsxpack_header at a time (the decode buffer
// is reused for the next header, so copies are mandatory). At named scope
// (not anonymous) to match WtServer's forward declaration.
struct HeaderSet
{
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<char>                                buf;
    lsxpack_header                                   xhdr{};
};

// The engine's header-set interface (ea_hsi_if): the test_hset_if recipe
// from lsquic's own tests/test_h3_framing.c:447-530, but keeping every
// name/value pair instead of just counting them.
struct WtHsetIf
{
    static const struct lsquic_hset_if kIf;

    static void* CreateHeaderSet(void* /*ctx*/, lsquic_stream_t* /*stream*/, int /*is_push_promise*/)
    {
        return new HeaderSet{};
    }

    static lsxpack_header* PrepareDecode(void* hset_p, lsxpack_header* xhdr, std::size_t req_space)
    {
        auto* hset = static_cast<HeaderSet*>(hset_p);
        req_space  = std::max<std::size_t>(req_space, 0x100);
        if (req_space > hset->buf.size())
        {
            hset->buf.resize(req_space);
        }
        if (xhdr == nullptr)
        {
            lsxpack_header_prepare_decode(&hset->xhdr, hset->buf.data(), 0, req_space);
        }
        else
        {
            hset->xhdr.buf     = hset->buf.data(); // the buffer may have moved
            hset->xhdr.val_len = req_space;
        }
        return &hset->xhdr;
    }

    static int ProcessHeader(void* hset_p, lsxpack_header* xhdr)
    {
        auto* hset = static_cast<HeaderSet*>(hset_p);
        if (xhdr != nullptr)
        {
            const char* name  = lsxpack_header_get_name(xhdr);
            const char* value = lsxpack_header_get_value(xhdr);
            hset->headers.emplace_back(std::string(name, name + xhdr->name_len),
                                       std::string(value, value + xhdr->val_len));
        }
        return 0; // every header (including `:protocol`) is accepted
    }

    static void DiscardHeaderSet(void* hset_p) { delete static_cast<HeaderSet*>(hset_p); }
};

const struct lsquic_hset_if WtHsetIf::kIf = {
    .hsi_create_header_set  = WtHsetIf::CreateHeaderSet,
    .hsi_prepare_decode     = WtHsetIf::PrepareDecode,
    .hsi_process_header     = WtHsetIf::ProcessHeader,
    .hsi_discard_header_set = WtHsetIf::DiscardHeaderSet,
    .hsi_flags              = static_cast<enum lsquic_hsi_flag>(0),
};

// Per-connection state: datagram send queue (framed at enqueue time) and
// the sessions living on the connection.
struct WtServer::ConnCtx
{
    WtServer*                             server = nullptr;
    lsquic_conn_t*                        conn   = nullptr;
    std::deque<std::vector<std::uint8_t>> send_queue;
    std::vector<std::uint64_t>            session_handles; // handles to reap on close
    // Datagram-context routing is PER CONNECTION: every client's CONNECT
    // stream is stream 0, so the quarter-stream-id context (0 for all of
    // them) only identifies a session within its own connection.
    std::map<std::uint64_t, std::uint64_t> ctx_to_handle;
    bool                                   datagram_write_size_known = false;
    std::size_t                            datagram_write_size       = 0;
};

// One extended-CONNECT stream: a session once established.
struct WtServer::Session
{
    WtSessionHandle         handle;
    std::uint64_t           stream_id = UINT64_MAX;
    StreamCtx*              sc        = nullptr;
    ConnCtx*                conn      = nullptr;
    lsquic_stream_t*        stream    = nullptr;
    websrt::WtCapsuleParser caps; // partial capsules + sticky CLOSE flag
    bool                    headers_done = false;
    bool                    established  = false;
    bool                    terminal     = false;
    std::string             peer_ip; // admission key ("" when unknown)
};

// Per-stream state: the CONNECT/session stream or a WT client substream.
struct WtServer::StreamCtx
{
    WtServer* server          = nullptr;
    Session*  session         = nullptr; // null for WT substreams / rejected streams
    bool      is_wt_substream = false;
};

// lsquic callback shims: `this` rides as the engine/stream-if ctx, ConnCtx
// as the per-connection ctx (so the no-ctx callbacks find the server),
// StreamCtx as the stream ctx.
struct WtServerCallbacks
{
    static const struct lsquic_stream_if kStreamIf;

    static WtServer::StreamCtx* SC(lsquic_stream_ctx_t* h) { return reinterpret_cast<WtServer::StreamCtx*>(h); }

    static WtServer* FromConn(lsquic_conn_t* conn)
    {
        auto* cc = reinterpret_cast<WtServer::ConnCtx*>(lsquic_conn_get_ctx(conn));
        return cc == nullptr ? nullptr : cc->server;
    }

    static lsquic_conn_ctx_t* OnNewConn(void* ctx, lsquic_conn_t* conn)
    {
        auto* server = static_cast<WtServer*>(ctx);
        auto* cc     = new WtServer::ConnCtx{};
        cc->server   = server;
        cc->conn     = conn;
        server->conns_[reinterpret_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(conn))] = cc;
        // PMTU gate + write pin (the Rust oracle's post-accept check,
        // gateway.rs:525-543): lsquic has no max-datagram-size getter, but
        // set_min_datagram_size doubles as the query - it fails exactly
        // when datagrams are unsupported (the oracle's None case) or the
        // peer's advertised MAX_DATAGRAM_FRAME_SIZE is below the request
        // (its Some(max < 1200) case). A transport that cannot carry a
        // 1200-byte datagram cannot move SRT payloads, so the connection
        // is closed instead of left to drop every datagram whole. On
        // success the on_dg_write floor is >= 1200, which preserves the
        // 1184-byte kMaxDatagramSize write pin above it.
        if (lsquic_conn_set_min_datagram_size(conn, kPmtuFloorBytes) != 0)
        {
            Log("WT datagram PMTU too small (required %zu bytes); closing connection", kPmtuFloorBytes);
            lsquic_conn_close(conn);
        }
        return reinterpret_cast<lsquic_conn_ctx_t*>(cc);
    }

    static void OnConnClosed(lsquic_conn_t* conn)
    {
        auto* server = FromConn(conn);
        if (server == nullptr)
        {
            return;
        }
        auto* cc = reinterpret_cast<WtServer::ConnCtx*>(lsquic_conn_get_ctx(conn));
        // The evidence line for conn-death diagnosis: CID matches the
        // engine's own [QUIC:CID] log lines (reason lives there).
        char cid[17 * 2 + 1] = {0};
        {
            const lsquic_cid_t*      c   = lsquic_conn_id(conn);
            static const char* const hex = "0123456789ABCDEF";
            for (std::size_t i = 0; i < c->len && i * 2 + 1 < sizeof cid - 1; ++i)
            {
                cid[i * 2]     = hex[c->idbuf[i] >> 4];
                cid[i * 2 + 1] = hex[c->idbuf[i] & 0xF];
            }
        }
        Log("connection %s closed (%zu session(s) affected, local close: %s)",
            cid,
            cc->session_handles.size(),
            server->tearing_down_ || server->closing_ ? "yes" : "no");
        // The connection object is gone once this callback returns.
        server->conns_.erase(reinterpret_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(conn)));
        for (const std::uint64_t handle_id : cc->session_handles)
        {
            const auto it = server->sessions_.find(handle_id);
            if (it == server->sessions_.end())
            {
                continue;
            }
            WtServer::Session* session = it->second;
            if (session->sc != nullptr)
            {
                session->sc->session = nullptr;
            }
            server->UncountSession(*session);
            server->sessions_.erase(it);
            if (!server->tearing_down_)
            {
                server->listener_.OnSessionClosed(WtSessionHandle{handle_id}, "connection closed");
            }
            delete session;
        }
        delete cc;
    }

    static lsquic_stream_ctx_t* OnNewStream(void* ctx, lsquic_stream_t* stream)
    {
        auto* server = static_cast<WtServer*>(ctx);
        auto* sc     = new WtServer::StreamCtx{};
        sc->server   = server;
        if (lsquic_stream_is_webtransport_client_bidi_stream(stream) != 0 || (lsquic_stream_id(stream) & 3) != 0)
        {
            sc->is_wt_substream = true; // 0x41 substream, or a stream we only drain
        }
        else
        {
            // A client-initiated bidi request stream: the WT CONNECT
            // candidate. The Session dies with the stream (on_close).
            auto* session      = new WtServer::Session{};
            session->handle    = WtSessionHandle{server->next_handle_++};
            session->stream_id = lsquic_stream_id(stream);
            session->sc        = sc;
            session->stream    = stream;
            session->conn      = reinterpret_cast<WtServer::ConnCtx*>(lsquic_conn_get_ctx(lsquic_stream_conn(stream)));
            sc->session        = session;
        }
        lsquic_stream_wantread(stream, 1);
        return reinterpret_cast<lsquic_stream_ctx_t*>(sc);
    }

    static void OnRead(lsquic_stream_t* stream, lsquic_stream_ctx_t* h)
    {
        WtServer::StreamCtx* sc = SC(h);
        if (sc->is_wt_substream)
        {
            sc->server->HandleSubstreamRead(stream);
        }
        else
        {
            sc->server->HandleSessionStreamRead(*sc);
        }
    }

    static void OnWrite(lsquic_stream_t* stream, lsquic_stream_ctx_t* /*h*/)
    {
        // Drains a stashed :status header block: send_headers may stash it
        // (qpack encoder dependency), the write dispatch then buffers it,
        // and a short headers-only response never crosses the flush
        // threshold on its own - WTClient sends its headers from this
        // callback for the same reason. Disarm after (no deferred writes).
        lsquic_stream_flush(stream);
        lsquic_stream_wantwrite(stream, 0);
    }

    static void OnClose(lsquic_stream_t* /*stream*/, lsquic_stream_ctx_t* h)
    {
        WtServer::StreamCtx* sc = SC(h);
        if (sc->session != nullptr)
        {
            // Not our own close: TerminateSession nulls sc->session first,
            // so a session present here means the PEER closed the stream.
            Log("session %" PRIu64 ": peer closed the session stream", sc->session->handle.Id());
            sc->server->TerminateSession(*sc->session, "session stream closed");
        }
        delete sc;
    }

    static void OnDatagram(lsquic_conn_t* conn, const void* buf, std::size_t size)
    {
        auto* server = FromConn(conn);
        auto* cc     = reinterpret_cast<WtServer::ConnCtx*>(lsquic_conn_get_ctx(conn));
        if (server == nullptr || cc == nullptr)
        {
            return;
        }
        const auto* p   = static_cast<const std::uint8_t*>(buf);
        const auto  ctx = VarintGet(p, size);
        if (!ctx || ctx->second >= size)
        {
            return; // malformed context prefix
        }
        WtServer::Session* session = server->FindSessionByContext(*cc, ctx->first);
        if (session == nullptr || !session->established)
        {
            return; // datagram for an unknown or unestablished session
        }
        server->datagrams_received_.fetch_add(1);
        server->listener_.OnDatagram(session->handle, p + ctx->second, size - ctx->second);
    }

    static ssize_t OnDgWrite(lsquic_conn_t* conn, void* buf, std::size_t size)
    {
        auto* server = FromConn(conn);
        auto* cc     = reinterpret_cast<WtServer::ConnCtx*>(lsquic_conn_get_ctx(conn));
        if (server == nullptr || cc == nullptr)
        {
            return 0;
        }
        if (!cc->datagram_write_size_known)
        {
            cc->datagram_write_size_known = true;
            cc->datagram_write_size       = size;
            Log("datagram write size: %zu", size);
        }
        while (!cc->send_queue.empty())
        {
            std::vector<std::uint8_t>& front = cc->send_queue.front();
            if (front.size() > size)
            {
                cc->send_queue.pop_front();
                server->datagrams_dropped_.fetch_add(1);
                Log("dropping %zu-byte datagram over the %zu-byte transport ceiling", front.size(), size);
                continue;
            }
            const std::size_t n = front.size();
            std::memcpy(buf, front.data(), n);
            cc->send_queue.pop_front();
            server->datagrams_written_.fetch_add(1);
            lsquic_conn_want_datagram_write(conn, cc->send_queue.empty() ? 0 : 1);
            return static_cast<ssize_t>(n);
        }
        lsquic_conn_want_datagram_write(conn, 0);
        return 0;
    }

    // Server certificate plumbing: one identity for every SNI. The engine
    // fetches the SSL_CTX per connection through ea_get_ssl_ctx (peer ctx
    // = the WtServer pointer passed to lsquic_engine_packet_in); ea_lookup
    // / ea_cert_lu_ctx stay unset - see the note at the engine setup below.
    static SSL_CTX* GetSslCtx(void* peer_ctx, const struct sockaddr* /*local*/)
    {
        auto* server = static_cast<WtServer*>(peer_ctx);
        return server->ssl_ctx_;
    }

    static int PacketsOut(void* ctx, const struct lsquic_out_spec* specs, unsigned count)
    {
        auto* server = static_cast<WtServer*>(ctx);
        int   sent   = 0;
        for (unsigned i = 0; i < count; ++i)
        {
            socklen_t dst_len = sizeof(sockaddr_in);
            if (specs[i].dest_sa->sa_family == AF_INET6)
            {
                dst_len = sizeof(sockaddr_in6);
            }
            const ssize_t n =
                ::sendto(server->fd_, specs[i].iov->iov_base, specs[i].iov->iov_len, 0, specs[i].dest_sa, dst_len);
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    break;
                }
                return sent > 0 ? sent : -1;
            }
            ++sent;
        }
        return sent;
    }
};

const struct lsquic_stream_if WtServerCallbacks::kStreamIf = {
    .on_new_conn                = WtServerCallbacks::OnNewConn,
    .on_goaway_received         = nullptr,
    .on_conn_closed             = WtServerCallbacks::OnConnClosed,
    .on_new_stream              = WtServerCallbacks::OnNewStream,
    .on_read                    = WtServerCallbacks::OnRead,
    .on_write                   = WtServerCallbacks::OnWrite,
    .on_close                   = WtServerCallbacks::OnClose,
    .on_dg_write                = WtServerCallbacks::OnDgWrite,
    .on_datagram                = WtServerCallbacks::OnDatagram,
    .on_hsk_done                = nullptr,
    .on_new_token               = nullptr,
    .on_sess_resume_info        = nullptr,
    .on_reset                   = nullptr,
    .on_conncloseframe_received = nullptr,
    .on_hset_in                 = nullptr,
};

WtServer::WtServer(websrt::EventLoop&                   loop,
                   const CertProvider&                  cert,
                   std::shared_ptr<const SessionPolicy> policy,
                   WtServerListener&                    listener,
                   AdmissionCheck                       admission,
                   WtServerLimits                       limits)
    : loop_(loop)
    , cert_(cert)
    , policy_(std::move(policy))
    , listener_(listener)
    , admission_(std::move(admission))
    , limits_(limits)
{
}

WtServer::~WtServer()
{
    if (engine_ == nullptr)
    {
        return; // never bound, or already torn down
    }
    assert(!loop_.OnLoopThread()); // never destroy from inside a callback
    if (loop_.IsRunning())
    {
        auto done = teardown_done_.get_future();
        loop_.Post(
            [this]
            {
                Teardown();
                teardown_done_.set_value();
            });
        done.wait();
    }
    else
    {
        Teardown();
    }
}

bool WtServer::Bind(const std::string& host, std::uint16_t port)
{
    if (bound_ || port == 0)
    {
        return false;
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1)
    {
        return false;
    }

    // Process-wide lsquic init: CLIENT|SERVER so this server and any
    // WTClient (whose own once-flag inits CLIENT) coexist in one process.
    // Whichever runs second re-runs lsquic_global_init and leaks a couple
    // of BoringSSL ex-data indexes - benign, and both orders work.
    static std::once_flag global_init_once;
    std::call_once(global_init_once,
                   []
                   {
                       if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER))
                       {
                           Log("lsquic_global_init failed");
                       }
                   });

    fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0)
    {
        Log("socket failed: %s", std::strerror(errno));
        return false;
    }
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0)
    {
        Log("bind %s:%u failed: %s", host.c_str(), port, std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    socklen_t len = sizeof local_sa_;
    if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&local_sa_), &len) != 0)
    {
        Log("getsockname failed: %s", std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    // The TLS identity: one SSL_CTX for every connection and SNI
    // (cert.h's WT-server wiring note; ownership stays with us).
    ssl_ctx_ = NewServerSslCtx(cert_);
    if (ssl_ctx_ == nullptr)
    {
        Log("SSL_CTX setup failed");
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, SelectAlpn, nullptr);

    struct lsquic_engine_settings settings;
    lsquic_engine_init_settings(&settings, LSENG_HTTP_SERVER);
    // lsquic's no-progress watchdog aborts a conn after
    // LSQUIC_DF_NOPROGRESS_TIMEOUT_SERVER (60 s) without USER STREAM
    // activity - and WT sessions carry all media on DATAGRAMS, so their
    // session stream is silent after the handshake. Healthy 33 Mbps
    // datagram sessions died at exactly 60 s ("connection timed out due
    // to lack of progress"). Disabled: SRT owns liveness (quinn parity -
    // the Rust gateway has no such watchdog).
    settings.es_noprogress_timeout              = 0;
    settings.es_versions                        = 1U << LSQVER_I001; // QUIC v1 + h3, as the clients speak
    settings.es_datagrams                       = 1;                 // advertise MAX_DATAGRAM_FRAME_SIZE
    settings.es_webtransport_server             = 1;                 // SETTINGS_ENABLE_WEBTRANSPORT
    settings.es_max_webtransport_server_streams = 100;               // sane default; CLI config lands later
    // WT idle timeout (Rust limits.rs max_idle_timeout, quinn parity):
    // a connection silent for this many seconds is closed. lsquic's own
    // default is 30 s; the oracle runs 10 s. Media flows reset it (any
    // received packet does - datagrams, ACKs, the lsquic client's 15 s
    // keepalive PINGs), so only truly abandoned connections hit it.
    settings.es_idle_timeout = static_cast<unsigned>(limits_.idle_timeout_s);
    // QUIC handshake budget (Rust handshake_timeout; lsquic's default is
    // also 10 s, made config-driven for parity).
    settings.es_handshake_to = static_cast<unsigned long>(limits_.handshake_timeout_s) * 1000000UL;
    // No-op-CC approximation (P3 step 7; PLAN.md risk 1): the Rust gateway
    // runs a no-op quinn congestion controller (nocc.rs: window() ==
    // u64::MAX, never paces) so SRT owns all congestion control and
    // reliability. lsquic has NO pluggable no-op controller - es_cc_algo
    // offers only Cubic / BBRv1 / Adaptive (lsquic.h:750-758) - so this
    // approximates: the pacer is switched OFF (es_pace_packets=0: packets
    // leave as soon as cwnd allows, the "never paces" half of nocc) and the
    // flow-control windows we advertise are made generous (16 MiB conn /
    // 8 MiB stream) so QUIC FC never bottlenecks the session streams. The
    // media path itself - WT datagrams - is exempt from flow control
    // entirely (RFC 9221 s.4), leaving congestion control as the only
    // limiter. Residual difference, documented in PLAN.md step 7: under
    // real loss, cubic/BBR cwnd still bounds in-flight bytes (a true
    // unlimited window does not exist); the e2e and concurrency tests
    // measure sustained send throughput == app write rate on loopback,
    // where cwnd never engages.
    settings.es_pace_packets                     = 0;
    settings.es_cfcw                             = 16 * 1024 * 1024;
    settings.es_sfcw                             = 8 * 1024 * 1024;
    settings.es_init_max_data                    = 16 * 1024 * 1024;
    settings.es_init_max_stream_data_bidi_remote = 8 * 1024 * 1024;
    char err_buf[256];
    if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP_SERVER, err_buf, sizeof err_buf))
    {
        Log("engine settings rejected: %s", err_buf);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    struct lsquic_engine_api api{};
    api.ea_settings        = &settings;
    api.ea_packets_out     = WtServerCallbacks::PacketsOut;
    api.ea_packets_out_ctx = this;
    api.ea_stream_if       = &WtServerCallbacks::kStreamIf;
    api.ea_stream_if_ctx   = this;
    // ea_get_ssl_ctx ALONE, never ea_lookup_cert: the per-SNI cert_cb is a
    // second, optional way to fetch an SSL_CTX (lsquic_enc_sess_ietf.c:
    // 1484-1485), but iquic_lookup_cert REFUSES to return anything when the
    // ClientHello carries no SNI on an HTTP engine (same file, 1335-1342),
    // failing the handshake with a BoringSSL cert_cb error - which the
    // client sees as TLS alert 80 (internal_error), QUIC CONNECTION_CLOSE
    // 0x100 + "TLS alert 80". Browsers send no SNI for an IP literal (RFC
    // 6066 s.3), so https://127.0.0.1:4434 - the closed-network WebSRT
    // default, and the P3 browser gate's URL - could never complete. The
    // callback would only ever hand back ssl_ctx_ anyway: one identity for
    // every name, so the lookup is pure overhead with a fatal gate bolted
    // on. iquic_esfi_init_server builds each server SSL from
    // ea_get_ssl_ctx's ctx (1454), so the certificate, key and the h3 ALPN
    // selector below all still apply.
    api.ea_get_ssl_ctx = WtServerCallbacks::GetSslCtx;
    api.ea_hsi_if      = &WtHsetIf::kIf;
    api.ea_hsi_ctx     = nullptr;
    engine_            = lsquic_engine_new(LSENG_HTTP_SERVER, &api);
    if (engine_ == nullptr)
    {
        Log("lsquic_engine_new failed");
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    bound_ = true;
    if (!loop_.OnLoopThread() && loop_.IsRunning())
    {
        loop_.Post([this] { AttachLoop(); });
    }
    else
    {
        AttachLoop();
    }
    Log("listening on %s:%u (WT server)", host.c_str(), port);
    return true;
}

void WtServer::AttachLoop()
{
    loop_.AddFd(fd_, EPOLLIN, [this](int, std::uint32_t) { HandleServerReadable(); });
    fd_registered_ = true;
    loop_.SetEngineHost(this);
}

bool WtServer::SendDatagram(WtSessionHandle handle, const void* data, std::size_t size)
{
    if (!handle.IsValid() || size == 0 || size > kMaxDatagramSize || !bound_)
    {
        return false;
    }
    std::vector<std::uint8_t> payload(static_cast<const std::uint8_t*>(data),
                                      static_cast<const std::uint8_t*>(data) + size);
    if (loop_.OnLoopThread())
    {
        const auto it = sessions_.find(handle.Id());
        if (it == sessions_.end())
        {
            return false;
        }
        EnqueueDatagram(*it->second, std::move(payload));
    }
    else
    {
        loop_.Post(
            [this, handle, payload = std::move(payload)]() mutable
            {
                const auto it = sessions_.find(handle.Id());
                if (it != sessions_.end())
                {
                    EnqueueDatagram(*it->second, std::move(payload));
                }
            });
    }
    return true;
}

void WtServer::EnqueueDatagram(Session& session, std::vector<std::uint8_t> payload)
{
    if (closing_ || tearing_down_ || session.terminal || session.conn == nullptr)
    {
        return; // the session closed under us; the datagram is moot
    }
    ConnCtx& cc = *session.conn;
    if (cc.send_queue.size() >= kMaxQueuedDatagrams)
    {
        datagrams_dropped_.fetch_add(1);
        return;
    }
    std::vector<std::uint8_t> framed;
    framed.reserve(payload.size() + 8);
    std::uint8_t      varint[8];
    const std::size_t varint_len = VarintPut(varint, session.stream_id >> 2);
    framed.insert(framed.end(), varint, varint + varint_len);
    framed.insert(framed.end(), payload.begin(), payload.end());
    cc.send_queue.push_back(std::move(framed));
    lsquic_conn_want_datagram_write(cc.conn, 1);
}

void WtServer::Close()
{
    if (!bound_)
    {
        return;
    }
    if (loop_.OnLoopThread())
    {
        CloseOnLoop();
    }
    else
    {
        loop_.Post([this] { CloseOnLoop(); });
    }
}

void WtServer::CloseOnLoop()
{
    if (closing_)
    {
        return;
    }
    closing_ = true;
    for (auto& [_, cc] : conns_)
    {
        lsquic_conn_close(cc->conn); // peers observe CONNECTION_CLOSE
    }
}

void WtServer::CloseSession(WtSessionHandle handle, const std::string& reason)
{
    if (!bound_ || !handle.IsValid())
    {
        return;
    }
    if (loop_.OnLoopThread())
    {
        CloseSessionOnLoop(handle, reason);
    }
    else
    {
        loop_.Post([this, handle, reason] { CloseSessionOnLoop(handle, reason); });
    }
}

void WtServer::CloseConnection(WtSessionHandle handle, const std::string& reason)
{
    if (!bound_ || !handle.IsValid())
    {
        return;
    }
    if (loop_.OnLoopThread())
    {
        CloseConnectionOnLoop(handle, reason);
    }
    else
    {
        loop_.Post([this, handle, reason] { CloseConnectionOnLoop(handle, reason); });
    }
}

void WtServer::CloseConnectionOnLoop(WtSessionHandle handle, const std::string& reason)
{
    if (closing_ || tearing_down_)
    {
        return;
    }
    const auto it = sessions_.find(handle.Id());
    if (it == sessions_.end())
    {
        return;
    }
    Log("closing the connection of session %" PRIu64 ": %s", handle.Id(), reason.c_str());
    // lsquic_conn_close only marks the connection closing; the sessions'
    // terminal OnSessionClosed fires from OnConnClosed later.
    lsquic_conn_close(it->second->conn->conn);
}

void WtServer::CloseSessionOnLoop(WtSessionHandle handle, const std::string& reason)
{
    if (closing_ || tearing_down_)
    {
        return;
    }
    const auto it = sessions_.find(handle.Id());
    if (it == sessions_.end() || it->second->terminal)
    {
        return;
    }
    // TerminateSession nulls sc->session, fires OnSessionClosed and frees;
    // callers past a listener callback must not touch the session after
    // this (HandleSessionStreamRead's sc.session null check covers the
    // accept-path rejection, the same pattern as the policy rejections).
    TerminateSession(*it->second, reason);
}

void WtServer::Teardown()
{
    if (tearing_down_)
    {
        return;
    }
    tearing_down_ = true;
    loop_.SetEngineHost(nullptr);
    if (fd_registered_)
    {
        loop_.DelFd(fd_);
        fd_registered_ = false;
    }
    if (engine_ != nullptr)
    {
        // Fires remaining on_close / on_conn_closed callbacks; they skip
        // listener notification on the tearing_down_ path.
        lsquic_engine_destroy(engine_);
        engine_ = nullptr;
    }
    for (auto& [_, session] : sessions_)
    {
        if (session->sc != nullptr)
        {
            session->sc->session = nullptr;
        }
        delete session;
    }
    sessions_.clear();
    conns_.clear();
    if (fd_ >= 0)
    {
        ::close(fd_);
        fd_ = -1;
    }
    if (ssl_ctx_ != nullptr)
    {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    bound_ = false;
}

WtServer::Session* WtServer::FindSessionByContext(const ConnCtx& cc, std::uint64_t context_id) const
{
    const auto it = cc.ctx_to_handle.find(context_id);
    if (it == cc.ctx_to_handle.end())
    {
        return nullptr;
    }
    const auto sit = sessions_.find(it->second);
    return sit == sessions_.end() ? nullptr : sit->second;
}

std::chrono::microseconds WtServer::SmoothedRtt(WtSessionHandle handle) const
{
    // Loop thread only (see wt_server.h). lci_rtt is the connection's
    // smoothed RTT in microseconds (lsquic_rtt_stats_get_srtt).
    const auto it = sessions_.find(handle.Id());
    if (it == sessions_.end() || it->second->conn == nullptr)
    {
        return std::chrono::microseconds{0};
    }
    struct lsquic_conn_info info;
    if (0 != lsquic_conn_get_info(it->second->conn->conn, &info))
    {
        return std::chrono::microseconds{0};
    }
    return std::chrono::microseconds{info.lci_rtt};
}

// One :status response written on the session stream. With half_close this
// is the 404/403/429 fix for the Rust gateway's 404-reset race: the header
// block goes out with eos=0 plus an explicit flush, so it lands in
// outgoing packets NOW; the write side is then shut down, which sends a
// FIN after (never instead of) that data. QUIC delivers a stream's direction
// in order, so the client necessarily reads :status before observing
// end-of-stream - no RESET is ever sent, no grace timer is needed. The
// connection stays open for the well-behaved client to close itself (WT
// clients close after a non-200 response); a stray one idles out.
void WtServer::Respond(lsquic_stream_t* stream, const char* status, bool half_close)
{
    const std::string block = ":status" + std::string{status}; // name+val contiguous
    lsxpack_header    header{};
    const std::size_t name_len = block.size() - std::strlen(status);
    lsxpack_header_set_offset2(&header, block.data(), 0, name_len, name_len, std::strlen(status));
    lsquic_http_headers_t hdrs{};
    hdrs.count   = 1;
    hdrs.headers = &header;
    if (0 == lsquic_stream_send_headers(stream, &hdrs, 0))
    {
        lsquic_stream_flush(stream); // the header block reaches the wire now
        // send_headers may STASH the block instead of buffering it (qpack
        // encoder dependency on a fresh connection); the stash only drains
        // on a write dispatch, and the internal want-write arming does not
        // mark the connection tickable. The public wantwrite does - without
        // it, a headers-only response never leaves (the flush is a noop on
        // an empty buffer). OnWrite disarms once the block is out.
        lsquic_stream_wantwrite(stream, 1);
        if (half_close)
        {
            lsquic_stream_wantread(stream, 0); // a rejection reads no more
            lsquic_stream_shutdown(stream, 1); // write-side FIN, in order
        }
    }
    else
    {
        Log("lsquic_stream_send_headers failed: %s", std::strerror(errno));
        lsquic_stream_close(stream);
    }
}

// The accept path: one pass over the CONNECT header set, no blocking, the
// policy answered inline (why the Rust accept-loop stall cannot reproduce
// here - see wt_server.h).
void WtServer::ProcessConnectHeaders(StreamCtx& sc, Session& session, HeaderSet& hset)
{
    std::string                             method;
    std::string                             protocol;
    std::string                             authority;
    std::string                             path_and_query;
    std::multimap<std::string, std::string> headers(hset.headers.begin(), hset.headers.end());
    for (const auto& [name, value] : hset.headers)
    {
        if (name == ":method")
        {
            method = value;
        }
        else if (name == ":protocol")
        {
            protocol = value;
        }
        else if (name == ":authority")
        {
            authority = value;
        }
        else if (name == ":path")
        {
            path_and_query = value;
        }
    }
    delete &hset; // ownership transferred by lsquic_stream_get_hset

    const std::size_t      q    = path_and_query.find('?');
    const std::string_view path = std::string_view{path_and_query}.substr(0, q);
    const std::string_view query =
        q == std::string::npos ? std::string_view{} : std::string_view{path_and_query}.substr(q + 1);

    // Remote peer, for the policy.
    char               remote_host[INET_ADDRSTRLEN] = {};
    const sockaddr_in* peer                         = nullptr;
    const sockaddr*    local_sa                     = nullptr;
    const sockaddr*    peer_sa                      = nullptr;
    if (0 == lsquic_conn_get_sockaddr(session.conn->conn, &local_sa, &peer_sa) && peer_sa != nullptr)
    {
        peer = reinterpret_cast<const sockaddr_in*>(peer_sa);
        ::inet_ntop(AF_INET, &peer->sin_addr, remote_host, sizeof remote_host);
    }

    const auto find_header = [&headers](const char* name) -> std::optional<std::string_view>
    {
        const auto it = headers.find(name);
        if (it == headers.end())
        {
            return std::nullopt;
        }
        return std::string_view{it->second};
    };

    const SessionRequest req{
        .path       = path,
        .query      = query,
        .origin     = find_header("origin"),
        .authority  = authority,
        .user_agent = find_header("user-agent"),
        .headers    = &headers,
        .remote_address =
            SocketAddress{.host = remote_host,
                          .port = static_cast<std::uint16_t>(peer != nullptr ? ntohs(peer->sin_port) : 0)},
    };

    const bool     is_wt_connect = method == "CONNECT" && protocol == "webtransport";
    const Decision decision      = is_wt_connect ? policy_->Decide(req) : Decision::Reject;

    if (decision != Decision::Accept)
    {
        sessions_rejected_.fetch_add(1);
        Log("session rejected on stream %" PRIu64 ": HTTP %s (path %.*s)",
            session.stream_id,
            StatusForDecision(decision),
            static_cast<int>(path.size()),
            path.data());
        Respond(session.stream, StatusForDecision(decision), true);
        sc.session = nullptr; // on_close must not touch the dead session
        delete &session;
        return;
    }

    // Connection limit (per-IP + global), the Rust tracker.try_acquire
    // (gateway.rs:461-472): between the policy and the occupancy checks,
    // answered 429 on the CONNECT response the caller is waiting for.
    if (!SessionLimitOk(remote_host))
    {
        sessions_rejected_.fetch_add(1);
        Log("session rejected: connection limit exceeded on stream %" PRIu64 " (peer %s, %zu established)",
            session.stream_id,
            remote_host,
            established_sessions_);
        Respond(session.stream, StatusForDecision(Decision::TooManyRequests), true);
        sc.session = nullptr; // on_close must not touch the dead session
        delete &session;
        return;
    }

    // Query decomposition exactly like the Rust oracle's accept loop
    // (gateway.rs:476-483): ?stream= then ?subscribe= names the stream to
    // view; ?publish= names the stream to publish. Done BEFORE the 200 so
    // the admission gate below sees the same routing the session gets.
    std::optional<std::string> subscribe = ParseQueryParam(query, "stream");
    if (!subscribe.has_value())
    {
        subscribe = ParseQueryParam(query, "subscribe");
    }
    const std::string remote_text =
        peer != nullptr ? std::string{remote_host} + ":" + std::to_string(ntohs(peer->sin_port)) : std::string{};
    const WtSessionStart start{
        .path           = std::string{path},
        .query          = std::string{query},
        .publish_name   = ParseQueryParam(query, "publish"),
        .subscribe_name = std::move(subscribe),
        .remote         = remote_text,
    };

    // Admission: the gateway's own runtime gate (first-wins occupancy,
    // viewer cap), AFTER the policy and BEFORE the 200 - see
    // WtServer::AdmissionCheck.
    if (admission_)
    {
        const Decision admit = admission_(start);
        if (admit != Decision::Accept)
        {
            sessions_rejected_.fetch_add(1);
            Log("session rejected on admission on stream %" PRIu64 ": HTTP %s (path %.*s)",
                session.stream_id,
                StatusForDecision(admit),
                static_cast<int>(path.size()),
                path.data());
            Respond(session.stream, StatusForDecision(admit), true);
            sc.session = nullptr;
            delete &session;
            return;
        }
    }

    // Accepted: 200, flush, mark the WT session stream, expose the session.
    Respond(session.stream, "200", false);
    lsquic_stream_set_webtransport_session(session.stream);
    session.peer_ip = remote_host;
    CountSession(session); // established = true + the limit accounting
    session.conn->session_handles.push_back(session.handle.Id());
    session.conn->ctx_to_handle[session.stream_id >> 2] = session.handle.Id();
    sessions_[session.handle.Id()]                      = &session;
    sessions_accepted_.fetch_add(1);
    Log("session %" PRIu64 " accepted on stream %" PRIu64 " (path %.*s)",
        session.handle.Id(),
        session.stream_id,
        static_cast<int>(path.size()),
        path.data());
    listener_.OnWtSession(session.handle, start);
}

void WtServer::HandleSessionStreamRead(StreamCtx& sc)
{
    if (sc.session == nullptr)
    {
        return;
    }
    Session*         session = sc.session;
    lsquic_stream_t* stream  = session->stream;
    if (!session->headers_done)
    {
        // Must be claimed before the first lsquic_stream_read
        // (include/lsquic.h:1798-1810).
        session->headers_done = true;
        void* hsetp           = lsquic_stream_get_hset(stream);
        if (hsetp == nullptr)
        {
            Log("stream %" PRIu64 " readable without a header set", session->stream_id);
            return;
        }
        ProcessConnectHeaders(sc, *session, *static_cast<HeaderSet*>(hsetp));
        if (sc.session == nullptr)
        {
            return; // rejected: status written and flushed, reads disabled
        }
    }

    std::uint8_t buf[kRecvBufSize];
    for (;;)
    {
        const ssize_t n = lsquic_stream_read(stream, buf, sizeof buf);
        if (n > 0)
        {
            if (!ParseCapsules(*session, buf, static_cast<std::size_t>(n)))
            {
                TerminateSession(*session, "WT CLOSE capsule");
                return;
            }
            continue;
        }
        if (n == 0)
        {
            if (sc.session != nullptr)
            {
                TerminateSession(*session, "session stream FIN");
            }
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return;
        }
        if (sc.session != nullptr)
        {
            TerminateSession(*session, std::string("session stream read error: ") + std::strerror(errno));
        }
        return;
    }
}

// WT client-initiated substreams (stream type 0x41): raw session payload,
// surfaced uninterpreted for G4/G5 capsule work. WebSRT data rides
// datagrams; nothing here is interpreted today. The varint lsquic parses
// after 0x41 identifies the owning session - WT-over-HTTP/3 calls it the
// Session Id (the CONNECT stream id divided by 4), so both that reading
// and a raw stream id are tried when routing.
void WtServer::HandleSubstreamRead(lsquic_stream_t* stream)
{
    auto* cc = reinterpret_cast<ConnCtx*>(lsquic_conn_get_ctx(lsquic_stream_conn(stream)));
    if (cc == nullptr)
    {
        lsquic_stream_wantread(stream, 0);
        return;
    }
    const long long sid   = lsquic_stream_get_webtransport_session_stream_id(stream);
    Session*        owner = sid < 0 ? nullptr : FindSessionByContext(*cc, static_cast<std::uint64_t>(sid));
    if (owner == nullptr && sid >= 0)
    {
        owner = FindSessionByContext(*cc, static_cast<std::uint64_t>(sid) >> 2);
    }
    std::uint8_t buf[kRecvBufSize];
    for (;;)
    {
        const ssize_t n = lsquic_stream_read(stream, buf, sizeof buf);
        if (n > 0)
        {
            if (owner != nullptr && !tearing_down_)
            {
                listener_.OnSessionStreamData(owner->handle, buf, static_cast<std::size_t>(n));
            }
            continue;
        }
        if (n == 0)
        {
            lsquic_stream_wantread(stream, 0); // a FIN'd stream would spin on_read
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return;
        }
        lsquic_stream_wantread(stream, 0);
        return;
    }
}

// Capsule consumption via libwebsrt's WtCapsuleParser (RFC 9599): type +
// length varints, skip the payload. CLOSE (0x2843) is the only type that
// changes session state; it is reported (false) rather than acted on so
// this function never frees the session underneath its caller.
bool WtServer::ParseCapsules(Session& session, const std::uint8_t* data, std::size_t size)
{
    session.caps.Feed(data, size);
    if (session.caps.closed() && !session.terminal)
    {
        Log("WT CLOSE capsule received on stream %" PRIu64, session.stream_id);
        return false;
    }
    return true;
}

bool WtServer::SessionLimitOk(const char* peer_ip) const
{
    if (limits_.max_sessions > 0 && established_sessions_ >= static_cast<std::size_t>(limits_.max_sessions))
    {
        return false;
    }
    if (limits_.max_sessions_per_ip > 0)
    {
        const auto it = sessions_per_ip_.find(peer_ip);
        if (it != sessions_per_ip_.end() && it->second >= static_cast<std::size_t>(limits_.max_sessions_per_ip))
        {
            return false;
        }
    }
    return true;
}

void WtServer::CountSession(Session& session)
{
    session.established = true;
    ++established_sessions_;
    ++sessions_per_ip_[session.peer_ip];
}

void WtServer::UncountSession(Session& session)
{
    if (!session.established)
    {
        return; // rejected pre-200 sessions were never counted
    }
    session.established = false;
    --established_sessions_;
    const auto it = sessions_per_ip_.find(session.peer_ip);
    if (it != sessions_per_ip_.end() && --it->second == 0)
    {
        sessions_per_ip_.erase(it);
    }
}

void WtServer::TerminateSession(Session& session, const std::string& reason)
{
    session.terminal = true;
    UncountSession(session);
    // sc is set at Session creation (OnNewStream) and never null; clearing
    // it here is how callers detect the free.
    session.sc->session = nullptr;
    if (session.conn != nullptr)
    {
        session.conn->ctx_to_handle.erase(session.stream_id >> 2);
    }
    sessions_.erase(session.handle.Id());
    if (session.conn != nullptr)
    {
        std::erase(session.conn->session_handles, session.handle.Id());
    }
    if (session.stream != nullptr)
    {
        lsquic_stream_wantread(session.stream, 0);
        lsquic_stream_shutdown(session.stream, 1); // FIN so the client sees the end
        session.stream = nullptr;
    }
    if (!tearing_down_)
    {
        listener_.OnSessionClosed(session.handle, reason);
    }
    delete &session;
}

bool WtServer::NextTick(std::chrono::microseconds& diff)
{
    if (engine_ == nullptr)
    {
        return false;
    }
    int diff_us = 0;
    if (lsquic_engine_earliest_adv_tick(engine_, &diff_us) != 0)
    {
        diff = std::chrono::microseconds{diff_us};
        return true;
    }
    return false;
}

void WtServer::Pump()
{
    if (engine_ == nullptr)
    {
        return;
    }
    int diff_us = 0;
    if (lsquic_engine_earliest_adv_tick(engine_, &diff_us) != 0 && diff_us <= 0)
    {
        lsquic_engine_process_conns(engine_);
    }
    if (lsquic_engine_has_unsent_packets(engine_) != 0)
    {
        lsquic_engine_send_unsent_packets(engine_);
    }
}

void WtServer::HandleServerReadable()
{
    if (engine_ == nullptr)
    {
        return;
    }
    std::uint8_t buf[kRecvBufSize];
    for (;;)
    {
        sockaddr_in   peer{};
        socklen_t     peer_len = sizeof peer;
        const ssize_t n = ::recvfrom(fd_, buf, sizeof buf, MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n > 0)
        {
            // peer_ctx = this: ea_get_ssl_ctx returns our one SSL_CTX.
            lsquic_engine_packet_in(engine_,
                                    buf,
                                    static_cast<std::size_t>(n),
                                    reinterpret_cast<sockaddr*>(&local_sa_),
                                    reinterpret_cast<sockaddr*>(&peer),
                                    this,
                                    0);
            continue;
        }
        return; // EAGAIN or an ICMP error; nothing to feed
    }
}

} // namespace websrt::gateway
