// WebTransport SERVER over lsquic - the P3 step 3 accept path, and the
// deliberate fixes for the two Rust-gateway defects (PLAN.md):
//
// - Accept-loop stall: there is NO accept queue here. Every UDP packet is
//   fed to the engine on the event-loop thread (HandleServerReadable), the
//   engine hashes connections and advances every handshake independently
//   inside Pump, and each CONNECT is answered inline from on_read. Nothing
//   between packet-in and the :status response can block: SessionPolicy
//   implementations are contractually non-blocking (policy.h) and there is
//   no serialized await point like wtransport's accept() future. N
//   concurrent handshakes cost N engine connections ticking in the same
//   process_conns pass - they cannot stall each other for 10-20 s.
// - 404-reset race: a rejected CONNECT is NEVER reset. See
//   RespondAndHalfClose() in wt_server.cpp for the mechanism (response
//   headers, explicit flush, then write-side FIN - in-order delivery makes
//   the client observe the status before end-of-stream, deterministically).
//
// Threading: ALL Listener callbacks and ALL state transitions run on the
// EventLoop's thread. SendDatagram/Close are thread-safe (they Post).
// WtServer must be the loop's ONLY EngineHost (EventLoop hosts at most one
// engine - same constraint WTClient has; run client engines on their own
// loops).

#ifndef WEBSRT_GATEWAY_WT_SERVER_H
#define WEBSRT_GATEWAY_WT_SERVER_H

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include <netinet/in.h>

#include <openssl/ssl.h>

#include "core/event_loop.h"
#include "gateway/cert.h"
#include "gateway/policy.h"
#include "proto/constants.h"

struct lsquic_engine;
struct lsquic_conn;
struct lsquic_stream;
using lsquic_engine_t = struct lsquic_engine;
using lsquic_conn_t   = struct lsquic_conn;
using lsquic_stream_t = struct lsquic_stream;

namespace websrt::gateway
{

/// The decoded CONNECT header set (defined in wt_server.cpp).
struct HeaderSet;

/// Cheap value-type identity of one accepted WebTransport session. Stable
/// for the session's lifetime; pass it back into WtServer::SendDatagram.
/// Invalid when default-constructed (Id() == 0).
class WtSessionHandle
{
public:
    WtSessionHandle() = default;

    [[nodiscard]] constexpr std::uint64_t Id() const { return id_; }
    [[nodiscard]] constexpr bool          IsValid() const { return id_ != 0; }

    constexpr bool operator==(const WtSessionHandle& other) const { return id_ == other.id_; }
    constexpr bool operator!=(const WtSessionHandle& other) const { return id_ != other.id_; }

    /// A publisher identity that is NOT a WebTransport session: the SRT/UDP
    /// ingest (P3 step 5) publishes without a WT session behind it, but the
    /// registry holds publisher occupancy by handle so first-wins is shared
    /// across both source kinds. `ordinal` distinguishes concurrent ingest
    /// claims; the resulting ids live above every session id WtServer mints,
    /// so the two spaces can never collide. No SessionRegistry entry backs
    /// such a handle, so SessionInfoFor() reports "unknown" for it - which is
    /// exactly right: an ingest source frames its own messages and is not
    /// bound by a negotiated payload ceiling.
    static WtSessionHandle ExternalSource(std::uint64_t ordinal) { return WtSessionHandle{kExternalIdBase + ordinal}; }

private:
    friend class WtServer;
    friend struct WtServerCallbacks; // lsquic shims mint handles (wt_server.cpp)

    static constexpr std::uint64_t kExternalIdBase = 1ULL << 62;

    explicit constexpr WtSessionHandle(std::uint64_t id)
        : id_(id)
    {
    }

    std::uint64_t id_ = 0;
};

/// What OnWtSession tells the consumer about the accepted session, with the
/// query already decomposed the way the Rust oracle's accept loop does
/// (gateway.rs:326-333): `?stream=`/`?subscribe=` names the stream to view,
/// `?publish=` names the stream to publish (a session may ask for both).
/// Names are percent-decoded (ParseQueryParam).
struct WtSessionStart
{
    std::string                path;           ///< path portion of :path (before '?')
    std::string                query;          ///< raw query string (after '?')
    std::optional<std::string> publish_name;   ///< ?publish= if present
    std::optional<std::string> subscribe_name; ///< ?stream=/ ?subscribe= if present
    std::string                remote;         ///< "ip:port" of the peer ("" when unavailable; webhooks, P4.3)
};

/// Consumer callbacks. ALL of them fire on the WtServer's event-loop thread
/// and may call back into WtServer (e.g. SendDatagram from OnDatagram).
class WtServerListener
{
public:
    virtual ~WtServerListener() = default;

    /// A WT CONNECT was accepted (:status 200 written and flushed); the
    /// session stream is established and SendDatagram may be used.
    virtual void OnWtSession(WtSessionHandle /*handle*/, const WtSessionStart& /*start*/) {}

    /// Terminal event for a session, fired at most once per handle: WT CLOSE
    /// capsule, session-stream FIN, or the connection closing (Close()
    /// included). The handle is invalid afterwards.
    virtual void OnSessionClosed(WtSessionHandle /*handle*/, const std::string& /*reason*/) {}

    /// A WT datagram payload arrived on this session; the quarter-stream-id
    /// context prefix is already stripped. Malformed frames are dropped.
    virtual void OnDatagram(WtSessionHandle /*handle*/, const std::uint8_t* /*data*/, std::size_t /*size*/) {}

    /// Raw bytes arrived on a WT client-initiated bidirectional substream
    /// (stream type 0x41) of this session. Surfaced uninterpreted for later
    /// capsule work (G4/G5); WebSRT data rides datagrams, not substreams.
    virtual void OnSessionStreamData(WtSessionHandle /*handle*/, const std::uint8_t* /*data*/, std::size_t /*size*/) {}
};

/// One WebTransport server: a bound UDP socket, one lsquic HTTP/3 server
/// engine (WT server support compiled in), and the accept path that runs
/// the SessionPolicy seam. Mirrors WTClient's proven engine recipe
/// (libwebsrt src/wt/client.cpp) on the server side.
class WtServer : private websrt::EngineHost
{
public:
    /// Largest payload SendDatagram accepts (fits next to the context
    /// prefix in a minimum-MTU datagram frame; SRT's 1128-byte payloads
    /// do). Aliases libwebsrt's shared protocol constants so the client
    /// library and the gateway cannot drift apart.
    static constexpr std::size_t kMaxDatagramSize    = websrt::kMaxDatagramSize;
    static constexpr std::size_t kMaxQueuedDatagrams = websrt::kMaxQueuedDatagrams;

    /// ADMISSION CONTROL - consulted AFTER the SessionPolicy accepts and
    /// BEFORE the 200 response is written, with the query already
    /// decomposed into publish/subscribe names. Returning anything but
    /// Accept answers the CONNECT with that decision's status (403 / 429 /
    /// 404) INSTEAD of 200, so the client observes the refusal on the
    /// response it is waiting for - the Rust oracle's pre-accept occupancy
    /// check (gateway.rs:343-355, where the 403 precedes the WT handshake).
    /// This is deliberately a separate seam from SessionPolicy: the policy
    /// answers "may this caller address this name at all" (path, origin,
    /// token, allowlist), admission answers "can this stream take it right
    /// now" (first-wins occupancy, viewer cap) - a runtime property of the
    /// gateway's live state, not a static rule. An empty callback admits
    /// everything the policy accepted.
    ///
    /// Contract: loop thread (inline in the accept path), must not block.
    using AdmissionCheck = std::function<Decision(const WtSessionStart&)>;

    /// `cert` supplies the TLS identity (SSL_CTX built once and handed to
    /// lsquic through ea_get_ssl_ctx - SNI is ignored, one identity).
    /// `policy` decides every incoming CONNECT (must not block). `listener`
    /// must outlive the server. `admission` (optional) is the pre-200
    /// admission gate above. Supported teardown: Close() then destroy,
    /// or stop the loop and destroy in any order. Never destroy from inside
    /// a listener callback; never race the destructor with EventLoop::Stop.
    WtServer(websrt::EventLoop&                   loop,
             const CertProvider&                  cert,
             std::shared_ptr<const SessionPolicy> policy,
             WtServerListener&                    listener,
             AdmissionCheck                       admission = {});
    ~WtServer() override;

    WtServer(const WtServer&)            = delete;
    WtServer& operator=(const WtServer&) = delete;

    /// Bind `host`:`port` (IPv4 literal, e.g. "127.0.0.1") and start
    /// serving. Returns false (server stays inert) on a bad address, socket
    /// or bind failure, or when already bound. Thread-safe; the loop may be
    /// running or not.
    bool Bind(const std::string& host, std::uint16_t port);

    /// Thread-safe. Queue one WT datagram on the session's connection (the
    /// quarter-stream-id context prefix is added internally). Returns false
    /// for an unknown/invalid handle, an empty or oversized payload, or
    /// when the server is not bound. A full queue - or a payload over the
    /// transport's learned ceiling - drops the datagram whole (counted in
    /// DatagramsDropped()), the same policy as WTClient.
    bool SendDatagram(WtSessionHandle handle, const void* data, std::size_t size);

    /// Thread-safe. Graceful shutdown: sends CONNECTION_CLOSE on every live
    /// connection (each session's OnSessionClosed fires as its connection
    /// finishes closing). The engine itself is torn down by the destructor
    /// (posted, never inside an engine callback). No-op when not bound.
    void Close();

    /// Thread-safe. Closes ONE session: write-side FIN on its session
    /// stream (the RFC 9599 session termination the browser observes as
    /// wtClosed; the connection stays up) and the terminal
    /// OnSessionClosed fires. The per-session close the session registry
    /// needs for SRT-side ends (health reaps, viewer EOF when the stream
    /// ends). No-op for an unknown/already-closed handle.
    void CloseSession(WtSessionHandle handle, const std::string& reason);

    /// Thread-safe. Closes the whole QUIC connection carrying `handle`
    /// (CONNECTION_CLOSE; every session on it terminates with
    /// OnSessionClosed "connection closed"). This is what the Rust oracle
    /// does when a stream ends - registry.rs:370-386 closes the viewer's
    /// WT connection "which the browser surfaces as wtClosed so its
    /// auto-reconnect can resubscribe" - and it is the close a WT client
    /// observes as a session end: a session-stream FIN alone leaves the
    /// connection (and a libwebsrt Subscriber's SRT session) running.
    /// No-op for an unknown handle or an unknown/closing server.
    void CloseConnection(WtSessionHandle handle, const std::string& reason);

    /// Loop thread only. Swap the policy consulted on NEW CONNECTs (the
    /// P4.1 SIGHUP hot reload): Decide() runs on this thread in
    /// ProcessConnectHeaders, so an inline assignment cannot race an
    /// in-flight consult. Sessions already accepted keep their
    /// already-granted access - the policy is never re-asked about them.
    void SetPolicy(std::shared_ptr<const SessionPolicy> policy) { policy_ = std::move(policy); }

    /// Evidence getters (thread-safe).
    [[nodiscard]] int SessionsAccepted() const { return sessions_accepted_.load(); }
    [[nodiscard]] int SessionsRejected() const { return sessions_rejected_.load(); }
    [[nodiscard]] int DatagramsReceived() const { return datagrams_received_.load(); }
    [[nodiscard]] int DatagramsWritten() const { return datagrams_written_.load(); }
    [[nodiscard]] int DatagramsDropped() const { return datagrams_dropped_.load(); }

    /// The session's QUIC smoothed RTT (lsquic_conn_get_info().lci_rtt,
    /// microseconds) - the seed the per-session SRT initiator derives its
    /// SRTO_INITIAL_RTT from (PLAN.md: RTT seeding via lci_rtt). 0 when
    /// unmeasured or the handle is unknown. Loop thread only (called at
    /// session accept).
    [[nodiscard]] std::chrono::microseconds SmoothedRtt(WtSessionHandle handle) const;

private:
    // ---- types known to the .cpp ----
    struct ConnCtx;
    struct Session;
    struct StreamCtx;

    friend struct WtServerCallbacks; // lsquic shims (wt_server.cpp)
    friend struct WtHsetIf;          // header-set interface (wt_server.cpp)

    // EngineHost: loop-thread engine driving (same recipe as WTClient).
    bool NextTick(std::chrono::microseconds& diff) override;
    void Pump() override;

    // Loop-thread internals (wt_server.cpp).
    void                   AttachLoop();
    void                   HandleServerReadable();
    void                   EnqueueDatagram(Session& session, std::vector<std::uint8_t> payload);
    void                   CloseOnLoop();
    void                   CloseSessionOnLoop(WtSessionHandle handle, const std::string& reason);
    void                   CloseConnectionOnLoop(WtSessionHandle handle, const std::string& reason);
    void                   Teardown(); // idempotent; engine destroy outside callbacks
    [[nodiscard]] Session* FindSessionByContext(const ConnCtx& cc, std::uint64_t context_id) const;
    static void            Respond(lsquic_stream_t* stream, const char* status, bool half_close);
    void                   ProcessConnectHeaders(StreamCtx& sc, Session& session, HeaderSet& hset);
    void                   HandleSessionStreamRead(StreamCtx& sc);
    void                   HandleSubstreamRead(lsquic_stream_t* stream);
    // Returns false when a CLOSE capsule terminated the session (the
    // caller stops and terminates - ParseCapsules never frees).
    [[nodiscard]] static bool ParseCapsules(Session& session, const std::uint8_t* data, std::size_t size);
    void                      TerminateSession(Session& session, const std::string& reason);

    websrt::EventLoop&                   loop_;
    const CertProvider&                  cert_;
    std::shared_ptr<const SessionPolicy> policy_;
    WtServerListener&                    listener_;
    AdmissionCheck                       admission_;

    // Bound state (loop thread or Bind's caller, before attach).
    bool           bound_         = false;
    int            fd_            = -1;
    bool           fd_registered_ = false;
    sockaddr_in    local_sa_{};
    lsquic_engine* engine_       = nullptr;
    SSL_CTX*       ssl_ctx_      = nullptr;
    std::uint64_t  next_handle_  = 1;
    bool           closing_      = false; // Close() was called
    bool           tearing_down_ = false; // destructor teardown running

    // Live server state, loop thread only.
    std::map<std::uint64_t, ConnCtx*> conns_;    // keyed by raw conn ptr
    std::map<std::uint64_t, Session*> sessions_; // handle -> session
    // (Datagram context routing lives per connection in ConnCtx: every
    // client's CONNECT stream is stream 0, so a context id only names a
    // session within its own connection.)

    // Evidence.
    std::atomic<int> sessions_accepted_{0};
    std::atomic<int> sessions_rejected_{0};
    std::atomic<int> datagrams_received_{0};
    std::atomic<int> datagrams_written_{0};
    std::atomic<int> datagrams_dropped_{0};

    // Resolved by the destructor's posted teardown when the loop still
    // runs; makes mid-flight destruction safe outside callbacks.
    std::promise<void> teardown_done_;
};

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_WT_SERVER_H
