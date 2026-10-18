# Parity matrix — QuicSRT-gateway vs the Rust WebSRT gateway

Measured 2026-10-12 against the running local gateways (measurement and
documentation only; no gateway behavior was changed for parity):

- **C++**: dev instance, `QuicSRT-gateway --config /tmp/opencode/gw.conf`
  — WT 127.0.0.1:4434, SRT ingest 9100, health 9291 (HTTP), web 8080,
  self-signed cert (pinned hash via runtime cert-hash.js).
- **Rust**: supervisord `websrt` service — WT 0.0.0.0:4433, SRT ingest
  9000, health 9091 (HTTP), self-signed cert (runtime cert-hash.js).

2026-10-15: two documented divergences closed in code —
`send_failures` semantics and the `/health` `ingester` map (below);
the ingester shape was re-checked against the live oracle.

2026-10-16: robustness ports from the oracle (GatewayLimits, the
>= 1200-byte datagram PMTU gate, public-bind warnings) landed with
parity rows below; the per-session TSBPD latency was decoupled to the
Rust 10 ms floor; drifted gateway.rs citations were re-anchored after
upstream refactors.

2026-10-17: robustness additions on this branch — the ingest
concurrent-session cap, the broadcaster per-ring byte budget, the web
request-header total deadline, the capsule-overflow session kill, the
sub-188 negotiated-payload clamp — landed with rows below; the
zero-viewer stream drop closed a divergence this matrix had not yet
recorded. Oracle behavior for every new row was re-verified against
the WebSRT source, including the wtransport 0.7.1 and hyper 1.11
dependency paths the capsule and header-deadline rows turn on.

2026-10-17 (later): COOP/COEP headers added to every player response —
the in-progress emcc/pthreads wasm rewrite needs SharedArrayBuffer,
which the browser grants only cross-origin-isolated documents. Oracle
side verified against the WebSRT source (Content-Type only). Row below.

2026-10-18: the embedded player dist switched from the Rust WebSRT
release artifact to the latest websrt-wasm-cpp release
(`websrt-wasm-dist.zip`, fetched by build.sh) — the emcc/pthreads C++
player, the same artifact the deployed gateway serves via web_root. One
source of truth for the player; the Rust player stops being the embedded
parity reference. The serving mechanism is unchanged (row below).

Client tooling: libwebsrt's patched ffmpeg (`websrt://` protocol) and
`websrt-dump`, plus the WebSRT oracle bins (`wt_hs_probe`, `mock_obs`).

## Behavior matrix

| Behavior | Rust gateway | C++ gateway | Verdict |
|---|---|---|---|
| Publish to occupied name | HTTP 403 at pre-accept (gateway.rs:501-507); ffmpeg publish exits 158 "Address already in use" | HTTP 403 at admission (Gateway::Admit → WtServer); ffmpeg publish exits 158 "Address already in use" | **Parity** (measured both, identical ffmpeg exit + message) |
| Subscribe unknown stream | HTTP 404 (stream not alive, gateway.rs:489-497); ffmpeg subscribe exits 145 "Connection refused" | HTTP 404 (allowlist Reject for unconfigured names) or admission Reject; ffmpeg subscribe exits 145 "Connection refused" | **Parity** (measured both, identical) |
| Subscribe configured-but-idle stream | 404 (no live broadcaster) | **Accepted — waiting viewer** (idle stream, served when a publisher appears) | **Deliberate divergence** (refinement item 2, documented; kills client retry hacks; e2e test §2) |
| Publisher end → viewers | clean EOF; viewer ffmpeg exits 0 (out 5.15 s / 58468 B) | clean EOF; viewer ffmpeg exits 0 (out 5.15 s / 58468 B, byte-identical encode) | **Parity** (measured both) |
| Idle entry after publisher end | dead entry stays in the map until the ticker's 60 s cleanup (gateway.rs:640-656; stream_registry.rs:190-194); it never blocks a re-publish — occupancy checks `is_alive`, not map presence (stream_registry.rs:94) | dropped at last participant exit: zero-viewer publisher end drops the stream immediately, with viewers the final viewer detach does | **Parity** (was: the zero-viewer case left the idle entry in the registry forever; restored 2026-10-17 — ours drops immediately, the oracle reaps within 60 s) |
| First-wins occupancy (cross-source) | WT publisher vs SRT ingester contend for one name | same shared `StreamRegistry::PublishAttempt` claim (WT + ingest) | **Parity** (design + e2e/ingest tests) |
| No `?stream=` query on CONNECT | defaults to stream `"default"` (gateway.rs:476-483); 404 unless "default" is alive | 404 always (no name resolved) | **Minor divergence** (only observable with a stream literally named "default"; ours is stricter) |
| Dual-role `?publish=X&stream=Y` | one session publishes X and views Y — a different name (gateway.rs:546-566) | publish-only: `?publish=` wins and the subscribe half is ignored (`ResolveRole`) | **Deliberate divergence** (single-role sessions keep admission and the registry simple; no current consumer needs the dual role) |
| Viewer cap exceeded | post-accept: `subscribe()` fails after the 200 and the connection is closed (gateway.rs:572-580) | pre-accept: 429 answered on the CONNECT response (`ViewerSlotFree` → admission) | **C++ improvement** (the refused viewer observes the status on the response it is waiting for, same as the other refusals) |
| Web-port endpoints | static player only — `/health` and `/stats` live on the health port | static player plus `/health` and `/stats` on the web port too | **Additive** (one port fewer to expose in simple deployments) |
| Unknown web paths | SPA fallback: unknown paths serve `index.html` (web_server.rs:79-95) | 404 | **Minor divergence** (the player is a single page with no client-side routes; nothing depends on the fallback) |
| Request-header deadline | none configured: the web server is a bare axum_server bind/serve (web_server.rs:54-58), `/health` an `axum::serve` on a TcpListener (main.rs:482-490); hyper's 30 s `header_read_timeout` default is inert in both — neither stack installs the Timer it requires | `[server].request_header_timeout_s` (default 30 s, 1..600): total budget for one request's headers on the web and health servers; on expiry answered 408 and closed, so a byte-trickling client cannot hold a bounded worker | **C++ improvement** (a trickle never trips the per-read idle timeout; only a total budget catches it) |
| `max_bandwidth` knob | `SrtConfig.max_bandwidth` → srt `LiveBandwidthMode::Max` (srt_sender.rs:161-165) | `[server].max_bandwidth_kbps` parsed, validated, and unwired (documented in the example conf) | **Deliberate divergence** (reserved for a later port; nothing dials it in this build) |
| Connection limits | `GatewayLimits` defaults: 10 sessions/IP, 1000 global, 10 s WT idle, 10 s handshake (limits.rs:40-49; idle = quinn `max_idle_timeout`) | same defaults via `[server].max_sessions_per_ip` / `max_sessions` / `wt_idle_timeout_s` / `wt_handshake_timeout_s`; over-cap CONNECTs answered 429; counting is per established WT session where the oracle counts connections | **Parity** (defaults and enforcement point match; counting unit documented) |
| WT datagram PMTU | post-accept session check: `max_datagram_size() < 1200` (or datagrams unsupported) → close (gateway.rs:525-543) | per connection at `on_new_conn`: the min-datagram pin requested at 1200 fails on exactly the same conditions → connection closed | **Parity** (same 1200 floor, enforced one step earlier — before the CONNECT is answered) |
| Public-bind warnings | none at boot | WARNING when an open-mode WT listener or a passphrase-less SRT ingest binds non-loopback | **C++ additive** (robustness; loopback binds stay silent) |
| Session stream rejected (404/403) | wtransport resets the stream — client can observe a transport error instead of the status (the 404-reset race, PLAN.md defect 2) | response headers flushed, then write-side FIN — status observed deterministically (RespondAndHalfClose) | **C++ fixes an oracle defect** |
| Session-stream capsule overflow | the session stream is driven inside wtransport 0.7.1 (the gateway itself reads only datagrams, session.rs:200); a capsule must complete within one HTTP/3 DATA frame — frames are capped at 4096 B and an over-limit frame declaration kills the connection with H3 ExcessiveLoad, while a capsule whose length varint exceeds its frame is skipped as unknown (session lives) | the stream feeds a bounded capsule parser; a header demanding more than the 1 MiB pending ceiling (`WtCapsuleParser::kMaxPendingBytes`) kills the session — close reason "capsule framing overflow", session-stream FIN (wt_overflow_test: kill < 1 s, server healthy after) | **Deliberate divergence** (same one-client OOM vector, bounded at different layers: ours accumulates a pending tail and kills its owner; the oracle never accumulates across reads and merely skips what it cannot frame) |
| ≥3 concurrent WT handshakes | accept-loop stall 10–20 s (PLAN.md defect 1; ffmpeg-gate staggers handshakes to avoid it) | 50 concurrent handshakes complete in ~0.6 s (concurrency_test) | **C++ fixes an oracle defect** |
| SRT payload | 1128 (6×188, srt_sender.rs:29) | 1128 (constant throughout) | **Parity** |
| Viewer send chunking | no gateway-side chunker: the ticker hands whole ring messages to `push_message` (registry.rs:354-363) and srt-protocol fragments to the configured payload inside the duplex connection (srt_sender.rs:269-286) — no negotiated-payload readback, so no whole-message fallback exists | chunk = negotiated payload, clamped UP to 188 when the readback lands below one TS packet (`ViewerChunkSize`); was: whole-message fallback below 188 | **C++ improvement** (payloads ≥ 188 pass through unchanged; the clamp only bounds the degenerate HSv5 MTU-readback case, which the oracle's path cannot reach) |
| Per-session TSBPD latency | 10 ms floor on the gateway's SRT sockets (SrtConfig default, srt_sender.rs:58-59) — the client couples with the gateway, not with the publisher | 10 ms floor (`RegistryConfig.latency_ms`); decoupled 2026-10-16 from `[server].latency_ms`, which is the SRT/UDP ingest listener's knob only (ingest default stays 120) | **Parity** (was: initiators mirrored the ingest latency) |
| Ticker cadence/budgets | 500 Hz / 2 ms tick, 256 msgs/tick, 16-session tick concurrency (registry.rs:38-53) | same numbers (RegistryConfig; sessions_serviced_per_tick maps TICK_CONCURRENCY to a rotating-service bound) | **Parity** (documented mapping, session_registry.h) |
| drop_backlog on first connect | viewer's handshake-era backlog dropped, cursor at live edge | same via PopBacklogDrop + PrimeViewer | **Parity** |
| Broadcaster ring bounds | message count only: a tokio broadcast channel of depth 32768 (gateway.rs:29; broadcaster.rs:102) — no byte accounting anywhere in the fanout | count cap plus `[server].broadcast_byte_budget` (default 64 MiB, 4 MiB..1 TiB): past either bound the OLDEST messages drop, counted in `ring_drops` exactly like count-cap drops | **C++ improvement** (whole multi-packet SRT messages make the count alone bound no byte volume; the 4 MiB floor keeps one maximum-size message buffered) |
| QUIC congestion control | no-op controller `nocc.rs` (window=∞, never paces) — SRT owns CC | lsquic: pacer OFF + 16 MiB/8 MiB FC windows; no no-op CC exists | **Documented approximation** (PLAN.md step 7; sustained-rate evidence in concurrency_test) |
| Ingest chunking | ingester hands srt messages to the ring unframed (listener MSS-sized) | SrtIngest re-frames with TsChunker rules (≤1128, 188-aligned) so viewer payload ceilings are never exceeded | **Deliberate divergence** (G6, srt_ingest.h "FRAMING") |
| Ingest streamid required | connection refused without streamid (srt_listener.rs:92-95) | same (rejected_no_streamid counter + refusal) | **Parity** (mock_obs probe, below) |
| Ingest connection cap | none: the accept loop admits every streamid-carrying connection — the only refusals are no-streamid and name-occupied (srt_listener.rs:81-110) | `[server].max_ingest_sessions` (default 100, 0 = unlimited): past the cap the connection is refused at accept, before any streamid/gate/claim work, counted `rejected_session_cap` in `/stats` | **C++ improvement** (the ingest analogue of the WT `max_sessions` cap; each accepted publisher holds latency-scaled srt buffers) |
| TLS / SNI | wtransport serves one identity; accepts IP-literal (no-SNI) clients | one SSL_CTX via `ea_get_ssl_ctx` only — SNI ignored, no-SNI clients (IP literals) complete; mkcert/PEM mode + cert-hash.js contract identical | **Parity** (browser gate passed on both; wt_hs_probe on 127.0.0.1) |
| cert-hash.js contract | `CERT_HASH` (self) / `null` (mkcert) + `WT_PORT` | same runtime emission (cert.h) | **Parity** |
| Player serving | web/dist embedded at compile time (rust-embed), cert-hash.js served dynamically | web/dist embedded at compile time (CMake-generated table from the latest websrt-wasm-cpp release dist — the emcc/pthreads C++ player, not the oracle's Rust player), cert-hash.js served dynamically; optional `web_root` disk override (the oracle's own `--web-root`) | **Deliberate divergence** (mechanism identical; the embedded build is the wasm-cpp artifact, matching the deployed web_root — swapped 2026-10-18, was the WebSRT release dist) |
| Player COOP/COEP | none — axum serves the rust-embed table and cert-hash.js with Content-Type only (web_server.rs:96-122) | every player response (disk override and embedded table, 304s included) carries `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` (`PlayerHeaders`, web_server.cpp) | **C++ additive** (the emcc pthreads wasm rewrite needs a cross-origin-isolated document for SharedArrayBuffer; all player subresources are same-origin, so require-corp excludes nothing the current dist loads) |

## /health shape diff (key-by-key, equivalent live `browsertest` stream + one WT viewer on each)

Top-level keys: **identical except our two additive keys**
(`uptime_ms`, `active_sessions`). No missing Rust key at the top level.

Nested objects:

- `per_session[]`: **identical field sets** — `session_id`, `stream`,
  `tx_data`, `tx_buffered`, `tx_retransmit`, `tx_loss`, `rtt_ms`,
  `messages_pushed`, `viewer_lag`, `buffer_lag`.
- `per_stream[]`: **identical field sets** — `name`, `alive`, `viewers`,
  `messages_sent`, `send_failures`.
- `ticker`: **identical field sets** — `count`, `avg_us`, `max_us`.
  Semantics differ under repeated scrapes: the oracle's counters are
  read-and-reset per poll (`ticker_stats_reset`, a per-scrape window;
  registry.rs), ours accumulate over the process lifetime
  (`TickAvgUs`, session_registry.h) — no decision reads them, so the
  divergence only shows when comparing consecutive scrapes.
- `ingester`: **parity (ported 2026-10-15)** — a map keyed by stream
  name carrying that publisher connection's TS-continuity probe
  (`cc_checks`, `cc_gaps`, `messages_seen`), `null` while no publisher
  has ever connected (shape confirmed against the live oracle:
  `{"ingester":null,...}`). Entries appear when a publisher claims the
  name, persist after the connection ends (frozen counters) and start
  fresh when the name is claimed again — the oracle's TsStatsHandle-map
  behavior (main.rs:669-689). Our probe (`ts_continuity.h`, the oracle
  `CcChecker` semantics: payload-only, duplicates tolerated, wrap ok,
  signalled resets not counted) scans the chunker's 188-aligned output
  rather than raw SRT messages, so it cannot misparse on message-boundary
  misalignment the way the oracle's per-message `chunks_exact` can. The
  aggregate ingest counters this slot used to carry live only in our
  `/stats` (`ingest`), which the Rust gateway does not have at all
  (`/stats` → 404 on the Rust gateway; ours is additive).

`/stats` (ours only): `uptime_ms`, `stream_count`, `alive_streams`,
`viewers`, `max_viewers`, `active_sessions`, `ticker`,
`server.{sessions_accepted,sessions_rejected,datagrams_received,
datagrams_written,datagrams_dropped}`, `streams[]` (ring accounting),
`sessions[]`, `ingest` (full counters + live `connections[]`, each
carrying its continuity probe).

## Oracle bin runs against the C++ gateway (P3 gates)

### wt_hs_probe — PASS

`wt_hs_probe --url https://127.0.0.1:4434/wt?stream=browsertest
--hash <pinned> --seconds 10` against the live ffmpeg→ingest stream:

```
connected: session_id=0
✓ handshake complete
received messages: 1692 (1692 started with 0x47)
received bytes:    1101116
TS packet advances: 5852, gaps detected: 0
gap rate: 0.00%
```

Raw `srt_protocol` listener semantics (skip-induction handshake over WT
datagrams) interop with our initiator; TS continuity counters show zero
unrecovered gaps. The probe's default URL carries no `?stream=`, which
both gateways refuse (Rust: "default" not alive → 404; ours: nameless →
404) — run it with an explicit `--url .../wt?stream=<name>`.

### mock_obs — refused identically by BOTH ingests (documented, not faked)

`mock_obs --dst 127.0.0.1:9100` (ours): connects, then "send failed
because receiver is gone" — our ingest refuses the connection at accept
(`srt-ingest: rejected publisher ... no streamid`). Against the Rust
ingest (9000) it fails at handshake the same way: `mock_obs` calls
`SrtSocket::builder().call(dst, None)` — **streamid None** — and both
gateways require a streamid (Rust srt_listener.rs:92-95; our
SrtIngest::StreamIdOf check). The bin predates the streamid-required
rule and cannot complete against either modern gateway; its expectation
legitimately differs, so the pass/fail call is **refused-by-both =
parity** rather than a C++ failure.
