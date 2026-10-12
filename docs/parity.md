# Parity matrix — websrt-gateway-cpp vs the Rust WebSRT gateway

Measured 2026-10-12 against the running local gateways (measurement and
documentation only; no gateway behavior was changed for parity):

- **C++**: dev instance, `websrt-gateway --config /tmp/opencode/gw.conf`
  — WT 127.0.0.1:4434, SRT ingest 9100, health 9291 (HTTP), web 8080,
  self-signed cert (pinned hash via runtime cert-hash.js).
- **Rust**: supervisord `websrt` service — WT 0.0.0.0:4433, SRT ingest
  9000, health 9091 (HTTP), self-signed cert (runtime cert-hash.js).

Client tooling: libwebsrt's patched ffmpeg (`websrt://` protocol) and
`websrt-dump`, plus the WebSRT oracle bins (`wt_hs_probe`, `mock_obs`).

## Behavior matrix

| Behavior | Rust gateway | C++ gateway | Verdict |
|---|---|---|---|
| Publish to occupied name | HTTP 403 at pre-accept (gateway.rs:352); ffmpeg publish exits 158 "Address already in use" | HTTP 403 at admission (Gateway::Admit → WtServer); ffmpeg publish exits 158 "Address already in use" | **Parity** (measured both, identical ffmpeg exit + message) |
| Subscribe unknown stream | HTTP 404 (stream not alive, gateway.rs:345-349); ffmpeg subscribe exits 145 "Connection refused" | HTTP 404 (allowlist Reject for unconfigured names) or admission Reject; ffmpeg subscribe exits 145 "Connection refused" | **Parity** (measured both, identical) |
| Subscribe configured-but-idle stream | 404 (no live broadcaster) | **Accepted — waiting viewer** (idle stream, served when a publisher appears) | **Deliberate divergence** (refinement item 2, documented; kills client retry hacks; e2e test §2) |
| Publisher end → viewers | clean EOF; viewer ffmpeg exits 0 (out 5.15 s / 58468 B) | clean EOF; viewer ffmpeg exits 0 (out 5.15 s / 58468 B, byte-identical encode) | **Parity** (measured both) |
| First-wins occupancy (cross-source) | WT publisher vs SRT ingester contend for one name | same shared `StreamRegistry::PublishAttempt` claim (WT + ingest) | **Parity** (design + e2e/ingest tests) |
| No `?stream=` query on CONNECT | defaults to stream `"default"` (gateway.rs:330-332); 404 unless "default" is alive | 404 always (no name resolved) | **Minor divergence** (only observable with a stream literally named "default"; ours is stricter) |
| Session stream rejected (404/403) | wtransport resets the stream — client can observe a transport error instead of the status (the 404-reset race, PLAN.md defect 2) | response headers flushed, then write-side FIN — status observed deterministically (RespondAndHalfClose) | **C++ fixes an oracle defect** |
| ≥3 concurrent WT handshakes | accept-loop stall 10–20 s (PLAN.md defect 1; ffmpeg-gate staggers handshakes to avoid it) | 50 concurrent handshakes complete in ~0.6 s (concurrency_test) | **C++ fixes an oracle defect** |
| SRT payload | 1128 (6×188, srt_sender.rs:29) | 1128 (constant throughout) | **Parity** |
| Ticker cadence/budgets | 500 Hz / 2 ms tick, 256 msgs/tick, 16-session tick concurrency (registry.rs:38-53) | same numbers (RegistryConfig; sessions_serviced_per_tick maps TICK_CONCURRENCY to a rotating-service bound) | **Parity** (documented mapping, session_registry.h) |
| drop_backlog on first connect | viewer's handshake-era backlog dropped, cursor at live edge | same via PopBacklogDrop + PrimeViewer | **Parity** |
| QUIC congestion control | no-op controller `nocc.rs` (window=∞, never paces) — SRT owns CC | lsquic: pacer OFF + 16 MiB/8 MiB FC windows; no no-op CC exists | **Documented approximation** (PLAN.md step 7; sustained-rate evidence in concurrency_test) |
| Ingest chunking | ingester hands srt messages to the ring unframed (listener MSS-sized) | SrtIngest re-frames with TsChunker rules (≤1128, 188-aligned) so viewer payload ceilings are never exceeded | **Deliberate divergence** (G6, srt_ingest.h "FRAMING") |
| Ingest streamid required | connection refused without streamid (srt_listener.rs:92-95) | same (rejected_no_streamid counter + refusal) | **Parity** (mock_obs probe, below) |
| TLS / SNI | wtransport serves one identity; accepts IP-literal (no-SNI) clients | one SSL_CTX via `ea_get_ssl_ctx` only — SNI ignored, no-SNI clients (IP literals) complete; mkcert/PEM mode + cert-hash.js contract identical | **Parity** (browser gate passed on both; wt_hs_probe on 127.0.0.1) |
| cert-hash.js contract | `CERT_HASH` (self) / `null` (mkcert) + `WT_PORT` | same runtime emission (cert.h) | **Parity** |

## /health shape diff (key-by-key, equivalent live `browsertest` stream + one WT viewer on each)

Top-level keys: **identical except our two additive keys**
(`uptime_ms`, `active_sessions`). No missing Rust key at the top level.

Nested objects:

- `per_session[]`: **identical field sets** — `session_id`, `stream`,
  `tx_data`, `tx_buffered`, `tx_retransmit`, `tx_loss`, `rtt_ms`,
  `messages_pushed`, `viewer_lag`, `buffer_lag`.
- `per_stream[]`: **identical field sets** — `name`, `alive`, `viewers`,
  `messages_sent`, `send_failures`. (Semantics note: ours counts
  `send_failures` on every append with no viewer attached; the Rust
  oracle's tokio-broadcast accounting shows 0 in the same scenario.)
- `ticker`: **identical field sets** — `count`, `avg_us`, `max_us`.
- `ingester`: **structured differently**. Rust: a map keyed by stream
  name with per-connection TS-continuity counters (`cc_checks`,
  `cc_gaps`, `messages_seen`) plus the built-in `rustref` self-monitor.
  Ours: aggregate counters (`publishers_accepted`, `publishers_rejected`,
  `publishers_ended`, `messages_in`, `chunks_out`). Real gap: we do not
  surface per-ingest-connection TS continuity counters in /health
  (functionality the Rust oracle uses for its own NAK/retransmit
  monitoring). The richer per-connection data exists in our `/stats`
  (`ingest.connections[]`), which the Rust gateway does not have at all
  (`/stats` → 404 on the Rust gateway; ours is additive).

`/stats` (ours only): `uptime_ms`, `stream_count`, `alive_streams`,
`viewers`, `max_viewers`, `active_sessions`, `ticker`,
`server.{sessions_accepted,sessions_rejected,datagrams_received,
datagrams_written,datagrams_dropped}`, `streams[]` (ring accounting),
`sessions[]`, `ingest` (full counters + live `connections[]`).

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
