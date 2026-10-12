# websrt-gateway-cpp — Plan

**Status: P3 implemented (unpushed); P4 pending.** Steps 1–6 of P3 are built
(`./build.sh test`: 18/18 green) and the **browser gate passes**: an unmodified
WebSRT player page connects to this gateway over WebTransport, the SRT session
carries the stream (3.4k packets / 2.4 MB, 0 loss / 0 retransmit, 0.2 ms
RTT), and audio decodes — SRT stats indistinguishable from the Rust gateway's.
Video decode fails in the player with `VideoDecoder.configure() →
"Unsupported configuration"`; the identical failure occurs against the **Rust**
gateway in the same browser (Chrome 151), so it is a pre-existing
WebSRT-player/Chrome issue, **not** a gateway defect (H.264 `isConfigSupported`
is true in that browser). Still to do: the 50-viewer concurrency gate, the
Rust-oracle bin runs (`wt_hs_probe`, `mock_obs`), and the parity matrix; then
P4 (hot reload, stats page, webhooks, packaging, CI).

The plan below was recovered from libwebsrt's history (where the gateway was
phases P3/P4) and was refined with the human before implementation started.
Companion repos: `libwebsrt` (submodule `deps/libwebsrt` — the client
library whose exports this gateway consumes), `WebSRT` (Rust — the reference
implementation and interop oracle, **never modified from this repo**), and
`maxolgi/srt` (fork of Haivision/srt, consumed transitively via libwebsrt's
own submodule).

## Refinement queue (agreed with the human, before P3 implementation starts)

1. **Gateway core as an embeddable library + thin CLI binary** (mirrors the
   Rust split: `crates/websrt` library vs `websrt-gateway` reference binary).
   The library owns accept loop, per-session SRT initiators, broadcaster
   ring/registry, cert modes; the binary only wires CLI/config/ingest.
   Motivation: embedded-device scenario — a C++ app linking the gateway core
   in-process and handing it MPEG-TS bytes through an API (no separate
   process, no local SRT-loopback hop). Browsers can only dial out, so any
   device serving websrt video to a web page needs this WT-server/SRT-initiator
   role somewhere; embedding it beats running a sidecar process. Decide during
   refinement: the in-process TS source API shape, how the CLI binary's
   ingest paths (SRT-UDP, WT publish) map onto it, and what stays binary-only
   (supervisord, web/dist serving policy).
2. **Stream access control — SLS-inspired allowlist config** (agreed): the
   gateway takes an optional `--config FILE` (TOML, parsed via vendored
   toml++ single header) defining allowed streams; it must not "just accept
   any caller". Decisions locked with the human:
   - **No config → open** (accept-all, first-wins — Rust-oracle parity for
     dev/tests) with a loud startup warning. **Config present → deny by
     default** for everything the allowlist governs.
   - Matching: exact names **and globs** (`"test-*"`).
   - **Publishers gated**: WT `?publish=` and SRT-UDP ingest `streamid=`
     must match a `[[stream]]` entry with `publish = true`, else 403 (WT) /
     connection refused (ingest). **Viewers gated too**: `?stream=` must
     match an entry with `subscribe = true`, else 404.
   - **Waiting viewers**: a configured stream with no publisher yet accepts
     subscriber sessions that wait (SRT initiator idles until data flows).
     Deliberate divergence from the Rust oracle's 404 — documented; kills
     clients' retry hacks. Waiting applies pre-first-publish; after
     publisher end viewers close (parity) and may re-wait by reconnecting.
   - Per-stream optional `token` (`?token=`, constant-time compare).
     First-wins occupancy unchanged within the allowlist.
   - Schema sketch: `[server]` (wt_port, srt_ingest_port, latency_ms…) and
     `[[stream]]` (name, publish, subscribe, token). CLI flags override
     file scalars.
   - **Library/binary split** (composes with item 1): the core library gets
     the `SessionPolicy` seam (ported from Rust `hooks.rs`) + built-in
     `StreamAllowlistPolicy`; TOML parsing and `--config` live in the CLI
     binary only — embedded consumers supply a policy in code.
   - Deferred to P4: SIGHUP hot reload, HTTP stats page, on_connect/on_close
     webhooks (SLS has these; not v1).

## Deliverable

**The C++ gateway** — full CLI-parity replacement of the Rust WebSRT
gateway. CLI-only (no GUI), production intent. Serves the existing browser
player (`web/dist` from the WebSRT checkout) unchanged.

### Scope boundaries (inherited, locked — do not re-litigate)

| Decision | Rationale |
|---|---|
| Browser side stays Rust WASM (srt-wasm, mpeg2ts-wasm, web UI) | Wire-compatible; porting libsrt to WASM is research-grade; no benefit |
| CLI-only; the Rust egui GUI is dropped | User decision |
| Serves the existing `web/dist` player, never rebuilt here | Rust WASM + TS owned by the WebSRT repo |
| Consumes libwebsrt as a submodule (pin discipline) | Gateway sessions are the same WT/SRT machinery the library exports; no code duplication |
| Rust WebSRT repo: ZERO changes | The fork speaks skip-induction, so the existing gateway interops as-is |

## Architecture

```
                          ┌───────────────────────────────────────────────┐
  browsers (WT) ─────────►│ websrt-gateway                                 │
  OBS / SRT-UDP ingest ──►│                                                │
                          │  lsquic WT server ── per-session SRT initiator │
                          │  (skip-induction, cookie 0) ── broadcaster ring │
                          │  ── stream registry (first-wins)               │
                          │  + stock-mode libsrt UDP ingest                │
                          │  + web server (static web/dist, health)        │
                          │  + cert modes + runtime cert-hash.js           │
                          │                                                │
                          │  libwebsrt (deps/libwebsrt, submodule):        │
                          │  EventLoop, srt fork exports, lsquic/BoringSSL │
                          └───────────────────────────────────────────────┘
```

**Pin discipline (two levels):** this repo pins `deps/libwebsrt` (gitlink);
libwebsrt pins its own `deps/srt`. Fork work lands in `~/maxolgi/srt` →
human pushes → libwebsrt bumps its pin → this repo bumps libwebsrt. Agents
commit; humans push; a gitlink pin is only resolvable after the human pushes
the submodule's repo.

**Consumer discipline:** the gateway links ONLY libwebsrt's exported
interface targets — `websrt::websrt` (public + internal headers, gated srt
fork API), `websrt::srt-deps` (raw forked-socket surface),
`websrt::wt-deps` (lsquic + BoringSSL + zlib chain). Never raw `deps/`
paths.

## Port map (Rust → C++, gateway rows)

| Rust source | C++ equivalent |
|---|---|
| `gateway.rs` (accept loop, viewer cap, graceful drain) | `src/gateway/gateway.cpp` |
| `hooks.rs` (SessionPolicy: path / origin / token, chainable — stream names NOT gated by default) | `src/gateway/policy.{h,cpp}` (core library): same seam + built-in `StreamAllowlistPolicy` (exact+glob, publish/subscribe roles, per-stream token); TOML `--config` parsing in the CLI binary — see refinement item 2 |
| `session.rs` (recv_pump, LossInjector sim-loss, QUIC stats log) | `src/gateway/session.cpp` |
| `registry.rs` (~2 ms ticker, tick concurrency 16, credit budget 256 msgs/tick, `drop_backlog` on first connect) | `src/gateway/registry.cpp` |
| `stream_registry.rs` + `broadcaster.rs` (ring fanout, first-wins publish) | `src/gateway/stream_registry.cpp` + core ring |
| `srt_sender.rs` (SrtConfig, initiator drive, PAYLOAD_SIZE) | srt fork initiator role |
| `ingest/srt_listener.rs` (streamid required, first-wins, latency-scaled buffers 8192–320000, FC ≥ RCVBUF discipline) | `src/gateway/ingest/srt_ingest.cpp` (stock libsrt UDP mode) |
| `cert.rs` (self-signed regen per boot, mkcert, runtime cert-hash.js) | `src/gateway/cert.cpp` |
| `web_server.rs` (health endpoint, static `web/dist`) | `src/gateway/web_server.cpp` — serves the existing player unchanged |
| `nocc.rs` (no-op QUIC CC so SRT owns congestion control) | **no lsquic equivalent** — approximate via max pacing rate + large flow-control windows; document as behavioral difference |
| egui GUI / `gui.rs` | none — CLI-only by decision |
| `log_buffer.rs` | plain stderr/stdout logging (no GUI to feed) |

## Protocol constants & inherited behaviors

- SRT payload **1128** (6 × 188), negotiated `min(gateway, client)` — see
  `crates/websrt/src/srt_sender.rs:29` in WebSRT. Do not "fix" to 1316.
- WT datagrams: require ≥ 1200, warn > 1400.
- TSBPD latency = `max(sender, receiver)`; gateway-side floor 10 ms; ingest
  default 120 ms.
- Skip-induction 1-RTT handshake everywhere (WT's TLS replaces the SRT
  cookie's DoS role). The gateway's per-session initiator uses the caller
  role: Conclusion-first, cookie = 0.
- RTT seeding: WT/QUIC smoothed RTT (`lsquic_conn_get_info().lci_rtt`) →
  `SRTO_INITIAL_RTT` for correct cold-start retransmit timing.
- One fixed `/wt` path; routing by query: `?stream=`/`?subscribe=` (view),
  `?publish=` (browser publish); OBS ingest derives the name from the SRT
  `?streamid=`.
- First-wins publish occupancy; TS bytes never modified server-side.
- QUIC connection migration is inherited; WT pacing vs TSBPD interaction is
  expected (too-late drops are correct live behavior).

## Phases & gates

- **P3 — Gateway.** Sub-steps in build order:
  1. lsquic WT server accept + cert modes: self-signed ECDSA regenerated on
     every boot (never persisted), mkcert PEM mode, runtime `cert-hash.js`
     emission (hash for self-signed, null for mkcert).
  2. Session policy seam: port `hooks.rs` (`SessionRequest` →
     `Decision{Accept, 404, 403, 429}`, chainable) into the core library;
     `StreamAllowlistPolicy` (exact+glob, roles, per-stream token); CLI
     `--config` TOML (toml++ vendored), open-with-warning when absent —
     refinement item 2.
  3. Per-session SRT initiator (caller, skip-induction, cookie 0) + ~2 ms
     ticker: bounded tick concurrency (16), credit-based drain budget
     (256 msgs/tick), `drop_backlog` on first connected tick.
  4. Broadcaster ring + stream registry: first-wins occupancy, challengers
     rejected; TS bytes never modified. Idle (waiting-viewer) broadcasters
     for configured-but-unpublished streams.
  5. SRT/UDP ingest via stock-mode libsrt: streamid required (allowlist
     enforced), first-wins, latency-scaled buffers (8192–320000 pkts),
     FC window ≥ RCVBUF.
  6. Web server: static `web/dist` serving + health endpoint; supervisord
     conf (`scripts/websrt-cpp.conf`).
  7. No-op-CC approximation: max pacing rate + large FC windows (documented
     behavioral difference vs Rust `nocc.rs`).

  *Gates:* unmodified browser pages play from the C++ gateway; Rust
  `wt_hs_probe` / `mock_obs` pass against it; 50-viewer concurrency
  (ticker avg < 5 ms, zero viewer lag); parity matrix vs the Rust gateway.
- **P4 — Hardening.** SIGHUP config hot-reload, HTTP stats page,
  on_connect/on_close webhooks, packaging, docs, CI polish.

## Rust-gateway defects the C++ gateway must not reproduce

- Accept-loop stall: ≥ 3 concurrent WT handshakes within seconds can stall
  the wtransport accept loop 10–20 s; sessions attaching during recovery can
  see `messages_pushed=0` until EOF. Short client connect timeouts worsen it.
- 404-reset race: resetting the CONNECT stream before the client reads the
  404 makes the client see a transport failure instead of a clean rejection.
  Flush the response before resetting.

## Testing & oracles

- `./build.sh test` — for now the gateway selftest (consumer gate); grows
  with each sub-step.
- Rust bins `wt_hs_probe` / `mock_obs` run against the C++ gateway.
- Browser pages from the Rust gateway are the final arbiter — the same pages
  served unchanged by the C++ gateway.
- Golden acceptance commands (must always work against the running gateway,
  via the libwebsrt-patched ffmpeg):

  ```
  ffmpeg -f lavfi -i testsrc2=size=1280x720:rate=30 -f lavfi -i sine=frequency=440 \
         -c:v libx264 -preset veryfast -c:a aac -f mpegts websrt://gw:443?stream=test
  ffmpeg -f mpegts -i websrt://gw:443?stream=test -c copy out.ts
  ```

## Risks (accepted)

1. **No no-op QUIC congestion controller exists in lsquic** (Rust `nocc.rs`
   silences quinn CC so SRT owns it). We approximate with max pacing rate +
   large flow-control windows and document the difference.
2. Two gateways = behavioral-parity burden — mitigated by the shared gate
   matrix (parity checks vs the Rust gateway at every step).
3. Fresh clones fail at `deps/libwebsrt` until the GitHub repo exists —
   AGENTS.md "Soft pin" documents the sibling-clone workaround.
