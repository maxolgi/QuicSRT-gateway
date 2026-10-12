# websrt-gateway-cpp — Plan

**Status: planned — refinement pending; nothing implemented yet.** The plan
below was recovered from libwebsrt's history (where the gateway was phases
P3/P4) and will be refined with the human before implementation starts.
Companion repos: `libwebsrt` (submodule `deps/libwebsrt` — the client
library whose exports this gateway consumes), `WebSRT` (Rust — the reference
implementation and interop oracle, **never modified from this repo**), and
`maxolgi/srt` (fork of Haivision/srt, consumed transitively via libwebsrt's
own submodule).

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
  2. Per-session SRT initiator (caller, skip-induction, cookie 0) + ~2 ms
     ticker: bounded tick concurrency (16), credit-based drain budget
     (256 msgs/tick), `drop_backlog` on first connected tick.
  3. Broadcaster ring + stream registry: first-wins occupancy, challengers
     rejected; TS bytes never modified.
  4. SRT/UDP ingest via stock-mode libsrt: streamid required, first-wins,
     latency-scaled buffers (8192–320000 pkts), FC window ≥ RCVBUF.
  5. Web server: static `web/dist` serving + health endpoint; supervisord
     conf (`scripts/websrt-cpp.conf`).
  6. No-op-CC approximation: max pacing rate + large FC windows (documented
     behavioral difference vs Rust `nocc.rs`).

  *Gates:* unmodified browser pages play from the C++ gateway; Rust
  `wt_hs_probe` / `mock_obs` pass against it; 50-viewer concurrency
  (ticker avg < 5 ms, zero viewer lag); parity matrix vs the Rust gateway.
- **P4 — Hardening.** Config-file support, packaging, docs, CI polish.

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
