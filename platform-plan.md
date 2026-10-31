# Platform plan — the QuicSRT application

Implementation plan for the licensed QuicSRT product: **one C++ binary** that
merges this gateway with a media engine (libav ingest, recording) and an admin
plane (HTTP API + SolidJS UI), presented through **four market models**.
Local-first: no cloud, no real addresses, no telemetry. Licensed per channel.

Status: planning document, the contract for implementation. Phases P0–P6 are
meant to be executed in order; each has a definition of done.

## 1. Product shape

| Property | Decision |
|---|---|
| Deliverable | Single C++ binary + frontend dist embedded at build (player already is) |
| Deployment | Runs anywhere: laptop, NUC, appliance. systemd unit provided; Docker deferred (wrapper, not foundation) |
| Licensing | Offline signed key, **per number of channels**; tiers TBD (e.g. 2/8/16/unlimited) |
| Markets | 4 presets ("models"): Return Feeds, Venue, Site, Field — landing page shows all four; deployment restriction via license model bitmask later |
| Recording | **Everything recorded goes to an embedded TAMS store** (Time Addressable Media Store, BBC R&D open API, github.com/bbc/tams) — interop-first, not a private file format |
| Network posture | Local-first. Bind defaults: WT/UDP + player web port on LAN; admin API on 127.0.0.1 unless explicitly opened, token-protected |
| Bonding | Parked ("maybe one day"). Lives in engine-land (dual-path publish) if ever |

### Decisions log (why it looks like this)

- **No supervisord, no child processes.** The engine links libav* directly;
  ingest/remux/record are threads in one process. Per-channel restart policy
  replaces process supervision; systemd wraps the single binary.
- **No Rust.** The serving plane (WT server, fan-out, SRT ingest, player,
  stats, hot reload, packaging) already exists here in C++. The deprecated
  Rust gateway is not a dependency of this product.
- **No ffmpeg subprocesses internally.** The patched-ffmpeg `quicsrt://`
  path stays what it is: external interop. Internally we *are* the ffmpeg.
- **Recorder = fan-out tap.** The broadcaster already fans out to browser
  sessions; recording is one more sink. Zero extra sessions, zero hops.
- **Recording is TAMS.** Segments land in an embedded, spec-shaped
  Time-addressable Media Store instead of a private pile of TS files:
  recordings become readable by any TAMS client (AWS reference store,
  Omakase, future MAMs), timeline addressing is standardized (NMOS UUIDs,
  nanosecond timeranges), and clips can eventually reference media
  instead of copying it.
- **M2 LAN failover is architectural, not a feature.** Player + stream are
  served from the same box the mixer feeds; WAN loss cannot interrupt it.

## 2. Architecture

```
┌─ QuicSRT app (single binary = gateway + engine + admin) ─────────────┐
│                                                                      │
│ serving plane [exists]           engine [new]                        │
│  WT server (lsquic) 4433/UDP      channel manager (state, license    │
│  fan-out ("broadcaster")            gate = enabled channel count)    │
│  SRT/UDP ingest 9000 [exists]    libav inputs: RTSP pull, RTMP       │
│  quicsrt:// publish ingest         listen, file/hold-slide           │
│  embedded wasm player [exists]   remux TS → in-process publish into   │
│  stats / webhooks [exists]         the existing broadcaster          │
│  toml config + hot reload        recorder sink: fan-out tap →        │
│  .deb packaging + CI [exists]      TAMS flow segments + retention    │
│                                                                      │
│ admin plane [new, extends existing HTTP ports]                       │
│  REST + WS admin API          SolidJS SPA embedded like the player   │
│  license verifier (Ed25519    landing page = the 4 models            │
│  via BoringSSL, already        workspaces per model                  │
│  in the tree)                 recordings browser                     │
│                                                                      │
│ supervision: threads + per-channel restart policy; systemd outside   │
└──────────────────────────────────────────────────────────────────────┘
```

Reuse anchors already in the tree:

- `broadcaster fanout` — engine inputs become just another publisher.
- toml config + **hot reload** — the admin API's "apply" writes config and
  triggers reload; mechanism exists.
- HTML stats → add a JSON/WS view of the same counters for the SPA.
- webhooks — the alerting primitive (channel down, uplink degraded, disk).
- `web/dist` embedding (player) — same mechanism embeds the admin SPA.
- SRT ingest (`srt://...?streamid=name`) — stock OBS 29+ publishes today
  with zero new code: the Venue/Field default ingest path is already done.

## 3. Engine specification

### 3.1 Channel manager

A **channel** = one configured feed, end to end:

```toml
[[channel]]
id        = "cam-1"
name      = "Loading dock"
models    = ["site"]            # tags; purely UI/defaults grouping
enabled   = true                # license counts enabled channels
stream    = "cam1"              # gateway stream name (subscriber URL ?stream=)
latency_ms = 120                # TSBPD handed to publisher/subscribers
input     = { type = "rtsp", url = "rtsp://admin:@192.168.1.42/stream1" }
#        | { type = "srt_listen", port = 9001 }        # exists today globally
#        | { type = "rtmp_listen", port = 1935 }
#        | { type = "file", path = "hold-slide.ts", loop = true }
record    = { enabled = true, retention_h = 336, seg_s = 600 }
```

Responsibilities: lifecycle (start/stop/restart with backoff — a hostile RTSP
stream may only kill its own channel, restart target < 1 s), license gate at
enable time, stats aggregation per channel, config persistence through the
existing toml + hot-reload path.

### 3.2 libav inputs (new code, the core engine work)

- Link `libavformat`/`libavcodec`/`libavutil` **dynamically** (LGPL hygiene
  for a distributed binary). Copy-only: demux → `AVCodecParameters` passthrough
  → MPEG-TS remux. **No transcoding in v1** (keeps us LGPL-clean and small).
- Inputs: RTSP pull (TCP interleaved first, UDP fallback; cameras are the
  hostile-input case — restart policy above), RTMP listen (libavformat
  `listen=1`), file loop (hold-slide / fallback media).
- Output: publish into the broadcaster in-process (same path the SRT ingest
  uses internally); reference implementation of the glue patterns:
  `examples/ffmpeg/0001-avformat-add-quicsrt-protocol.patch` in libquicsrt
  (quicsrtproto.c does exactly this dance for the ffmpeg CLI).
- Threading: per-channel demux thread feeds the publisher; no shared locks
  across channels beyond the broadcaster's own.

### 3.3 Recorder sink → TAMS store

Recording speaks TAMS (Time Addressable Media Store, BBC R&D open API,
Apache-2.0): media as immutable, time-addressed segments behind an open
REST interface. Everything recorded is written to an **embedded TAMS
store** served by the admin plane — recordings are readable by any TAMS
client, not just our UI.

Write path (recorder = fan-out tap):

- Channel start → create Source (muxed) + Flow (MPEG-TS; media timeline
  PTS → TAMS nanosecond flow timeline anchored at wall clock), UUIDs per
  NMOS IS-04 scheme; label/tags from channel config (Field session
  metadata rides here).
- Segments: GOP-aligned TS chunks (`seg_s`, default 600 s — complete
  decodable units per spec), registered on the timeline with `[start_end)`
  timeranges. Immutable once written.
- Index: per-flow JSONL manifest + in-memory timerange index — still no
  external database; SQLite only if scale ever demands it.
- Retention: the spec permits erasing timeline regions — hourly pruner
  erases/deletes beyond `retention_h`; disk budget (`max_gb`) wins if set.

Read path (embedded store on the admin HTTP plane, admin token,
default 127.0.0.1):

- `GET flows`, `GET flows/<id>/segments?timerange=…` per spec; objects
  served from `recordings/`. Segments readable the moment they're
  written → the recordings browser gets **live-tail** (review while
  recording) for free.
- Clip export v1: remux cut over the timerange (stream copy — the spec's
  own `object_timerange` recipe). Later: copy-on-write clips as new Flows
  referencing existing Media Objects — edit-by-reference, no essence copy.

## 4. Admin plane specification

### 4.1 HTTP API (extends the existing health/web ports)

```
GET    /api/models                    # 4 model descriptors + enabled state
GET    /api/channels                  GET one / POST / PATCH / DELETE
POST   /api/channels/{id}/start|stop  POST /api/config/apply (hot reload)
GET    /api/channels/{id}/stats       # per-channel SRT stats snapshot
WS     /api/ws                        # live stats + channel state events
GET    /api/flows                     # recordings = TAMS flows (§3.3)
GET    /api/flows/{id}/segments?timerange=   # embedded TAMS read side
GET    /api/recordings/clip?flow=&from=&to=  # export: remux cut (v1)
POST   /api/license                   # upload key; returns channels x/y
GET    /api/ptz/{channel}             POST /api/ptz/{channel}   (Site phase)
```

Auth: bearer token for admin (config-generated on first run, printed to
console + written to config); viewer tokens/PINs stay the player's existing
mechanism. Admin listens 127.0.0.1 by default; LAN opt-in is explicit.

### 4.2 SolidJS admin SPA

- Vite + SolidJS SPA, no SSR, built into `web/admin-dist` and embedded in the
  binary exactly like the player dist (fetch-at-setup or build-time; keep the
  existing CMake embedding pattern).
- **Landing page: the four models** — cards for Return Feeds, Venue, Site,
  Field, each showing its channels at a glance. All four always render in
  dev; per-deployment restriction comes later via the license model bitmask.
- Workspaces per model (§6). Shared components: player tile (embed the wasm
  player), latency setting, stats overlay, uplink traffic-light.
- Recordings browser talks to the embedded TAMS read API — timeline scrub
  via timerange queries, live-tail while recording.
- Talks only to its own origin; zero external requests (fonts bundled).

### 4.3 Licensing

- Key = Ed25519-signed payload `{product, licensee, channels, models,
  issued, expiry?}`. **Verifier in-app via BoringSSL (already linked)**;
  keygen is a private tool (tiny C++ util, lives outside this repo or in
  `scripts/keygen` marked internal-only).
- Enforcement: at channel enable and on config load — `enabled channels ≤
  licensed channels`, else channel refuses with a clear UI message.
  Unsigned/dev builds: unlimited with a visible "development" banner.
- Stance: honest-user licensing, no DRM rabbit hole, no phone-home.

## 5. Process & supervision model

- One process. Channels are threads with restart policies (backoff capped,
  e.g. 1s → 30s; storm protection: 5 restarts/minute → channel goes to
  `faulted`, UI shows the ffmpeg-style last error string).
- systemd unit (`quicsrt.service`): `Restart=on-failure`, watchdog optional
  later. Windows service wrapper: investigation item, §9.
- No supervisord anywhere. No child processes except optional future
  demux-helper isolation if a camera proves truly hostile (defer).

## 6. The four models (presets = defaults + workspace UI)

### M1 — Return Feeds *(ships first; smallest delta)*
Crew/director monitoring on venue Wi-Fi.
- Ingest: existing SRT listen + quicsrt:// push; RTSP pull (engine P1).
- Grid workspace: 1/4/9 layouts, labels, tally colors, solo, audio meters,
  per-feed latency, stats overlay toggle.
- Read-only crew links (viewer tokens, TTL).
- **Done when:** 4×3 Mbps feeds through 3% loss + 20 ms jitter (netem) hold
  glass-to-glass ≤ latency_ms + 100 ms with zero stalls > 250 ms; a killed
  channel restarts < 1 s without disturbing the others.

### M2 — Venue (worship / small venue)
- Ingest: mixer/encoder pushes SRT to the box (stock OBS works today).
- Player page + QR for overflow/nursery/lobby; PIN; audio-only mode.
- **LAN failover: free** (player + stream served locally) — document it,
  demo it, don't build it.
- Hold-slide: `file` input auto-promoted on program loss (engine input
  switch, backoff on return).
- Schedule: service times auto-start/stop recording.
- **Done when:** pulling the WAN cable mid-"service" changes nothing
  locally; program loss swaps to hold-slide < 2 s and back.

### M3 — Site (construction / monitoring)
- Cams: RTSP pull onboarding wizard (URL + creds, probe + preview).
- PTZ: minimal ONVIF client (SOAP over HTTP: ContinuousMove, Stop,
  GotoPreset, SetPreset) in the admin process; investigate a C++ lib vs
  hand-rolled thin client (surface is tiny; lean hand-rolled).
- Delivery: viewers reach the box by port-forward or tailscale — documented
  pattern; no relay service in this product (non-goal).
- Recordings browser: timeline scrub via TAMS timerange queries; event clips.
- **Done when:** PTZ control loop (command → see motion) ≤ 400 ms over LAN;
  4 cams × 2 Mbps × 14 d ring stays inside disk budget with margin.

### M4 — Field (contribution)
- "Go live": quick-start flow → OBS/laptop publishes SRT to the box over
  hotspot/tailscale; newsroom views via the grid workspace.
- Metadata per session (reporter, location, GPS pin) recorded as TAMS
  flow tags/label with the session; ISO record via the recorder sink.
- Resilience v1: session-level failover Wi-Fi↔LTE (auto-reconnect,
  1–3 s gap) — documented honestly. Bonding: parked.
- **Done when:** 5% loss on LTE keeps newsroom latency pinned at
  `latency_ms`; interface failover gap ≤ 3 s with automatic resume.

## 7. Packaging & distribution

- Extend the existing `.deb` CI + dev/stable release flow; the binary ships:
  itself + embedded player + embedded admin SPA. Nothing else to install.
- `gateway.conf`-style first run: bare start writes a fully commented
  `app.conf` including admin token and one example channel per model.
- LGPL: libav* dynamically linked (system packages or bundled .so, never
  static). Object-file offer per LGPL §6 if we ever bundle patched libav.
- Docker: later, as a wrapper around the same binary — explicitly not a
  foundation (decision log).

## 8. Milestones

| Phase | Deliverable | Definition of done |
|---|---|---|
| P0 | Foundations: channel manager skeleton, config schema, admin API CRUD + apply, SolidJS scaffold with 4-model landing, license skeleton (dev banner) | Landing page renders 4 models from /api/models; channel CRUD round-trips through hot reload |
| P1 | Engine: libav linkage, RTSP pull + file inputs publishing into the broadcaster, channel restart policy | RTSP cam → browser in < 5 min setup; kill -9 style demuxer failure recovers < 1 s |
| P2 | M1 complete: grid workspace, crew links, per-channel stats WS | M1 acceptance (§6) under netem |
| P3 | Recorder sink → embedded TAMS store (write+read paths, retention); M2: hold-slide, schedule, QR/PIN player polish | M2 acceptance incl. WAN-pull test; a third-party TAMS client reads our recordings |
| P4 | M3: cam wizard, ONVIF PTZ, recordings browser | M3 acceptance incl. PTZ loop budget |
| P5 | M4: quick-start, metadata, failover docs | M4 acceptance |
| P6 | Licensing hardening (keygen, enforcement UX), packaging polish, installer script, release | A clean machine installs via one command and runs a licensed 2-channel M1 box |

## 9. Risks & investigations

- **RTSP demuxer robustness** (hostile cams) — restart policy + faulted state
  first; optional demux-helper process isolation only if field reports
  demand it.
- **ONVIF in C++** — thin hand-rolled SOAP vs library; decide at P4 start.
- **Windows** — srt, lsquic, libav, BoringSSL all build on Windows; the work
  is build-system + service-wrapper plumbing. Decision point after P4; not a
  v1 promise. (Single binary keeps this door open.)
- **libav ABI churn** — pin builds against distro libav or a bundled,
  versioned .so set; never track master.
- **TAMS spec churn** — the API is versioned and still evolving; pin the
  embedded store to the major/minor we implement (track bbc/tams releases)
  and implement only the subset we exercise: flows, segments query,
  storage upload, object download.

## 10. Non-goals

Hosted control plane · relay/tunnel service · Docker (until asked) ·
bonding/multipath · transcoding · conferencing/talkback · ABR/CDN-scale
distribution · MoQ egress · DRM · phone-home anything.

## 11. Open decisions

1. Pricing numbers per tier (before P6; needs market check).
2. License `models` bitmask — gate per model or all-models-every-key?
3. Bundled libav vs distro libav for the .deb (bundles help odd distros;
   distro keeps CVE updates external).
4. Admin SPA update cadence — embedded at build (like the player) vs
   `web_root` override for fast iteration during P0–P2.
5. External TAMS/S3-compatible target for large installs (site-model
   30-day rings) — embedded-only v1, config option later.
6. Clip export v1: remux cut (stream copy) vs copy-on-write Flow
   referencing existing Media Objects (edit-by-reference).
