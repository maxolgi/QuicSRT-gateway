# QuicSRT-gateway

A single-binary live-streaming gateway. Publish a stream with the tools you
already have — OBS or any FFmpeg over SRT, or native WebTransport clients —
and watch it in a modern browser over HTTP/3 WebTransport. No plugins, no
separate web deployment: the browser player is embedded in the binary.

QuicSRT carries SRT's live-streaming semantics — TSBPD latency control,
retransmission, too-late-to-play drops — to browsers over WebTransport,
built on [libquicsrt](https://github.com/maxolgi/libquicsrt) and its
lsquic + srt forks, vendored as the `deps/libquicsrt` submodule.

## Features

- **The browser is a viewer** — WebTransport (HTTP/3, TLS) with the player
  page served by the gateway itself; self-signed certificates are pinned
  the way browsers pin them (SHA-256 of the certificate DER).
- **Publish with what you have** — OBS or any FFmpeg with `libsrt` on the
  SRT/UDP ingest; the browser's own publish page (screen/webcam capture);
  FFmpeg's `quicsrt://` protocol or C++/C clients via libquicsrt over
  WebTransport.
- **One publisher, many viewers** — broadcaster fan-out through a bounded
  per-stream ring: a slow viewer lags and drops, it never blocks the
  publisher.
- **Access control** — a stream allowlist with globs and per-stream
  tokens, per-stream viewer caps, per-IP and total session limits.
- **Operations built in** — JSON/HTML health and stats endpoints,
  session-lifecycle webhooks, SIGHUP hot reload, supervisord-ready
  packaging.

## How it works

    OBS / ffmpeg ──SRT/UDP──▶┌───────────────────┐──WebTransport──▶ browser player
    browser / C++ ──WT──────▶│  QuicSRT-gateway  │──WebTransport──▶ native clients

- Every stream has at most one publisher, first-wins: a second publisher
  of the same name is refused. Viewers may attach before any publisher
  exists (an idle waiting stream) and see a clean end-of-stream when the
  publisher stops.
- Media is MPEG-TS, framed as SRT live messages (6 × 188 B each). Each
  stream fans out through a bounded ring (`broadcast_capacity` messages /
  `broadcast_byte_budget` bytes): when a viewer falls behind, the OLDEST
  messages drop and the viewer counts the gap as lag — the publisher is
  never blocked.
- All QUIC engine work runs on a single event loop; the HTTP servers and
  the webhook dispatcher run on their own threads.

| Listener             | Default          | Serves                                    |
| -------------------- | ---------------- | ----------------------------------------- |
| WebTransport         | `127.0.0.1:4433` | browser + native client sessions (TLS)    |
| SRT ingest           | `127.0.0.1:9000` | OBS / ffmpeg publishers (UDP; they call in) |
| Player (HTTPS)       | `127.0.0.1:5173` | the embedded player page                  |
| Health / metrics     | off (`0`)        | plain-HTTP `/health` + `/stats`           |

## Build

    ./build.sh setup     # one-time: submodules (recursive), player dist fetch, BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libquicsrt + srt fork + lsquic)
    ./build.sh gateway   # build only the QuicSRT-gateway binary
    ./build.sh test      # run the test suites (ctest)
    ./build.sh web-dist  # refresh the embedded player, then re-configure

Requires gcc 13+, CMake 3.24+, ninja, nasm, curl + unzip, and Go +
zlib1g-dev (the BoringSSL build uses Go).

The player is **embedded in the binary** at compile time: `./build.sh setup`
fetches a `quicsrt-wasm-dist.zip` from
[QuicSRT-wasm releases](https://github.com/maxolgi/QuicSRT-wasm/releases)
into `web/dist` (gitignored) and CMake bakes it into the gateway, so the
deployed artifact is a lone binary with nothing else to ship. The release is
pinned (`WEB_DIST_TAG` in `build.sh`) for reproducible builds — set
`WEB_DIST_TAG=latest` to track the newest release. Configuring fails while
`web/dist` is missing; run `setup` first.

## Quickstart

1. **Generate a config.** A bare first run writes the fully commented
   example configuration to `./gateway.conf` (never when `--config` is
   given) and runs in open mode — every stream name accepted, with a loud
   warning. Open mode serves no player page and no SRT ingest, so for
   anything beyond a smoke test, edit the config and restart:

        ./build/release/QuicSRT-gateway            # writes ./gateway.conf, runs open mode
        # edit gateway.conf: set health_port = 9091 (the player's
        # web_port = 5173 is already on by default; all binds stay loopback)
        ./build/release/QuicSRT-gateway --config gateway.conf

2. **Publish.** Any FFmpeg with `libsrt` works — the stream name rides the
   `streamid` (OBS's custom SRT output works the same way):

        ffmpeg -re -f lavfi -i testsrc2=size=1280x720:rate=30 \
               -c:v libx264 -preset veryfast -f mpegts \
               "srt://127.0.0.1:9000?streamid=test&mode=caller&latency=120"

3. **Watch.** Open the player (accept the self-signed certificate once):

        https://127.0.0.1:5173/?stream=test

4. **Check health.**

        curl http://127.0.0.1:9091/health

To expose the gateway beyond loopback, change the `*_bind` addresses and
see the configuration notes below on cert modes and the allowlist.

## Configuration

Configuration is TOML, loaded with `--config`. The example file is the
reference — every key commented, every default shown: it is what a bare
first run writes (`./gateway.conf`), what sits at
`scripts/gateway.example.conf`, and what `cmake --install` drops at
`/usr/local/etc/QuicSRT-gateway/gateway.example.conf`. Unknown keys are
errors.

- **Open mode vs allowlist.** With no `[[stream]]` sections every stream
  name is accepted (open mode — dev/tests only, warned loudly at boot).
  With a config present, publishing and viewing are denied by default and
  each `[[stream]]` entry allows names: exact or glob (`*` any chars, `?`
  one char), first matching entry wins.
- **Per-entry flags.** `publish = false` makes a name viewer-only;
  `subscribe = false` makes it publish-only; `token = "…"` requires a
  constant-time token match. A token cannot ride an SRT `streamid`, so
  token-protected entries are for browser/native WT sessions only — SRT
  publishers are refused on them.
- **Cert modes.** `cert_mode = "self"` (default): a fresh ECDSA
  certificate every boot; browsers and native clients pin its hash via the
  gateway-served `cert-hash.js`. `cert_mode = "mkcert"` with `cert_pem` +
  `key_pem`: normal PKI validation (e.g. Let's Encrypt) — no pinning, and
  `cert-hash.js` advertises `null`.
- **Player over plain HTTP.** `web_tls = false` serves the same page over
  plain HTTP — the closed-network mode, for origins a browser already
  treats as secure (e.g. `http://127.0.0.1`, where WebTransport still
  works). WebTransport itself stays TLS regardless.
- **SRT passphrase.** `srt_passphrase` is accepted but not available in
  this build: the srt fork is compiled without built-in crypto
  (WebTransport's TLS provides it), so a non-empty value exits at startup
  with that reason. Keep the ingest on loopback or behind a firewall.

## Publishing

### SRT ingest — OBS, FFmpeg, anything that speaks SRT

The ingest is a stock libsrt listener; publishers connect as callers
(`mode=caller`) and the stream name rides the `streamid`:

    ffmpeg -re -f lavfi -i testsrc2=size=1280x720:rate=30 \
           -c:v libx264 -preset veryfast -f mpegts \
           "srt://127.0.0.1:9000?streamid=test&mode=caller&latency=120"

`latency` should match `[server].latency_ms` (default 120). The name must
match an allowlist entry with publishing allowed (in open mode, any name).

### Browser — the publish page

`https://<web-bind>:<web_port>/publish.html` is a full publisher UI: pick
screen or webcam capture, set the endpoint (`wt://host:port` shorthand)
and the stream name in the page, and it publishes over WebTransport —
through the same allowlist and first-wins occupancy as every other
publisher. `call.html` is the 1:1-call variant (camera/mic lobby with a
room name; `?host=`/`?port=` override the endpoint).

### WebTransport — FFmpeg `quicsrt://`, C++ / C clients

Native clients publish over the WT port via
[libquicsrt](https://github.com/maxolgi/libquicsrt). FFmpeg needs the
patched build (from a libquicsrt checkout:
`./build.sh setup && ./build.sh lib && ./build.sh install && ./build.sh ffmpeg`,
binary at `deps/ffmpeg/ffmpeg`). The same URL publishes as an output and
subscribes as an input:

    curl -k https://127.0.0.1:5173/cert-hash.js -o cert-hash.js
    ./deps/ffmpeg/ffmpeg -re -f lavfi -i testsrc2=size=1280x720:rate=30 \
           -c:v libx264 -preset veryfast -f mpegts \
           "quicsrt://127.0.0.1:4433?stream=test&cert_hash_file=cert-hash.js"

A self-signed gateway must be pinned: `cert_hash_file=` (the fetched
`cert-hash.js`) or `cert_hash=<64 hex>` — the hash is printed at boot
(`WebTransport cert DER SHA-256: …`) and changes every restart in self
mode, so re-fetch after a restart. Without a cert parameter the client
does normal PKI validation. The full URL grammar is in
`deps/libquicsrt/examples/ffmpeg/README.md`.

## Viewing

- **Player.** `https://<web-bind>:<web_port>/?stream=NAME`. In self cert
  mode accept the browser warning once; after a gateway restart the hash
  changed — reload the page. Behind a reverse proxy that terminates 443,
  the page still dials the gateway's WebTransport port (it reads the port
  from `cert-hash.js`), so that port must stay reachable.
- **Record a copy.** Same `quicsrt://` URL as an input:

        ffmpeg -f mpegts \
               -i "quicsrt://127.0.0.1:4433?stream=test&cert_hash_file=cert-hash.js" \
               -c copy out.ts

The embedded player ships several pages on the web port:

| Page                     | Purpose                                                       |
| ------------------------ | ------------------------------------------------------------- |
| `/` (index.html)         | the viewer — `?stream=NAME[&token=T][&latency=MS]`            |
| `/publish.html`          | browser publisher — screen/webcam capture, config in the page |
| `/call.html`             | 1:1 call — camera/mic lobby, room name, PiP self-view         |
| `/element.html`, `/videojs.html` | player-SDK demos                                       |

The player is also an embedding SDK — a `<quicsrt-video>` web component,
a video.js tech, and a programmatic handle; any of the pages can be
iframed as-is. See **[docs/embedding.md](docs/embedding.md)**.

## Monitoring

`health_port` serves plain HTTP on its own port: `/health` and `/stats`,
JSON by default.

- **`/health`** — a liveness/overview snapshot. `status` is `"ok"` once at
  least one publisher is live, `"no_source"` otherwise; alongside uptime,
  stream/viewer/session totals, a `per_stream` array (`name`, `alive`,
  `viewers`, `messages_sent`, `send_failures`), a `per_session` array
  (`stream`, `rtt_ms`, `viewer_lag`, `buffer_lag`, SRT counters), and a
  `ticker` object (event-loop tick count and avg/max duration — a rising
  `max_us` means loop stalls). Example:

        {
          "status": "ok", "uptime_ms": 61000,
          "streams": 1, "alive_streams": 1, "viewers": 2, "max_viewers": 16,
          "active_sessions": 3,
          "per_stream":  [ { "name": "test", "alive": true, "viewers": 2, ... } ],
          "per_session": [ { "session_id": 7, "stream": "test", "rtt_ms": 3, "viewer_lag": 0, ... } ],
          "ticker": { "count": 3050, "avg_us": 120, "max_us": 900 }
        }

- **`/stats`** — the operator view: everything in `/health` plus per-stream
  ring depth and drops (`ring_drops`, `oversize_drops` — messages dropped
  from the head of the ring to keep the publisher unblocked), per-session
  SRT sender/receiver counters, accept/reject and datagram counters
  (`server`), ingest admission counters (`ingest`), and webhook delivery
  counters (`webhooks`: `delivered`, `dropped`, `failed`).
- **HTML rendering** — the same `/stats` as a table page:

        curl -H "Accept: text/html" http://127.0.0.1:9091/stats

### Webhooks

An optional `[webhooks]` table posts session-lifecycle events as small
JSON bodies (`fire-and-forget`, one dedicated worker thread, bounded
queue, exactly one retry per event, drops counted in `/stats`):

    [webhooks]
    on_event_url = "http://127.0.0.1:9090/hook"
    timeout_ms = 2000          # per POST attempt

Events: `viewer_connect`, `viewer_disconnect`, `publisher_connect`,
`publisher_disconnect`, `publisher_end` — for WebTransport sessions and
SRT ingest publishers alike. Body shape:

    {"event":"viewer_connect","stream":"test","role":"viewer","remote":"127.0.0.1:52341","session_id":7,"timestamp_ms":1762990000123}

Plain `http://` receivers only. The URL and timeout are hot-reloadable.

## Running in production

    QuicSRT-gateway [--config FILE] [--log-level LEVEL] [--selftest]

- `--config FILE` — the TOML configuration. Without it the gateway runs in
  open mode (warned loudly); a bare first run also writes `./gateway.conf`.
- `--log-level LEVEL` — lsquic diagnostic logging on stderr (`emerg` …
  `debug`). The config key `log_level` does the same; the flag wins at
  boot.
- `--selftest` — internal smoke check (the ctest entry).

Signals: `SIGINT`/`SIGTERM` drain and exit; `SIGHUP` hot-reloads the config
(see below). The gateway logs to stderr — under supervisord that lands in
the program's `stderr_logfile`.

**Hot reload.** `kill -HUP` re-parses the config and atomically applies the
stream allowlist, `max_viewers`, `log_level`, and the `[webhooks]` URL and
timeout; everything else (binds, ports, cert, ring sizing, session caps,
timeouts) requires a restart and is logged as such per changed key. A
malformed file keeps the current config — the gateway stays healthy.
Without `--config`, SIGHUP is ignored.

**Install + supervisord.** `cmake --install build/release` (default prefix
`/usr/local`) installs the binary, the example config, and a supervisord
conf:

    sudo cp /usr/local/etc/supervisor/conf.d/QuicSRT-gateway.conf /etc/supervisor/conf.d/
    sudo mkdir -p /etc/QuicSRT-gateway /var/log/QuicSRT-gateway && sudo chown www-data:www-data /var/log/QuicSRT-gateway
    sudo cp /usr/local/etc/QuicSRT-gateway/gateway.example.conf /etc/QuicSRT-gateway/gateway.conf
    # edit /etc/QuicSRT-gateway/gateway.conf (binds, ports, cert mode; see the
    # example's production block)
    sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl restart QuicSRT-gateway

After a code change: rebuild and `sudo supervisorctl restart
QuicSRT-gateway` — a rebuild alone changes nothing until the restart.

## Testing

    ./build.sh test                 # all suites
    ctest --preset release -R name  # one suite
    ctest --preset tsan             # ThreadSanitizer build

The suites cover each subsystem (config, policy, WT server, ingest,
broadcaster, webhooks, reload, end-to-end) against in-process gateway
cores with ephemeral ports — no external services needed. A few libquicsrt
integration suites dial a live gateway by address; when none is running
they self-skip, and skips are green, not failures.

## License

[MPL-2.0](LICENSE).
