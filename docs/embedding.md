# Embedding the player

The embedded player shipped in the gateway binary is also an SDK: the same
wasm engine that powers the viewer page is available as embeddable pieces,
served from the gateway's web port:

- **`<quicsrt-video>`** — a chrome-free web component (`/bundle/element.js`,
  demo at `/element.html`): drop it in a page, it plays a QuicSRT source
  with the native `<video>` controls.
- **A video.js tech** registered as `quicsrt` (`/bundle/videojs.js`, demo at
  `/videojs.html`): the stock video.js skin and plugin ecosystem driving a
  QuicSRT source.
- **A programmatic player handle** underneath both (`mountPlayer`), exposed
  on the component as `.player` — stream switching, latency control,
  quality rungs, playback state.

## Requirements

- A browser with WebTransport + WebCodecs + WebAssembly (the tech's
  support check is exactly that): current Chromium-based browsers and
  recent Safari.
- **Cross-origin isolation.** The wasm engine uses pthreads
  (SharedArrayBuffer), so the embedding document must be COOP+COEP
  isolated. The gateway sends
  `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp` on every player response —
  both for the embedded dist and for a `web_root` override. If you serve
  the bundle yourself, you must send those headers yourself.
- **The certificate pin.** Pages load `/cert-hash.js`, which sets
  `window.CERT_HASH` (the SHA-256 of the gateway's certificate DER) and
  `window.WT_PORT`. In `cert_mode = "self"` the hash is pinned
  browser-style; in `cert_mode = "mkcert"` it is `null` and the player
  does normal PKI validation. A missing `cert-hash.js` is a hard error
  ("is the gateway running?"). The video.js tech also accepts an explicit
  `certHash` option that overrides the global.

## Source URLs

Everything takes the same source grammar:

    quicsrt://host:port[/stream][?token=T&latency=MS]
    https://host:port/wt?stream=NAME[&token=T]

The `quicsrt://` form resolves to the gateway's WebTransport endpoint
(`https://host:port/wt?stream=…`). The stream name defaults to `default`;
`token` must match the stream's allowlist entry; `latency` is the TSBPD
target in milliseconds.

## Quick embed: iframe

The zero-integration route — any of the gateway's pages can be iframed
from any site, and the page's own origin carries the isolation:

    <iframe src="https://gw.example.com:8443/?stream=test"
            allow="autoplay; fullscreen"
            style="width:100%;aspect-ratio:16/9;border:0"></iframe>

Page parameters (on the viewer and the demo pages):

| Param       | Meaning                                                     |
| ----------- | ----------------------------------------------------------- |
| `stream`    | stream name (the viewer requires it to be useful)           |
| `token`     | allowlist token for the stream                              |
| `latency`   | TSBPD target in ms                                          |
| `host`, `port` | WebTransport endpoint overrides (default: the page's host and `window.WT_PORT` from cert-hash.js) |
| `wt`        | a full source URL, passed through verbatim (demo pages)     |

## Same-origin pages via `web_root`

`[server].web_root` serves your own site from the gateway (instead of the
embedded dist), with the SDK bundles still available under `/bundle/` and
`/cert-hash.js` same-origin:

    <script src="/cert-hash.js"></script>
    <quicsrt-video controls autoplay style="max-width:960px"></quicsrt-video>
    <script type="module" src="/bundle/element.js"></script>

**Wiring caveat:** the served `/bundle/element.js` is also the
`/element.html` demo entry — on load it resolves the first
`<quicsrt-video>` on the page from the page's query string (`?wt=` for a
full source URL, else `?host=`/`?port=`/`?stream=`/`?token=`/`?latency=`),
overwriting a hardcoded `src` attribute. Drive same-origin embeds from the
URL — e.g. `mypage.html?wt=quicsrt://127.0.0.1:4433/test`. The same
applies to `/bundle/videojs.js`, which expects a `<video-js id="player">`
element and builds its own player. Bundle entries without the demo wiring
come from the [QuicSRT-wasm](https://github.com/maxolgi/QuicSRT-wasm)
tree.

## Self-hosting the bundle

For full control, serve the player dist (the same
`quicsrt-wasm-dist.zip` the gateway embeds) from your own origin, with
COOP+COEP headers on the document. Pin the gateway by loading its
`cert-hash.js` as a classic script (classic scripts are not CORS-gated):

    <script src="https://gw.example.com:8443/cert-hash.js"></script>

The WebTransport connection itself is made directly to the gateway's WT
port and is unaffected by your origin (the pin travels with the session).

## `<quicsrt-video>` reference

| Attribute    | Meaning                                                                     |
| ------------ | --------------------------------------------------------------------------- |
| `src`        | source URL (grammar above); changing it remounts a live pipeline             |
| `stream`     | stream name, applied when `src` is `quicsrt://host:port` with an empty path  |
| `token`      | allowlist token, applied to the `src` query                                 |
| `latency`    | TSBPD target in ms (live-adjustable)                                        |
| `muted`      | autoplay-safe default: an absent attribute starts muted; `muted="false"` opts out |
| `autoplay`   | start playing on connect                                                    |
| `controls`   | native `<video>` controls                                                   |
| `worker-url` | engine worker URL (the served entry defaults it to `/bundle/worker.js`)      |

- **Methods/properties:** `play()`, `pause()`, `paused`, `currentTime`,
  `duration`, `volume`, and `.player` — the mounted player handle (null
  before the first `play()`).
- **Events** (bridged from the handle): `loadstart`, `loadedmetadata`,
  `canplay`, `play`, `playing`, `pause`, `timeupdate`, `volumechange`,
  `durationchange`, `waiting`, `ended`, `resize`, `qualitychange`,
  `error` (with `event.detail.message`).
- **Host video:** a direct child `<video>` is adopted and left to your
  CSS; without one the component creates it (playsinline, responsive
  inline styles — no stylesheet dependency).
- A source-affecting attribute change (`src`, `stream`, `token`,
  `worker-url`) tears down and remounts a live pipeline — a playing
  element keeps playing the new source.

## video.js reference

The tech registers under the name `quicsrt` and claims the
`application/quicsrt` MIME type:

    videojs(el, {
      techOrder: ["quicsrt", "html5"],
      liveui: true,
      controls: true,
      muted: true,
      responsive: true,
      fluid: true,
      sources: [{ src: "quicsrt://gw.example.com:4433/test", type: "application/quicsrt" }],
      quicsrt: { workerUrl: "/bundle/worker.js" }
    });

Options under `quicsrt` (or flat on the player options): `workerUrl`,
`certHash`, `hwMode` (`"prefer-software"` / `"prefer-hardware"`),
`latencyMs`. A source change that only alters the stream name switches in
place over the live connection; anything else remounts.

## The player handle

Both wrappers expose the same handle (`.player` on the component; the
tech holds it internally): `play()`, `pause()`, `setStream(name)`,
`setLatencyMs(ms)`, `setMuted(bool)`, `volume`, `paused`, `ended`,
`currentTime`, `duration`, `buffered`, `seekable`, `readyState`,
`state` (`"connecting"`, `"reconnecting"`, …), the quality surface
(`setRungs`, `qualityLevels`), `destroy()`, and the events listed above.
