# QuicSRT-gateway

An lsquic
WebTransport server bridging browser WT datagram sessions to per-session SRT
(skip-induction) plus stock-mode SRT/UDP ingest, with broadcaster fanout,
cert modes, and runtime `cert-hash.js` emission. Built on
[libquicsrt](https://github.com/maxolgi/libquicsrt), consumed as the
`deps/libquicsrt` submodule strictly through its exported interface targets.

**Status:** feature-complete through P4 (hot reload, HTML stats, webhooks,
packaging).

## Build

    ./build.sh setup     # one-time: submodule init (recursive), player dist fetch (websrt-wasm-cpp release), BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libquicsrt + srt fork + lsquic)
    ./build.sh gateway   # build the QuicSRT-gateway binary
    ./build.sh test      # run tests (the 4 Rust-gateway probes from libquicsrt self-skip)
    ./build.sh web-dist  # refresh the embedded player (latest websrt-wasm-cpp release), then re-configure

Requires gcc 13+, CMake 3.24+, ninja, nasm, curl + unzip.

The player (the browser web app) is **embedded in the binary** at compile
time: `./build.sh setup`
fetches the latest `websrt-wasm-dist.zip` from
[websrt-wasm-cpp releases](https://github.com/maxolgi/websrt-wasm-cpp/releases)
into `web/dist` (gitignored), and CMake bakes it into the gateway. The
dist is the C++/emscripten player — the same artifact the deployed
gateway serves via `web_root`; re-running setup (or web-dist) picks up
newer releases.

## Quickstart

1. **Config.** Just run the binary once bare — the first run writes a
   fully commented example configuration as `./gateway.conf` (never when
   `--config` is given). Edit it and enable the endpoints (the player is
   already inside the binary — no `web_root` needed):

        ./QuicSRT-gateway                 # writes ./gateway.conf, runs in open mode
        # edit gateway.conf: set health_port = 9091, web_port = 5173
        ./QuicSRT-gateway --config gateway.conf

2. **Run.**

       build/release/QuicSRT-gateway --config gw.conf

3. **Publish.** Via WebTransport (`websrt://`, needs the libquicsrt-patched
   ffmpeg — `deps/ffmpeg/ffmpeg` in a libquicsrt checkout; the golden
   acceptance commands, host adapted):

       ffmpeg -f lavfi -i testsrc2=size=1280x720:rate=30 -f lavfi -i sine=frequency=440 \
              -c:v libx264 -preset veryfast -c:a aac -f mpegts websrt://127.0.0.1:4433?stream=test

   or via plain SRT ingest (`srt://`, any ffmpeg with libsrt — same
   command the example config documents):

       ffmpeg -re -f lavfi -i testsrc2=size=1280x720:rate=30 \
              -c:v libx264 -preset veryfast -f mpegts \
              "srt://127.0.0.1:9000?streamid=test&mode=caller&latency=120"

4. **Watch.** The player page (accept the self-signed cert once; in self
   mode the hash changes every boot, so reload after a restart):

       https://127.0.0.1:5173/?stream=test

   or record a copy (golden viewer command):

       ffmpeg -f mpegts -i websrt://127.0.0.1:4433?stream=test -c copy out.ts

5. **Health check.**

       curl http://127.0.0.1:9091/health    # JSON (also /stats)
       curl -H "Accept: text/html" http://127.0.0.1:9091/stats   # HTML rendering

## Deployment

`cmake --install build/release` (default prefix `/usr/local`) installs:

- `/usr/local/bin/QuicSRT-gateway` — the binary (`scripts/QuicSRT-gateway.conf`'s
  `command=` expects exactly this path)
- `/usr/local/etc/QuicSRT-gateway/gateway.example.conf` — the example config
- `/usr/local/etc/supervisor/conf.d/QuicSRT-gateway.conf` — the supervisord conf

Production setup (no player directory
to deploy — it is embedded in the binary):

    sudo cp /usr/local/etc/supervisor/conf.d/QuicSRT-gateway.conf /etc/supervisor/conf.d/
    sudo mkdir -p /etc/QuicSRT-gateway /var/log/QuicSRT-gateway && sudo chown www-data:www-data /var/log/QuicSRT-gateway
    sudo cp /usr/local/etc/QuicSRT-gateway/gateway.example.conf /etc/QuicSRT-gateway/gateway.conf
    # edit /etc/QuicSRT-gateway/gateway.conf (binds, ports, cert mode; see the
    # example's production block)
    sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl restart QuicSRT-gateway

After a rebuild or a config edit: `sudo supervisorctl restart QuicSRT-gateway`;
a config edit alone can also be applied live with
`sudo kill -HUP $(pidof QuicSRT-gateway)` (hot-reloadable settings only:
the stream allowlist, viewer cap, log level, webhook settings — the rest
is restart-required and logged as such).
