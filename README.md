# websrt-gateway-cpp

CLI-parity C++ replacement of the Rust
[WebSRT](https://github.com/maxolgi/WebSRT) gateway: an lsquic
WebTransport server bridging browser WT datagram sessions to per-session SRT
(skip-induction) plus stock-mode SRT/UDP ingest, with broadcaster fanout,
cert modes, and runtime `cert-hash.js` emission. Built on
[libwebsrt](https://github.com/maxolgi/libwebsrt), consumed as the
`deps/libwebsrt` submodule strictly through its exported interface targets.

**Status:** feature-complete through P4 (hot reload, HTML stats, webhooks,
packaging). Behavioral parity vs the Rust gateway is measured row-by-row
in [docs/parity.md](docs/parity.md); the phase/gate record is the git
history (the P3/P4 gate commits) — PLAN.md was retired once every phase
and gate had closed.

## Build

    ./build.sh setup     # one-time: submodule init (recursive), player dist fetch (websrt-wasm-cpp release), BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libwebsrt + srt fork + lsquic)
    ./build.sh gateway   # build the websrt-gateway binary
    ./build.sh test      # run tests (live-oracle tests self-skip without the Rust gateway)
    ./build.sh web-dist  # refresh the embedded player (pinned websrt-wasm-cpp release), then re-configure

Requires gcc 13+, CMake 3.24+, ninja, nasm, curl + unzip.

The player (the browser web app) is **embedded in the binary** at compile
time, exactly like the Rust gateway's rust-embed: `./build.sh setup`
fetches a pinned `websrt-wasm-dist.zip` from
[websrt-wasm-cpp releases](https://github.com/maxolgi/websrt-wasm-cpp/releases)
into `web/dist` (gitignored), and CMake bakes it into the gateway. The
dist is the C++/emscripten player — the same artifact the deployed
gateway serves via `web_root`; bump the pin in `build.sh` to pick up a
newer player.

## Quickstart

1. **Config.** Just run the binary once bare — the first run writes a
   fully commented example configuration as `./gateway.conf` (never when
   `--config` is given). Edit it and enable the endpoints (the player is
   already inside the binary — no `web_root` needed):

        ./websrt-gateway                 # writes ./gateway.conf, runs in open mode
        # edit gateway.conf: set health_port = 9091, web_port = 5173
        ./websrt-gateway --config gateway.conf

2. **Run.**

       build/release/websrt-gateway --config gw.conf

3. **Publish.** Via WebTransport (`websrt://`, needs the libwebsrt-patched
   ffmpeg — `deps/ffmpeg/ffmpeg` in a libwebsrt checkout; the golden
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

- `/usr/local/bin/websrt-gateway` — the binary (`scripts/websrt-cpp.conf`'s
  `command=` expects exactly this path)
- `/usr/local/etc/websrt-cpp/gateway.example.conf` — the example config
- `/usr/local/etc/supervisor/conf.d/websrt-cpp.conf` — the supervisord conf

Production setup mirrors the Rust gateway's pattern (no player directory
to deploy — it is embedded in the binary):

    sudo cp /usr/local/etc/supervisor/conf.d/websrt-cpp.conf /etc/supervisor/conf.d/
    sudo mkdir -p /etc/websrt-cpp /var/log/websrt-cpp && sudo chown www-data:www-data /var/log/websrt-cpp
    sudo cp /usr/local/etc/websrt-cpp/gateway.example.conf /etc/websrt-cpp/gateway.conf
    # edit /etc/websrt-cpp/gateway.conf (binds, ports, cert mode; see the
    # example's production block)
    sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl restart websrt-cpp

After a rebuild or a config edit: `sudo supervisorctl restart websrt-cpp`;
a config edit alone can also be applied live with
`sudo kill -HUP $(pidof websrt-gateway)` (hot-reloadable settings only:
the stream allowlist, viewer cap, log level, webhook settings — the rest
is restart-required and logged as such).
