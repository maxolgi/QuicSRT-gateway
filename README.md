# websrt-gateway-cpp

CLI-parity C++ replacement of the Rust
[WebSRT](https://github.com/maxolgi/WebSRT) gateway: an lsquic
WebTransport server bridging browser WT datagram sessions to per-session SRT
(skip-induction) plus stock-mode SRT/UDP ingest, with broadcaster fanout,
cert modes, and runtime `cert-hash.js` emission. Built on
[libwebsrt](https://github.com/maxolgi/libwebsrt), consumed as the
`deps/libwebsrt` submodule strictly through its exported interface targets.

**Status:** feature-complete through P4 (hot reload, HTML stats, webhooks,
packaging). The phase/gate log lives in [PLAN.md](PLAN.md); behavioral
parity vs the Rust gateway is measured row-by-row in
[docs/parity.md](docs/parity.md).

## Build

    ./build.sh setup     # one-time: submodule init (recursive), BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libwebsrt + srt fork + lsquic)
    ./build.sh gateway   # build the websrt-gateway binary
    ./build.sh test      # run tests (live-oracle tests self-skip without the Rust gateway)

Requires gcc 13+, CMake 3.24+, ninja, nasm.

Fresh clones fail at `deps/libwebsrt` until the GitHub repo exists — see
AGENTS.md ("Soft pin") for the sibling-clone workaround.

## Quickstart

1. **Config.** Copy the example, point `web_root` at a built player
   (`web/dist` from the WebSRT checkout — this repo never builds it) and
   turn on the health endpoint:

       cp scripts/gateway.example.conf gw.conf
       # edit gw.conf: set web_root = "<path>/WebSRT/web/dist",
       #               set health_port = 9091

2. **Run.**

       build/release/websrt-gateway --config gw.conf

3. **Publish.** Via WebTransport (`websrt://`, needs the libwebsrt-patched
   ffmpeg — `deps/ffmpeg/ffmpeg` in a libwebsrt checkout; the golden
   commands from PLAN.md's Testing section, host adapted):

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

Production setup mirrors the Rust gateway's pattern:

    sudo cp /usr/local/etc/supervisor/conf.d/websrt-cpp.conf /etc/supervisor/conf.d/
    sudo mkdir -p /etc/websrt-cpp /var/log/websrt-cpp && sudo chown www-data:www-data /var/log/websrt-cpp
    sudo cp /usr/local/etc/websrt-cpp/gateway.example.conf /etc/websrt-cpp/gateway.conf
    # edit /etc/websrt-cpp/gateway.conf (web_root, binds, cert mode; see the
    # example's production block)
    sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl restart websrt-cpp

After a rebuild or a config edit: `sudo supervisorctl restart websrt-cpp`;
a config edit alone can also be applied live with
`sudo kill -HUP $(pidof websrt-gateway)` (hot-reloadable settings only —
see PLAN.md P4.1).
