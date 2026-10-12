# websrt-gateway-cpp

CLI-parity C++ replacement of the Rust
[WebSRT](https://github.com/maxolgi/WebSRT) gateway: an lsquic
WebTransport server bridging browser WT datagram sessions to per-session SRT
(skip-induction) plus stock-mode SRT/UDP ingest, with broadcaster fanout,
cert modes, and runtime `cert-hash.js` emission. Built on
[libwebsrt](https://github.com/maxolgi/libwebsrt), consumed as the
`deps/libwebsrt` submodule strictly through its exported interface targets.

**Status: planned — skeleton.** Nothing is implemented yet; `src/main.cpp`
is the consumer gate over libwebsrt's exports. The phases and gates live in
[PLAN.md](PLAN.md) (refinement pending before implementation starts).

## Build

    ./build.sh setup     # one-time: submodule init (recursive), BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libwebsrt + srt fork + lsquic)
    ./build.sh gateway   # build the websrt-gateway binary
    ./build.sh test      # run tests (gateway selftest for now)

Requires gcc 13+, CMake 3.24+, ninja, nasm.

Fresh clones fail at `deps/libwebsrt` until the GitHub repo exists — see
AGENTS.md ("Soft pin") for the sibling-clone workaround.
