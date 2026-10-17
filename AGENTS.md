# AGENTS.md

Repo-specific guidance. (Behavioral guidelines live in `~/maxolgi/AGENTS.md`.)

C++ CLI-parity replacement of the Rust [WebSRT](https://github.com/maxolgi/WebSRT)
gateway, consumed via the `deps/libwebsrt` submodule strictly through its
exported interface targets. Behavioral parity vs the Rust oracle is tracked
row-by-row in `docs/parity.md` — a deliberate behavior change or divergence
needs a row there. Companion repos (siblings in `~/maxolgi/WebSRT-cpp/`):
`libwebsrt` (client library + srt fork), `srt` (the fork's working clone),
`WebSRT` (Rust reference — **never modified from this repo**).

## Build

    ./build.sh setup     # one-time: submodules --recursive, player dist fetch, BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libwebsrt + srt fork + lsquic)
    ./build.sh gateway   # build only the websrt-gateway binary
    ./build.sh test      # ctest --preset release --parallel
    ./build.sh web-dist  # refresh the embedded player (latest WebSRT release) + re-configure

Toolchain: gcc 13+, CMake ≥ 3.24, ninja, nasm, curl + unzip, **Go + zlib1g-dev**
(BoringSSL build needs Go — README omits it; CI installs it). `WEBSRT_ENABLE_WT=ON`
is mandatory (configure fatals otherwise; `build.sh setup` passes it).

Configure fatals if `web/dist/` is missing — it is fetched (gitignored), never
committed, and the player asset table is generated at **configure** time:
refreshing `web/dist` requires a re-configure (`build.sh web-dist` does both).

## Submodule pin discipline (two levels)

1. Gateway changes only (`src/`, `tests/`) → `./build.sh gateway`, no submodule work.
2. libwebsrt changes → work in `~/maxolgi/WebSRT-cpp/libwebsrt`, **never edit
   `deps/libwebsrt` in place** (git clobbers submodule checkouts). Commit there,
   human pushes, then bump this repo's gitlink and rebuild. Pins track
   libwebsrt master head; bump routinely, as their own commit:
   `Bump deps/libwebsrt to <short-sha> (reason)` — see `git log` for examples.
3. srt fork changes → two hops: `~/maxolgi/WebSRT-cpp/srt` per libwebsrt's fork
   discipline, then libwebsrt bumps its `deps/srt` pin, then step 2.

A gitlink is only resolvable after the human pushes the submodule — bump and
commit anyway; resolution follows the push.

## Consumer discipline

Link only libwebsrt's exported interface targets — `websrt::websrt`,
`websrt::srt-deps`, `websrt::wt-deps` (the last also propagates
`LSQUIC_WEBTRANSPORT_SERVER_SUPPORT`). Never add raw `deps/libwebsrt/deps/...`
include paths or link anything the targets don't export.

## Layout

- `src/main.cpp` — CLI entry (config wiring, SIGHUP); `src/gateway/` — the
  embeddable core (`websrtgw` lib: wt_server, srt_initiator, registries,
  broadcaster, policy, webhooks, cert, web_server, ingest/); `config.cpp` +
  `reload.cpp` live in `websrtgw_config` (TOML stays out of the core lib).
- `scripts/` — `gateway.example.conf` (embedded into the binary), supervisord conf.
- `tests/` — one plain-check test per area; wired in `CMakeLists.txt`.
- `build/release/embedded_*.cpp` — CMake-generated; never edit.

## Testing

    ctest --preset release -R <name>          # single test (binaries in build/release/)
    ctest --preset tsan                       # TSan build; cmake/tsan.supp suppressions

- The 4 live-oracle tests from libwebsrt (`wt_echo`, `subscriber_test`,
  `publisher_test`, `c_api_test`) self-skip (SKIP_RETURN_CODE 77) without the
  Rust gateway running locally — skips are green, not failures.
- Tests probe-bind preferred ports (4434/9100…) with ephemeral fallback, so
  `--parallel` is safe; `concurrency_test` is RUN_SERIAL (CPU-tight, fails
  under core contention).
- The tsan preset excludes `srt_initiator_test` (TSan slowdown alone blows its
  10 s internal deadline).
- Golden acceptance commands against a running gateway (via the
  libwebsrt-patched ffmpeg, `~/maxolgi/WebSRT-cpp/libwebsrt/deps/ffmpeg/ffmpeg`):
  `ffmpeg -f lavfi -i testsrc2 … -f mpegts websrt://gw:443?stream=test` and
  `ffmpeg -f mpegts -i websrt://gw:443?stream=test -c copy out.ts`.

## Formatting / lint

- clang-format **19** (CI pins `clang-format==19.1.7` via pip; 18 formats some
  constructs differently and will fail CI). Checked on `src tests` only —
  never `deps/`: `find src tests -name '*.cpp' -o -name '*.h' | xargs clang-format --dry-run --Werror`
- clang-tidy config exists but is deliberately NOT in CI (needs
  compile_commands.json from the full configure); don't gate on it.

## Gotchas

- lsquic engine is single-threaded: all engine calls and callbacks happen on
  the event-loop thread — drive everything through `websrt::EventLoop`; timer
  arming and log-level changes must ride the loop thread too (see reload.cpp).
- The srt fork spawns internal threads in virtual mode; srt API calls are
  thread-safe, but socket setup/teardown belongs to session code.
- `cert-hash.js` is runtime-generated (never committed); in self cert mode the
  cert regenerates every boot, so the browser pin changes on restart.
- A bare first run writes `./gateway.conf` (the embedded example); never when
  `--config` is given.
- Never commit: `cert-hash.js`, `web/dist/`, `build/`, submodule checkouts' contents.
- MPL-2.0 (this repo and the srt fork patches).
