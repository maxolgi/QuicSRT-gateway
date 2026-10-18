# AGENTS.md

Repo-specific guidance. (Behavioral guidelines live in `~/maxolgi/AGENTS.md`.)

QuicSRT-gateway: a C++ WebTransport-to-SRT bridging gateway, consumed via
the `deps/libquicsrt` submodule strictly through its exported interface
targets. Companion repos (siblings under the WebSRT-cpp workspace root):
`libquicsrt` (client library + srt fork), `srt` (the fork's working clone).

## Build

    ./build.sh setup     # one-time: submodules --recursive, player dist fetch, BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libquicsrt + srt fork + lsquic)
    ./build.sh gateway   # build only the QuicSRT-gateway binary
    ./build.sh test      # ctest --preset release --parallel
    ./build.sh web-dist  # refresh the embedded player (latest websrt-wasm-cpp release) + re-configure

Toolchain: gcc 13+, CMake ≥ 3.24, ninja, nasm, curl + unzip, **Go + zlib1g-dev**
(BoringSSL build needs Go — README omits it; CI installs it). `QUICSRT_ENABLE_WT=ON`
is mandatory (configure fatals otherwise; `build.sh setup` passes it).

Configure fatals if `web/dist/` is missing — it is fetched (gitignored), never
committed, and the player asset table is generated at **configure** time:
refreshing `web/dist` requires a re-configure (`build.sh web-dist` does both).

## Submodule pin discipline (two levels)

1. Gateway changes only (`src/`, `tests/`) → `./build.sh gateway`, no submodule work.
2. libquicsrt changes → work in the sibling `../libquicsrt` checkout, **never edit
   `deps/libquicsrt` in place** (git clobbers submodule checkouts). Commit there,
   human pushes, then bump this repo's gitlink and rebuild. Pins track
   libquicsrt master head; bump routinely, as their own commit:
   `Bump deps/libquicsrt to <short-sha> (reason)` — see `git log` for examples.
3. srt fork changes → two hops: the sibling `../srt` checkout per libquicsrt's fork
   discipline, then libquicsrt bumps its `deps/srt` pin, then step 2.

A gitlink is only resolvable after the human pushes the submodule — bump and
commit anyway; resolution follows the push.

## Consumer discipline

Link only libquicsrt's exported interface targets — `quicsrt::quicsrt`,
`quicsrt::srt-deps`, `quicsrt::wt-deps` (the last also propagates
`LSQUIC_WEBTRANSPORT_SERVER_SUPPORT`). Never add raw `deps/libquicsrt/deps/...`
include paths or link anything the targets don't export.

## Layout

- `src/main.cpp` — CLI entry (config wiring, SIGHUP); `src/gateway/` — the
  embeddable core (`QuicSRTgw` lib: wt_server, srt_initiator, registries,
  broadcaster, policy, webhooks, cert, web_server, ingest/); `config.cpp` +
  `reload.cpp` live in `QuicSRTgw_config` (TOML stays out of the core lib).
- `scripts/` — `gateway.example.conf` (embedded into the binary), supervisord conf.
- `tests/` — one plain-check test per area; wired in `CMakeLists.txt`.
- `build/release/embedded_*.cpp` — CMake-generated; never edit.

## Testing

    ctest --preset release -R <name>          # single test (binaries in build/release/)
    ctest --preset tsan                       # TSan build; cmake/tsan.supp suppressions

- The 4 libquicsrt tests that probe a live Rust gateway (`wt_echo`,
  `subscriber_test`, `publisher_test`, `c_api_test`) self-skip
  (SKIP_RETURN_CODE 77) when none is running — skips are green, not failures.
- Tests probe-bind preferred ports (4434/9100…) with ephemeral fallback, so
  `--parallel` is safe; `concurrency_test` is RUN_SERIAL (CPU-tight, fails
  under core contention).
- The tsan preset excludes `srt_initiator_test` (TSan slowdown alone blows its
  10 s internal deadline).
- Golden acceptance commands against the supervised gateway (via the
  libquicsrt-patched ffmpeg, `../libquicsrt/deps/ffmpeg/ffmpeg`; the
  self-signed gateway needs a pin — fetch `cert-hash.js` from the web port
  and pass `cert_hash_file=`, see `../libquicsrt/examples/ffmpeg/README.md`):
  `ffmpeg -f lavfi -i testsrc2 … -f mpegts quicsrt://gw:4435?stream=test` and
  `ffmpeg -f mpegts -i quicsrt://gw:4435?stream=test&cert_hash_file=… -c copy out.ts`.

## Live gateway (supervisord)

The host's gateway runs under supervisord — program `QuicSRT-gateway`, straight
from this repo's build tree, open mode (every stream name accepted) —
alongside the always-on publisher `QuicSRT-gateway-testpub` (stream
`browsertest`). All live testing (golden commands, parity measurements,
`/health` and `/stats` curls, the player page) goes through these services;
never launch ad-hoc `QuicSRT-gateway` processes (bare runs, `/tmp` dev
configs).

- Ports as deployed: WT `0.0.0.0:4435`, SRT ingest `0.0.0.0:9102`, player
  (HTTPS) `0.0.0.0:8443` — e.g. `https://127.0.0.1:8443/?stream=browsertest`
  — health (plain HTTP, loopback) `127.0.0.1:9292` — e.g.
  `curl http://127.0.0.1:9292/health`.
- Logs: `/var/log/QuicSRT-gateway/` — `gateway.err.log` is the gateway's main
  output (level `notice`), `testpub.err.log` the publisher's.
- Deploy a code change: `./build.sh gateway && sudo supervisorctl restart
  QuicSRT-gateway` (a rebuild alone does nothing until the restart; agents may
  restart freely). Config edit touching hot-reloadable keys only:
  `sudo kill -HUP $(pidof QuicSRT-gateway)`.
- Test stream: `sudo supervisorctl restart QuicSRT-gateway-testpub` — never run
  the publisher script by hand.
- ctest suites are the exception: they run in-process gateway cores with
  ephemeral-port fallback and never touch the supervised services.

## Formatting / lint

- clang-format **19** (CI pins `clang-format==19.1.7` via pip; 18 formats some
  constructs differently and will fail CI). Checked on `src tests` only —
  never `deps/`: `find src tests -name '*.cpp' -o -name '*.h' | xargs clang-format --dry-run --Werror`
- clang-tidy config exists but is deliberately NOT in CI (needs
  compile_commands.json from the full configure); don't gate on it.

## Gotchas

- lsquic engine is single-threaded: all engine calls and callbacks happen on
  the event-loop thread — drive everything through `quicsrt::EventLoop`; timer
  arming and log-level changes must ride the loop thread too (see reload.cpp).
- The srt fork spawns internal threads in virtual mode; srt API calls are
  thread-safe, but socket setup/teardown belongs to session code.
- `cert-hash.js` is runtime-generated (never committed); in self cert mode the
  cert regenerates every boot, so the browser pin changes on restart.
- A bare first run writes `./gateway.conf` (the embedded example); never when
  `--config` is given. Binary behavior — on this host never bare-run; test
  against the supervised gateway (see "Live gateway").
- Never commit: `cert-hash.js`, `web/dist/`, `build/`, submodule checkouts' contents.
- MPL-2.0 (this repo and the srt fork patches).
