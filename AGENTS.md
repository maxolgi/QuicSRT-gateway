# AGENTS.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---
Never revove these guidelines, only edit below.
---

C++ implementation of the WebSRT **gateway**: CLI-parity replacement of the
Rust gateway, consuming `libwebsrt` as the `deps/libwebsrt` submodule.
Companion repos: `WebSRT` (Rust — the reference implementation and interop
oracle, **never modified from this repo**), `libwebsrt` (the client library
+ srt fork machinery — its own AGENTS.md governs work inside it), and
`maxolgi/srt` (fork of Haivision/srt, consumed transitively via libwebsrt's
`deps/srt` submodule).

**Status: planned skeleton.** Nothing is implemented yet — `src/main.cpp`
is the consumer gate over libwebsrt's exported targets. The phases and
gates live in `PLAN.md` (refinement with the human pending before P3
starts).

## Build commands

    ./build.sh setup     # one-time: submodule init (recursive), BoringSSL fetch+build, cmake configure
    ./build.sh lib       # build the tree (libwebsrt + srt fork + lsquic)
    ./build.sh gateway   # build the websrt-gateway binary
    ./build.sh test      # ctest (gateway selftest for now)

Raw form (what the script wraps — useful when debugging the script itself):

    git submodule update --init --recursive
    cmake --preset release && cmake --build --preset release
    ctest --preset release

Toolchain: gcc 13, CMake ≥ 3.24, C++20 for our code (submodules build with
their own settings), BoringSSL fetched into `deps/libwebsrt/deps/boringssl`
(gitignored there), nasm.

## Critical build order (two-level pins)

1. Gateway changes only (`src/`) → `./build.sh gateway`, no submodule work.
2. libwebsrt changes → work in `~/maxolgi/libwebsrt` (**never edit
   `deps/libwebsrt` in place** — it is a submodule checkout and git will
   clobber it). Commit there, human pushes, then bump this repo's pin:
   `git -C deps/libwebsrt fetch && git -C deps/libwebsrt checkout <commit>`
   followed by `./build.sh setup && ./build.sh gateway`, then commit the
   gitlink bump here. Submodule pins are the equivalent of Cargo.lock —
   new libwebsrt commits are NOT picked up automatically.
3. srt fork changes → two hops: work in `~/maxolgi/srt` per libwebsrt's
   fork discipline (commit, human pushes, libwebsrt bumps its `deps/srt`
   pin), THEN bump this repo's `deps/libwebsrt` pin as above.

**Agents commit, humans push.** A gitlink pin is only resolvable after the
human pushes the submodule's repo — bump + commit anyway; resolution
follows the push.

### Soft pin: deps/libwebsrt

`.gitmodules` points at `https://github.com/maxolgi/libwebsrt.git`, which
does not exist yet (aspirational until the human creates and pushes it —
the same soft-pin situation the srt fork had). Fresh clones therefore fail
at `git submodule update --init --recursive` until then. Workaround: fetch
from the sibling clone —

    git -C deps/libwebsrt fetch /home/flibb/maxolgi/libwebsrt && \
    git -C deps/libwebsrt checkout <commit>

This checkout's `.git/config` carries the local URL, so `./build.sh setup`
works here regardless. (libwebsrt's own `deps/srt` pin IS pushed — nested
fetches work from fresh clones of libwebsrt once libwebsrt itself resolves.)

## Consumer discipline

Use ONLY libwebsrt's exported interface targets:

- `websrt::websrt` — libwebsrt plus its internal headers (`src/`) and the
  srt fork's headers/link with the `SRT_ENABLE_VIRTUAL_TRANSPORT` gate
  (so `srt_attach_virtual_transport`, `SRTO_SKIP_INDUCTION` are callable).
- `websrt::srt-deps` — the forked-srt surface alone, for raw socket driving.
- `websrt::wt-deps` — the lsquic + BoringSSL + zlib chain, for hosting our
  own lsquic engine (the gateway is exactly such a consumer).

Never add raw `deps/libwebsrt/deps/...` include paths or link anything the
interface targets don't export. libwebsrt's `tests/consumer/` is the canary;
`src/main.cpp` here is the same contract at full scale.

## Workspace structure (planned; PLAN.md is authoritative)

- `src/main.cpp` — consumer gate (now) → gateway entry point (P3)
- `src/gateway/` — P3 layout: `gateway.cpp` `session.cpp` `registry.cpp`
  `stream_registry.cpp` `cert.cpp` `web_server.cpp` `ingest/srt_ingest.cpp`
- `scripts/` — `websrt-cpp.conf` (supervisord) at P3 step 5
- `deps/libwebsrt/` — the submodule (carries the srt fork, lsquic, and the
  BoringSSL fetch)

## Runtime (production, recovered conventions)

- Runs under supervisord: config `scripts/websrt-cpp.conf` → deployed like
  WebSRT's (`/etc/supervisor/conf.d/`).
- Logs: `/var/log/websrt-cpp/`.
- Restart after rebuild: `sudo supervisorctl restart websrt-cpp`
  (production only).
- On boot the gateway writes `cert-hash.js` next to the served web assets
  (hash for self-signed, null for mkcert). Runtime-generated — gitignored,
  never committed.

## Cert modes

- `--cert-mode self` (default): self-signed ECDSA, **regenerated on every
  boot — never persisted**. `--cert-mode mkcert`: loads PEMs.
- Cert hash changes on every restart — browser must reload the page.

## Gotchas

- lsquic engine is single-threaded: all engine calls (packet_in,
  process_conns, send_unsent_packets) happen on the event-loop thread;
  callbacks fire there too. Drive everything through `websrt::EventLoop`.
- The srt fork still spawns its internal threads in virtual mode — srt API
  calls are thread-safe, but socket setup/teardown belongs to the session
  code.
- `web/dist` (the player) is served as-is from the WebSRT checkout; it is
  Rust WASM + TS and is NEVER modified or rebuilt from this repo.
- MPL-2.0 (this repo and the srt fork patches).

## Testing

- `./build.sh test` — the gateway selftest (consumer gate) for now.
- P3 gates (PLAN.md): unmodified browser pages play from the C++ gateway;
  Rust `wt_hs_probe` / `mock_obs` pass against it; 50-viewer concurrency
  (ticker avg < 5 ms, zero viewer lag); parity matrix vs the Rust gateway.
- Golden acceptance commands (must always work against the running gateway,
  via the libwebsrt-patched ffmpeg):
  `ffmpeg -f lavfi -i testsrc2 … -f mpegts websrt://gw:443?stream=test` and
  `ffmpeg -f mpegts -i websrt://gw:443?stream=test -c copy out.ts`.

## Git workflow for agents

**Agents commit, humans push.**

- Commit work as you complete each logical unit; small, focused commits
  with clear messages matching `git log --oneline -10`.
- Never push. Never run `git push`, `gh pr create`, or any remote command.
- Before committing: inspect `git status` and `git diff`; stage only
  intended files. Never commit `cert-hash.js` or build outputs.
- Submodule pin bumps are their own commits (bump deps/libwebsrt → rebuild
  → commit the gitlink).
- Rebase is fine for your own commits; never force-push.

## Behavioral guidelines

Think before coding, keep changes surgical, define success criteria. Match
existing code style (`.clang-format`; clang-format + clang-tidy where
configured).

### 1. Think Before Coding

State assumptions explicitly. If uncertain, ask. If multiple interpretations
exist, present them - don't pick silently. If a simpler approach exists, say
so. Push back when warranted. If something is unclear, stop, ask.

### 2. Simplicity First

Minimum code that solves the problem. No speculative features, no
abstractions for single-use code, no unrequested configurability, no error
handling for impossible scenarios. If 200 lines could be 50, rewrite.

### 3. Surgical Changes

Touch only what you must. Don't improve adjacent code. Match existing
style. Remove only orphans your own changes created. Every changed line
should trace to the request.

### 4. Goal-Driven Execution

Transform tasks into verifiable goals and loop until verified. For
multi-step tasks, state a plan with per-step verification. Phases and gates
in `PLAN.md` are the success criteria — do not declare a phase done without
its gate green.

If you are not sure about something dont overthink and use internet search
