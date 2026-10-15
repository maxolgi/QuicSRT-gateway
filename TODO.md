# TODO

Open carry-overs for websrt-gateway-cpp. Moved out of PLAN.md at P4
close-out so the plan stays the phase/gate record and this file is the
single source of truth for open items. (The submodule tracks its own items
in `deps/libwebsrt/websrt-todo.md` — never edit it from this repo.)

- **libwebsrt `Publisher::End()` drain budget** — consumes its full 30 s
  ACK-drain budget under 50-viewer fanout (client-side; EOF is clean
  everywhere — consider tuning the drain budget in libwebsrt).
- **Sim-loss P1 residual** — lives in libwebsrt's todo (needs a
  `--sim-loss` Rust gateway rebuild to verify).
- **VAAPI decode workaround** — VAAPI machines need the player's "Prefer
  Software" decode (documented in libwebsrt's todo).
