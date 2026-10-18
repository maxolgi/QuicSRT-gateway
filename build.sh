#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./build.sh <command>

Commands:
    setup      One-time: submodule init (recursive), player dist fetch, BoringSSL fetch+build, CMake configure (release)
    lib        Build the tree (libwebsrt + srt fork + lsquic)
    gateway    Build the websrt-gateway binary
    test       Run tests via ctest (release)
    web-dist   Fetch the player dist (pinned websrt-wasm-cpp release) into web/dist, then re-run cmake configure
EOF
}

# Pinned per lsquic's README.md and appveyor-linux.yml (tag 0.20250807.0 is
# the revision lsquic CI builds against). Same pin libwebsrt builds with.
BORINGSSL_COMMIT=e20e8486554098772673b55ea76bb003d0b330e5

# The player (web/dist) is EMBEDDED into the binary at compile time
# (rust-embed parity with the Rust gateway). The dist is never built here:
# it is fetched from a PINNED websrt-wasm-cpp release artifact — the
# C++/emscripten player (its ci publishes dev-<sha> tags off master, v*
# tags as stable cuts), engineered in the same zip shape. This replaces
# the Rust WebSRT dist deliberately: one source of truth for the player,
# matching what the deployed gateway serves via web_root. Bump the pin
# by hand; the tag resolution the Rust-era fetch needed is gone (a
# pinned /releases/download/ URL needs no API call and cannot 403).
# Divergence recorded in docs/parity.md ("Player serving").
WEB_DIST_URL=https://github.com/maxolgi/websrt-wasm-cpp/releases/download/dev-f26d29d/websrt-wasm-dist.zip

# Fetch the player dist into web/dist (gitignored). Requires curl + unzip.
fetch_web_dist() {
    command -v curl >/dev/null 2>&1 || { echo "build.sh: curl is required to fetch the player dist" >&2; exit 1; }
    command -v unzip >/dev/null 2>&1 || { echo "build.sh: unzip is required to unpack the player dist" >&2; exit 1; }
    local tag=${WEB_DIST_URL#*/download/}
    tag=${tag%%/*}
    local tmp
    tmp=$(mktemp -d)
    if ! curl -fsSL "${WEB_DIST_URL}" -o "${tmp}/dist.zip"; then
        rm -rf "${tmp}"
        echo "build.sh: cannot download the player dist from ${WEB_DIST_URL}" >&2
        exit 1
    fi
    rm -rf web/dist
    mkdir -p web/dist
    unzip -q "${tmp}/dist.zip" -d web/dist
    rm -rf "${tmp}"
    echo "build.sh: player dist ${tag} -> web/dist (embedded at compile time)"
}

# BoringSSL is fetched (not a submodule, gitignored by libwebsrt) into the
# libwebsrt checkout and built out-of-source; idempotent: no-op clone when
# the pin matches, fetch+checkout otherwise, incremental rebuild when
# already built.
setup_boringssl() {
    local bssl=deps/libwebsrt/deps/boringssl
    if [ ! -d "$bssl/.git" ]; then
        git clone https://github.com/google/boringssl.git "$bssl"
    fi
    if [ "$(git -C "$bssl" rev-parse HEAD)" != "$BORINGSSL_COMMIT" ]; then
        git -C "$bssl" fetch origin
        git -C "$bssl" checkout -f "$BORINGSSL_COMMIT"
    fi
    cmake -S "$bssl" -B "$bssl/build" \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
    cmake --build "$bssl/build" -j "$(nproc)"
}

case "${1:-}" in
    setup)
        # libwebsrt declares the srt fork and lsquic submodules; lsquic in
        # turn declares ls-qpack/ls-hpack, so --recursive. Local-path
        # submodule URLs (soft-pin workaround) need file transport allowed.
        git -c protocol.file.allow=always submodule update --init --recursive
        fetch_web_dist
        setup_boringssl
        cmake --preset release -DWEBSRT_ENABLE_WT=ON
        ;;
    lib)
        cmake --build --preset release
        ;;
    gateway)
        cmake --build --preset release --target websrt-gateway
        ;;
    test)
        # --parallel with no count = one job per core. Tests that share a
        # preferred port (4434/9100...) probe-bind and fall back to
        # ephemeral, so concurrent runs are safe by design.
        ctest --preset release --parallel
        ;;
    web-dist)
        # Refresh the embedded player: fetch + re-configure (the asset
        # table is generated at configure time), then rebuild via lib/gateway.
        fetch_web_dist
        cmake --preset release -DWEBSRT_ENABLE_WT=ON
        ;;
    -h | --help | help)
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
