#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./build.sh <command>

Commands:
    setup      One-time: submodule init (recursive), BoringSSL fetch+build, CMake configure (release)
    lib        Build the tree (libwebsrt + srt fork + lsquic)
    gateway    Build the websrt-gateway binary
    test       Run tests via ctest (release)
EOF
}

# Pinned per lsquic's README.md and appveyor-linux.yml (tag 0.20250807.0 is
# the revision lsquic CI builds against). Same pin libwebsrt builds with.
BORINGSSL_COMMIT=e20e8486554098772673b55ea76bb003d0b330e5

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
        ctest --preset release
        ;;
    -h | --help | help)
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
