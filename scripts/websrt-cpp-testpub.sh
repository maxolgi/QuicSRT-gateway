#!/usr/bin/env bash
# Always-on websrt:// test publisher for the C++ gateway (the
# WebTransport publish path, not the SRT ingest). Deployed as the
# supervisord program websrt-cpp-testpub (see websrt-cpp-testpub.conf)
# with command= pointing HERE, the same convention websrt.conf uses for
# the Rust gateway binary - run from the checkout, never installed.
#
# Fetches the gateway's live cert-hash.js first: self mode regenerates
# the cert every boot, so the pin must be refreshed each start; a fetch
# failure exits 1 and supervisor retries.
set -euo pipefail

GATEWAY=${GATEWAY:-https://127.0.0.1:8443}   # the C++ gateway's web port
WT_PORT=${WT_PORT:-4435}                     # its WebTransport port
STREAM=${STREAM:-browsertest}
FFMPEG=${FFMPEG:-/home/flibb/maxolgi/WebSRT-cpp/libwebsrt/deps/ffmpeg/ffmpeg}  # libwebsrt-patched

HASH_FILE=$(mktemp /tmp/websrt-cpp-cert-hash.XXXXXX.js)
trap 'rm -f "$HASH_FILE"' EXIT
for _ in $(seq 1 30); do
    if curl -sk --max-time 3 "$GATEWAY/cert-hash.js" -o "$HASH_FILE" && grep -q CERT_HASH "$HASH_FILE"; then
        exec "$FFMPEG" -hide_banner -loglevel error -re \
            -f lavfi -i testsrc2=size=640x360:rate=30 \
            -f lavfi -i sine=frequency=440 \
            -c:v libx264 -preset veryfast -c:a aac -f mpegts \
            "websrt://127.0.0.1:${WT_PORT}?stream=${STREAM}&cert_hash_file=${HASH_FILE}"
    fi
    sleep 2
done
echo "websrt-cpp-testpub: $GATEWAY/cert-hash.js unreachable" >&2
exit 1
