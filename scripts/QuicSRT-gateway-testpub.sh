#!/usr/bin/env bash
# Always-on quicsrt:// test publisher for the C++ gateway (the
# WebTransport publish path, not the SRT ingest). Deployed as the
# supervisord program QuicSRT-gateway-testpub (see QuicSRT-gateway-testpub.conf)
# with command= pointing HERE - run from the checkout, never installed.
#
# Publishes a two-rung simulcast ladder from one generated source, both
# rungs hardware-encoded (NVENC) in this one process:
#   ${STREAM}        1920x1080 @ ${SOURCE_BR}
#   ${STREAM}_540p    960x540  @ ${REND_BR}
# Both rungs ride the SAME input frames, so their PTS timelines are
# identical by construction and -copyts -mpegts_copyts 1 keep the TS
# muxers from rebasing either output: rungs share one clock and one
# 2 s keyframe grid (-g 60 on both — NOTE: -force_key_frames does NOT
# work with h264_nvenc, the GOP option is the one nvenc honors),
# which is what the player's overlap (zero-freeze) rung switching needs.
#
# Fetches the gateway's live cert-hash.js first: self mode regenerates
# the cert every boot, so the pin must be refreshed each start; a fetch
# failure exits 1 and supervisor retries.
set -euo pipefail

GATEWAY=${GATEWAY:-https://127.0.0.1:8443}   # the C++ gateway's web port
WT_PORT=${WT_PORT:-4435}                     # its WebTransport port
STREAM=${STREAM:-browsertest}
SOURCE_BR=${SOURCE_BR:-6000k}
REND_BR=${REND_BR:-2000k}
FFMPEG=${FFMPEG:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/libquicsrt/deps/ffmpeg/ffmpeg"}  # libquicsrt-patched (workspace sibling)

HASH_FILE=$(mktemp /tmp/QuicSRT-gateway-cert-hash.XXXXXX.js)
trap 'rm -f "$HASH_FILE"' EXIT
# cert-hash.js: `window.CERT_HASH = "<64 hex>";` (self mode) or `= null`
# (PKI). The ffmpeg protocol pins via cert_hash=<hex>; a fetch that
# yields anything but 64 hex chars keeps the retry loop going.
for _ in $(seq 1 30); do
    if curl -sk --max-time 3 "$GATEWAY/cert-hash.js" -o "$HASH_FILE" \
       && HASH=$(sed -n 's/.*"\([0-9a-fA-F]\{64\}\)".*/\1/p' "$HASH_FILE") \
       && [ "${#HASH}" -eq 64 ]; then
        exec "$FFMPEG" -hide_banner -loglevel error -re \
            -f lavfi -i testsrc2=size=1920x1080:rate=30 \
            -f lavfi -i sine=frequency=440 \
            -filter_complex "[0:v]split=2[v1][v2];[v2]scale=960:540[v2out]" \
            -map "[v1]" -map 1:a \
            -c:v h264_nvenc -preset p4 -tune ull -rc cbr \
            -b:v "$SOURCE_BR" -maxrate "$SOURCE_BR" -bufsize 2000k \
            -g 60 -c:a aac \
            -copyts -mpegts_copyts 1 \
            -f mpegts "quicsrt://127.0.0.1:${WT_PORT}?stream=${STREAM}&cert_hash=${HASH}" \
            -map "[v2out]" -map 1:a \
            -c:v h264_nvenc -preset p4 -tune ull -rc cbr \
            -b:v "$REND_BR" -maxrate "$REND_BR" -bufsize 700k \
            -g 60 -c:a aac \
            -copyts -mpegts_copyts 1 \
            -f mpegts "quicsrt://127.0.0.1:${WT_PORT}?stream=${STREAM}_540p&cert_hash=${HASH}"
    fi
    sleep 2
done
echo "QuicSRT-gateway-testpub: $GATEWAY/cert-hash.js unreachable" >&2
exit 1
