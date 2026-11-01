#!/usr/bin/env bash
# quicsrt:// ABR-ladder transcoder for the C++ gateway: subscribes ONE
# stream over WebTransport and re-publishes it as N lower-resolution
# renditions (${STREAM}_<name>) - the rungs a switching player selects
# between. Deployed as the supervisord program QuicSRT-gateway-transcode
# (see QuicSRT-gateway-transcode.conf) with command= pointing HERE - run
# from the checkout, never installed.
#
# The flag set is verified against the live gateway (2026-10-31):
#   - one ffmpeg process holds 1 subscriber + N publisher WT sessions
#   - -copyts -mpegts_copyts 1 keep every rendition on the SOURCE PTS
#     timeline (measured bit-exact: 0-tick video/audio mismatch between
#     renditions and source)
#   - the identical -force_key_frames expression + -sc_threshold 0 align
#     keyframes across renditions (measured 0-tick deltas on a 2 s grid)
# Those three properties are what make seamless player-side rung
# switching possible (shared timeline + shared keyframe grid = a swap
# point that needs no PTS remapping). Do not drop flags casually.
#
# Cert pin fetched fresh each start (self cert mode rotates per boot),
# the same dance as QuicSRT-gateway-testpub.sh; a fetch failure exits 1
# and supervisor retries. If the input stream stalls or ends, ffmpeg
# exits and supervisor restarts it (rejoin at live edge).
set -euo pipefail

GATEWAY=${GATEWAY:-https://127.0.0.1:8443}   # the C++ gateway's web port
WT_PORT=${WT_PORT:-4435}                     # its WebTransport port
STREAM=${STREAM:-browsertest}                # input stream to transcode
GOP_S=${GOP_S:-2}                            # rendition keyframe cadence, seconds
# LADDER: space-separated "name:WxH:bitrate:vbv-bufsize" entries; each
# rendition publishes as ${STREAM}_<name>. Source is 640x360, so the
# defaults step DOWN from it.
LADDER=${LADDER:-"288p:512x288:600k:200k 216p:384x216:300k:100k"}
FFMPEG=${FFMPEG:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/libquicsrt/deps/ffmpeg/ffmpeg"}  # libquicsrt-patched (workspace sibling)

HASH_FILE=$(mktemp /tmp/QuicSRT-gateway-cert-hash.XXXXXX.js)
trap 'rm -f "$HASH_FILE"' EXIT
ok=0
for _ in $(seq 1 30); do
    if curl -sk --max-time 3 "$GATEWAY/cert-hash.js" -o "$HASH_FILE" && grep -q CERT_HASH "$HASH_FILE"; then
        ok=1
        break
    fi
    sleep 2
done
[ "$ok" = 1 ] || { echo "QuicSRT-gateway-transcode: $GATEWAY/cert-hash.js unreachable" >&2; exit 1; }

IN_URL="quicsrt://127.0.0.1:${WT_PORT}?stream=${STREAM}&cert_hash_file=${HASH_FILE}"

# One decode, split + scale per rung: [0:v]split=N[s0]..[sN-1];[sI]scale=W:H[oI]
read -ra SPECS <<<"$LADDER"
COUNT=${#SPECS[@]}
FILTER="[0:v]split=${COUNT}"
for ((i = 0; i < COUNT; i++)); do
    FILTER+="[s${i}]"
done
OUT_ARGS=()
for ((i = 0; i < COUNT; i++)); do
    IFS=: read -r name size brate bufsize <<<"${SPECS[$i]}"
    W=${size%x*}
    H=${size#*x}
    FILTER+=";[s${i}]scale=${W}:${H}[o${i}]"
    OUT_ARGS+=(
        -map "[o${i}]" -map 0:a
        -c:v libx264 -preset veryfast -tune zerolatency
        -b:v "$brate" -maxrate "$brate" -bufsize "$bufsize"
        -force_key_frames "expr:gte(t,n_forced*${GOP_S})" -sc_threshold 0
        -c:a copy
        -copyts -mpegts_copyts 1
        -f mpegts "quicsrt://127.0.0.1:${WT_PORT}?stream=${STREAM}_${name}&cert_hash_file=${HASH_FILE}"
    )
done

exec "$FFMPEG" -hide_banner -loglevel error \
    -f mpegts -i "$IN_URL" \
    -filter_complex "$FILTER" \
    "${OUT_ARGS[@]}"
