#!/usr/bin/env bash
# Run the ACS-Core wire probes against the AGT reference Guardian in a checkout
# of GenAI-Security-Project/agent-control-standard.
#
#   run_against_agt.sh <acs checkout> <out dir> [expect.json]
#
# Starts the Guardian on a free local port with a fresh HMAC secret, runs every
# probe, restarts the Guardian once for D2c, and stops it. Needs bun and python3.
set -euo pipefail
ACS=$(cd "$1" && pwd)
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
EXPECT=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${ACS_PROBE_PORT:-18797}
SECRET=$(head -c 32 /dev/urandom | base64)
URL="http://127.0.0.1:${PORT}/acs"
PID=""

start() {
  (cd "$ACS/reference-implementations/agt" && \
    ACS_HMAC_SECRET="$SECRET" ACS_GUARDIAN_PORT="$PORT" \
    ACS_ENVELOPE_LOG="$OUT/guardian-envelopes-$1.jsonl" \
    ACS_SESSION_CONTEXT_LOG="$OUT/guardian-context-$1.jsonl" \
    exec bun run packages/guardian/src/main.ts) > "$OUT/guardian-$1.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 50); do
    grep -q "Guardian listening" "$OUT/guardian-$1.log" 2>/dev/null && return 0
    sleep 0.2
  done
  echo "Guardian did not start; see $OUT/guardian-$1.log" >&2
  return 2
}
stop() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap stop EXIT

probe() { python3 -I "$HERE/acs_wire_probes.py" --guardian "$URL" --ikm-b64 "$SECRET" \
  --out "$OUT" "$@"; }

start a
rc=0
if [ -n "$EXPECT" ]; then probe --expect "$EXPECT" || rc=$?; else probe || rc=$?; fi
probe --replay-save "$OUT/replay.json" || true
stop
start b
if [ -n "$EXPECT" ]; then probe --replay-send "$OUT/replay.json" --expect "$EXPECT" || rc=$?
else probe --replay-send "$OUT/replay.json" || true; fi
exit "$rc"
