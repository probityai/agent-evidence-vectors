#!/usr/bin/env bash
# Run the ACS-Core hook probes against the Claude Code shim in a checkout of
# GenAI-Security-Project/agent-control-standard, with that checkout's own
# reference Guardian behind it.
#
#   run_against_agt.sh <acs checkout> <out dir> [expect.json]
#
# Four phases: the Guardian up under the default posture, the Guardian
# unreachable, the Guardian up under on_decision_failure deny, and the
# Guardian stopped again with that session's posture stored. The up phases
# also read the Guardian's envelope log, so a shim that answers without
# sending anything is caught there. Then, with an expectation, a coverage
# check that every probe it names was produced. The exit status is the worst
# any step returned: 2 when the shim or the Guardian could not run, 1 on drift
# or a missing probe. Needs bun and python3. The out directory must not hold a
# previous run's captures, state, results or Guardian logs; they would read as
# this run's.
set -euo pipefail
ACS=$(cd "$1" && pwd)
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
EXPECT=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${ACS_PROBE_PORT:-18807}
# The shim at the recorded refs signs nothing and the Guardian there reads
# neither variable. Guardians from pull request 229's later heads refuse to
# start without them, so they are set the way the wire-probe runner sets them.
SECRET=$(head -c 32 /dev/urandom | base64)
KEY_ID=${ACS_PROBE_KEY_ID:-conformance-k1}
URL="http://127.0.0.1:${PORT}/acs"
PID=""

for earlier in "$OUT/state" "$OUT/hook" "$OUT"/results-*.json "$OUT"/guardian-*; do
  if [ -e "$earlier" ]; then
    echo "$OUT already holds a run ($earlier); use an empty out directory" >&2
    exit 2
  fi
done

start() {
  (cd "$ACS/reference-implementations/agt" && \
    ACS_HMAC_SECRET="$SECRET" ACS_HMAC_KEY_ID="$KEY_ID" ACS_GUARDIAN_PORT="$PORT" \
    ACS_ON_DECISION_FAILURE="$2" \
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
stop() { if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; PID=""; }
trap stop EXIT

rc=0
worst() { if [ "$1" -gt "$rc" ]; then rc=$1; fi; }

probe() { # phase [guardian log]
  local phase=$1 status=0
  local -a args=(--acs "$ACS" --out "$OUT" --phase "$phase" --guardian "$URL")
  [ $# -gt 1 ] && args+=(--guardian-log "$2")
  [ -n "$EXPECT" ] && args+=(--expect "$EXPECT")
  python3 -I "$HERE/acs_hook_probes.py" "${args[@]}" || status=$?
  worst "$status"
}

start a proceed || worst $?
probe up "$OUT/guardian-envelopes-a.jsonl"
stop
probe down
start b deny || worst $?
probe deny-up "$OUT/guardian-envelopes-b.jsonl"
stop
probe deny-down
if [ -n "$EXPECT" ]; then
  python3 -I "$HERE/acs_hook_probes.py" --acs "$ACS" --out "$OUT" --expect "$EXPECT" \
    --check-coverage || worst $?
fi
exit "$rc"
