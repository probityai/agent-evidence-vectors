#!/usr/bin/env bash
# Mutation pass over the Go done readers (corpora/done*.go) against the whole
# corpora package test suite.
#
# Every single-site weakening that cmd/mutgen enumerates in a done*.go file is
# applied in its own copy of the tree and the corpora tests are run against it.
# A mutant is KILLED when some test fails, SURVIVED when every test passes, and
# INCONCLUSIVE (apply_failed, build_failed, timeout) otherwise; the three are
# never folded together.
#
# Three stages, one verdict. Stage 1 runs the Done tests except the member
# agreement (seconds per mutant), stage 2 the member agreement, stage 3 every
# other test of the package. A mutant goes on to the next stage only while it
# survives, and the three stages together are exactly the whole package, so the
# result is the result of running the whole package on every mutant, at a
# fraction of the cost. The record says which stage killed it.
#
# Survivors are compared with docs/DONE-MUTATION-EQUIVALENTS.json, the list of
# true equivalent mutants with the reason each one cannot be killed. The run
# exits 1 when a survivor is not listed (a gap) or a listed site was killed (an
# annotation the measurement disproves), and 0 only when neither happens.
#
# Usage, from the repository root (heavy: run it on a remote box):
#   scripts/done-mutation.sh [OUT_DIR]
# Environment: WORKERS (default nproc), ONLY_KEYS (a file of site keys to run).
set -u
out="${1:-mutout}"
mkdir -p "$out"
root="$PWD"
allow="$root/docs/DONE-MUTATION-EQUIVALENTS.json"

go build -o "$out/mutgen" ./cmd/mutgen || { echo "MUTGEN_BUILD_FAILED"; exit 2; }
"$out/mutgen" -pkg corpora -list > "$out/all.jsonl" || { echo "MUTGEN_LIST_FAILED"; exit 2; }
python3 - "$out" <<'EOF' || exit 2
import json, os, sys
out = sys.argv[1]
sites = [json.loads(line) for line in open(f"{out}/all.jsonl")]
done = [s for s in sites if s["file"].startswith("done")]
only = os.environ.get("ONLY_KEYS")
if only:
    keep = {line.strip() for line in open(only) if line.strip()}
    done = [s for s in done if s["key"] in keep]
with open(f"{out}/sites.txt", "w") as handle:
    handle.write("".join(s["key"] + "\t" + s["file"] + "\n" for s in done))
print("SITES_PACKAGE", len(sites), "SITES_DONE", len(done))
if not done:
    sys.exit("no done sites enumerated")
EOF

# The stages, as go test selection flags. Together they are the whole package.
stage_args() {
  case "$1" in
    1) echo "-run Done -skip TestDoneMembersAgreeWithPython" ;;
    2) echo "-run TestDoneMembersAgreeWithPython" ;;
    3) echo "-skip Done" ;;
  esac
}

# The unmutated tree must pass every stage, or no kill means anything. Each
# stage's timeout is six times its baseline plus five minutes.
for stage in 1 2 3; do
  start=$(date +%s)
  # shellcheck disable=SC2046
  go test ./corpora $(stage_args "$stage") -count=1 > "$out/baseline-stage$stage.log" 2>&1 || { echo "BASELINE_STAGE${stage}_FAILED"; tail -50 "$out/baseline-stage$stage.log"; exit 3; }
  took=$(( $(date +%s) - start ))
  eval "timeout_$stage=$(( took * 6 + 300 ))"
  echo "BASELINE stage$stage PASS ${took}s"
done

workers="${WORKERS:-$(nproc)}"
echo "WORKERS $workers TIMEOUTS ${timeout_1}s ${timeout_2}s ${timeout_3}s"
touch "$out/results.jsonl"
for w in $(seq 0 $((workers - 1))); do
  rm -rf "$out/w$w"; mkdir -p "$out/w$w"
  git ls-files -z | xargs -0 cp --parents -t "$out/w$w"
done

record() {
  python3 -c 'import json,sys; print(json.dumps({"key":sys.argv[1],"file":sys.argv[2],"status":sys.argv[3],"stage":sys.argv[4]}))' "$@" >> "$root/$out/results.jsonl"
}

# classify LOG RC: killed, build_failed or timeout for a non-zero exit.
classify() {
  if [ "$2" -eq 124 ]; then echo timeout
  elif grep -q "build failed\|setup failed" "$1"; then echo build_failed
  else echo killed; fi
}

run_worker() {
  w="$1"; cd "$root/$out/w$w" || exit 1
  i=0
  while IFS=$'\t' read -r key file; do
    if [ $((i % workers)) -eq "$w" ]; then
      cp "corpora/$file" "$root/$out/w$w.orig"
      log="$root/$out/w$w.log"
      if ! "$root/$out/mutgen" -pkg corpora -apply "$key" -write > /dev/null 2> "$root/$out/w$w.err"; then
        record "$key" "$file" apply_failed 0
      else
        status=survived; at=3
        for stage in 1 2 3; do
          eval "limit=\$timeout_$stage"
          # shellcheck disable=SC2046
          timeout "$limit" env GOMAXPROCS=1 go test -p 1 ./corpora $(stage_args "$stage") -count=1 > "$log" 2>&1
          rc=$?
          if [ "$rc" -ne 0 ]; then status=$(classify "$log" "$rc"); at=$stage; break; fi
        done
        record "$key" "$file" "$status" "$at"
      fi
      cp "$root/$out/w$w.orig" "corpora/$file"
    fi
    i=$((i + 1))
  done < "$root/$out/sites.txt"
}

pids=()
for w in $(seq 0 $((workers - 1))); do run_worker "$w" & pids+=($!); done
for p in "${pids[@]}"; do wait "$p"; done
for w in $(seq 0 $((workers - 1))); do rm -rf "${out:?}/w$w"; done

python3 - "$out" "$allow" <<'EOF'
import collections, json, os, sys
out, allow_path = sys.argv[1], sys.argv[2]
rows = [json.loads(line) for line in open(f"{out}/results.jsonl")]
sites = [line.split("\t")[0] for line in open(f"{out}/sites.txt")]
keys = {r["key"] for r in rows}
missing = set(sites) - keys
print("RESULTS", len(rows), "UNIQUE", len(keys), "EXPECTED", len(sites), "MISSING", len(missing))
print("BY_STATUS", dict(collections.Counter(r["status"] for r in rows)))
for name in sorted({r["file"] for r in rows}):
    print("FILE", name, dict(collections.Counter(r["status"] for r in rows if r["file"] == name)))
allowed = {}
if os.path.exists(allow_path):
    allowed = json.load(open(allow_path))["equivalents"]
status = {r["key"]: r["status"] for r in rows}
gaps = [k for k in sites if status.get(k) == "survived" and k not in allowed]
listed_killed = [k for k in allowed if status.get(k) == "killed"]
inconclusive = [k for k in sites if status.get(k) not in ("killed", "survived")]
for k in gaps:
    print("GAP", k)
for k in listed_killed:
    print("LISTED_BUT_KILLED", k)
for k in inconclusive:
    print("INCONCLUSIVE", status.get(k, "missing"), k)
print("SURVIVED", sum(1 for k in sites if status.get(k) == "survived"),
      "EQUIVALENT_LISTED", sum(1 for k in sites if status.get(k) == "survived" and k in allowed),
      "GAPS", len(gaps), "LISTED_BUT_KILLED", len(listed_killed), "INCONCLUSIVE", len(inconclusive),
      "OF", len(sites))
sys.exit(1 if gaps or listed_killed or inconclusive or missing else 0)
EOF
rc=$?
echo "DONE_MUTATION_FINISHED rc=$rc"
exit "$rc"
