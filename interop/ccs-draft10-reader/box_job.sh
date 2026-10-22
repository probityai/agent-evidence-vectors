#!/usr/bin/env bash
# Box job: run the draft-10 reader over the CCS v1.4.0 corpus at a pinned commit, twice,
# with jcs-admit cross-checking every canonical byte string, and print every result file.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
CORPUS_COMMIT=c848faeade7a2ad9d211cf065e0e1ef415b4a3e7
RUN_COMMIT_REPLAYED=effff90f231d11bb3be93d3d0d0792f36934cc78
echo "STEP clone"
git clone -q https://github.com/DSHCorrectover/ccs-conformance-vectors.git "$WORK/corpus"
git -C "$WORK/corpus" checkout -q "$CORPUS_COMMIT"
FULL=$(git -C "$WORK/corpus" rev-parse HEAD)
TREE_NOW=$(git -C "$WORK/corpus" rev-parse "HEAD:vectors/v1.4.0-conformance")
TREE_THEN=$(git -C "$WORK/corpus" rev-parse "$RUN_COMMIT_REPLAYED:vectors/v1.4.0-conformance")
echo "CORPUS_COMMIT $FULL"
echo "CORPUS_TREE $TREE_NOW (at $RUN_COMMIT_REPLAYED: $TREE_THEN)"
echo "STEP venv"
uv venv -q --python 3.12 "$WORK/venv"
uv pip install -q --python "$WORK/venv/bin/python" "agent-evidence-vectors==0.18.1" "cryptography==50.0.2"
"$WORK/venv/bin/python" -c "import sys, agent_evidence_vectors, cryptography; print('PY', sys.version.split()[0], 'cryptography', cryptography.__version__)"
"$WORK/venv/bin/python" -m pip --version >/dev/null 2>&1 || true
echo "STEP jcs-admit"
cp -r "$HERE/jcs-admit-check" "$WORK/jcs-admit-check"
(cd "$WORK/jcs-admit-check" && cargo build -q --release --locked 2>/dev/null || cargo build -q --release)
JA="$WORK/jcs-admit-check/target/release/jcs-admit-check"
grep -A2 'name = "jcs-admit"' "$WORK/jcs-admit-check/Cargo.lock" | tr '\n' ' '; echo
printf '{"b":1.0,"a":[1e21,-0.0,"\\u00e9"]}' | "$JA"; echo
echo "STEP run1"
PYTHONHASHSEED=0 JCS_ADMIT="$JA" "$WORK/venv/bin/python" -I "$HERE/ccs_spec_reader.py" "$WORK/corpus/vectors/v1.4.0-conformance" "$WORK/out1"
echo "STEP run2"
PYTHONHASHSEED=1 JCS_ADMIT="$JA" "$WORK/venv/bin/python" -I "$HERE/ccs_spec_reader.py" "$WORK/corpus/vectors/v1.4.0-conformance" "$WORK/out2"
echo "STEP compare"
(cd "$WORK/out1" && sha256sum cases.jsonl summary.json controls.json)
(cd "$WORK/out2" && sha256sum cases.jsonl summary.json controls.json)
cmp "$WORK/out1/cases.jsonl" "$WORK/out2/cases.jsonl" && cmp "$WORK/out1/summary.json" "$WORK/out2/summary.json" && cmp "$WORK/out1/controls.json" "$WORK/out2/controls.json" && echo "REPLAY_IDENTICAL yes"
for f in summary.json controls.json cases.jsonl; do
  echo "===BEGIN $f==="
  cat "$WORK/out1/$f"
  echo "===END $f==="
done
rm -rf "$WORK"
echo "STEPS failed=0"
