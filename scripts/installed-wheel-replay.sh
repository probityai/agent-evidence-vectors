#!/usr/bin/env bash
# Install the built wheel outside the checkout and replay every corpus it ships.
#
#   scripts/installed-wheel-replay.sh dist/agent_evidence_vectors-X.whl path/to/aee-verify
#
# release.yml runs this before it publishes, and ci.yml runs it on every pull
# request and every push to main. It used to live only in release.yml, so a
# corpus whose wheel copy could not find its vendored specification
# (vectors-self-reported-record, spec/self-reported-record/v1.md) passed every
# pull request and was first refused by the publish job of v0.17.8, after the
# tag was cut. The check has to run before a tag can exist.
#
# EVERY corpus the wheel ships is replayed, not only the default one, and each
# must end in one of two states: judged clean by a reader in this package, or
# refused by name (exit 2) because its suite has no reader here. A third state
# -- a verdict printed by a rail that does not implement the suite -- fails.
# The refused suites also run through the Go directory reader against the
# installed wheel data. SCITT-COSE explicitly needs a CBOR reader, and delegation-chain
# has only its Python reference reader, so the Go directory route refuses it by name.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "usage: $0 <wheel> <aee-verify binary>" >&2
  exit 2
fi
wheel="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
aee_verify="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/installed-wheel.XXXXXX")"
cd "$scratch"
uv run --no-project --with "$wheel" agent-evidence-vectors --list-corpora > corpora.txt
test -s corpora.txt
uv run --no-project --with "$wheel" agent-evidence-vectors --self-test
uv run --no-project --with "$wheel" agent-evidence-vectors --report report.json
python3 -c "import json; t = json.load(open('report.json'))['totals']; assert t['fail'] == 0 and t['suiteRefusals'] == 0, t; print(t)"
corpus_root="$(uv run --no-project --with "$wheel" python -c 'import pathlib, agent_evidence_vectors; print(pathlib.Path(agent_evidence_vectors.__file__).parent / "corpora")')"
while read -r corpus; do
  # Exercise the advertised directory route against installed data.
  # Repository-only criterion files must not hide a broken wheel.
  if "$aee_verify" "$corpus_root/$corpus" > "directory-$corpus.txt" 2>&1; then
    echo "$corpus: judged clean by the installed directory route"
  else
    directory_rc=$?
    if [ "$corpus" = vectors-scitt-cose ] && [ "$directory_rc" = 2 ] && \
       grep -q 'no reader here carries a CBOR decoder' "directory-$corpus.txt"; then
      echo "$corpus: explicitly requires a CBOR reader"
    elif [ "$corpus" = vectors-delegation-chain ] && [ "$directory_rc" = 2 ] && \
       grep -q 'its only reader is the Python reference reader' "directory-$corpus.txt"; then
      echo "$corpus: judged by its Python reference reader, refused by name here"
    elif [ "$corpus" = vectors-agent-registration-classification ] && [ "$directory_rc" = 2 ] && \
       grep -q 'no reader in this binary judges it' "directory-$corpus.txt"; then
      echo "$corpus: judged by its own check_vectors.py, refused by name here"
    else
      cat "directory-$corpus.txt"
      echo "::error::installed directory route for $corpus exited $directory_rc"
      exit 1
    fi
  fi
  if [ "$corpus" = vectors-source-coverage ]; then
    if uv run --no-project --with "$wheel" agent-evidence-vectors \
         --corpus "$corpus" --report "report-$corpus.json" > "out-$corpus.txt" 2>&1; then
      echo "::error::source coverage was judged without its external verifier"
      exit 1
    else
      rc=$?
    fi
    test "$rc" = 2
    grep -q "requires a named external verifier" "out-$corpus.txt"
    echo "$corpus: requires an external verifier"
    continue
  fi
  if uv run --no-project --with "$wheel" agent-evidence-vectors --corpus "$corpus" \
       --report "report-$corpus.json" > "out-$corpus.txt" 2>&1; then
    echo "$corpus: judged clean by the packaged rail"
    continue
  else
    rc=$?
  fi
  if [ "$rc" = 2 ] && grep -q "has no reader in this package" "out-$corpus.txt"; then
    echo "$corpus: refused by name; judged in CI by aee-verify <corpus-dir>"
    continue
  fi
  cat "out-$corpus.txt"
  echo "::error::corpus $corpus exited $rc and was neither judged clean nor refused by name"
  exit 1
done < corpora.txt
# A reader that cannot find its specification says so and still
# passes, which is how the observed-effect reader ran unchecked from
# every wheel up to 0.12.1: the note printed and the release went out.
if grep -q "is not beside this corpus" out-*.txt; then
  grep -h "is not beside this corpus" out-*.txt
  echo "::error::a packaged reader ran without the specification it cross-checks against"
  exit 1
fi
# The corpus directories' generators and checkers are repository
# tools. In the wheel they crashed on import (a repository-relative
# specification path, build-only dependencies) and nothing loaded them.
python3 - "$wheel" <<'PY'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
stray = [n for n in names if n.startswith("agent_evidence_vectors/corpora/") and n.endswith(".py")]
if stray:
    sys.exit("the wheel ships corpus-directory scripts: " + ", ".join(stray))
print("the wheel carries corpus data and the packaged readers only")
PY
