#!/bin/sh
# One command, nothing installed: run the conformance mode on the bundled cases,
# first with a verifier that gets every case right, then with one that accepts
# everything. The first passes; the second fails and names the two cases.
#   sh scripts/run-conformance-demo.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
fixture="$here/fixtures/action-v8/conformance"
py=$(command -v python3 || command -v python)
out=${TMPDIR:-/tmp}
echo "== a verifier that judges every case as listed"
"$py" -S "$here/action-conformance.py" --expected "$fixture/verify-expected.txt" \
  --cases "$fixture/cases" --verifier "$py -S $fixture/verifier.py" --report "$out/conformance-demo-good.json"
good=$?
echo "== a verifier that accepts everything"
"$py" -S "$here/action-conformance.py" --expected "$fixture/verify-expected.txt" \
  --cases "$fixture/cases" --verifier "$py -S $fixture/lenient-verifier.py" --report "$out/conformance-demo-lenient.json"
lenient=$?
echo "exit: good $good (want 0), lenient $lenient (want 1)"
[ "$good" -eq 0 ] && [ "$lenient" -eq 1 ]
