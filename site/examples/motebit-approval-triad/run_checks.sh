#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
cd "$root"
work="$(mktemp -d)"
output="${1:-.build/motebit-approval-triad}"
producer="${2:-}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
finish() {
  status=$?
  python3 - "$output" <<'PY'
import base64, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ['report.json', 'junit.xml', 'coverage.json', 'runtime.json']:
    path = root / name
    if path.is_file():
        raw = path.read_bytes()
        print('RETAINED_FILE ' + json.dumps({'name': name, 'bytes': len(raw),
              'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode()}))
PY
  rm -rf "$work"
  exit "$status"
}
trap finish EXIT
uv venv --python 3.12 "$work/venv"
uv pip install --python "$work/venv/bin/python" \
  -r examples/motebit-approval-triad/requirements.txt \
  pynacl==1.6.0 pytest==9.1.1 coverage==7.10.6
python_run="$work/venv/bin/python"
"$python_run" - "$output/runtime.json" <<'PY'
import importlib.metadata, json, platform
import pathlib, sys
runtime = {"python": platform.python_version(),
                  "versions": {name: importlib.metadata.version(name)
                               for name in ["cryptography", "rfc8785", "PyNaCl", "pytest", "coverage"]}}
pathlib.Path(sys.argv[1]).write_text(json.dumps(runtime, indent=2) + '\n')
print(json.dumps(runtime))
PY
if [[ -n "$producer" ]]; then
  "$python_run" "$producer/reader.py"
  "$python_run" "$producer/test_reader.py"
  echo "PRODUCER_READER_AND_MUTATIONS exit=0 source=$producer"
else
  echo "PRODUCER_READER_NOT_REQUESTED"
fi
export COVERAGE_FILE="$work/.coverage"
"$python_run" -m coverage run --source=examples/motebit-approval-triad \
  -m pytest -q examples/motebit-approval-triad/test_reader.py \
  --junitxml="$output/junit.xml"
"$python_run" -m coverage json -o "$output/coverage.json"
"$python_run" - "$output/coverage.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
d = json.loads(path.read_text())
matches = [(p, v['summary']) for p, v in d['files'].items() if p.endswith(('/reader.py', '/test_reader.py'))]
assert len(matches) == 2, matches
assert all(v['percent_covered'] >= 80 for _, v in matches), matches
print(json.dumps({'per_file_coverage': matches}))
PY
"$python_run" examples/motebit-approval-triad/reader.py > "$output/report.json"
"$python_run" tools/check_lab.py
"$python_run" tools/check_links.py
python3 scripts/readme-lint.py README.md
python3 scripts/readme-lint-test.py
