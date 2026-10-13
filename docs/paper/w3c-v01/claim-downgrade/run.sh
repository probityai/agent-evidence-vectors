#!/usr/bin/env bash
# Run the one-variable claim-downgrade experiment against agent-evidence-vectors 0.18.1.
# Python reader: the PyPI wheel, installed under its published sha256.
# Rust reader: readers/w3c-report-rs built --locked from the v0.18.1 tag.
# Prints the results JSON between BEGIN/END markers, then its sha256.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TAG=v0.18.1
WHEEL_SHA=3953c8ab3c48f3e8b6d1779c2eafacb997f0336555ea0e1e6a83056fe2c5755f

git clone --quiet --depth 1 --branch "$TAG" https://github.com/probityai/agent-evidence-vectors "$WORK/aev"
echo "AEV_COMMIT $(git -C "$WORK/aev" rev-parse HEAD)"
cargo build --quiet --release --locked -j1 \
  --manifest-path "$WORK/aev/readers/w3c-report-rs/Cargo.toml" --target-dir "$WORK/rs-target"
RS="$WORK/rs-target/release/w3c-report-rs"
echo "RUST_BINARY_SHA256 $(sha256sum "$RS" | cut -d' ' -f1)"
echo "CARGO $(cargo --version)"

printf 'agent-evidence-vectors==0.18.1 --hash=sha256:%s\n' "$WHEEL_SHA" > "$WORK/req.txt"
uv venv --quiet --python 3.13 "$WORK/venv"
uv pip install --quiet --python "$WORK/venv/bin/python" --require-hashes --no-deps -r "$WORK/req.txt"
"$WORK/venv/bin/python" -I "$HERE/claim_downgrade.py" --out "$WORK/results.json" --rust "$RS"
echo "BEGIN_RESULTS"
cat "$WORK/results.json"
echo "END_RESULTS"
echo "RESULTS_SHA256 $(sha256sum "$WORK/results.json" | cut -d' ' -f1)"
