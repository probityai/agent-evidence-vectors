#!/bin/sh
# Record a no-network run of docs/guides/offline-verify.md.
#
# Copies the page's folder to a scratch directory, runs connected.sh in a
# python:3.12-slim container with networking, then offline.sh in a fresh
# container started with --network none. Prints a transcript to stdout:
#   sh scripts/offline-verify-run.sh > docs/guides/offline-verify/TRANSCRIPT.txt
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)/docs/guides/offline-verify
image=python:3.12-slim
work=$(mktemp -d)
trap 'docker run --rm -v "$work":/w "$image" rm -rf /w/wheels /w/records /w/venv /w/pinned /w/unpinned >/dev/null 2>&1; rm -rf "$work"' EXIT
cp "$here"/requirements.txt "$here"/SHA256SUMS "$here"/keys.json "$here"/make_case.py "$here"/summary.py "$here"/connected.sh "$here"/offline.sh "$work"/
docker pull -q "$image" >/dev/null
echo "# recorded $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -sm), docker $(docker version --format '{{.Server.Version}}')"
echo "# image $(docker image inspect "$image" --format '{{index .RepoDigests 0}}')"
echo "# page folder digest: $(cd "$here" && sha256sum requirements.txt SHA256SUMS keys.json make_case.py summary.py connected.sh offline.sh | sha256sum | cut -c1-64)"
echo "## stage 1: connected container"
docker run --rm -v "$work":/w -w /w "$image" sh -x connected.sh 2>&1
echo "## stage 2: container started with --network none"
docker run --rm --network none -v "$work":/w -w /w "$image" sh -c '
  echo "interfaces: $(ls /sys/class/net | tr "\n" " ")"
  python3 -c "import urllib.request
try:
    urllib.request.urlopen(\"https://pypi.org/simple/\", timeout=5); print(\"network probe: REACHED pypi.org\")
except Exception as e:
    print(\"network probe: no route (\" + type(e).__name__ + \")\")"
  sh -x offline.sh' 2>&1
