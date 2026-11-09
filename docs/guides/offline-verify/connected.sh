# Connected machine: fetch the pinned verifier and the example records.
set -eu
python3 -m pip download --require-hashes --only-binary=:all: --dest wheels -r requirements.txt
mkdir -p records
for id in vfcb846afff2d6979 v550c91df0d36a218 v9cc570167acf4ae8 v577011f7dd9a08fe v02fd1bc1d7916002 v28b0cf874ea02de1 v131478f1be775746 vcb23d2c4509c9daf; do python3 -c "import sys, urllib.request; sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())" "https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.36.3/vectors/statements/$id.json" > "records/$id.json"; done
(cd records && sha256sum -c ../SHA256SUMS)
