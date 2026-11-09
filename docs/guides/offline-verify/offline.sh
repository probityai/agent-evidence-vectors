# Offline machine: install from the carried wheels and verify every record.
set -eu
python3 -m venv venv
venv/bin/pip install --no-index --find-links wheels --require-hashes -r requirements.txt
(cd records && sha256sum -c ../SHA256SUMS)
python3 make_case.py --out pinned --keys keys.json records/*.json
python3 make_case.py --out unpinned records/*.json
for c in pinned/*.case.json unpinned/*.case.json; do venv/bin/agent-evidence-verify "$c" --policy "$(dirname "$c")/policy.json" --artifact-root records --json > "${c%.case.json}.out.json"; done
cat pinned/vfcb846afff2d6979.out.json; echo
venv/bin/python summary.py pinned unpinned || echo "summary exit $?"
venv/bin/python summary.py pinned/ --allow NOT_RECONSTRUCTIBLE --allow NOT_PUBLICLY_VERIFIABLE || echo "summary exit $?"
