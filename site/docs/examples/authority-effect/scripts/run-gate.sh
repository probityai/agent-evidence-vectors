#!/usr/bin/env bash
set -euo pipefail
export UV_LINK_MODE=copy
LAB_GATE_PYTHON="${LAB_GATE_PYTHON:-3.14.7}"
uv sync --frozen --group dev --no-editable --python "$LAB_GATE_PYTHON"
.venv/bin/python -I authority_effect/isolated.py --script scripts/generate_fixtures.py -- --check
.venv/bin/python -I authority_effect/isolated.py --script scripts/generate_frequency_fixtures.py -- --check
.venv/bin/python -m ruff check authority_effect scripts tests
.venv/bin/python -m ruff format --check authority_effect scripts tests
.venv/bin/python -m pyright
mkdir -p gate-results
uv build --wheel --sdist --out-dir gate-results/dist
WHEEL_URI=$(.venv/bin/python -I -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]).resolve(); print(p.as_uri()+"#sha256="+hashlib.sha256(p.read_bytes()).hexdigest())' gate-results/dist/*.whl)
uv pip install --python .venv/bin/python --no-deps --reinstall "probity-authority-effect-cases @ $WHEEL_URI"
INSTALLED_SOURCE=$(.venv/bin/python -I -c 'import importlib.metadata,pathlib; root=importlib.metadata.distribution("probity-authority-effect-cases").locate_file(""); assert isinstance(root,pathlib.Path); print((root/"authority_effect").resolve())')
.venv/bin/python -I authority_effect/isolated.py --module coverage --cache-record gate-results/tests-cache-profile.json -- run --source="$INSTALLED_SOURCE" -m pytest -q --junitxml=gate-results/tests.xml
.venv/bin/python -I authority_effect/isolated.py --module coverage --cache-record gate-results/qualification-cache-profile.json -- run --source="$INSTALLED_SOURCE" --append scripts/qualify.py --output gate-results/installed --wheel gate-results/dist/*.whl
.venv/bin/python -I scripts/cache_controls.py --wheel gate-results/dist/*.whl --output gate-results/wheel-cache-controls
.venv/bin/python -m coverage json --include="$INSTALLED_SOURCE/*" -o gate-results/coverage.json
.venv/bin/python -I scripts/check_coverage.py gate-results/coverage.json gate-results/installed/qualification.json
.venv/bin/python -I scripts/audit_inventory.py --output gate-results/audit
.venv/bin/python -I -m pip_audit --no-deps --disable-pip --strict --format json --requirement gate-results/audit/third-party.txt --output gate-results/audit/audit.json
uv build --wheel --out-dir gate-results/sdist-wheel gate-results/dist/*.tar.gz
UV_PROJECT_ENVIRONMENT=.sdist-venv uv sync --frozen --group dev --no-editable --python "$LAB_GATE_PYTHON"
SDIST_URI=$(.venv/bin/python -I -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]).resolve(); print(p.as_uri()+"#sha256="+hashlib.sha256(p.read_bytes()).hexdigest())' gate-results/dist/*.tar.gz)
uv pip install --python .sdist-venv/bin/python --no-deps --reinstall "probity-authority-effect-cases @ $SDIST_URI"
.sdist-venv/bin/python -I scripts/qualify.py --wheel gate-results/sdist-wheel/*.whl --source-archive gate-results/dist/*.tar.gz --output gate-results/sdist-installed
.sdist-venv/bin/python -I scripts/cache_controls.py --wheel gate-results/sdist-wheel/*.whl --source-archive gate-results/dist/*.tar.gz --output gate-results/sdist-cache-controls
.sdist-venv/bin/python -I scripts/audit_inventory.py --output gate-results/sdist-audit
.sdist-venv/bin/python -I -m pip_audit --no-deps --disable-pip --strict --format json --requirement gate-results/sdist-audit/third-party.txt --output gate-results/sdist-audit/audit.json
