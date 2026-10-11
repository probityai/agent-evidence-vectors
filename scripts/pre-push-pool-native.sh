#!/bin/sh
# Each native snapshot owns its interpreter and installed dependencies.
set -eu
export UV_LINK_MODE=copy
export PYTHONDONTWRITEBYTECODE=1
export UV_PROJECT_ENVIRONMENT="$PWD/.venv"
check_environment() {
    .venv/bin/python -B - "$UV_PROJECT_ENVIRONMENT" <<'PY'
import os
import sys
expected = os.path.normcase(os.path.abspath(sys.argv[1]))
prefix = os.path.normcase(os.path.abspath(sys.prefix))
base = os.path.normcase(os.path.abspath(sys.base_prefix))
valid = (sys.version_info >= (3, 13) and prefix == expected and prefix != base
         and os.path.isfile(os.path.join(expected, "pyvenv.cfg")))
if not valid:
    print(f"pre-push: environment prefix {prefix}; base {base}; expected {expected}.",
          file=sys.stderr)
sys.exit(0 if valid else 1)
PY
}
if [ -x .venv/bin/python ]; then check_environment; fi
uv sync --locked --extra dev --python 3.13
check_environment
exec .venv/bin/python -B scripts/pre-push-pool.py remote "$1"
