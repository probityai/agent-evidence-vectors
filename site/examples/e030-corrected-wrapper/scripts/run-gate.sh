#!/usr/bin/env bash
set -euo pipefail
uv sync --locked --group dev
.venv/bin/python -m scripts.qualify
