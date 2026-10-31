#!/bin/sh
set -eu
uv sync --locked --group dev
exec .venv/bin/python -m scripts.qualify
