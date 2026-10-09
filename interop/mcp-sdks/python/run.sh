#!/bin/sh
# Image: python:3.13-slim. Installs the pinned SDK, then runs the harness.
set -eu
python -m venv /tmp/venv >&2
/tmp/venv/bin/pip install --quiet --disable-pip-version-check mcp==2.3.0 >&2
exec /tmp/venv/bin/python harness.py
