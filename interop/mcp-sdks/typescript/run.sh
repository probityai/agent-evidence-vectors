#!/bin/sh
# Image: node:22-bookworm. Installs the locked SDK, then runs the harness.
set -eu
npm ci --ignore-scripts --no-audit --no-fund --silent >&2
exec node harness.mjs
