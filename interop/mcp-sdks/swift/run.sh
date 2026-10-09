#!/bin/sh
# Image: swift:6.1. Builds against the pinned SDK, then runs.
set -eu
swift build -c release -q >&2
exec .build/release/Harness
