#!/bin/sh
# Image: golang:1.25. Builds against the module in go.sum, then runs.
set -eu
GOWORK=off GOFLAGS=-mod=readonly go build -o /tmp/harness . >&2
exec /tmp/harness
