#!/bin/sh
# Image: rust:1.90. Builds against Cargo.lock, then runs.
set -eu
cargo build --locked --release --quiet --target-dir /tmp/target >&2
exec /tmp/target/release/mcp-sdks-jcs-rust
