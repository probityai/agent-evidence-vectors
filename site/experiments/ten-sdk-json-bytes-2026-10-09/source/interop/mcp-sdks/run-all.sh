#!/bin/sh
# Run the JCS byte corpus through every official MCP SDK in a pinned container
# and print the divergence table. Needs docker and python3. Usage:
#   interop/mcp-sdks/run-all.sh [sdk ...]
set -eu
cd "$(dirname "$0")"

image() {
    case "$1" in
        jcs-admit|rust) echo rust:1.90-bookworm ;;
        typescript) echo node:22-bookworm ;;
        python) echo python:3.13-slim-bookworm ;;
        go) echo golang:1.25-bookworm ;;
        java) echo maven:3.9-eclipse-temurin-21 ;;
        kotlin) echo gradle:8.14-jdk21 ;;
        csharp) echo mcr.microsoft.com/dotnet/sdk:10.0 ;;
        swift) echo swift:6.1-bookworm ;;
        ruby) echo ruby:3.3-bookworm ;;
        php) echo composer:2 ;;
        *) echo "unknown sdk $1" >&2; exit 64 ;;
    esac
}

in_container() {
    sdk=$1
    echo "docker run --rm -i --user $(id -u):$(id -g) -e HOME=/tmp -v $PWD/$sdk:/w -w /w --entrypoint sh $(image "$sdk") run.sh"
}

sdks=${*:-"typescript python go java kotlin csharp swift rust ruby php"}
for sdk in jcs-admit $sdks; do
    docker pull -q "$(image "$sdk")" >&2
done
# shellcheck disable=SC2046
python3 driver.py admit -- $(in_container jcs-admit)
failed=""
for sdk in $sdks; do
    meta=$(docker image inspect --format '{"image":"{{index .RepoDigests 0}}"}' "$(image "$sdk")")
    # shellcheck disable=SC2046
    if ! HARNESS_META=$meta python3 driver.py run "$sdk" -- $(in_container "$sdk"); then
        echo "NOT RUN: $sdk (harness failed, see stderr above)" >&2
        failed="$failed $sdk"
    fi
done
python3 driver.py table
if [ -n "$failed" ]; then
    echo "harnesses that did not run:$failed" >&2
    exit 1
fi
