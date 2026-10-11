#!/bin/sh
# Image: mcr.microsoft.com/dotnet/sdk:10.0. Builds against the pinned SDK, then runs.
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
dotnet build -c Release -o out --nologo -v q >&2
exec dotnet out/Harness.dll
