#!/bin/sh
# Image: maven:3.9-eclipse-temurin-21. Builds against the pinned SDK, then runs.
set -eu
mvn -q -B compile dependency:copy-dependencies >&2
exec java -cp "target/classes:target/dependency/*" Harness
