#!/bin/sh
# Image: gradle:8.14-jdk21. Builds against the pinned SDK, then runs.
set -eu
gradle -q --no-daemon installDist >&2
# kotlin-logging prints a startup line on stdout unless told not to.
export JAVA_OPTS="-Dkotlin-logging.logStartupMessage=false"
exec build/install/jcs-kotlin/bin/jcs-kotlin
