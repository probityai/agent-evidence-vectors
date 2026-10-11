#!/bin/sh
# Image: composer:2 (bundles PHP). Installs the pinned SDK, then runs the harness.
set -eu
composer install --no-interaction --no-progress --quiet >&2
exec php harness.php
