#!/bin/sh
# Image: ruby:3.3. Installs the pinned gem, then runs the harness on stdin.
set -eu
bundle config set --local path vendor/bundle >&2
bundle install --quiet >&2
exec bundle exec ruby harness.rb
