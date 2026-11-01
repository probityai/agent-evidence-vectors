#!/bin/sh
# The fixture suite's corpus digest: SHA-256 over the case files in identifier order.
cat suite/cases/*.json | sha256sum | cut -d' ' -f1
