#!/bin/sh
# The fixture suite's checker: print the expectation a case carries.
sed -n 's/.*"expect": "\([a-z]*\)".*/\1/p' "$1"
