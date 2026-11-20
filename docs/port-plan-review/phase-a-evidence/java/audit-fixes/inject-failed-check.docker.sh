#!/usr/bin/env bash
# Fault injection: the embedded check itself fails with status 7; restore is real.
set -euo pipefail
if [[ "$*" == *"run --rm embedded-check"* ]]; then
	echo "injected: docker $* fails with 7" >&2
	exit 7
fi
exec "/usr/local/bin/docker" "$@"
