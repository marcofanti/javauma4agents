#!/usr/bin/env bash
# Fault injection: recreating the vault in embedded mode fails; all else is real.
set -euo pipefail
if [[ "${ENFORCEMENT_MODE:-}" == embedded && "$*" == *"up -d --force-recreate"* ]]; then
	echo "injected: embedded recreate fails" >&2
	exit 1
fi
exec "/usr/local/bin/docker" "$@"
