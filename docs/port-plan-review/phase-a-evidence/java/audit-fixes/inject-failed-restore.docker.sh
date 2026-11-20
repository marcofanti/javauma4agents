#!/usr/bin/env bash
# Fault injection: fail only the restore's gateway restart; everything else is real docker.
set -euo pipefail
if [[ "$*" == *"restart agentgateway"* ]]; then
	echo "injected: docker $* fails" >&2
	exit 1
fi
exec "/usr/local/bin/docker" "$@"
