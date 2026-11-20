#!/usr/bin/env bash
# Run the pinned embedded-check against a vault switched to ENFORCEMENT_MODE=embedded,
# then restore gateway mode explicitly and verify the restoration.
#
# Exit status: the check's own status when it failed; otherwise 1 if the switch or the
# restoration failed; otherwise 0. A failed restoration is always reported, and never
# hides a failed check.
set -euo pipefail

WAIT_S=${EMBEDDED_WAIT_S:-120}
RM_FLAG="--rm"

log() { printf '==> %s\n' "$*"; }

# Recreate the vault in one mode and wait for its healthcheck; fail if it never passes.
switch_vault() {
	local mode=$1
	# Explicit guards: callers evaluate this function in `if` and `&&`, where Bash
	# suspends errexit. Without them a failed recreation would fall through to a stale
	# container that already reports the requested mode.
	if ! ENFORCEMENT_MODE=$mode docker compose up -d --force-recreate --wait \
		--wait-timeout "$WAIT_S" alice-vault-mcp; then
		echo "could not recreate the vault in $mode mode" >&2
		return 1
	fi
	local actual
	if ! actual=$(docker compose exec -T alice-vault-mcp printenv ENFORCEMENT_MODE); then
		echo "could not read the vault's ENFORCEMENT_MODE" >&2
		return 1
	fi
	if [[ "$actual" != "$mode" ]]; then
		echo "vault reports ENFORCEMENT_MODE=$actual, expected $mode" >&2
		return 1
	fi
}

# The public route serves the restored vault again. This also waits for Envoy
# to reconnect after agentgateway restarts.
gateway_serves_vault() {
	local body='{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"embedded-restore","version":"1"}}}}'
	local attempt
	for attempt in $(seq 1 "$WAIT_S"); do
		if docker compose exec -T uma-as curl -sf --max-time 2 \
			--cacert /certs/rootCA.pem -X POST https://gateway.uma.lab/mcp \
			-H 'content-type: application/json' \
			-H 'accept: application/json, text/event-stream' \
			-H 'mcp-protocol-version: 2026-07-28' -H 'mcp-method: server/discover' \
			-d "$body" 2>/dev/null | grep -q '"supportedVersions"'; then
			return 0
		fi
		sleep 1
	done
	echo "the gateway did not serve the restored vault within ${WAIT_S}s (last try $attempt)" >&2
	return 1
}

restore_gateway() {
	log "Restoring ENFORCEMENT_MODE=gateway"
	switch_vault gateway &&
		docker compose restart agentgateway &&
		gateway_serves_vault
}

check_status=0
switch_status=0
if switch_vault embedded; then
	docker compose --profile test run "$RM_FLAG" embedded-check || check_status=$?
else
	switch_status=1
	echo "the vault did not come up in embedded mode; the check did not run" >&2
fi

restore_status=0
restore_gateway || restore_status=$?

log "embedded-check: check=$check_status switch=$switch_status restore=$restore_status"
if ((restore_status != 0)); then
	echo "RESTORE FAILED: the vault may still be in embedded mode; later gateway checks are not valid" >&2
fi
if ((check_status != 0)); then
	exit "$check_status"
fi
if ((switch_status != 0 || restore_status != 0)); then
	exit 1
fi
