#!/usr/bin/env bash
# The authority rotates its signing key under live grants (make rotation-check).
#
# The pinned rotation_check.py, unchanged, in two phases around a recreate of uma-as:
#   1. uma-as on a fresh Postgres (pg, Compose test profile), so the recreate keeps the
#      grant; a grant is negotiated and kept (--phase before);
#   2. a new key is written by a helper container, and uma-as is recreated signing with
#      it as uma-as-2 and still publishing uma-as-1 (--phase after).
# The enforcement point is never restarted: it has to learn the new key itself.
#
# Every recreate sets all six store and key variables explicitly, so nothing the caller
# exported leaks into a phase. Every exit after the first change restores the memory
# store and the original key, then verifies both from the running container: its
# environment, and /jwks publishing uma-as-1 alone. A restore that fails fails the check.
# Every wait is bounded. Follows COMPOSE_PROJECT_NAME like the other gates.
set -euo pipefail

readonly PG_URL=postgres://u4a:u4a@pg:5432/u4a
readonly ORIGINAL_KEY=/keys/uma-as-ed25519.pem
readonly ROTATED_KEY=/keys/uma-as-2.pem
changed=

# recreate <store> <database-url> <signing-key> <kid> <previous-keys> <previous-kids>
recreate() {
	UMA_AS_STORE=$1 UMA_AS_DATABASE_URL=$2 UMA_AS_SIGNING_KEY=$3 UMA_AS_KID=$4 \
		UMA_AS_PREVIOUS_KEYS=$5 UMA_AS_PREVIOUS_KIDS=$6 \
		docker compose up -d --force-recreate --no-deps uma-as
}

wait_for_as() {
	for _ in $(seq 1 60); do
		if docker compose exec -T uma-as curl -sf http://127.0.0.1:9000/health >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	echo "uma-as did not come up within two minutes" >&2
	return 1
}

running_env() {
	docker compose exec -T uma-as printenv "$1" 2>/dev/null || true
}

restored() {
	recreate memory "" "$ORIGINAL_KEY" uma-as-1 "" "" >/dev/null 2>&1 && wait_for_as || return 1
	local problems=() name want got
	for pair in UMA_AS_STORE=memory UMA_AS_DATABASE_URL= \
		"UMA_AS_SIGNING_KEY=$ORIGINAL_KEY" UMA_AS_KID=uma-as-1 \
		UMA_AS_PREVIOUS_KEYS= UMA_AS_PREVIOUS_KIDS=; do
		name=${pair%%=*}
		want=${pair#*=}
		got=$(running_env "$name")
		[[ "$got" == "$want" ]] || problems+=("$name is '$got', not '$want'")
	done
	local kids
	kids=$(docker compose exec -T uma-as curl -sf http://127.0.0.1:9000/jwks |
		grep -o '"kid":"[^"]*"' | tr '\n' ' ' || true)
	[[ "$kids" == '"kid":"uma-as-1" ' ]] || problems+=("/jwks publishes [${kids}]")
	if ((${#problems[@]})); then
		printf 'restore FAILED: %s\n' "${problems[@]}" >&2
		return 1
	fi
	echo "Restored: memory store, ${ORIGINAL_KEY} as uma-as-1, nothing retired"
}

finish() {
	local status=$?
	if [[ -n "$changed" ]]; then
		echo "Restoring the original signing key and the memory store"
		restored || status=1
	fi
	docker compose --profile test rm -sfv pg >/dev/null 2>&1 || true
	exit "$status"
}
trap finish EXIT

# A fresh database: durable test state is reset by replacing it.
docker compose --profile test rm -sfv pg >/dev/null 2>&1 || true
docker compose --profile test up -d --wait pg

changed=1
recreate postgres "$PG_URL" "$ORIGINAL_KEY" uma-as-1 "" ""
wait_for_as
docker compose --profile test run --rm rotation-check --phase before

docker compose --profile test run --rm --no-deps rotation-keygen "$ROTATED_KEY"
recreate postgres "$PG_URL" "$ROTATED_KEY" uma-as-2 "$ORIGINAL_KEY" uma-as-1
wait_for_as
docker compose --profile test run --rm rotation-check --phase after
