#!/usr/bin/env bash
# The store properties on memory and on real Postgres 17 (make store-test).
#
# Usage: scripts/store-test.sh <container-name-prefix> <test-classes>
#
# With UMA_AS_TEST_DSN set, runs against that database, which must be disposable: every
# Postgres test class drops the store's tables. Nothing is started or removed, and the
# server's version is whatever that database reports to the tests.
#
# Without it, starts one throwaway postgres:17-alpine under a name unique to this run
# (<prefix>-<pid>-<random>) on an ephemeral loopback port, and on every exit removes
# that container by the id `docker run` returned, and nothing else. A name already in use
# makes `docker run` fail rather than replacing someone else's container.
#
# -Duma.store.requirePostgres=true turns a missing database into a failure, so this gate
# cannot pass by skipping its Postgres half.
set -euo pipefail

prefix=$1
tests=$2
root=$(cd "$(dirname "$0")/.." && pwd)
started=

cleanup() {
	if [[ -n "$started" ]]; then
		docker rm -f "$started" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

if [[ -z "${UMA_AS_TEST_DSN:-}" ]]; then
	name="${prefix}-$$-${RANDOM}${RANDOM}"
	started=$(docker run -d --name "$name" -e POSTGRES_USER=u4a -e POSTGRES_PASSWORD=u4a \
		-e POSTGRES_DB=u4a -p 127.0.0.1::5432 postgres:17-alpine)
	printf 'Waiting for postgres (%s)' "$name"
	ready=
	for _ in $(seq 1 60); do
		if docker exec "$started" psql -U u4a -d u4a -qtAc 'select 1' >/dev/null 2>&1; then
			ready=1
			break
		fi
		printf '.'
		sleep 1
	done
	echo
	if [[ -z "$ready" ]]; then
		echo "postgres did not accept connections within a minute" >&2
		exit 1
	fi
	port=$(docker port "$started" 5432/tcp | head -1 | sed 's/.*://')
	export UMA_AS_TEST_DSN="postgres://u4a:u4a@127.0.0.1:${port}/u4a"
	echo "store-test against PostgreSQL" \
		"$(docker exec "$started" psql -U u4a -d u4a -qtAc 'show server_version')"
else
	echo "store-test against the database UMA_AS_TEST_DSN names"
fi

cd "$root"
mvn -B -ntp -pl services/uma-as -am verify -Duma.store.requirePostgres=true \
	-Dsurefire.failIfNoSpecifiedTests=false "-Dtest=${tests}"
