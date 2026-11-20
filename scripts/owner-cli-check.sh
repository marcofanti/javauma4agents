#!/usr/bin/env bash
set -euo pipefail

project=$1
run=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
compose=(docker compose -p "$project" -f compose.fixture.yml)
"${compose[@]}" --profile owner build owner-cli

owner() {
    "${compose[@]}" --profile owner run --rm --no-deps owner-cli "$@"
}

agent() {
    "${compose[@]}" --profile check run --rm --no-deps         -e "U4A_CLI_CHECK_RUN=$run" --entrypoint /bin/sh fixture-check -ec '
          pip install -q "httpx==0.28.1" "pyjwt[crypto]==2.15.1" "cryptography==50.0.2"
          exec python /driver/owner-cli-check.py "$1"
        ' loader "$1"
}

owner key | grep 'BEGIN PUBLIC KEY' >/dev/null
owner policy | grep '"tier1"' >/dev/null
owner resources | grep 'get_positions' >/dev/null
owner ledger >/dev/null
read -r family handle <<< "$(agent prepare)"
[[ "$family" =~ ^fam_[A-Za-z0-9_-]+$ && "$handle" == jkt:* ]]
owner pending | grep -F "$family" >/dev/null
owner approve "$family"
agent approved
owner revoke "$handle"
agent revoked
