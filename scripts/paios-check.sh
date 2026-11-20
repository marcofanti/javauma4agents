#!/usr/bin/env bash
set -euo pipefail

if [[ -n "$(docker compose ps --status running -q paios)" ]]; then
    echo "Stop the running pAI-OS instance before seeding this gate (make paios-down)." >&2
    exit 1
fi

run=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
docker compose --profile kwaai build paios
docker compose --profile kwaai run --rm --no-deps --entrypoint python -e "U4A_CHECK_RUN=$run"     paios /opt/u4a/paios-fixture.py seed

cleanup() {
    docker compose --profile kwaai stop paios >/dev/null || true
}
trap cleanup EXIT
docker compose --profile kwaai up -d paios
for _ in $(seq 1 45); do
    if docker compose exec -T paios grep -q '"event": "started"' /opt/paios/data/ability.log 2>/dev/null; then
        docker compose exec -T -e "U4A_CHECK_RUN=$run" paios python /opt/u4a/paios-fixture.py verify
        exit 0
    fi
    if [[ -z "$(docker compose ps --status running -q paios)" ]]; then
        docker compose logs --tail 30 paios
        exit 1
    fi
    sleep 2
done
docker compose logs --tail 30 paios
exit 1
