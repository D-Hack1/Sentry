#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set -a
source "$ROOT/.env"
set +a

TIMEOUT="${1:-$SA_TIMEOUT}"
INTERVAL=1
elapsed=0

sa_up() {
    docker exec "$1" ip xfrm state 2>/dev/null | grep -q "proto esp"
}

while [ "$elapsed" -lt "$TIMEOUT" ]; do
    if sa_up "$INITIATOR_CONTAINER" && sa_up "$RESPONDER_CONTAINER"; then
        echo "ESP SA established on initiator and responder after ${elapsed}s"
        exit 0
    fi
    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
done

echo "ESP SA not established within ${TIMEOUT}s" >&2
exit 1
