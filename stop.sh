#!/usr/bin/env bash
# =============================================================================
# stop.sh — tear down every Sentry service started by start.sh.
#
#   ./stop.sh               stop app processes + remove all containers/networks
#                           (Elasticsearch data volume is kept for next start)
#   ./stop.sh --purge       ...and delete volumes (all indexed sessions)
#   ./stop.sh --keep-infra  stop app processes only; leave Docker running
#
# App processes (dashboard, watcher, metrics, consumer, api) are stopped via
# their pid files in .run/: SIGTERM to the whole process group, SIGKILL after
# a grace period. Docker services are removed with `docker compose down`.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1
RUN_DIR="$ROOT/.run"
GRACE_SECONDS="${GRACE_SECONDS:-15}"

PURGE=0
KEEP_INFRA=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --keep-infra) KEEP_INFRA=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'; else C_OK=""; C_WARN=""; C_B=""; C_0=""; fi
ok()   { echo "  ${C_OK}✔${C_0} $*"; }
warn() { echo "  ${C_WARN}!${C_0} $*"; }
FAILED=0

stop_service() {
  local name="$1" pidfile="$RUN_DIR/$1.pid" pid waited=0
  if [ ! -f "$pidfile" ]; then
    return 0
  fi
  pid="$(cat "$pidfile" 2>/dev/null)"
  # Only act on a live process that still leads its own process group — guards
  # against signalling an unrelated process that reused a stale pid.
  if ! [[ "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null \
     || [ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" != "$pid" ]; then
    rm -f "$pidfile"
    ok "$name was not running"
    return 0
  fi
  # pid == process-group id (start.sh launches each service in its own session)
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$GRACE_SECONDS" ]; do
    sleep 1; waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    sleep 1
    warn "$name did not exit within ${GRACE_SECONDS}s — killed"
  else
    ok "$name stopped"
  fi
  # Reap stragglers left in the group (e.g. Vite's esbuild/rolldown helpers).
  kill -KILL -- "-$pid" 2>/dev/null || true
  if kill -0 "$pid" 2>/dev/null; then
    warn "could not stop $name (pid $pid)"; FAILED=1
  else
    rm -f "$pidfile"
  fi
}

echo "${C_B}==> Stopping application services${C_0}"
for svc in dashboard watcher metrics consumer api; do
  stop_service "$svc"
done
# Any other pid files (e.g. from older runs)
if [ -d "$RUN_DIR" ]; then
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -e "$pidfile" ] || continue
    stop_service "$(basename "$pidfile" .pid)"
  done
fi

if [ "$KEEP_INFRA" = 0 ]; then
  echo
  echo "${C_B}==> Removing Docker services${C_0}"
  if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
    warn "Docker daemon not reachable — skipping container teardown"
  else
    ENV_ARGS=()
    [ -f .env ] || ENV_ARGS=(--env-file .env.example)  # compose needs the variables to parse the file
    compose() { docker compose ${ENV_ARGS[@]+"${ENV_ARGS[@]}"} "$@"; }
    # stop + `rm -v` first: removes the containers together with their anonymous
    # volumes (Kafka/ZooKeeper images declare VOLUMEs), which `down` alone leaks.
    DOWN_ARGS=(down --remove-orphans)
    [ "$PURGE" = 1 ] && DOWN_ARGS+=(--volumes)
    if compose stop && compose rm -f -v && compose "${DOWN_ARGS[@]}"; then
      ok "containers, anonymous volumes and networks removed"
      if [ "$PURGE" = 1 ]; then
        ok "named volumes removed (Elasticsearch data deleted)"
      else
        ok "Elasticsearch data kept (volume sentry_es-data) — use --purge to delete it"
      fi
    else
      warn "docker compose teardown failed"; FAILED=1
    fi
  fi
fi

echo
if [ "$FAILED" = 0 ]; then
  echo "${C_B}All Sentry services stopped.${C_0}"
else
  echo "${C_B}Finished with warnings (see above).${C_0}"
fi
exit "$FAILED"
