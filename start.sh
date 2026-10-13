#!/usr/bin/env bash
# =============================================================================
# start.sh — bootstrap and start every Sentry service.
#
#   ./start.sh                 everything (infra + capture lab + app + dashboard)
#   ./start.sh --no-lab        skip the strongSwan capture lab containers
#   ./start.sh --no-dashboard  skip the Vite dashboard
#   ./start.sh --skip-install  don't (re)install Python / npm dependencies
#
# Bootstraps:  .env (from .env.example), Python venv + requirements,
#              dashboard node_modules, Elasticsearch index.
# Starts:      Docker: zookeeper, kafka (+ topic init), elasticsearch,
#                      [initiator, responder, monitor]
#              Local:  api (FastAPI :8000), consumer, metrics producer,
#                      watcher (+ Kafka producer), dashboard (Vite :5173)
# Safe to re-run: services that are already running are left alone.
# Stop everything with ./stop.sh
# =============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RUN_DIR="$ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"

WITH_LAB=1
WITH_DASHBOARD=1
DO_INSTALL=1

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case "$arg" in
    --no-lab) WITH_LAB=0 ;;
    --no-dashboard) WITH_DASHBOARD=0 ;;
    --skip-install) DO_INSTALL=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_B=""; C_0=""
fi
step() { echo; echo "${C_B}==> $*${C_0}"; }
ok()   { echo "  ${C_OK}✔${C_0} $*"; }
warn() { echo "  ${C_WARN}!${C_0} $*"; }
die()  { echo "  ${C_ERR}✘ $*${C_0}" >&2; exit 1; }
trap 'echo "${C_ERR}start.sh failed at line $LINENO. Logs: $LOG_DIR — run ./stop.sh to clean up.${C_0}" >&2' ERR
hash_file() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# ── 1. Preflight ─────────────────────────────────────────────────────────────
step "Preflight checks"
command -v docker >/dev/null || die "docker is not installed"
docker info >/dev/null 2>&1 || die "the Docker daemon is not running (or you lack permission to use it)"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 ('docker compose') is required"
command -v curl >/dev/null || die "curl is required"
ok "docker $(docker version --format '{{.Server.Version}}'), $(docker compose version --short 2>/dev/null || echo compose)"

PYTHON_BIN="${PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      PYTHON_BIN="$candidate"; break
    fi
  done
fi
[ -n "$PYTHON_BIN" ] || die "Python >= 3.11 is required (set PYTHON=/path/to/python3.11+)"
ok "$("$PYTHON_BIN" --version) ($PYTHON_BIN)"

if [ "$WITH_DASHBOARD" = 1 ]; then
  command -v node >/dev/null && command -v npm >/dev/null || die "Node.js >= 20 and npm are required for the dashboard (or use --no-dashboard)"
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
  [ "$NODE_MAJOR" -ge 20 ] || die "Node.js >= 20 is required (found $(node --version))"
  ok "node $(node --version), npm $(npm --version)"
fi

# ── 2. Configuration ─────────────────────────────────────────────────────────
step "Configuration"
if [ ! -f .env ]; then
  cp .env.example .env
  ok "created .env from .env.example (edit IPSEC_PSK before real captures)"
else
  ok ".env present"
fi
# shellcheck source=scripts/env.sh
source "$ROOT/scripts/env.sh"
load_env_file .env
API_PORT="${API_PORT:-8000}"
DASHBOARD_PORT="${DASHBOARD_PORT:-5173}"
CAPTURES_DIR="${CAPTURES_DIR:-$ROOT/${PCAP_DIR:-capture/pcaps}}"
export API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:$API_PORT}"
export CORS_ORIGINS="${CORS_ORIGINS:-http://localhost:$DASHBOARD_PORT,http://127.0.0.1:$DASHBOARD_PORT}"
export VITE_API_BASE_URL="${VITE_API_BASE_URL:-http://127.0.0.1:$API_PORT}"
export CAPTURES_DIR PYTHONUNBUFFERED=1
mkdir -p "$LOG_DIR" "$CAPTURES_DIR" "$ROOT/${CONFIG_DIR:-capture/configs}/initiator" \
         "$ROOT/${CONFIG_DIR:-capture/configs}/responder" "$ROOT/data/features"
ok "captures dir: $CAPTURES_DIR"

# ── 3. Python environment ────────────────────────────────────────────────────
step "Python environment (.venv)"
if [ ! -x "$PY" ]; then
  "$PYTHON_BIN" -m venv "$VENV" || die "could not create $VENV (on Debian/Ubuntu: apt install python3-venv)"
  "$PY" -m pip install --quiet --upgrade pip
  ok "created $VENV"
fi
REQ_HASH="$(hash_file requirements.txt)"
REQ_STAMP="$(cat "$VENV/.requirements.sha256" 2>/dev/null || true)"
# --skip-install only skips *re*-installs: a venv that never had the requirements gets them.
if { [ "$DO_INSTALL" = 1 ] && [ "$REQ_STAMP" != "$REQ_HASH" ]; } || [ -z "$REQ_STAMP" ]; then
  echo "  installing requirements.txt (first run takes a few minutes)..."
  "$PY" -m pip install --quiet --disable-pip-version-check -r requirements.txt
  echo "$REQ_HASH" > "$VENV/.requirements.sha256"
  ok "requirements installed"
else
  ok "requirements up to date"
fi
MODEL_DIR_CHECK="${MODEL_DIR:-$ROOT/ml}"
for f in protocol_model.joblib traffic_model.joblib anomaly_model.joblib encoder.joblib; do
  [ -f "$MODEL_DIR_CHECK/$f" ] || die "missing $MODEL_DIR_CHECK/$f — train with: $PY ml/train.py (needs data/features/*.parquet)"
done
ok "model artefacts present in $MODEL_DIR_CHECK"
if "$PY" -c "from weasyprint import HTML" >/dev/null 2>&1; then
  ok "WeasyPrint (PDF reports) available"
else
  warn "WeasyPrint cannot load its system libraries — PDF reports will fail."
  warn "Install Pango: apt install libpango-1.0-0 libpangoft2-1.0-0  |  brew install pango"
fi

# ── 4. Dashboard dependencies ────────────────────────────────────────────────
if [ "$WITH_DASHBOARD" = 1 ]; then
  step "Dashboard dependencies"
  LOCK_HASH="$(hash_file dashboard/package-lock.json)"
  LOCK_STAMP="$(cat dashboard/node_modules/.package-lock.sha256 2>/dev/null || true)"
  if { [ "$DO_INSTALL" = 1 ] && [ "$LOCK_STAMP" != "$LOCK_HASH" ]; } || [ ! -x dashboard/node_modules/.bin/vite ]; then
    (cd dashboard && npm ci --no-audit --no-fund --loglevel=error)
    echo "$LOCK_HASH" > dashboard/node_modules/.package-lock.sha256
    ok "npm ci done"
  else
    ok "node_modules up to date"
  fi
fi

# ── 5. Docker services ───────────────────────────────────────────────────────
container_of() { docker compose ps -a -q "$1" 2>/dev/null | head -n1; }

wait_healthy() {  # service timeout_seconds
  local svc="$1" timeout="$2" waited=0 cid status
  while :; do
    cid="$(container_of "$svc")"
    status="$( [ -n "$cid" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo missing)"
    [ "$status" = healthy ] && { ok "$svc healthy (${waited}s)"; return 0; }
    [ "$waited" -ge "$timeout" ] && die "$svc not healthy after ${timeout}s (status: $status) — see: docker compose logs $svc"
    sleep 3; waited=$((waited + 3))
  done
}

step "Infrastructure containers (zookeeper, kafka, elasticsearch)"
docker compose up -d zookeeper kafka kafka-init elasticsearch
wait_healthy kafka 180
wait_healthy elasticsearch 240
waited=0
while :; do
  cid="$(container_of kafka-init)"
  st=missing; code=""
  [ -n "$cid" ] && read -r st code < <(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$cid")
  if [ "$st" = exited ]; then
    [ "$code" = 0 ] || die "kafka-init failed (exit $code) — see: docker compose logs kafka-init"
    ok "Kafka topics created"; break
  fi
  [ "$waited" -ge 120 ] && die "kafka-init did not finish within 120s"
  sleep 2; waited=$((waited + 2))
done

if [ "$WITH_LAB" = 1 ]; then
  step "Capture lab containers (initiator, responder, monitor)"
  docker compose up -d --build initiator responder monitor \
    || die "lab build/start failed (Debian mirrors unreachable?). Re-run with --no-lab to start everything else."
  docker exec "$MONITOR_CONTAINER" ip link set eth0 promisc on \
    && ok "monitor eth0 in promiscuous mode" || warn "could not enable promiscuous mode on the monitor"
  docker run --rm --net=host --cap-add=NET_ADMIN sentry-monitor ip link set "$BRIDGE_NAME" type bridge ageing_time 0 \
    && ok "bridge $BRIDGE_NAME floods all frames to the monitor" \
    || warn "could not set bridge ageing_time (captures may miss traffic; Docker Desktop does not expose the bridge)"
fi

step "Health checks"
"$PY" kafka/health_check.py
"$PY" es/init_index.py
"$PY" es/health_check.py

# ── 6. Application processes ────────────────────────────────────────────────
LAUNCHER='
import os, sys
try:
    os.setsid()
except OSError:          # already a process-group leader: fork first
    if os.fork():
        os._exit(0)
    os.setsid()
with open(sys.argv[1], "w") as fh:
    fh.write(str(os.getpid()))
os.execvp(sys.argv[2], sys.argv[2:])
'
JUST_STARTED=0
pid_alive() {  # live AND still the leader of its own process group (not a recycled pid)
  local f="$RUN_DIR/$1.pid" pid
  [ -f "$f" ] || return 1
  pid="$(cat "$f" 2>/dev/null)"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null \
    && [ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" = "$pid" ]
}
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

start_service() {  # name workdir command...
  local name="$1" dir="$2"; shift 2
  local log="$LOG_DIR/$name.log" pidfile="$RUN_DIR/$name.pid"
  JUST_STARTED=0
  if pid_alive "$name"; then ok "$name already running (pid $(cat "$pidfile"))"; return 0; fi
  JUST_STARTED=1
  rm -f "$pidfile"
  echo "---- $(date -u +%FT%TZ) starting $name ----" >> "$log"
  # Each service gets its own session/process group (portable setsid via Python),
  # so stop.sh can signal the whole tree. The child writes its own pid — which is
  # also its process-group id — before exec'ing the real command.
  # Redirect the whole background job, and exec, so no helper shell keeps
  # start.sh's stdout open (that would hang `./start.sh | tee ...`).
  ( cd "$dir" && exec "$PY" -c "$LAUNCHER" "$pidfile" "$@" ) >> "$log" 2>&1 < /dev/null &
  local _
  for _ in $(seq 1 50); do [ -s "$pidfile" ] && break; sleep 0.1; done
  [ -s "$pidfile" ] || die "$name did not start — see $log"
}

wait_http() {  # name url timeout
  local name="$1" url="$2" timeout="$3" waited=0
  [ "$JUST_STARTED" = 1 ] || return 0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    if ! pid_alive "$name"; then echo; tail -n 25 "$LOG_DIR/$name.log" >&2; die "$name exited during startup — log above"; fi
    [ "$waited" -ge "$timeout" ] && { tail -n 25 "$LOG_DIR/$name.log" >&2; die "$name not reachable at $url after ${timeout}s"; }
    sleep 1; waited=$((waited + 1))
  done
  ok "$name up at $url (pid $(cat "$RUN_DIR/$name.pid"), log .run/logs/$name.log)"
}

confirm_running() {  # name — catches immediate crashes (bad config, Kafka down...)
  [ "$JUST_STARTED" = 1 ] || return 0
  sleep 3
  if ! pid_alive "$1"; then tail -n 25 "$LOG_DIR/$1.log" >&2; die "$1 exited right after starting — log above"; fi
  ok "$1 running (pid $(cat "$RUN_DIR/$1.pid"), log .run/logs/$1.log)"
}

step "Application services"
if ! pid_alive api && port_busy "$API_PORT"; then die "port $API_PORT is already in use by another process"; fi
start_service api "$ROOT" "$VENV/bin/uvicorn" api.main:app --host 127.0.0.1 --port "$API_PORT" --timeout-graceful-shutdown 5
wait_http api "http://127.0.0.1:$API_PORT/health" 120

start_service consumer "$ROOT" "$PY" kafka/consumer.py --api-url "$API_BASE_URL"
confirm_running consumer
start_service metrics "$ROOT" "$PY" kafka/metrics_producer.py
confirm_running metrics
start_service watcher "$ROOT" "$PY" -m features.watcher --captures-dir "$CAPTURES_DIR"
confirm_running watcher

if [ "$WITH_DASHBOARD" = 1 ]; then
  if ! pid_alive dashboard && port_busy "$DASHBOARD_PORT"; then die "port $DASHBOARD_PORT is already in use by another process"; fi
  start_service dashboard "$ROOT/dashboard" ./node_modules/.bin/vite --host 127.0.0.1 --port "$DASHBOARD_PORT" --strictPort
  wait_http dashboard "http://127.0.0.1:$DASHBOARD_PORT/" 60
fi

trap - ERR
HEALTH="$(curl -fsS "http://127.0.0.1:$API_PORT/health" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
echo
echo "${C_B}Sentry is running${C_0} (API health: $HEALTH)"
[ "$WITH_DASHBOARD" = 1 ] && echo "  Dashboard      http://localhost:$DASHBOARD_PORT"
echo "  API            http://localhost:$API_PORT   (docs: /docs)"
echo "  Elasticsearch  ${ES_HOST}"
echo "  Kafka          ${KAFKA_BOOTSTRAP}"
echo "  Watching       $CAPTURES_DIR for new .pcap files"
echo "  Logs           .run/logs/   (tail -f .run/logs/*.log)"
echo
echo "  Try it:        .venv/bin/python scripts/synth_pcap.py --traffic voip   # synthetic capture -> watcher"
echo "                 .venv/bin/python scripts/e2e_test.py                    # end-to-end self test"
[ "$WITH_LAB" = 1 ] && echo "                 make matrix                                             # real captures from the lab"
echo "  Stop:          ./stop.sh   (./stop.sh --purge also deletes Elasticsearch data)"
