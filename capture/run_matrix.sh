#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=../scripts/env.sh
source "$ROOT/scripts/env.sh"
load_env_file "$ROOT/.env" || { echo "missing $ROOT/.env (cp .env.example .env)" >&2; exit 1; }

# gen_config.py needs jinja2 + python-dotenv: prefer the project venv (created by start.sh)
PY="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3

PCAP_ABS="$ROOT/$PCAP_DIR"
mkdir -p "$PCAP_ABS"

CAPTURE_FILTER="esp or udp port 500 or udp port 4500"
CONN="sentry"

IFS=',' read -ra MODES <<< "$MATRIX_MODES"
IFS=',' read -ra CIPHERS <<< "$MATRIX_CIPHERS"
IFS=',' read -ra DHS <<< "$MATRIX_DH_GROUPS"
IFS=',' read -ra PFSS <<< "$MATRIX_PFS"
IFS=',' read -ra TRAFFICS <<< "$TRAFFIC_TYPES"

total=0
ok=0
failed=()

apply_config() {
    for c in "$INITIATOR_CONTAINER" "$RESPONDER_CONTAINER"; do
        docker exec "$c" bash -c \
            "cp /etc/ipsec.d/generated/ipsec.conf /etc/ipsec.conf && cp /etc/ipsec.d/generated/ipsec.secrets /etc/ipsec.secrets && chmod 600 /etc/ipsec.secrets"
    done
}

stop_ipsec() {
    for c in "$INITIATOR_CONTAINER" "$RESPONDER_CONTAINER"; do
        docker exec "$c" ipsec stop >/dev/null 2>&1
    done
}

start_ipsec() {
    docker exec "$RESPONDER_CONTAINER" ipsec start >/dev/null 2>&1
    docker exec "$INITIATOR_CONTAINER" ipsec start >/dev/null 2>&1
    for _ in $(seq 1 15); do
        if docker exec "$INITIATOR_CONTAINER" ipsec status >/dev/null 2>&1 &&
           docker exec "$RESPONDER_CONTAINER" ipsec status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start_servers() {
    docker exec -d "$RESPONDER_CONTAINER" iperf3 -s
    docker exec -d "$RESPONDER_CONTAINER" busybox httpd -f -p 80 -h /srv/www
    docker exec -d "$RESPONDER_CONTAINER" sh -c 'while true; do busybox nc -lu -p 5004 >/dev/null; done'
    docker exec -d "$RESPONDER_CONTAINER" sh -c 'while true; do busybox nc -lu -p 5006 >/dev/null; done'
}

stop_all_captures() {
    docker exec "$MONITOR_CONTAINER" sh -c 'for p in $(pidof tcpdump); do kill -INT $p; done' >/dev/null 2>&1
    for _ in $(seq 1 10); do
        docker exec "$MONITOR_CONTAINER" pidof tcpdump >/dev/null 2>&1 || return 0
        sleep 0.5
    done
}

start_capture() {
    stop_all_captures
    docker exec "$MONITOR_CONTAINER" rm -f "/data/capture/$1.pcap"
    docker exec -d "$MONITOR_CONTAINER" tcpdump -U -Z root -i eth0 -w "/data/capture/$1.pcap" "$CAPTURE_FILTER"
    sleep 2
}

generate_traffic() {
    local traffic="$1" t="$TRAFFIC_SECONDS"
    case "$traffic" in
        icmp)
            docker exec "$INITIATOR_CONTAINER" ping -c $((t * 5)) -i 0.2 "$RESPONDER_IP" >/dev/null 2>&1
            ;;
        web)
            docker exec "$INITIATOR_CONTAINER" bash -c \
                "end=\$((SECONDS + $t)); while [ \$SECONDS -lt \$end ]; do curl -s -o /dev/null http://$RESPONDER_IP/index.html; sleep 0.4; done"
            ;;
        file_transfer)
            docker exec "$INITIATOR_CONTAINER" iperf3 -c "$RESPONDER_IP" -t "$t" -b 20M >/dev/null 2>&1
            ;;
        voip)
            docker exec "$INITIATOR_CONTAINER" ffmpeg -loglevel error -re -f lavfi -i "sine=frequency=440:duration=$t" \
                -ar 8000 -ac 1 -acodec pcm_mulaw -f rtp "rtp://$RESPONDER_IP:5004" >/dev/null 2>&1
            ;;
        video_stream)
            docker exec "$INITIATOR_CONTAINER" ffmpeg -loglevel error -re -f lavfi -i "testsrc=size=640x360:rate=25:duration=$t" \
                -c:v libx264 -preset ultrafast -tune zerolatency -f mpegts "udp://$RESPONDER_IP:5006?pkt_size=1316" >/dev/null 2>&1
            ;;
    esac
}

run_combo() {
    local mode="$1" cipher="$2" dh="$3" pfs="$4" traffic="$5" seq="$6"
    local pfs_tag="pfs"
    [ "$pfs" = "no" ] && pfs_tag="nopfs"
    local name="${mode}_${cipher}_${dh}_${pfs_tag}_${traffic}_${seq}"

    total=$((total + 1))
    if [ "$SKIP_EXISTING" = "yes" ] && [ -s "$PCAP_ABS/$name.pcap" ]; then
        echo "[$total] $name skipped"
        ok=$((ok + 1))
        return
    fi
    echo "[$total] $name"

    "$PY" "$ROOT/capture/gen_config.py" --mode "$mode" --cipher "$cipher" --dh-group "$dh" --pfs "$pfs" || { failed+=("$name"); return; }

    stop_ipsec
    apply_config
    if ! start_ipsec; then
        echo "  strongswan failed to start"
        failed+=("$name")
        return
    fi

    start_capture "$name"
    docker exec "$INITIATOR_CONTAINER" ipsec up "$CONN" >/dev/null 2>&1

    if bash "$ROOT/capture/verify_sa.sh" "$SA_TIMEOUT"; then
        generate_traffic "$traffic"
        docker exec "$INITIATOR_CONTAINER" ipsec down "$CONN" >/dev/null 2>&1
        sleep 1
        stop_all_captures
        ok=$((ok + 1))
    else
        stop_all_captures
        rm -f "$PCAP_ABS/$name.pcap"
        failed+=("$name")
    fi

    stop_ipsec
}

start_servers

combos=()
for mode in "${MODES[@]}"; do
    for cipher in "${CIPHERS[@]}"; do
        for dh in "${DHS[@]}"; do
            for pfs in "${PFSS[@]}"; do
                combos+=("$mode $cipher $dh $pfs")
            done
        done
    done
done

n_traffic="${#TRAFFICS[@]}"

for i in "${!combos[@]}"; do
    run_combo ${combos[$i]} "${TRAFFICS[$((i % n_traffic))]}" 001
done

for i in $(seq 0 $((EXTRA_SESSIONS - 1))); do
    idx=$((i * ${#combos[@]} / EXTRA_SESSIONS))
    run_combo ${combos[$idx]} "${TRAFFICS[$(((idx + 1) % n_traffic))]}" 002
done

stop_all_captures
echo "completed $ok/$total"
if [ "${#failed[@]}" -gt 0 ]; then
    printf 'failed: %s\n' "${failed[@]}" >&2
    exit 1
fi
