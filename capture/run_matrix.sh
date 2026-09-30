#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
set -a
source <(sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/\1="\2"/' "$ROOT/.env")
set +a

PCAP_ABS="$ROOT/$PCAP_DIR"
MANIFEST_ABS="$ROOT/capture/manifests"
mkdir -p "$PCAP_ABS" "$MANIFEST_ABS"

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

start_traffic_server() {
    local traffic="$1"
    case "$traffic" in
        web)
            docker exec -d "$RESPONDER_CONTAINER" sh -c \
                'python3 /opt/traffic/web_traffic.py --server-mode --bind-host 0.0.0.0 --target-port 80 & echo $! > /tmp/srv.pid'
            ;;
        file_transfer)
            docker exec -d "$RESPONDER_CONTAINER" sh -c \
                'nginx -c /etc/nginx-file-transfer.conf -g "daemon off;" & echo $! > /tmp/srv.pid'
            ;;
        voip)
            docker exec -d "$RESPONDER_CONTAINER" sh -c \
                'python3 /opt/traffic/voip_sim.py --server-mode --bind-host 0.0.0.0 --target-port 5004 & echo $! > /tmp/srv.pid'
            ;;
        video_stream)
            docker exec -d "$RESPONDER_CONTAINER" sh -c \
                'python3 /opt/traffic/video_stream.py --server-mode --bind-host 0.0.0.0 --target-port 8080 & echo $! > /tmp/srv.pid'
            ;;
    esac
    sleep 1
}

stop_traffic_server() {
    docker exec "$RESPONDER_CONTAINER" sh -c 'kill $(cat /tmp/srv.pid) 2>/dev/null; rm -f /tmp/srv.pid' >/dev/null 2>&1
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
    local traffic="$1" name="$2" t="$TRAFFIC_SECONDS"
    local manifest="/data/manifest/$name.json"
    case "$traffic" in
        icmp)
            docker exec "$INITIATOR_CONTAINER" python3 /opt/traffic/icmp_flood.py \
                --target-host "$RESPONDER_IP" --duration "$t" >/dev/null 2>&1
            ;;
        web)
            docker exec "$INITIATOR_CONTAINER" python3 /opt/traffic/web_traffic.py \
                --target-host "$RESPONDER_IP" --target-port 80 --duration "$t" --start-delay 0 \
                --session-id "$name" --manifest-out "$manifest" >/dev/null 2>&1
            ;;
        file_transfer)
            docker exec "$INITIATOR_CONTAINER" python3 /opt/traffic/file_transfer.py \
                --target-host "$RESPONDER_IP" --target-port 80 --duration "$t" --start-delay 0 \
                --session-id "$name" --manifest-out "$manifest" >/dev/null 2>&1
            ;;
        voip)
            docker exec "$INITIATOR_CONTAINER" python3 /opt/traffic/voip_sim.py \
                --target-host "$RESPONDER_IP" --target-port 5004 --duration "$t" --start-delay 0 \
                --session-id "$name" --manifest-out "$manifest" >/dev/null 2>&1
            ;;
        video_stream)
            docker exec "$INITIATOR_CONTAINER" python3 /opt/traffic/video_stream.py \
                --target-host "$RESPONDER_IP" --target-port 8080 --duration "$t" --start-delay 0 \
                --session-id "$name" --manifest-out "$manifest" >/dev/null 2>&1
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

    python3 "$ROOT/capture/gen_config.py" --mode "$mode" --cipher "$cipher" --dh-group "$dh" --pfs "$pfs" || { failed+=("$name"); return; }

    stop_ipsec
    apply_config
    if ! start_ipsec; then
        echo "  strongswan failed to start"
        failed+=("$name")
        return
    fi

    start_capture "$name"
    start_traffic_server "$traffic"
    docker exec "$INITIATOR_CONTAINER" ipsec up "$CONN" >/dev/null 2>&1

    if bash "$ROOT/capture/verify_sa.sh" "$SA_TIMEOUT"; then
        generate_traffic "$traffic" "$name"
        docker exec "$INITIATOR_CONTAINER" ipsec down "$CONN" >/dev/null 2>&1
        sleep 1
        stop_all_captures
        ok=$((ok + 1))
    else
        stop_all_captures
        rm -f "$PCAP_ABS/$name.pcap"
        failed+=("$name")
    fi

    stop_traffic_server
    stop_ipsec
}

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
