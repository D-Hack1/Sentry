"""
traffic/web_traffic.py
======================
AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
Web Traffic Generator (Aadi - ML)

Generates web application traffic across >= 6 behavioral profiles with:
- Seeded randomization per run (reproducible debugging).
- Multi-phase session behavior (changing dynamics while preserving 'web' label).
- Non-fixed packet/request sizes, IATs, jitter, and throughput.
- Support for live network sockets (client/server) and dry-run simulation.
- Detailed manifest recording meeting Requirement 20 & 22.
"""

from __future__ import annotations

import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import os
import sys

# Ensure repository root is on sys.path for direct CLI execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic.common import (
    GenerationManifest,
    TrafficPhase,
    TrafficRNG,
    build_common_parser,
    parse_and_init_traffic_session,
)

TRAFFIC_CLASS = "web"
DEFAULT_PORT = 80

AVAILABLE_PROFILES = [
    "bursty_browsing",
    "small_request_browsing",
    "large_download_browsing",
    "api_heavy_traffic",
    "asymmetric_browsing",
    "idle_heavy_browsing",
]


# ---------------------------------------------------------------------------
# Profile Configurations
# ---------------------------------------------------------------------------

def build_web_phases(profile: str, duration: float, rng: TrafficRNG) -> List[TrafficPhase]:
    """
    Construct multi-phase schedule for a web traffic session.
    Duration is partitioned into 4 to 8 dynamic phases.
    """
    phases: List[TrafficPhase] = []
    time_remaining = duration

    # Helper to allocate phase duration
    def alloc_duration(min_d: float, max_d: float) -> float:
        nonlocal time_remaining
        d = rng.sample_uniform(min_d, max_d)
        d = min(d, max(1.0, time_remaining))
        time_remaining -= d
        return round(d, 2)

    if profile == "bursty_browsing":
        while time_remaining > 2.0:
            # Phase: Initial or navigation burst
            d_burst = alloc_duration(3.0, 8.0)
            phases.append(TrafficPhase(
                name="page_load_burst",
                duration_sec=d_burst,
                params={
                    "request_count": rng.sample_int(8, 25),
                    "req_size_mean": rng.sample_trunc_norm(450, 100, 250, 800),
                    "resp_size_mean": rng.sample_trunc_norm(15000, 8000, 2000, 60000),
                    "iat_mean_ms": rng.sample_trunc_norm(80, 40, 20, 200),
                    "jitter_ratio": rng.sample_uniform(0.1, 0.4),
                }
            ))
            if time_remaining <= 2.0:
                break
            # Phase: User reading idle
            d_idle = alloc_duration(4.0, 12.0)
            phases.append(TrafficPhase(
                name="user_reading_idle",
                duration_sec=d_idle,
                params={"req_rate_per_sec": 0.0}
            ))

    elif profile == "small_request_browsing":
        while time_remaining > 2.0:
            d = alloc_duration(4.0, 10.0)
            phases.append(TrafficPhase(
                name="asset_icon_burst",
                duration_sec=d,
                params={
                    "request_count": rng.sample_int(12, 35),
                    "req_size_mean": rng.sample_trunc_norm(320, 50, 200, 500),
                    "resp_size_mean": rng.sample_trunc_norm(2500, 1000, 800, 6000),
                    "iat_mean_ms": rng.sample_trunc_norm(40, 15, 10, 100),
                    "jitter_ratio": rng.sample_uniform(0.05, 0.25),
                }
            ))
            if time_remaining <= 2.0:
                break
            d_short_gap = alloc_duration(1.5, 4.0)
            phases.append(TrafficPhase(
                name="short_think_gap",
                duration_sec=d_short_gap,
                params={"req_rate_per_sec": 0.0}
            ))

    elif profile == "large_download_browsing":
        while time_remaining > 2.0:
            # Phase 1: Small request initiator
            d_init = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="download_initiation",
                duration_sec=d_init,
                params={
                    "request_count": rng.sample_int(2, 6),
                    "req_size_mean": rng.sample_trunc_norm(500, 100, 300, 900),
                    "resp_size_mean": rng.sample_trunc_norm(10000, 3000, 4000, 25000),
                    "iat_mean_ms": 150,
                    "jitter_ratio": 0.2,
                }
            ))
            if time_remaining <= 2.0:
                break
            # Phase 2: Sustained heavy transfer
            d_heavy = alloc_duration(10.0, 25.0)
            phases.append(TrafficPhase(
                name="sustained_content_download",
                duration_sec=d_heavy,
                params={
                    "chunk_count": rng.sample_int(20, 80),
                    "req_size_mean": rng.sample_trunc_norm(400, 60, 250, 600),
                    "resp_size_mean": rng.sample_trunc_norm(65000, 20000, 20000, 131072),
                    "iat_mean_ms": rng.sample_trunc_norm(25, 10, 5, 60),
                    "jitter_ratio": rng.sample_uniform(0.15, 0.5),
                }
            ))
            if time_remaining <= 2.0:
                break
            # Phase 3: Pause
            d_pause = alloc_duration(3.0, 7.0)
            phases.append(TrafficPhase(
                name="download_complete_idle",
                duration_sec=d_pause,
                params={"req_rate_per_sec": 0.0}
            ))

    elif profile == "api_heavy_traffic":
        while time_remaining > 2.0:
            d_api = alloc_duration(4.0, 9.0)
            phases.append(TrafficPhase(
                name="rest_api_polling_batch",
                duration_sec=d_api,
                params={
                    "request_count": rng.sample_int(10, 28),
                    "req_size_mean": rng.sample_trunc_norm(800, 250, 400, 1800),
                    "resp_size_mean": rng.sample_trunc_norm(4000, 1500, 1200, 12000),
                    "iat_mean_ms": rng.sample_trunc_norm(120, 40, 50, 300),
                    "jitter_ratio": rng.sample_uniform(0.08, 0.3),
                }
            ))
            if time_remaining <= 2.0:
                break
            d_poll_gap = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="api_polling_interval",
                duration_sec=d_poll_gap,
                params={"req_rate_per_sec": 0.0}
            ))

    elif profile == "asymmetric_browsing":
        # Form/data upload dominant
        while time_remaining > 2.0:
            d_up = alloc_duration(5.0, 12.0)
            phases.append(TrafficPhase(
                name="upload_dominant_post",
                duration_sec=d_up,
                params={
                    "request_count": rng.sample_int(5, 15),
                    "req_size_mean": rng.sample_trunc_norm(45000, 15000, 15000, 90000),
                    "resp_size_mean": rng.sample_trunc_norm(800, 200, 300, 1500),
                    "iat_mean_ms": rng.sample_trunc_norm(250, 100, 80, 600),
                    "jitter_ratio": rng.sample_uniform(0.1, 0.35),
                }
            ))
            if time_remaining <= 2.0:
                break
            d_ack_gap = alloc_duration(3.0, 7.0)
            phases.append(TrafficPhase(
                name="post_processing_idle",
                duration_sec=d_ack_gap,
                params={"req_rate_per_sec": 0.0}
            ))

    else:  # idle_heavy_browsing
        while time_remaining > 2.0:
            d_burst = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="quick_read_burst",
                duration_sec=d_burst,
                params={
                    "request_count": rng.sample_int(3, 8),
                    "req_size_mean": rng.sample_trunc_norm(400, 80, 250, 700),
                    "resp_size_mean": rng.sample_trunc_norm(8000, 3000, 2000, 25000),
                    "iat_mean_ms": rng.sample_trunc_norm(100, 30, 40, 250),
                    "jitter_ratio": rng.sample_uniform(0.1, 0.4),
                }
            ))
            if time_remaining <= 2.0:
                break
            d_long_idle = alloc_duration(8.0, 18.0)
            phases.append(TrafficPhase(
                name="extended_idle_reading",
                duration_sec=d_long_idle,
                params={"req_rate_per_sec": 0.0}
            ))

    # Pad remaining fraction of a second if any
    if time_remaining > 0.0:
        phases.append(TrafficPhase(
            name="final_settle_idle",
            duration_sec=round(time_remaining, 2),
            params={"req_rate_per_sec": 0.0}
        ))

    return phases


# ---------------------------------------------------------------------------
# Simple HTTP Server for Responder Container
# ---------------------------------------------------------------------------

class ResponderHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default noisy console logs

    def do_GET(self) -> None:
        resp_size = 4096
        # Parse optional size query param /?size=1024
        if "?" in self.path:
            parts = self.path.split("?")[-1].split("&")
            for p in parts:
                if p.startswith("size="):
                    try:
                        resp_size = max(64, min(2_000_000, int(p.split("=")[1])))
                    except ValueError:
                        pass
        data = b"X" * resp_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            _ = self.rfile.read(content_len)
        resp = json.dumps({"status": "ok", "received_bytes": content_len}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def run_http_server(bind_host: str, port: int) -> None:
    server = HTTPServer((bind_host, port), ResponderHTTPHandler)
    print(f"[*] Web responder server running on {bind_host}:{port} (Ctrl+C to stop)...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# Traffic Generation Engine
# ---------------------------------------------------------------------------

def execute_web_session(
    target_host: str,
    target_port: int,
    profile: str,
    duration: float,
    start_delay: float,
    rng: TrafficRNG,
    session_id: str,
    dry_run: bool = False,
) -> Tuple[GenerationManifest, int, int]:
    """
    Execute all phases of a web session, pacing requests and recording stats.
    """
    print(f"[*] Starting web traffic generation:")
    print(f"    Profile:     {profile}")
    print(f"    Seed:        {rng.seed}")
    print(f"    Duration:    {duration:.2f}s")
    print(f"    Start Delay: {start_delay:.2f}s")
    print(f"    Target:      {target_host}:{target_port} (dry-run: {dry_run})")

    # Start delay (Requirement 10)
    if not dry_run and start_delay > 0:
        time.sleep(start_delay)

    phases = build_web_phases(profile, duration, rng)
    phase_descriptions = [
        {"name": p.name, "duration_sec": p.duration_sec, "params": p.params}
        for p in phases
    ]

    total_packets = 0
    total_bytes = 0
    start_time = time.time()
    session_success = True
    failure_msg = None

    for idx, phase in enumerate(phases):
        phase_start = time.time()
        print(f"  -> Phase {idx+1}/{len(phases)}: {phase.name} ({phase.duration_sec}s)")

        if "request_count" in phase.params:
            req_count = phase.params["request_count"]
            req_size_mean = phase.params["req_size_mean"]
            resp_size_mean = phase.params["resp_size_mean"]
            iat_mean_ms = phase.params["iat_mean_ms"]
            jitter_ratio = phase.params["jitter_ratio"]

            for r_idx in range(req_count):
                now = time.time()
                if now - start_time >= duration:
                    break

                # Sample packet sizes from distributions (Requirements 4, 12, 13)
                req_size = int(rng.sample_trunc_norm(
                    req_size_mean, req_size_mean * 0.25, 128, 120_000
                ))
                resp_size = int(rng.sample_trunc_norm(
                    resp_size_mean, resp_size_mean * 0.35, 256, 300_000
                ))

                if not dry_run:
                    try:
                        conn = http.client.HTTPConnection(target_host, target_port, timeout=4.0)
                        if "upload" in phase.name:
                            # POST upload
                            payload = b"U" * req_size
                            headers = {"Content-Type": "application/octet-stream"}
                            conn.request("POST", "/api/upload", body=payload, headers=headers)
                        else:
                            # GET download
                            conn.request("GET", f"/?size={resp_size}")

                        resp = conn.getresponse()
                        _ = resp.read()
                        conn.close()
                    except Exception as e:
                        # Non-fatal during live trace if target momentarily stalls
                        session_success = False
                        failure_msg = f"HTTP error during {phase.name}: {e}"

                # Calculate volume metrics (approx. IP packet framing ~ 1400 MTU)
                req_pkts = max(1, req_size // 1420 + 1)
                resp_pkts = max(1, resp_size // 1420 + 1)
                total_packets += (req_pkts + resp_pkts)
                total_bytes += (req_size + resp_size)

                # Sample IAT with jitter (Requirements 5, 6, 14)
                iat_ms = rng.apply_jitter(iat_mean_ms, jitter_ratio, min_val=2.0)
                iat_sec = iat_ms / 1000.0

                if not dry_run:
                    time.sleep(min(iat_sec, max(0.0, (phase_start + phase.duration_sec) - time.time())))

        # Idle phase
        elapsed_phase = time.time() - phase_start
        remaining_phase = phase.duration_sec - elapsed_phase
        if remaining_phase > 0 and not dry_run:
            time.sleep(remaining_phase)

    actual_duration = round(time.time() - start_time, 2)
    if dry_run:
        actual_duration = duration

    # Build manifest
    manifest = GenerationManifest(
        session_id=session_id,
        traffic_class=TRAFFIC_CLASS,
        profile=profile,
        seed=rng.seed,
        duration_sec=actual_duration,
        start_delay_sec=start_delay,
        generation_params={
            "profile": profile,
            "target": f"{target_host}:{target_port}",
            "phases": phase_descriptions,
        },
        status="valid" if (session_success or dry_run) else "failed",
        failure_reason=None if (session_success or dry_run) else failure_msg,
        packets_sent=total_packets,
        bytes_sent=total_bytes,
    )

    return manifest, total_packets, total_bytes


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_common_parser(
        traffic_class=TRAFFIC_CLASS,
        default_port=DEFAULT_PORT,
        available_profiles=AVAILABLE_PROFILES,
        description="SIH 2026 Web Traffic Generator with behavioral profiles and multi-phase schedules.",
    )

    args, rng, duration, start_delay, session_id = parse_and_init_traffic_session(
        parser=parser,
        traffic_class=TRAFFIC_CLASS,
        available_profiles=AVAILABLE_PROFILES,
    )

    if args.server_mode:
        run_http_server(args.bind_host, args.target_port)
        return

    manifest, pkts, bytes_total = execute_web_session(
        target_host=args.target_host,
        target_port=args.target_port,
        profile=args.profile,
        duration=duration,
        start_delay=start_delay,
        rng=rng,
        session_id=session_id,
        dry_run=args.dry_run,
    )

    manifest.write_to_file(args.manifest_out)
    print(f"[+] Web session completed successfully:")
    print(f"    Packets:   {pkts}")
    print(f"    Bytes:     {bytes_total}")
    print(f"    Manifest:  {args.manifest_out}")


if __name__ == "__main__":
    main()
