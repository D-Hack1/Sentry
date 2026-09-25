"""
traffic/video_stream.py
=======================
AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
Video Streaming Generator (Aadi - ML)

Generates DASH/HLS-style chunked video streaming traffic across >= 6 behavioral profiles.
Strictly adheres to SIH 2026 requirements:
- NEVER uses a single fixed bitrate, burst interval, or packet size.
- Profiles model adaptive bitrates (360p to 4K), buffering stalls, quality switching,
  variable chunk durations, and bursty segment downloads over TCP.
- Seeded randomization per run, recorded in the manifest.
- TCP/HTTP chunk downloader with built-in video server responder and dry-run simulation.
"""

from __future__ import annotations

import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic.common import (
    GenerationManifest,
    TrafficPhase,
    TrafficRNG,
    build_common_parser,
    parse_and_init_traffic_session,
)

TRAFFIC_CLASS = "video_stream"
DEFAULT_PORT = 8080

AVAILABLE_PROFILES = [
    "low_bitrate_stream",
    "medium_bitrate_stream",
    "high_bitrate_stream",
    "bursty_adaptive_stream",
    "buffering_heavy_stream",
    "variable_quality_stream",
]


# ---------------------------------------------------------------------------
# Profile Configurations
# ---------------------------------------------------------------------------

def build_video_phases(profile: str, duration: float, rng: TrafficRNG) -> List[TrafficPhase]:
    """
    Construct multi-phase schedules for video streaming sessions.
    Each profile models segment fetches (bursts) and playback intervals (gaps).
    """
    phases: List[TrafficPhase] = []
    time_remaining = duration

    def alloc_duration(min_d: float, max_d: float) -> float:
        nonlocal time_remaining
        d = rng.sample_uniform(min_d, max_d)
        d = min(d, max(1.0, time_remaining))
        time_remaining -= d
        return round(d, 2)

    if profile == "low_bitrate_stream":
        # 360p/480p mobile video: smaller segment bursts (150KB - 400KB)
        while time_remaining > 2.0:
            d_init = alloc_duration(3.0, 6.0)
            phases.append(TrafficPhase(
                name="low_res_initial_buffering",
                duration_sec=d_init,
                params={
                    "segment_count": rng.sample_int(3, 5),
                    "chunk_size_mean": rng.sample_trunc_norm(180_000, 30_000, 100_000, 300_000),
                    "chunk_size_std": 25_000.0,
                    "segment_iat_sec": 0.4,
                    "jitter_ratio": 0.15,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_play = alloc_duration(8.0, 20.0)
            phases.append(TrafficPhase(
                name="low_res_steady_playback",
                duration_sec=d_play,
                params={
                    "segment_count": rng.sample_int(2, 6),
                    "chunk_size_mean": rng.sample_trunc_norm(220_000, 35_000, 120_000, 350_000),
                    "chunk_size_std": 30_000.0,
                    "segment_iat_sec": rng.sample_trunc_norm(3.0, 0.5, 2.0, 4.5),
                    "jitter_ratio": 0.2,
                }
            ))

    elif profile == "medium_bitrate_stream":
        # 720p/1080p standard HD: moderate bursts (600KB - 2MB)
        while time_remaining > 2.0:
            d_buf = alloc_duration(3.0, 7.0)
            phases.append(TrafficPhase(
                name="hd_buffer_precharge",
                duration_sec=d_buf,
                params={
                    "segment_count": rng.sample_int(3, 6),
                    "chunk_size_mean": rng.sample_trunc_norm(750_000, 100_000, 450_000, 1_200_000),
                    "chunk_size_std": 80_000.0,
                    "segment_iat_sec": 0.35,
                    "jitter_ratio": 0.12,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_steady = alloc_duration(10.0, 24.0)
            phases.append(TrafficPhase(
                name="hd_steady_cadence",
                duration_sec=d_steady,
                params={
                    "segment_count": rng.sample_int(4, 9),
                    "chunk_size_mean": rng.sample_trunc_norm(900_000, 150_000, 500_000, 1_600_000),
                    "chunk_size_std": 120_000.0,
                    "segment_iat_sec": rng.sample_trunc_norm(2.5, 0.4, 1.8, 3.8),
                    "jitter_ratio": 0.15,
                }
            ))

    elif profile == "high_bitrate_stream":
        # 4K UHD: heavy multi-megabyte chunk bursts (2.5MB - 7MB)
        while time_remaining > 2.0:
            d_4k_burst = alloc_duration(4.0, 10.0)
            phases.append(TrafficPhase(
                name="4k_large_chunk_burst",
                duration_sec=d_4k_burst,
                params={
                    "segment_count": rng.sample_int(3, 7),
                    "chunk_size_mean": rng.sample_trunc_norm(3_500_000, 600_000, 2_000_000, 6_500_000),
                    "chunk_size_std": 450_000.0,
                    "segment_iat_sec": 0.8,
                    "jitter_ratio": 0.25,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_gap = alloc_duration(5.0, 14.0)
            phases.append(TrafficPhase(
                name="4k_playback_drain",
                duration_sec=d_gap,
                params={
                    "segment_count": rng.sample_int(2, 4),
                    "chunk_size_mean": rng.sample_trunc_norm(4_000_000, 700_000, 2_500_000, 7_000_000),
                    "chunk_size_std": 500_000.0,
                    "segment_iat_sec": 3.0,
                    "jitter_ratio": 0.2,
                }
            ))

    elif profile == "bursty_adaptive_stream":
        # ABR dynamic quality switching: 1080p -> throttle down 480p -> scale up 1080p
        while time_remaining > 2.0:
            d_high = alloc_duration(6.0, 14.0)
            phases.append(TrafficPhase(
                name="abr_1080p_high_profile",
                duration_sec=d_high,
                params={
                    "segment_count": rng.sample_int(3, 7),
                    "chunk_size_mean": rng.sample_trunc_norm(1_200_000, 200_000, 800_000, 2_000_000),
                    "chunk_size_std": 150_000.0,
                    "segment_iat_sec": 2.0,
                    "jitter_ratio": 0.15,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_throttle = alloc_duration(5.0, 12.0)
            phases.append(TrafficPhase(
                name="abr_downshift_480p_throttled",
                duration_sec=d_throttle,
                params={
                    "segment_count": rng.sample_int(3, 6),
                    "chunk_size_mean": rng.sample_trunc_norm(260_000, 40_000, 150_000, 400_000),
                    "chunk_size_std": 30_000.0,
                    "segment_iat_sec": 1.8,
                    "jitter_ratio": 0.3,
                }
            ))

    elif profile == "buffering_heavy_stream":
        # Buffer fill -> stall/rebuffering (zero throughput) -> aggressive recovery download
        while time_remaining > 2.0:
            d_init = alloc_duration(3.0, 7.0)
            phases.append(TrafficPhase(
                name="stall_initial_fetch",
                duration_sec=d_init,
                params={
                    "segment_count": rng.sample_int(2, 4),
                    "chunk_size_mean": rng.sample_trunc_norm(500_000, 80_000, 300_000, 800_000),
                    "chunk_size_std": 60_000.0,
                    "segment_iat_sec": 0.5,
                    "jitter_ratio": 0.1,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_stall = alloc_duration(4.0, 10.0)
            phases.append(TrafficPhase(
                name="video_rebuffering_stall_gap",
                duration_sec=d_stall,
                params={"segment_count": 0}  # Complete idle stall
            ))
            if time_remaining <= 2.0:
                break
            d_recov = alloc_duration(5.0, 12.0)
            phases.append(TrafficPhase(
                name="aggressive_recovery_burst",
                duration_sec=d_recov,
                params={
                    "segment_count": rng.sample_int(5, 10),
                    "chunk_size_mean": rng.sample_trunc_norm(900_000, 150_000, 500_000, 1_500_000),
                    "chunk_size_std": 100_000.0,
                    "segment_iat_sec": 0.4,
                    "jitter_ratio": 0.2,
                }
            ))

    else:  # variable_quality_stream
        # Frequent stepped quality variations due to scene complexity changes
        while time_remaining > 2.0:
            scene_type = rng.sample_choice(["high_motion_action", "static_dialogue"])
            d = alloc_duration(5.0, 12.0)
            if scene_type == "high_motion_action":
                phases.append(TrafficPhase(
                    name="scene_high_motion_spike",
                    duration_sec=d,
                    params={
                        "segment_count": rng.sample_int(3, 7),
                        "chunk_size_mean": rng.sample_trunc_norm(1_800_000, 300_000, 1_200_000, 3_000_000),
                        "chunk_size_std": 200_000.0,
                        "segment_iat_sec": 1.6,
                        "jitter_ratio": 0.18,
                    }
                ))
            else:
                phases.append(TrafficPhase(
                    name="scene_dialogue_low_bitrate",
                    duration_sec=d,
                    params={
                        "segment_count": rng.sample_int(2, 5),
                        "chunk_size_mean": rng.sample_trunc_norm(420_000, 60_000, 250_000, 700_000),
                        "chunk_size_std": 50_000.0,
                        "segment_iat_sec": 2.2,
                        "jitter_ratio": 0.15,
                    }
                ))

    if time_remaining > 0.0:
        phases.append(TrafficPhase(
            name="stream_end_cooldown",
            duration_sec=round(time_remaining, 2),
            params={"segment_count": 0}
        ))

    return phases


# ---------------------------------------------------------------------------
# Video HTTP Server for Responder Container
# ---------------------------------------------------------------------------

class VideoServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        chunk_size = 500_000
        if "?" in self.path:
            parts = self.path.split("?")[-1].split("&")
            for p in parts:
                if p.startswith("size="):
                    try:
                        chunk_size = max(1000, min(10_000_000, int(p.split("=")[1])))
                    except ValueError:
                        pass
        self.send_response(200)
        self.send_header("Content-Type", "video/mp2t")
        self.send_header("Content-Length", str(chunk_size))
        self.end_headers()

        # Stream chunk in 32KB blocks to model real TCP video chunk streaming
        bytes_left = chunk_size
        block = b"V" * 32768
        while bytes_left > 0:
            to_write = min(bytes_left, len(block))
            try:
                self.wfile.write(block[:to_write])
                bytes_left -= to_write
            except Exception:
                break


def run_video_server(bind_host: str, port: int) -> None:
    server = HTTPServer((bind_host, port), VideoServerHandler)
    print(f"[*] Video streaming server running on {bind_host}:{port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# Traffic Generation Engine
# ---------------------------------------------------------------------------

def execute_video_session(
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
    Execute all phases of a video streaming session, downloading chunks over TCP/HTTP.
    """
    print(f"[*] Starting video stream generation:")
    print(f"    Profile:     {profile}")
    print(f"    Seed:        {rng.seed}")
    print(f"    Duration:    {duration:.2f}s")
    print(f"    Start Delay: {start_delay:.2f}s")
    print(f"    Target:      {target_host}:{target_port} (dry-run: {dry_run})")

    if not dry_run and start_delay > 0:
        time.sleep(start_delay)

    phases = build_video_phases(profile, duration, rng)
    phase_descriptions = [
        {"name": p.name, "duration_sec": p.duration_sec, "params": p.params}
        for p in phases
    ]

    total_packets = 0
    total_bytes = 0
    start_time = time.time()
    current_sim_time = 0.0
    session_success = True
    failure_msg = None

    for idx, phase in enumerate(phases):
        phase_start_real = time.time()
        phase_elapsed = 0.0
        seg_count = phase.params.get("segment_count", 0)
        chunk_mean = phase.params.get("chunk_size_mean", 500_000.0)
        chunk_std = phase.params.get("chunk_size_std", 50_000.0)
        seg_iat = phase.params.get("segment_iat_sec", 2.0)
        jitter_ratio = phase.params.get("jitter_ratio", 0.15)

        print(f"  -> Phase {idx+1}/{len(phases)}: {phase.name} ({phase.duration_sec}s, chunks: {seg_count})")

        for s_idx in range(seg_count):
            if (current_sim_time if dry_run else (time.time() - start_time)) >= duration:
                break
            if phase_elapsed >= phase.duration_sec:
                break

            # Sample chunk size from distribution (Requirements 4, 12)
            chunk_size = int(rng.sample_trunc_norm(
                chunk_mean, chunk_std, 50_000.0, 15_000_000.0
            ))

            if not dry_run:
                try:
                    conn = http.client.HTTPConnection(target_host, target_port, timeout=8.0)
                    conn.request("GET", f"/video/segment_{s_idx}.ts?size={chunk_size}")
                    resp = conn.getresponse()
                    # Read chunk in blocks
                    while True:
                        chunk_part = resp.read(65536)
                        if not chunk_part:
                            break
                    conn.close()
                except Exception as e:
                    session_success = False
                    failure_msg = f"HTTP video fetch error: {e}"

            # Calculate packets (TCP MSS ~ 1400 bytes payload)
            # Both inbound video frames and outbound small TCP ACKs (approx 1 ACK per 2 data frames)
            data_pkts = max(1, chunk_size // 1420 + 1)
            ack_pkts = max(1, data_pkts // 2)
            total_packets += (data_pkts + ack_pkts)
            total_bytes += (chunk_size + ack_pkts * 54)

            # Sample IAT with jitter (Requirements 5, 6)
            iat_actual = rng.apply_jitter(seg_iat, jitter_ratio, min_val=0.05)

            if dry_run:
                phase_elapsed += iat_actual
                current_sim_time += iat_actual
            else:
                time.sleep(iat_actual)
                phase_elapsed = time.time() - phase_start_real

        # Idle remainder of phase if any
        if not dry_run:
            rem = phase.duration_sec - (time.time() - phase_start_real)
            if rem > 0:
                time.sleep(rem)
        else:
            rem = max(0.0, phase.duration_sec - phase_elapsed)
            current_sim_time += rem

    actual_duration = round(time.time() - start_time, 2)
    if dry_run:
        actual_duration = duration

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
        description="SIH 2026 Video Streaming Generator with adaptive bitrates, buffer models, and variable chunk sizes.",
    )

    args, rng, duration, start_delay, session_id = parse_and_init_traffic_session(
        parser=parser,
        traffic_class=TRAFFIC_CLASS,
        available_profiles=AVAILABLE_PROFILES,
    )

    if args.server_mode:
        run_video_server(args.bind_host, args.target_port)
        return

    manifest, pkts, bytes_total = execute_video_session(
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
    print(f"[+] Video session completed successfully:")
    print(f"    Packets:   {pkts}")
    print(f"    Bytes:     {bytes_total}")
    print(f"    Manifest:  {args.manifest_out}")


if __name__ == "__main__":
    main()
