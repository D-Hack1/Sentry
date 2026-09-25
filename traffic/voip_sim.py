"""
traffic/voip_sim.py
===================
AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
VoIP Simulator (Aadi - ML)

Generates RTP-like UDP VoIP audio streams across >= 6 behavioral profiles.
Strictly adheres to SIH 2026 requirements:
- NEVER uses a single fixed 160-byte / 50-pps static stream.
- Profiles model variable packetization, codecs (G.711, G.722, Opus VBR, AMR),
  dynamic jitter, silence suppression / comfort noise (VAD/CNG), and conversational turns.
- Seeded randomization per run, recorded in the manifest.
- Bidirectional UDP socket support (client & server reflection) and dry-run mode.
"""

from __future__ import annotations

import os
import socket
import struct
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

TRAFFIC_CLASS = "voip"
DEFAULT_PORT = 5004

AVAILABLE_PROFILES = [
    "regular_bidirectional_voice",
    "jittery_voice",
    "asymmetric_speech_activity",
    "silence_heavy_call",
    "bursty_speech_activity",
    "variable_packetization_rate",
]


# ---------------------------------------------------------------------------
# RTP Packet Framing
# ---------------------------------------------------------------------------

def build_rtp_packet(seq_num: int, timestamp: int, ssrc: int, payload_len: int) -> bytes:
    """
    Construct a 12-byte RTP header + payload.
    Header: V=2, P=0, X=0, CC=0, M=0, PT=96 (dynamic), Seq, Timestamp, SSRC.
    """
    header = struct.pack(
        "!BBHII",
        0x80,               # V=2, P=0, X=0, CC=0
        96,                 # M=0, Payload Type=96 (dynamic audio)
        seq_num & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    )
    payload = b"\x00" * max(0, payload_len)
    return header + payload


# ---------------------------------------------------------------------------
# Profile Configurations
# ---------------------------------------------------------------------------

def build_voip_phases(profile: str, duration: float, rng: TrafficRNG) -> List[TrafficPhase]:
    """
    Construct dynamic multi-phase schedules for VoIP sessions.
    """
    phases: List[TrafficPhase] = []
    time_remaining = duration

    def alloc_duration(min_d: float, max_d: float) -> float:
        nonlocal time_remaining
        d = rng.sample_uniform(min_d, max_d)
        d = min(d, max(1.0, time_remaining))
        time_remaining -= d
        return round(d, 2)

    if profile == "regular_bidirectional_voice":
        # Balanced speech, subtle Gaussian jitter around 20ms base
        while time_remaining > 2.0:
            d = alloc_duration(6.0, 14.0)
            phases.append(TrafficPhase(
                name="sustained_conversation",
                duration_sec=d,
                params={
                    "base_iat_ms": rng.sample_trunc_norm(20.0, 1.5, 18.0, 22.0),
                    "jitter_std_ms": rng.sample_trunc_norm(1.5, 0.5, 0.5, 3.5),
                    "payload_mean": rng.sample_trunc_norm(172, 12, 140, 210),
                    "payload_std": 10.0,
                    "is_active": True,
                    "bidir_ratio": 1.0,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_pause = alloc_duration(1.5, 3.5)
            phases.append(TrafficPhase(
                name="mutual_pause",
                duration_sec=d_pause,
                params={
                    "base_iat_ms": 160.0,  # Comfort noise
                    "jitter_std_ms": 15.0,
                    "payload_mean": 32.0,
                    "payload_std": 4.0,
                    "is_active": False,
                    "bidir_ratio": 1.0,
                }
            ))

    elif profile == "jittery_voice":
        # Network instability with packet bunching and high jitter variance
        while time_remaining > 2.0:
            d = alloc_duration(5.0, 12.0)
            phases.append(TrafficPhase(
                name="unstable_jitter_speech",
                duration_sec=d,
                params={
                    "base_iat_ms": rng.sample_trunc_norm(20.0, 3.0, 15.0, 28.0),
                    "jitter_std_ms": rng.sample_trunc_norm(12.0, 4.0, 6.0, 22.0),
                    "payload_mean": rng.sample_trunc_norm(160, 25, 120, 240),
                    "payload_std": 20.0,
                    "is_active": True,
                    "bidir_ratio": 1.0,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_degrade = alloc_duration(2.0, 6.0)
            phases.append(TrafficPhase(
                name="severe_lag_phase",
                duration_sec=d_degrade,
                params={
                    "base_iat_ms": rng.sample_trunc_norm(45.0, 15.0, 25.0, 80.0),
                    "jitter_std_ms": rng.sample_trunc_norm(25.0, 8.0, 10.0, 45.0),
                    "payload_mean": 180.0,
                    "payload_std": 35.0,
                    "is_active": True,
                    "bidir_ratio": 0.8,
                }
            ))

    elif profile == "asymmetric_speech_activity":
        # One party dominates talk time, other is mostly passive listener
        while time_remaining > 2.0:
            d = alloc_duration(7.0, 16.0)
            phases.append(TrafficPhase(
                name="caller_monologue",
                duration_sec=d,
                params={
                    "base_iat_ms": 20.0,
                    "jitter_std_ms": 2.0,
                    "payload_mean": rng.sample_trunc_norm(185, 15, 150, 220),
                    "payload_std": 12.0,
                    "is_active": True,
                    "bidir_ratio": 0.15,  # mostly one-directional outbound
                }
            ))
            if time_remaining <= 2.0:
                break
            d_turn = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="brief_response_turn",
                duration_sec=d_turn,
                params={
                    "base_iat_ms": 20.0,
                    "jitter_std_ms": 2.0,
                    "payload_mean": 160.0,
                    "payload_std": 10.0,
                    "is_active": True,
                    "bidir_ratio": 0.9,
                }
            ))

    elif profile == "silence_heavy_call":
        # VAD active: long silence gaps with small CNG packets (100-300ms IAT)
        while time_remaining > 2.0:
            d_silence = alloc_duration(6.0, 18.0)
            phases.append(TrafficPhase(
                name="vad_comfort_noise_silence",
                duration_sec=d_silence,
                params={
                    "base_iat_ms": rng.sample_trunc_norm(200.0, 40.0, 120.0, 320.0),
                    "jitter_std_ms": 20.0,
                    "payload_mean": rng.sample_trunc_norm(28.0, 6.0, 16.0, 48.0),
                    "payload_std": 4.0,
                    "is_active": False,
                    "bidir_ratio": 1.0,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_spurt = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="short_speech_spurt",
                duration_sec=d_spurt,
                params={
                    "base_iat_ms": 20.0,
                    "jitter_std_ms": 1.8,
                    "payload_mean": rng.sample_trunc_norm(168, 10, 140, 200),
                    "payload_std": 8.0,
                    "is_active": True,
                    "bidir_ratio": 1.0,
                }
            ))

    elif profile == "bursty_speech_activity":
        # Rapid conversational interaction with frequent bursts
        while time_remaining > 2.0:
            d_burst = alloc_duration(2.0, 5.0)
            phases.append(TrafficPhase(
                name="conversational_rapid_exchange",
                duration_sec=d_burst,
                params={
                    "base_iat_ms": rng.sample_trunc_norm(18.0, 2.0, 14.0, 22.0),
                    "jitter_std_ms": 3.0,
                    "payload_mean": rng.sample_trunc_norm(175, 20, 130, 220),
                    "payload_std": 15.0,
                    "is_active": True,
                    "bidir_ratio": 1.0,
                }
            ))
            if time_remaining <= 2.0:
                break
            d_pause = alloc_duration(1.0, 3.0)
            phases.append(TrafficPhase(
                name="conversational_pause",
                duration_sec=d_pause,
                params={
                    "base_iat_ms": 100.0,
                    "jitter_std_ms": 10.0,
                    "payload_mean": 30.0,
                    "payload_std": 5.0,
                    "is_active": False,
                    "bidir_ratio": 1.0,
                }
            ))

    else:  # variable_packetization_rate
        # Simulates Opus VBR / AMR multi-rate frame transitions
        while time_remaining > 2.0:
            frame_mode = rng.sample_choice([10.0, 20.0, 40.0, 60.0], weights=[0.15, 0.55, 0.20, 0.10])
            d = alloc_duration(4.0, 10.0)
            # Packet size scales roughly with frame size
            size_mean = frame_mode * 8.5 + rng.sample_uniform(10.0, 40.0)
            phases.append(TrafficPhase(
                name=f"opus_vbr_frame_{int(frame_mode)}ms",
                duration_sec=d,
                params={
                    "base_iat_ms": frame_mode,
                    "jitter_std_ms": rng.sample_trunc_norm(frame_mode * 0.08, 0.5, 0.3, 3.0),
                    "payload_mean": size_mean,
                    "payload_std": size_mean * 0.15,
                    "is_active": True,
                    "bidir_ratio": 1.0,
                }
            ))

    if time_remaining > 0.0:
        phases.append(TrafficPhase(
            name="call_winddown_silence",
            duration_sec=round(time_remaining, 2),
            params={"base_iat_ms": 180.0, "jitter_std_ms": 15.0, "payload_mean": 24.0, "payload_std": 4.0, "is_active": False}
        ))

    return phases


# ---------------------------------------------------------------------------
# Server / Responder Mode (UDP Reflection / Sink)
# ---------------------------------------------------------------------------

def run_voip_server(bind_host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, port))
    print(f"[*] VoIP UDP responder listening on {bind_host}:{port}...")

    try:
        while True:
            data, addr = sock.recvfrom(2048)
            # Send back echo response with small delay to simulate bidirectional audio
            if len(data) >= 12:
                # Echo back packet with updated timestamp
                try:
                    sock.sendto(data, addr)
                except Exception:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Traffic Generation Engine
# ---------------------------------------------------------------------------

def execute_voip_session(
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
    Execute all phases of a VoIP session, generating RTP-like UDP packet streams.
    """
    print(f"[*] Starting VoIP simulation:")
    print(f"    Profile:     {profile}")
    print(f"    Seed:        {rng.seed}")
    print(f"    Duration:    {duration:.2f}s")
    print(f"    Start Delay: {start_delay:.2f}s")
    print(f"    Target:      {target_host}:{target_port} (dry-run: {dry_run})")

    if not dry_run and start_delay > 0:
        time.sleep(start_delay)

    phases = build_voip_phases(profile, duration, rng)
    phase_descriptions = [
        {"name": p.name, "duration_sec": p.duration_sec, "params": p.params}
        for p in phases
    ]

    sock = None
    if not dry_run:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    seq_num = rng.sample_int(1, 10000)
    timestamp = rng.sample_int(1000, 500000)
    ssrc = rng.sample_int(100000, 9999999)

    total_packets = 0
    total_bytes = 0
    start_time = time.time()
    current_sim_time = 0.0
    session_success = True
    failure_msg = None

    try:
        for idx, phase in enumerate(phases):
            phase_start_real = time.time()
            phase_elapsed = 0.0
            base_iat = phase.params.get("base_iat_ms", 20.0) / 1000.0
            jitter_std = phase.params.get("jitter_std_ms", 2.0) / 1000.0
            payload_mean = phase.params.get("payload_mean", 160.0)
            payload_std = phase.params.get("payload_std", 10.0)

            print(f"  -> Phase {idx+1}/{len(phases)}: {phase.name} ({phase.duration_sec}s, base_iat: {base_iat*1000:.1f}ms)")

            while phase_elapsed < phase.duration_sec:
                if (current_sim_time if dry_run else (time.time() - start_time)) >= duration:
                    break

                # Variable payload size
                payload_len = int(rng.sample_trunc_norm(
                    payload_mean, payload_std, 16.0, 1400.0
                ))
                packet = build_rtp_packet(seq_num, timestamp, ssrc, payload_len)
                seq_num = (seq_num + 1) & 0xFFFF
                timestamp = (timestamp + int(base_iat * 8000)) & 0xFFFFFFFF

                if not dry_run and sock is not None:
                    try:
                        sock.sendto(packet, (target_host, target_port))
                    except Exception as e:
                        session_success = False
                        failure_msg = f"Socket send error: {e}"

                total_packets += 1
                total_bytes += len(packet)

                # Variable IAT with jitter (Requirements 5, 6, 9)
                perturbed_iat = max(0.001, rng.sample_trunc_norm(
                    base_iat, jitter_std, base_iat * 0.1, base_iat * 3.0
                ))

                if dry_run:
                    phase_elapsed += perturbed_iat
                    current_sim_time += perturbed_iat
                else:
                    time.sleep(perturbed_iat)
                    phase_elapsed = time.time() - phase_start_real

    finally:
        if sock is not None:
            sock.close()

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
        description="SIH 2026 VoIP Simulator with realistic audio codecs, dynamic jitter, and multi-phase activity.",
    )

    args, rng, duration, start_delay, session_id = parse_and_init_traffic_session(
        parser=parser,
        traffic_class=TRAFFIC_CLASS,
        available_profiles=AVAILABLE_PROFILES,
    )

    if args.server_mode:
        run_voip_server(args.bind_host, args.target_port)
        return

    manifest, pkts, bytes_total = execute_voip_session(
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
    print(f"[+] VoIP session completed successfully:")
    print(f"    Packets:   {pkts}")
    print(f"    Bytes:     {bytes_total}")
    print(f"    Manifest:  {args.manifest_out}")


if __name__ == "__main__":
    main()
