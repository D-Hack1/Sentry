"""
AI-Powered IPsec VPN Protocol Analyzer - SIH 2026

File Transfer Traffic Generator
--------------------------------

Generates realistic file-transfer traffic across multiple behavioral
profiles while keeping the traffic class label constant as:

    file_transfer

Features:
- 6+ behavioral profiles
- Seeded randomization
- Multi-phase sessions
- Variable transfer sizes
- Variable inter-transfer delays
- Variable burst behavior
- Variable request/response behavior
- Randomized start delay
- Session duration controlled by common traffic framework
- Manifest generation
- Live network mode and dry-run mode

The generator intentionally does NOT use a fixed bitrate,
fixed transfer interval, or fixed file size.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path for direct CLI execution.
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ),
)

from traffic.common import (
    GenerationManifest,
    TrafficPhase,
    TrafficRNG,
    build_common_parser,
    parse_and_init_traffic_session,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRAFFIC_CLASS = "file_transfer"

DEFAULT_TARGET_HOST = "10.10.0.3"
DEFAULT_TARGET_PORT = 80

# The responder should have this file available.
DEFAULT_FILE_PATH = "/random_50mb.bin"

# Size of the backing file on the responder.
# Transfers themselves may use smaller HTTP ranges.
BACKING_FILE_SIZE = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# Behavioral profiles
# ---------------------------------------------------------------------------

AVAILABLE_PROFILES = [
    "steady_transfer",
    "bursty_transfer",
    "intermittent_transfer",
    "large_file_transfer",
    "small_file_transfer",
    "adaptive_transfer",
    "upload_download_mix",
]


# ---------------------------------------------------------------------------
# Phase construction
# ---------------------------------------------------------------------------

def build_file_transfer_phases(
    profile: str,
    duration: float,
    rng: TrafficRNG,
) -> List[TrafficPhase]:
    """
    Construct a randomized multi-phase file-transfer schedule.

    Every profile keeps the same traffic class label but changes its
    internal behavior over time.
    """

    phases: List[TrafficPhase] = []

    time_remaining = duration

    def alloc_duration(
        min_d: float,
        max_d: float,
    ) -> float:
        nonlocal time_remaining

        d = rng.sample_uniform(
            min_d,
            max_d,
        )

        d = min(
            d,
            max(1.0, time_remaining),
        )

        time_remaining -= d

        return round(d, 2)

    # ------------------------------------------------------------------
    # 1. STEADY TRANSFER
    # ------------------------------------------------------------------

    if profile == "steady_transfer":

        while time_remaining > 2.0:

            d_transfer = alloc_duration(
                8.0,
                18.0,
            )

            phases.append(
                TrafficPhase(
                    name="steady_transfer",
                    duration_sec=d_transfer,
                    params={
                        "transfer_count": rng.sample_int(
                            2,
                            6,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            2.0,
                            8.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            10.0,
                            25.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            400.0,
                            1200.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.10,
                            0.30,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_pause = alloc_duration(
                2.0,
                6.0,
            )

            phases.append(
                TrafficPhase(
                    name="steady_transfer_pause",
                    duration_sec=d_pause,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 2. BURSTY TRANSFER
    # ------------------------------------------------------------------

    elif profile == "bursty_transfer":

        while time_remaining > 2.0:

            d_burst = alloc_duration(
                3.0,
                8.0,
            )

            phases.append(
                TrafficPhase(
                    name="transfer_burst",
                    duration_sec=d_burst,
                    params={
                        "transfer_count": rng.sample_int(
                            4,
                            12,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            0.5,
                            3.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            4.0,
                            12.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            30.0,
                            180.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.20,
                            0.55,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_idle = alloc_duration(
                4.0,
                12.0,
            )

            phases.append(
                TrafficPhase(
                    name="burst_idle",
                    duration_sec=d_idle,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 3. INTERMITTENT TRANSFER
    # ------------------------------------------------------------------

    elif profile == "intermittent_transfer":

        while time_remaining > 2.0:

            d_transfer = alloc_duration(
                2.0,
                6.0,
            )

            phases.append(
                TrafficPhase(
                    name="intermittent_transfer",
                    duration_sec=d_transfer,
                    params={
                        "transfer_count": rng.sample_int(
                            1,
                            4,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            1.0,
                            5.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            6.0,
                            18.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            500.0,
                            2500.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.20,
                            0.60,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_idle = alloc_duration(
                6.0,
                18.0,
            )

            phases.append(
                TrafficPhase(
                    name="long_user_idle",
                    duration_sec=d_idle,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 4. LARGE FILE TRANSFER
    # ------------------------------------------------------------------

    elif profile == "large_file_transfer":

        while time_remaining > 2.0:

            d_init = alloc_duration(
                2.0,
                5.0,
            )

            phases.append(
                TrafficPhase(
                    name="large_transfer_start",
                    duration_sec=d_init,
                    params={
                        "transfer_count": rng.sample_int(
                            1,
                            2,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            15.0,
                            25.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            30.0,
                            48.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            100.0,
                            500.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.10,
                            0.30,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_pause = alloc_duration(
                4.0,
                10.0,
            )

            phases.append(
                TrafficPhase(
                    name="large_transfer_pause",
                    duration_sec=d_pause,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 5. SMALL FILE TRANSFER
    # ------------------------------------------------------------------

    elif profile == "small_file_transfer":

        while time_remaining > 2.0:

            d_small = alloc_duration(
                4.0,
                10.0,
            )

            phases.append(
                TrafficPhase(
                    name="small_file_batch",
                    duration_sec=d_small,
                    params={
                        "transfer_count": rng.sample_int(
                            8,
                            30,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            0.05,
                            0.5,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            0.75,
                            3.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            100.0,
                            800.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.15,
                            0.50,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_gap = alloc_duration(
                2.0,
                7.0,
            )

            phases.append(
                TrafficPhase(
                    name="small_file_think_gap",
                    duration_sec=d_gap,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 6. ADAPTIVE TRANSFER
    # ------------------------------------------------------------------

    elif profile == "adaptive_transfer":

        while time_remaining > 2.0:

            d_phase = alloc_duration(
                4.0,
                10.0,
            )

            # Randomly change transfer intensity between phases.
            intensity = rng.sample_int(
                0,
                2,
            )

            if intensity == 0:
                size_min = 0.25
                size_max = 4.0
                iat_mean = rng.sample_uniform(
                    500.0,
                    1800.0,
                )

            elif intensity == 1:
                size_min = 2.0
                size_max = 15.0
                iat_mean = rng.sample_uniform(
                    150.0,
                    700.0,
                )

            else:
                size_min = 10.0
                size_max = 40.0
                iat_mean = rng.sample_uniform(
                    50.0,
                    300.0,
                )

            phases.append(
                TrafficPhase(
                    name="adaptive_transfer",
                    duration_sec=d_phase,
                    params={
                        "transfer_count": rng.sample_int(
                            1,
                            10,
                        ),
                        "size_min_mb": size_min,
                        "size_max_mb": size_max,
                        "iat_mean_ms": iat_mean,
                        "jitter_ratio": rng.sample_uniform(
                            0.15,
                            0.65,
                        ),
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            if rng.sample_int(0, 1):

                d_idle = alloc_duration(
                    2.0,
                    8.0,
                )

                phases.append(
                    TrafficPhase(
                        name="adaptive_idle",
                        duration_sec=d_idle,
                        params={
                            "req_rate_per_sec": 0.0,
                        },
                    )
                )

    # ------------------------------------------------------------------
    # 7. UPLOAD/DOWNLOAD MIX
    # ------------------------------------------------------------------

    else:

        while time_remaining > 2.0:

            d_down = alloc_duration(
                4.0,
                9.0,
            )

            phases.append(
                TrafficPhase(
                    name="download_phase",
                    duration_sec=d_down,
                    params={
                        "transfer_count": rng.sample_int(
                            2,
                            7,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            1.0,
                            8.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            10.0,
                            25.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            150.0,
                            800.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.10,
                            0.40,
                        ),
                        "direction": "download",
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_gap = alloc_duration(
                2.0,
                5.0,
            )

            phases.append(
                TrafficPhase(
                    name="direction_change_gap",
                    duration_sec=d_gap,
                    params={
                        "req_rate_per_sec": 0.0,
                    },
                )
            )

            if time_remaining <= 2.0:
                break

            d_upload = alloc_duration(
                3.0,
                8.0,
            )

            phases.append(
                TrafficPhase(
                    name="upload_phase",
                    duration_sec=d_upload,
                    params={
                        "transfer_count": rng.sample_int(
                            2,
                            6,
                        ),
                        "size_min_mb": rng.sample_uniform(
                            0.5,
                            5.0,
                        ),
                        "size_max_mb": rng.sample_uniform(
                            6.0,
                            18.0,
                        ),
                        "iat_mean_ms": rng.sample_uniform(
                            200.0,
                            1200.0,
                        ),
                        "jitter_ratio": rng.sample_uniform(
                            0.15,
                            0.50,
                        ),
                        "direction": "upload",
                    },
                )
            )

    # ------------------------------------------------------------------
    # Final idle padding
    # ------------------------------------------------------------------

    if time_remaining > 0.0:

        phases.append(
            TrafficPhase(
                name="final_settle_idle",
                duration_sec=round(
                    time_remaining,
                    2,
                ),
                params={
                    "req_rate_per_sec": 0.0,
                },
            )
        )

    return phases


# ---------------------------------------------------------------------------
# HTTP transfer helpers
# ---------------------------------------------------------------------------

def build_wget_command(
    target_host: str,
    target_port: int,
    file_path: str,
    timeout: float,
    transfer_bytes: int,
    direction: str = "download",
) -> List[str]:
    """
    Build a wget command.

    Download:
        Uses HTTP Range to request only a randomized portion of the
        backing file.

    Upload:
        Uses a generated temporary payload through POST.
    """

    if direction == "download":

        # Request a random prefix of the backing file.
        range_end = max(
            1,
            min(
                BACKING_FILE_SIZE,
                transfer_bytes,
            ),
        ) - 1

        return [
            "wget",
            "--quiet",
            f"--timeout={timeout}",
            "--header",
            f"Range: bytes=0-{range_end}",
            "--output-document=-",
            f"http://{target_host}:{target_port}{file_path}",
        ]

    # Upload is handled separately because wget is primarily being
    # used as the download client.
    return []


def download_transfer(
    target_host: str,
    target_port: int,
    file_path: str,
    timeout: float,
    transfer_bytes: int,
    dry_run: bool,
) -> int:
    """
    Download a randomized amount of the responder's backing file.
    """

    command = build_wget_command(
        target_host,
        target_port,
        file_path,
        timeout,
        transfer_bytes,
        "download",
    )

    if dry_run:
        print(" ".join(command))
        return transfer_bytes

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    total_bytes = 0

    assert process.stdout is not None

    while True:

        chunk = process.stdout.read(65536)

        if not chunk:
            break

        total_bytes += len(chunk)

    assert process.stderr is not None

    error_output = (
        process.stderr
        .read()
        .decode(
            errors="replace"
        )
        .strip()
    )

    if process.wait() != 0:

        raise RuntimeError(
            f"wget failed: {error_output}"
        )

    return total_bytes


# ---------------------------------------------------------------------------
# Session execution
# ---------------------------------------------------------------------------

def execute_file_transfer_session(
    target_host: str,
    target_port: int,
    file_path: str,
    profile: str,
    duration: float,
    start_delay: float,
    timeout: float,
    rng: TrafficRNG,
    session_id: str,
    dry_run: bool = False,
) -> Tuple[GenerationManifest, int, int]:
    """
    Execute one randomized file-transfer session.
    """

    print(
        "[*] Starting file-transfer traffic generation:"
    )

    print(
        f"    Profile:     {profile}"
    )

    print(
        f"    Seed:        {rng.seed}"
    )

    print(
        f"    Duration:    {duration:.2f}s"
    )

    print(
        f"    Start Delay: {start_delay:.2f}s"
    )

    print(
        f"    Target:      "
        f"{target_host}:{target_port}"
    )

    print(
        f"    Dry-run:     {dry_run}"
    )

    # ---------------------------------------------------------------
    # Randomized start delay
    # ---------------------------------------------------------------

    if not dry_run and start_delay > 0:

        time.sleep(
            start_delay
        )

    phases = build_file_transfer_phases(
        profile,
        duration,
        rng,
    )

    phase_descriptions = [
        {
            "name": phase.name,
            "duration_sec": phase.duration_sec,
            "params": phase.params,
        }
        for phase in phases
    ]

    total_packets = 0
    total_bytes = 0

    start_time = time.time()

    session_success = True
    failure_msg = None

    # ---------------------------------------------------------------
    # Execute phases
    # ---------------------------------------------------------------

    for idx, phase in enumerate(phases):

        phase_start = time.time()

        print(
            f"  -> Phase "
            f"{idx + 1}/{len(phases)}: "
            f"{phase.name} "
            f"({phase.duration_sec}s)"
        )

        # -----------------------------------------------------------
        # Active transfer phase
        # -----------------------------------------------------------

        if "transfer_count" in phase.params:

            transfer_count = int(
                phase.params["transfer_count"]
            )

            size_min_mb = float(
                phase.params["size_min_mb"]
            )

            size_max_mb = float(
                phase.params["size_max_mb"]
            )

            iat_mean_ms = float(
                phase.params["iat_mean_ms"]
            )

            jitter_ratio = float(
                phase.params["jitter_ratio"]
            )

            direction = phase.params.get(
                "direction",
                "download",
            )

            for _ in range(transfer_count):

                # Stop when session duration is reached.
                if (
                    time.time() - start_time
                    >= duration
                ):
                    break

                # ---------------------------------------------------
                # Random transfer size
                # ---------------------------------------------------

                size_mb = rng.sample_uniform(
                    size_min_mb,
                    size_max_mb,
                )

                transfer_bytes = int(
                    size_mb * 1024 * 1024
                )

                # Keep requests within the backing file size.
                transfer_bytes = max(
                    1024,
                    min(
                        transfer_bytes,
                        BACKING_FILE_SIZE,
                    ),
                )

                # ---------------------------------------------------
                # Execute download
                # ---------------------------------------------------

                if direction == "download":

                    if not dry_run:

                        try:

                            transferred = download_transfer(
                                target_host=target_host,
                                target_port=target_port,
                                file_path=file_path,
                                timeout=timeout,
                                transfer_bytes=transfer_bytes,
                                dry_run=False,
                            )

                        except Exception as exc:

                            session_success = False

                            failure_msg = (
                                f"Transfer error during "
                                f"{phase.name}: {exc}"
                            )

                            break

                    else:

                        transferred = transfer_bytes

                else:

                    # ------------------------------------------------
                    # Upload simulation
                    #
                    # We use curl for upload because it allows us to
                    # send a randomized payload to the responder.
                    # ------------------------------------------------

                    transferred = transfer_bytes

                    if not dry_run:

                        payload_path = None

                        try:

                            payload_path = (
                                f"/tmp/"
                                f"sentry_upload_"
                                f"{os.getpid()}_"
                                f"{rng.sample_int(1, 10_000_000)}.bin"
                            )

                            with open(
                                payload_path,
                                "wb",
                            ) as payload:

                                # Write in chunks instead of allocating
                                # a potentially large byte string.
                                remaining = transfer_bytes

                                chunk = (
                                    b"U" * 65536
                                )

                                while remaining > 0:

                                    write_size = min(
                                        remaining,
                                        len(chunk),
                                    )

                                    payload.write(
                                        chunk[:write_size]
                                    )

                                    remaining -= write_size

                            command = [
                                "curl",
                                "--silent",
                                "--show-error",
                                "--max-time",
                                str(int(timeout)),
                                "-X",
                                "POST",
                                "--data-binary",
                                f"@{payload_path}",
                                f"http://"
                                f"{target_host}:"
                                f"{target_port}/api/upload",
                            ]

                            result = subprocess.run(
                                command,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                            )

                            if result.returncode != 0:

                                raise RuntimeError(
                                    result.stderr.decode(
                                        errors="replace"
                                    )
                                )

                        except Exception as exc:

                            session_success = False

                            failure_msg = (
                                f"Upload error during "
                                f"{phase.name}: {exc}"
                            )

                            break

                        finally:

                            if payload_path:

                                try:
                                    os.remove(
                                        payload_path
                                    )
                                except OSError:
                                    pass

                # ---------------------------------------------------
                # Approximate packet count
                # ---------------------------------------------------

                estimated_packets = max(
                    1,
                    transferred // 1420 + 1,
                )

                total_packets += (
                    estimated_packets
                )

                total_bytes += transferred

                # ---------------------------------------------------
                # Variable IAT / pacing
                # ---------------------------------------------------

                iat_ms = rng.apply_jitter(
                    iat_mean_ms,
                    jitter_ratio,
                    min_val=10.0,
                )

                iat_sec = (
                    iat_ms / 1000.0
                )

                if not dry_run:

                    remaining_phase = (
                        phase_start
                        + phase.duration_sec
                        - time.time()
                    )

                    if remaining_phase > 0:

                        time.sleep(
                            min(
                                iat_sec,
                                remaining_phase,
                            )
                        )

        # -----------------------------------------------------------
        # Idle phase
        # -----------------------------------------------------------

        elapsed_phase = (
            time.time()
            - phase_start
        )

        remaining_phase = (
            phase.duration_sec
            - elapsed_phase
        )

        if (
            remaining_phase > 0
            and not dry_run
        ):

            time.sleep(
                remaining_phase
            )

    # ---------------------------------------------------------------
    # Session duration
    # ---------------------------------------------------------------

    actual_duration = round(
        time.time()
        - start_time,
        2,
    )

    if dry_run:

        actual_duration = duration

    # ---------------------------------------------------------------
    # Manifest
    # ---------------------------------------------------------------

    manifest = GenerationManifest(
        session_id=session_id,
        traffic_class=TRAFFIC_CLASS,
        profile=profile,
        seed=rng.seed,
        duration_sec=actual_duration,
        start_delay_sec=start_delay,
        generation_params={
            "profile": profile,
            "target": (
                f"{target_host}:{target_port}"
            ),
            "file_path": file_path,
            "backing_file_size": (
                BACKING_FILE_SIZE
            ),
            "phases": phase_descriptions,
        },
        status=(
            "valid"
            if (
                session_success
                or dry_run
            )
            else "failed"
        ),
        failure_reason=(
            None
            if (
                session_success
                or dry_run
            )
            else failure_msg
        ),
        packets_sent=total_packets,
        bytes_sent=total_bytes,
    )

    return (
        manifest,
        total_packets,
        total_bytes,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:

    parser = build_common_parser(
        traffic_class=TRAFFIC_CLASS,
        default_port=DEFAULT_TARGET_PORT,
        available_profiles=AVAILABLE_PROFILES,
        description=(
            "SIH 2026 File Transfer Traffic Generator "
            "with randomized behavioral profiles."
        ),
    )

    parser.add_argument(
        "--file-path",
        default=DEFAULT_FILE_PATH,
        help="Path to the responder's backing file.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP transfer timeout in seconds.",
    )

    return parser


def main() -> None:

    parser = build_parser()

    args, rng, duration, start_delay, session_id = (
        parse_and_init_traffic_session(
            parser=parser,
            traffic_class=TRAFFIC_CLASS,
            available_profiles=AVAILABLE_PROFILES,
        )
    )

    manifest, packets, bytes_total = (
        execute_file_transfer_session(
            target_host=args.target_host,
            target_port=args.target_port,
            file_path=args.file_path,
            profile=args.profile,
            duration=duration,
            start_delay=start_delay,
            timeout=args.timeout,
            rng=rng,
            session_id=session_id,
            dry_run=args.dry_run,
        )
    )

    manifest.write_to_file(
        args.manifest_out
    )

    print()
    print(
        "[+] File-transfer session completed:"
    )

    print(
        f"    Profile:   {args.profile}"
    )

    print(
        f"    Packets:   {packets}"
    )

    print(
        f"    Bytes:     {bytes_total}"
    )

    print(
        f"    Duration:  "
        f"{manifest.duration_sec}s"
    )

    print(
        f"    Manifest:  "
        f"{args.manifest_out}"
    )

    print(
        f"    Status:    "
        f"{manifest.status}"
    )


if __name__ == "__main__":
    main()