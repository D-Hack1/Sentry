from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


DEFAULT_TARGET_HOST = "10.10.0.3"
PAYLOAD_SIZES = (8, 64, 512, 1024)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send ICMP traffic through the VPN using four payload sizes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def build_ping_command(target_host: str, payload_size: int, interval: float) -> list[str]:
    return [
        "ping",
        "-n",
        "-i",
        str(interval),
        "-s",
        str(payload_size),
        target_host,
    ]


def run_flood(target_host: str, duration: float, interval: float, dry_run: bool) -> list[list[str]]:
    if duration <= 0:
        raise ValueError("duration must be greater than zero")
    if interval <= 0:
        raise ValueError("interval must be greater than zero")

    commands = [
        build_ping_command(target_host, payload_size, interval)
        for payload_size in PAYLOAD_SIZES
    ]
    if dry_run:
        for command in commands:
            print(" ".join(command))
        return commands

    processes = [
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for command in commands
    ]
    try:
        time.sleep(duration)
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return commands


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    commands = run_flood(args.target_host, args.duration, args.interval, args.dry_run)
    print(f"ping_streams={len(commands)} payload_sizes={','.join(map(str, PAYLOAD_SIZES))}")


if __name__ == "__main__":
    main()
