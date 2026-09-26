from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


DEFAULT_TARGET_HOST = "10.10.0.3"
DEFAULT_TARGET_PORT = 80
DEFAULT_FILE_PATH = "/random_50mb.bin"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repeatedly download the responder's 50 MB nginx file through the VPN.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--target-host", default=DEFAULT_TARGET_HOST)
    parser.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT)
    parser.add_argument("--file-path", default=DEFAULT_FILE_PATH)
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def download_file(target_host: str, target_port: int, file_path: str, timeout: float) -> int:
    command = build_wget_command(target_host, target_port, file_path, timeout)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total_bytes = 0
    assert process.stdout is not None
    while chunk := process.stdout.read(65536):
        total_bytes += len(chunk)
    assert process.stderr is not None
    error_output = process.stderr.read().decode(errors="replace").strip()
    if process.wait() != 0:
        raise RuntimeError(f"wget failed for {file_path}: {error_output}")
    return total_bytes


def build_wget_command(
    target_host: str,
    target_port: int,
    file_path: str,
    timeout: float,
) -> list[str]:
    return [
        "wget",
        "--quiet",
        f"--timeout={timeout}",
        "--output-document=-",
        f"http://{target_host}:{target_port}{file_path}",
    ]


def run_downloads(
    target_host: str,
    target_port: int,
    file_path: str,
    duration: float,
    timeout: float,
    dry_run: bool,
) -> tuple[int, int]:
    if duration <= 0:
        raise ValueError("duration must be greater than zero")
    if dry_run:
        print(" ".join(build_wget_command(target_host, target_port, file_path, timeout)))
        return 0, 0

    deadline = time.monotonic() + duration
    downloads = 0
    total_bytes = 0
    while time.monotonic() < deadline:
        total_bytes += download_file(target_host, target_port, file_path, timeout)
        downloads += 1
    return downloads, total_bytes


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    downloads, total_bytes = run_downloads(
        args.target_host,
        args.target_port,
        args.file_path,
        args.duration,
        args.timeout,
        args.dry_run,
    )
    print(f"downloads={downloads} bytes={total_bytes}")


if __name__ == "__main__":
    main()
