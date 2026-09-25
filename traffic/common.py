"""
traffic/common.py
=================
Shared utilities, statistical distribution samplers, manifest management,
and CLI argument parsing for all traffic generators (web, voip, video).

Adheres strictly to SIH 2026 specifications:
- Unique random seed per run (reproducible debugging when specified).
- Seed and generation parameters recorded in manifest.
- Non-fixed distributions for packet sizes, IATs, jitter, throughput, and phases.
"""

from __future__ import annotations

import argparse
import dataclasses
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import math
import os
import random
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Manifest Schema
# ---------------------------------------------------------------------------

@dataclass
class GenerationManifest:
    """
    Manifest entry for every generated traffic session.
    Meets Requirement 20 & 22 of the SIH 2026 specification.
    """
    session_id: str
    traffic_class: str
    profile: str
    seed: int
    duration_sec: float
    start_delay_sec: float
    generation_params: Dict[str, Any]
    vpn_config: Dict[str, Any] = field(default_factory=dict)
    pcap: Optional[str] = None
    status: str = "valid"  # "valid" | "failed"
    failure_reason: Optional[str] = None
    packets_sent: int = 0
    bytes_sent: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def write_to_file(self, filepath: str) -> None:
        """Write or append manifest entry to the target file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        entries = []
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        entries = data
                    elif isinstance(data, dict):
                        entries = [data]
            except Exception:
                entries = []

        entries.append(self.to_dict())
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2)


# ---------------------------------------------------------------------------
# Randomization & Statistical Samplers
# ---------------------------------------------------------------------------

def generate_seed() -> int:
    """Generate a 31-bit positive unique random seed."""
    return secrets.randbits(31)


class TrafficRNG:
    """
    Seeded pseudo-random number generator offering diverse distributions
    for realistic network traffic modeling.
    """

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed if seed is not None else generate_seed()
        self.rng = random.Random(self.seed)

    def sample_uniform(self, low: float, high: float) -> float:
        return self.rng.uniform(low, high)

    def sample_int(self, low: int, high: int) -> int:
        return self.rng.randint(low, high)

    def sample_choice(self, choices: List[Any], weights: Optional[List[float]] = None) -> Any:
        return self.rng.choices(choices, weights=weights, k=1)[0]

    def sample_trunc_norm(
        self, mean: float, std: float, low: float, high: float
    ) -> float:
        """Sample from a truncated normal distribution."""
        for _ in range(25):
            val = self.rng.gauss(mean, std)
            if low <= val <= high:
                return val
        return max(low, min(high, self.rng.gauss(mean, std)))

    def sample_lognormal(
        self, mean: float, sigma: float, low: float, high: float
    ) -> float:
        """
        Sample from a log-normal distribution.
        `mean` is the desired linear mean, `sigma` is shape parameter.
        """
        mu = math.log(max(1e-6, mean)) - 0.5 * (sigma ** 2)
        val = self.rng.lognormvariate(mu, sigma)
        return max(low, min(high, val))

    def sample_exponential(self, mean: float, low: float, high: float) -> float:
        """Sample from an exponential distribution with rate lambda = 1/mean."""
        rate = 1.0 / max(1e-6, mean)
        val = self.rng.expovariate(rate)
        return max(low, min(high, val))

    def sample_pareto(self, alpha: float, scale: float, low: float, high: float) -> float:
        """Sample from a Pareto (heavy-tailed) distribution."""
        val = scale * self.rng.paretovariate(alpha)
        return max(low, min(high, val))

    def apply_jitter(self, base_val: float, jitter_ratio: float, min_val: float = 0.0) -> float:
        """
        Apply timing jitter perturbation: base_val +/- (jitter_ratio * base_val * gaussian_noise).
        """
        noise = self.rng.gauss(0.0, jitter_ratio)
        jittered = base_val * (1.0 + noise)
        return max(min_val, jittered)


# ---------------------------------------------------------------------------
# Phase Scheduling
# ---------------------------------------------------------------------------

@dataclass
class TrafficPhase:
    """A distinct behavioral phase within a single session."""
    name: str
    duration_sec: float
    params: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Common CLI Argument Parsing
# ---------------------------------------------------------------------------

def build_common_parser(
    traffic_class: str,
    default_port: int,
    available_profiles: List[str],
    description: str
) -> argparse.ArgumentParser:
    """
    Build a standardized CLI parser for a traffic generator.
    """
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--profile",
        type=str,
        default=available_profiles[0],
        choices=available_profiles,
        help=f"Behavioral profile name. Choices: {', '.join(available_profiles)}",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="Session duration in seconds (30.0 - 120.0). If omitted, randomly chosen in range.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible generation. If omitted, unique random seed is used.",
    )
    parser.add_argument(
        "--target-host",
        type=str,
        default="10.10.0.3",
        help="Target IP or hostname (responder inside IPsec tunnel).",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=default_port,
        help=f"Target port on the responder (default: {default_port}).",
    )
    parser.add_argument(
        "--start-delay",
        type=float,
        default=None,
        help="Pre-traffic start delay in seconds (after tunnel up). If omitted, sampled randomly.",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Unique session ID. If omitted, generated using timestamp and profile.",
    )
    parser.add_argument(
        "--manifest-out",
        type=str,
        default="data/manifest.json",
        help="Path to output JSON manifest.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate traffic generation without opening real network sockets (useful for tests).",
    )
    parser.add_argument(
        "--server-mode",
        action="store_true",
        help="Run in server/responder mode to receive and answer traffic.",
    )
    parser.add_argument(
        "--bind-host",
        type=str,
        default="0.0.0.0",
        help="Host address to bind to when running in server mode.",
    )

    return parser


def parse_and_init_traffic_session(
    parser: argparse.ArgumentParser,
    traffic_class: str,
    available_profiles: List[str]
) -> Tuple[argparse.Namespace, TrafficRNG, float, float, str]:
    """
    Parse arguments and initialize RNG, duration, start delay, and session ID.
    Returns (args, rng, duration, start_delay, session_id).
    """
    args = parser.parse_args()

    # Initialize RNG with provided seed or unique seed
    rng = TrafficRNG(args.seed)

    # Randomized session duration (30 - 120 sec) if not explicitly set
    if args.duration is not None:
        duration = float(args.duration)
    else:
        duration = round(rng.sample_uniform(30.0, 120.0), 2)

    # Randomized pre-traffic start delay (1.0 - 5.0 sec) if not explicitly set
    if args.start_delay is not None:
        start_delay = float(args.start_delay)
    else:
        start_delay = round(rng.sample_uniform(1.0, 5.0), 2)

    # Session ID
    if args.session_id:
        session_id = args.session_id
    else:
        session_id = f"session_{traffic_class}_{args.profile}_{rng.seed}"

    return args, rng, duration, start_delay, session_id
