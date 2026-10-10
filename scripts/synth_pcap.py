"""
scripts/synth_pcap.py — write a synthetic IPsec capture (IKEv2 + ESP) without the lab.

Useful to demo or test the watcher pipeline when the strongSwan lab containers
are not running:

    python scripts/synth_pcap.py --traffic voip --cipher aes256_cbc --dh group19 --out-dir capture/pcaps

The capture contains a plaintext IKE_SA_INIT exchange (SA, KE, Nonce payloads),
an IKE_AUTH exchange (encrypted payload), then bidirectional ESP traffic whose
sizes/timing follow the requested traffic class. The file is written to a
temporary name and renamed into place, so a watcher sees only complete files.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import ESP, IP, UDP, Raw, wrpcap  # noqa: E402
from scapy.contrib.ikev2 import (  # noqa: E402
    IKEv2,
    IKEv2_Encrypted,
    IKEv2_KE,
    IKEv2_Nonce,
    IKEv2_Proposal,
    IKEv2_SA,
    IKEv2_Transform,
)

CIPHERS = {  # name -> (ENCR transform id, key length bits, integrity transform id or None)
    "aes128_cbc": (12, 128, 12),
    "aes256_cbc": (12, 256, 12),
    "aes128_gcm": (20, 128, None),
    "aes256_gcm": (20, 256, None),
}
DH_GROUPS = {"group2": 2, "group5": 5, "group14": 14, "group19": 19, "group20": 20}
KE_SIZES = {2: 128, 5: 192, 14: 256, 19: 64, 20: 96}

# traffic -> (packets, duration s, size sampler(rng, outbound), outbound share)
TRAFFIC = {
    "voip": (360, 8.4, lambda r, out: int(r.gauss(246, 12)), 0.96),
    "video_stream": (300, 8.4, lambda r, out: r.choice([1500, 1500, 1500, 900, 300]), 0.97),
    "web": (1800, 7.4, lambda r, out: 68 if out else (1500 if r.random() < 0.85 else 68), 0.35),
    "file_transfer": (15000, 8.4, lambda r, out: 1500 if out else 68, 0.92),
    "icmp": (80, 8.4, lambda r, out: 120, 0.5),
}


def _sa_payload(cipher: str, dh: int) -> IKEv2_SA:
    encr_id, key_len, integ_id = CIPHERS[cipher]
    transforms = IKEv2_Transform(transform_type=1, transform_id=encr_id, length=12, key_length=key_len)
    transforms = transforms / IKEv2_Transform(transform_type=2, transform_id=5)  # PRF_HMAC_SHA2_256
    count = 3
    if integ_id is not None:
        transforms = transforms / IKEv2_Transform(transform_type=3, transform_id=integ_id)
        count += 1
    transforms = transforms / IKEv2_Transform(transform_type=4, transform_id=dh)
    return IKEv2_SA(prop=IKEv2_Proposal(proposal=1, proto=1, trans_nb=count, trans=transforms))


def build_packets(traffic: str, cipher: str, dh_group: str, initiator: str, responder: str,
                  start: float, seed: int | None = None) -> list:
    rng = random.Random(seed)
    dh = DH_GROUPS[dh_group]
    spi_i, spi_r = os.urandom(8), os.urandom(8)
    packets = []

    def add(pkt, ts):
        pkt.time = ts
        packets.append(pkt)

    ike = IP(src=initiator, dst=responder) / UDP(sport=500, dport=500)
    ike_back = IP(src=responder, dst=initiator) / UDP(sport=500, dport=500)
    add(ike / IKEv2(init_SPI=spi_i, exch_type=34, flags="Initiator")
        / _sa_payload(cipher, dh) / IKEv2_KE(group=dh, ke=os.urandom(KE_SIZES[dh]))
        / IKEv2_Nonce(nonce=os.urandom(32)), start)
    add(ike_back / IKEv2(init_SPI=spi_i, resp_SPI=spi_r, exch_type=34, flags="Response")
        / _sa_payload(cipher, dh) / IKEv2_KE(group=dh, ke=os.urandom(KE_SIZES[dh]))
        / IKEv2_Nonce(nonce=os.urandom(32)), start + 0.012)
    add(ike / IKEv2(init_SPI=spi_i, resp_SPI=spi_r, exch_type=35, flags="Initiator", id=1)
        / IKEv2_Encrypted(load=os.urandom(320)), start + 0.020)
    add(ike_back / IKEv2(init_SPI=spi_i, resp_SPI=spi_r, exch_type=35, flags="Response", id=1)
        / IKEv2_Encrypted(load=os.urandom(256)), start + 0.031)

    count, duration, size_of, out_share = TRAFFIC[traffic]
    spi_out, spi_in = rng.randrange(0xC0000000, 0xCFFFFFFF), rng.randrange(0xC0000000, 0xCFFFFFFF)
    t = start + 0.05
    step = duration / count
    for seq in range(count):
        outbound = rng.random() < out_share
        if traffic == "icmp":
            outbound = seq % 2 == 0
            gap = 0.1 + rng.uniform(-0.002, 0.002)
        elif traffic == "web":  # page loads: ~100-packet bursts separated by think time
            gap = rng.expovariate(1 / 0.0005) if seq % 100 else rng.uniform(0.3, 0.45)
        elif traffic == "file_transfer":  # TCP windows: ~100-packet bursts, 30-70 ms apart
            gap = rng.uniform(0.00002, 0.00006) if seq % 100 else rng.uniform(0.03, 0.07)
        else:
            gap = max(0.00001, rng.gauss(step, step * 0.3))
        t += gap
        size = max(68, min(1500, size_of(rng, outbound)))
        src, dst, spi = (initiator, responder, spi_out) if outbound else (responder, initiator, spi_in)
        add(IP(src=src, dst=dst) / ESP(spi=spi, seq=seq + 1, data=os.urandom(max(1, size - 8))), t)
    return packets


def write_capture(out_dir: Path, session_id: str, traffic: str, cipher: str, dh_group: str,
                  initiator: str = "10.10.0.2", responder: str = "10.10.0.3",
                  seed: int | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    final = out_dir / f"{session_id}.pcap"
    tmp = out_dir / f".{session_id}.pcap.tmp"
    wrpcap(str(tmp), build_packets(traffic, cipher, dh_group, initiator, responder, time.time(), seed))
    os.replace(tmp, final)  # atomic: watchers only ever see the complete file
    return final


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Write a synthetic IKEv2 + ESP capture")
    parser.add_argument("--traffic", choices=sorted(TRAFFIC), default="voip")
    parser.add_argument("--cipher", choices=sorted(CIPHERS), default="aes256_gcm")
    parser.add_argument("--dh", choices=sorted(DH_GROUPS), default="group19")
    parser.add_argument("--session-id", default=None, help="Default: synthetic_<traffic>_<unix time>")
    parser.add_argument("--out-dir", type=Path, default=ROOT / os.getenv("PCAP_DIR", "capture/pcaps"))
    parser.add_argument("--initiator", default="10.10.0.2")
    parser.add_argument("--responder", default="10.10.0.3")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)
    session_id = args.session_id or f"synthetic_{args.traffic}_{int(time.time())}"
    path = write_capture(args.out_dir, session_id, args.traffic, args.cipher, args.dh,
                         args.initiator, args.responder, args.seed)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
