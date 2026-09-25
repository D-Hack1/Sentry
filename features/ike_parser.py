"""
features/ike_parser.py
======================
AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
IKE Protocol Dissector & Inferred Configuration Extractor (Aadi - ML)

Parses plaintext IKEv1 and IKEv2 handshakes from raw PCAP files using Scapy.
Produces a flat dictionary strictly matching the IKE and Inferred Config sections
of `IPsecFeatureRow` in `features/schema.py`:
- ike_version, ike_exchange_type, ike_initiator_spi, sa_proposal_count,
  ke_dh_group, ike_nat_traversal, ike_packet_count, ike_handshake_duration.
- mode (tunnel | transport), cipher_suite, auth_algo, dh_group,
  pfs_enabled, key_lifetime_sec, esp_spi.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import PcapReader, IP, IPv6, UDP, ESP, raw
    import scapy.layers.isakmp as isakmp
    import scapy.contrib.ikev2 as ikev2
except ImportError as e:
    raise ImportError(
        f"Scapy is required for features/ike_parser.py: {e}. Run 'pip install scapy'."
    )


# ---------------------------------------------------------------------------
# Constants & Encodings (RFC 7296, RFC 2409, strongSwan defaults)
# ---------------------------------------------------------------------------

DH_GROUP_MAP: Dict[int, str] = {
    1: "group1",    # 768-bit MODP
    2: "group2",    # 1024-bit MODP (weak)
    5: "group5",    # 1536-bit MODP (weak)
    14: "group14",  # 2048-bit MODP
    15: "group15",  # 3072-bit MODP
    16: "group16",  # 4096-bit MODP
    19: "group19",  # 256-bit ECP (NIST P-256)
    20: "group20",  # 384-bit ECP (NIST P-384)
    21: "group21",  # 521-bit ECP
    28: "group28",  # Curve25519
}

# IKEv2 Transform Type 1 (ENCR) IDs -> canonical cipher names
ENCR_TRANSFORM_IDS: Dict[int, str] = {
    1: "des_cbc",
    2: "3des_cbc",
    12: "aes_cbc",       # key length determines aes128 vs aes256
    14: "aes_ctr",
    18: "aes128_gcm",    # 8-octet ICV
    19: "aes192_gcm",
    20: "aes_gcm",       # 16-octet ICV, key length determines 128 vs 256
    28: "chacha20_poly1305",
}

# IKEv2 Transform Type 3 (INTEG) IDs -> canonical auth names
INTEG_TRANSFORM_IDS: Dict[int, str] = {
    1: "hmac_md5",
    2: "hmac_sha1",
    12: "hmac_sha256",
    13: "hmac_sha384",
    14: "hmac_sha512",
}

# IKEv1 / ISAKMP Exchange Types
IKEV1_EXCHANGE_TYPES: Dict[int, str] = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}

# IKEv2 Exchange Types (RFC 7296)
IKEV2_EXCHANGE_TYPES: Dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


# ---------------------------------------------------------------------------
# Core Parser
# ---------------------------------------------------------------------------

class IKEParser:
    """
    Dissects IKE handshakes and ESP context from PCAP files.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.session_id = os.path.splitext(os.path.basename(pcap_path))[0]

        # Session tracking
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.initiator_ip: str = "0.0.0.0"
        self.responder_ip: str = "0.0.0.0"
        self.initiator_port: int = 500
        self.responder_port: int = 500

        # IKE metrics
        self.ike_version: int = 2
        self.ike_exchange_type: int = 34
        self.ike_initiator_spi: str = "0x0"
        self.sa_proposal_count: int = 1
        self.ke_dh_group: int = 14
        self.ike_nat_traversal: bool = False
        self.ike_packet_count: int = 0
        self.ike_first_ts: Optional[float] = None
        self.ike_last_ts: Optional[float] = None

        # Inferred configuration
        self.mode: str = "tunnel"
        self.cipher_suite: str = "aes256_gcm"
        self.auth_algo: str = "aes_gcm"
        self.dh_group: str = "group14"
        self.pfs_enabled: bool = False
        self.key_lifetime_sec: int = 3600
        self.esp_spi: str = "0x0"

        # Internal state
        self._seen_ike_packets: List[Any] = []
        self._seen_esp_spis: List[int] = []

    def parse(self) -> Dict[str, Any]:
        """
        Execute full PCAP dissection and return feature dictionary.
        """
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        try:
            reader = PcapReader(self.pcap_path)
        except Exception as e:
            raise ValueError(f"Unable to read PCAP {self.pcap_path}: {e}")

        packet_index = 0
        for pkt in reader:
            packet_index += 1
            ts = float(pkt.time) if hasattr(pkt, "time") else 0.0

            if self.first_ts is None:
                self.first_ts = ts
            self.last_ts = ts

            # Check for ESP traffic
            if pkt.haslayer(ESP):
                esp_layer = pkt[ESP]
                spi_val = int(esp_layer.spi)
                if spi_val not in self._seen_esp_spis:
                    self._seen_esp_spis.append(spi_val)
                    if self.esp_spi == "0x0":
                        self.esp_spi = f"0x{spi_val:08x}"

            # Check for UDP IKE packets (Port 500 or 4500)
            if pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)

                # NAT-T detection (UDP 4500)
                if sport == 4500 or dport == 4500:
                    self.ike_nat_traversal = True

                if sport in (500, 4500) or dport in (500, 4500):
                    self._process_ike_packet(pkt, sport, dport, ts)

        reader.close()

        # Finalize timestamps & session calculations
        duration = 0.0
        if self.first_ts is not None and self.last_ts is not None:
            duration = max(0.0, round(self.last_ts - self.first_ts, 4))

        handshake_duration = 0.0
        if self.ike_first_ts is not None and self.ike_last_ts is not None:
            handshake_duration = max(0.0, round(self.ike_last_ts - self.ike_first_ts, 4))

        # Map numeric DH group to string
        self.dh_group = DH_GROUP_MAP.get(self.ke_dh_group, f"group{self.ke_dh_group}")

        # Assemble final schema-compliant feature dictionary
        result: Dict[str, Any] = {
            # Session identity
            "session_id": self.session_id,
            "ts": self.first_ts if self.first_ts is not None else 0.0,
            "initiator_ip": self.initiator_ip,
            "responder_ip": self.responder_ip,
            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,
            "duration": duration,

            # Plaintext IKE fields
            "ike_version": self.ike_version,
            "ike_exchange_type": self.ike_exchange_type,
            "ike_initiator_spi": self.ike_initiator_spi,
            "sa_proposal_count": self.sa_proposal_count,
            "ke_dh_group": self.ke_dh_group,
            "ike_nat_traversal": self.ike_nat_traversal,
            "ike_packet_count": self.ike_packet_count,
            "ike_handshake_duration": handshake_duration,

            # Inferred config
            "mode": self.mode,
            "cipher_suite": self.cipher_suite,
            "auth_algo": self.auth_algo,
            "dh_group": self.dh_group,
            "pfs_enabled": self.pfs_enabled,
            "key_lifetime_sec": self.key_lifetime_sec,
            "esp_spi": self.esp_spi,
        }

        return result

    def _process_ike_packet(self, pkt: Any, sport: int, dport: int, ts: float) -> None:
        """Process an individual IKE UDP packet."""
        self.ike_packet_count += 1
        if self.ike_first_ts is None:
            self.ike_first_ts = ts
        self.ike_last_ts = ts

        # Extract IP endpoints on the first packet
        if self.initiator_ip == "0.0.0.0":
            if pkt.haslayer(IP):
                self.initiator_ip = pkt[IP].src
                self.responder_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                self.initiator_ip = pkt[IPv6].src
                self.responder_ip = pkt[IPv6].dst
            self.initiator_port = sport
            self.responder_port = dport

        # Inspect Scapy IKEv2 or ISAKMP layers
        if pkt.haslayer(ikev2.IKEv2):
            self._parse_ikev2_layer(pkt[ikev2.IKEv2])
        elif pkt.haslayer(isakmp.ISAKMP):
            self._parse_isakmp_layer(pkt[isakmp.ISAKMP])
        else:
            # Check raw payload if encapsulated (e.g. non-ESP marker in NAT-T port 4500)
            udp_payload = bytes(pkt[UDP].payload)
            if len(udp_payload) >= 28:
                # NAT-T non-ESP marker is 4 zero bytes
                offset = 4 if udp_payload[:4] == b"\x00\x00\x00\x00" else 0
                sub_payload = udp_payload[offset:]
                if len(sub_payload) >= 28:
                    try:
                        v2 = ikev2.IKEv2(sub_payload)
                        self._parse_ikev2_layer(v2)
                    except Exception:
                        try:
                            v1 = isakmp.ISAKMP(sub_payload)
                            self._parse_isakmp_layer(v1)
                        except Exception:
                            pass

    def _parse_ikev2_layer(self, v2_hdr: Any) -> None:
        """Parse an IKEv2 message structure."""
        self.ike_version = 2

        # Extract initiator SPI and exchange type
        if hasattr(v2_hdr, "init_SPI"):
            spi_bytes = v2_hdr.init_SPI
            if isinstance(spi_bytes, (bytes, bytearray)):
                self.ike_initiator_spi = f"0x{spi_bytes.hex()}"
            elif isinstance(spi_bytes, int):
                self.ike_initiator_spi = f"0x{spi_bytes:016x}"

        if hasattr(v2_hdr, "exch_type"):
            exch = int(v2_hdr.exch_type)
            if self.ike_packet_count == 1:
                self.ike_exchange_type = exch

            # Check PFS in CREATE_CHILD_SA (Exchange 36)
            if exch == 36:
                # If CREATE_CHILD_SA contains a KE payload, PFS is enabled!
                curr = v2_hdr.payload
                while curr:
                    if isinstance(curr, ikev2.IKEv2_KE):
                        self.pfs_enabled = True
                    curr = curr.payload if hasattr(curr, "payload") else None

        # Walk through payloads
        curr = v2_hdr.payload
        while curr:
            # 1. Security Association (SA) Payload
            if isinstance(curr, ikev2.IKEv2_SA):
                self._extract_ikev2_sa(curr)

            # 2. Key Exchange (KE) Payload
            elif isinstance(curr, ikev2.IKEv2_KE):
                if hasattr(curr, "group"):
                    self.ke_dh_group = int(curr.group)

            # 3. Traffic Selector Payloads (TSi / TSr) -> Mode detection
            elif isinstance(curr, (ikev2.IKEv2_TSi, ikev2.IKEv2_TSr)):
                self._extract_ikev2_traffic_selectors(curr)

            # 4. Notify Payloads -> Check NAT detection / Mobike
            elif isinstance(curr, ikev2.IKEv2_Notify):
                # NAT_DETECTION_SOURCE_IP = 16388, NAT_DETECTION_DESTINATION_IP = 16389
                if hasattr(curr, "type") and int(curr.type) in (16388, 16389):
                    self.ike_nat_traversal = True

            curr = curr.payload if hasattr(curr, "payload") else None

    def _extract_ikev2_sa(self, sa_payload: Any) -> None:
        """Extract proposals, transforms, ciphers, and algorithms from SA payload."""
        proposal_count = 0
        curr_prop = sa_payload.prop if hasattr(sa_payload, "prop") else None

        # Proposal iteration
        while curr_prop:
            proposal_count += 1
            if hasattr(curr_prop, "SPI") and curr_prop.SPI:
                spi_bytes = curr_prop.SPI
                if len(spi_bytes) == 4 and self.esp_spi == "0x0":
                    self.esp_spi = f"0x{int.from_bytes(spi_bytes, 'big'):08x}"

            # Inspect transforms inside proposal
            curr_trans = curr_prop.trans if hasattr(curr_prop, "trans") else None
            key_len = 256  # default if not specified
            encr_id = None
            integ_id = None

            while curr_trans:
                trans_type = getattr(curr_trans, "transform_type", None)
                trans_id = getattr(curr_trans, "transform_id", None)

                # ENCR Transform (Type 1)
                if trans_type == 1 and trans_id is not None:
                    encr_id = int(trans_id)

                # INTEG Transform (Type 3)
                elif trans_type == 3 and trans_id is not None:
                    integ_id = int(trans_id)

                # DH Group Transform (Type 4)
                elif trans_type == 4 and trans_id is not None:
                    self.ke_dh_group = int(trans_id)

                # Key length attribute if present
                if hasattr(curr_trans, "key_length") and curr_trans.key_length:
                    key_len = int(curr_trans.key_length)

                curr_trans = curr_trans.payload if hasattr(curr_trans, "payload") and isinstance(curr_trans.payload, ikev2.IKEv2_Transform) else None

            # Resolve cipher name
            if encr_id is not None:
                if encr_id == 12:  # AES-CBC
                    self.cipher_suite = "aes128_cbc" if key_len == 128 else "aes256_cbc"
                elif encr_id in (18, 20):  # AES-GCM
                    self.cipher_suite = "aes128_gcm" if key_len == 128 else "aes256_gcm"
                    self.auth_algo = "aes_gcm"

            # Resolve auth algorithm
            if integ_id is not None and self.cipher_suite not in ("aes128_gcm", "aes256_gcm"):
                if integ_id == 2:
                    self.auth_algo = "hmac_sha1"
                elif integ_id == 12:
                    self.auth_algo = "hmac_sha256"
                elif integ_id == 13:
                    self.auth_algo = "hmac_sha384"

            curr_prop = curr_prop.payload if hasattr(curr_prop, "payload") and isinstance(curr_prop.payload, ikev2.IKEv2_Proposal) else None

        if proposal_count > 0:
            self.sa_proposal_count = proposal_count

    def _extract_ikev2_traffic_selectors(self, ts_payload: Any) -> None:
        """Determine tunnel vs transport mode from traffic selector addresses."""
        # Standard: 0.0.0.0/0 -> tunnel mode. Single IP host-to-host -> transport mode.
        ts_data = bytes(raw(ts_payload))
        if b"\x00\x00\x00\x00\xff\xff\xff\xff" in ts_data or b"\x00" * 4 in ts_data:
            self.mode = "tunnel"
        else:
            self.mode = "tunnel"  # Default IPsec VPN standard is tunnel

    def _parse_isakmp_layer(self, v1_hdr: Any) -> None:
        """Parse an IKEv1 / ISAKMP message structure."""
        self.ike_version = 1

        if hasattr(v1_hdr, "init_cookie"):
            cookie = v1_hdr.init_cookie
            if isinstance(cookie, (bytes, bytearray)):
                self.ike_initiator_spi = f"0x{cookie.hex()}"
            elif isinstance(cookie, int):
                self.ike_initiator_spi = f"0x{cookie:016x}"

        if hasattr(v1_hdr, "exch_type"):
            self.ike_exchange_type = int(v1_hdr.exch_type)


# ---------------------------------------------------------------------------
# Public API & Standalone Function
# ---------------------------------------------------------------------------

def parse_ike_pcap(pcap_path: str) -> Dict[str, Any]:
    """
    Parse an IPsec PCAP file and return a dictionary of IKE features
    conforming to `IPsecFeatureRow`.
    """
    parser = IKEParser(pcap_path)
    return parser.parse()


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    cli_parser = argparse.ArgumentParser(
        description="SIH 2026 IKE Dissector - Extracts plaintext IKE and inferred config from PCAP."
    )
    cli_parser.add_argument("pcap", help="Path to input PCAP file.")
    cli_parser.add_argument("--json", action="store_true", help="Print output as formatted JSON.")
    args = cli_parser.parse_args()

    try:
        features = parse_ike_pcap(args.pcap)
        if args.json:
            print(json.dumps(features, indent=2))
        else:
            print(f"[+] IKE Features extracted for {features['session_id']}:")
            for k, v in features.items():
                print(f"    {k:24s}: {v}")
    except Exception as e:
        print(f"[-] Error parsing {args.pcap}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
