
"""
features/ike_parser.py
======================

AI-Powered IPsec VPN Protocol Analyzer - SIH 2026

IKE Protocol Dissector & Inferred Configuration Extractor.

IMPORTANT:
    This parser NEVER derives protocol features from the PCAP filename.

    mode:
        Derived only from observed IKEv2 Traffic Selector payloads.

    pfs_enabled:
        Derived only from an observed KE payload in CREATE_CHILD_SA.

    If the required information is encrypted or absent from the PCAP,
    the parser returns None instead of inventing a value.

Parses plaintext IKEv1/IKEv2 handshake information and ESP metadata
using Scapy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

# Ensure repository root is on sys.path
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

try:
    from scapy.all import PcapReader, IP, IPv6, UDP, ESP, raw
    import scapy.layers.isakmp as isakmp
    import scapy.contrib.ikev2 as ikev2
except ImportError as e:
    raise ImportError(
        f"Scapy is required for features/ike_parser.py: {e}. "
        f"Run 'pip install scapy'."
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DH_GROUP_MAP: Dict[int, str] = {
    1: "group1",
    2: "group2",
    5: "group5",
    14: "group14",
    15: "group15",
    16: "group16",
    19: "group19",
    20: "group20",
    21: "group21",
    28: "group28",
}


# IKEv2 Transform Type 1 = Encryption
ENCR_TRANSFORM_IDS: Dict[int, str] = {
    1: "des_cbc",
    2: "3des_cbc",
    12: "aes_cbc",
    14: "aes_ctr",
    18: "aes128_gcm",
    19: "aes192_gcm",
    20: "aes_gcm",
    28: "chacha20_poly1305",
}


# IKEv2 Transform Type 3 = Integrity
INTEG_TRANSFORM_IDS: Dict[int, str] = {
    1: "hmac_md5",
    2: "hmac_sha1",
    12: "hmac_sha256",
    13: "hmac_sha384",
    14: "hmac_sha512",
}


IKEV1_EXCHANGE_TYPES: Dict[int, str] = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
}


IKEV2_EXCHANGE_TYPES: Dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


# IKEv2 Notify types
NAT_DETECTION_SOURCE_IP = 16388
NAT_DETECTION_DESTINATION_IP = 16389


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class IKEParser:
    """
    Dissects IKE handshakes and ESP context from a PCAP.

    IMPORTANT DESIGN RULE:

        PCAP CONTENT -> FEATURES

    NOT:

        PCAP FILENAME -> FEATURES
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

        # Filename is used ONLY as an identifier.
        # It is NEVER used to infer protocol configuration.
        self.session_id = os.path.splitext(
            os.path.basename(pcap_path)
        )[0]

        # ---------------------------------------------------------------
        # Session tracking
        # ---------------------------------------------------------------

        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        self.initiator_ip: str = "0.0.0.0"
        self.responder_ip: str = "0.0.0.0"

        self.initiator_port: int = 500
        self.responder_port: int = 500

        # ---------------------------------------------------------------
        # IKE metrics
        # ---------------------------------------------------------------

        self.ike_version: Optional[int] = None
        self.ike_exchange_type: Optional[int] = None
        self.ike_initiator_spi: str = "0x0"

        self.sa_proposal_count: int = 0
        self.ke_dh_group: Optional[int] = None

        self.ike_nat_traversal: bool = False

        self.ike_packet_count: int = 0
        self.ike_first_ts: Optional[float] = None
        self.ike_last_ts: Optional[float] = None

        # ---------------------------------------------------------------
        # Inferred configuration
        #
        # IMPORTANT:
        # None means:
        #   "Not observable from the captured plaintext packets."
        #
        # It does NOT mean:
        #   "False"
        # ---------------------------------------------------------------

        self.mode: Optional[str] = None

        self.cipher_suite: Optional[str] = None
        self.auth_algo: Optional[str] = None

        self.dh_group: Optional[str] = None

        self.pfs_enabled: Optional[bool] = None

        self.key_lifetime_sec: Optional[int] = None

        self.esp_spi: str = "0x0"

        # ---------------------------------------------------------------
        # Internal state
        # ---------------------------------------------------------------

        self._seen_esp_spis: List[int] = []

        # Track whether we actually observed relevant protocol evidence.
        self._observed_traffic_selector = False
        self._observed_child_sa_ke = False

    # -------------------------------------------------------------------
    # Main parser
    # -------------------------------------------------------------------

    def parse(self) -> Dict[str, Any]:
        """
        Parse the PCAP and return IKE-derived features.

        No protocol feature is derived from the filename.
        """

        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(
                f"PCAP file not found: {self.pcap_path}"
            )

        try:
            reader = PcapReader(self.pcap_path)
        except Exception as e:
            raise ValueError(
                f"Unable to read PCAP {self.pcap_path}: {e}"
            )

        try:
            for pkt in reader:

                ts = float(pkt.time) if hasattr(pkt, "time") else 0.0

                if self.first_ts is None:
                    self.first_ts = ts

                self.last_ts = ts

                # -------------------------------------------------------
                # ESP
                # -------------------------------------------------------

                if pkt.haslayer(ESP):
                    self._process_esp_packet(pkt)

                # -------------------------------------------------------
                # IKE
                # -------------------------------------------------------

                if pkt.haslayer(UDP):

                    udp_layer = pkt[UDP]

                    sport = int(udp_layer.sport)
                    dport = int(udp_layer.dport)

                    # NAT-T uses UDP/4500.
                    if sport == 4500 or dport == 4500:
                        self.ike_nat_traversal = True

                    # IKE normally uses UDP/500 or UDP/4500.
                    if sport in (500, 4500) or dport in (500, 4500):
                        self._process_ike_packet(
                            pkt,
                            sport,
                            dport,
                            ts,
                        )

        finally:
            reader.close()

        # ----------------------------------------------------------------
        # Finalize
        # ----------------------------------------------------------------

        duration = 0.0

        if self.first_ts is not None and self.last_ts is not None:
            duration = max(
                0.0,
                round(self.last_ts - self.first_ts, 4),
            )

        handshake_duration = 0.0

        if (
            self.ike_first_ts is not None
            and self.ike_last_ts is not None
        ):
            handshake_duration = max(
                0.0,
                round(
                    self.ike_last_ts - self.ike_first_ts,
                    4,
                ),
            )

        # DH group is derived from observed KE/SA data.
        if self.ke_dh_group is not None:
            self.dh_group = DH_GROUP_MAP.get(
                self.ke_dh_group,
                f"group{self.ke_dh_group}",
            )

        # ---------------------------------------------------------------
        # IMPORTANT:
        #
        # There is intentionally NO filename fallback here.
        #
        # DO NOT add:
        #
        #     session_id.split("_")
        #
        # to infer:
        #
        #     mode
        #     pfs_enabled
        #     cipher_suite
        #     dh_group
        #
        # Doing so would leak ground-truth labels into extracted features.
        # ---------------------------------------------------------------

        result: Dict[str, Any] = {

            # -----------------------------------------------------------
            # Session identity
            # -----------------------------------------------------------

            "session_id": self.session_id,

            "ts": (
                self.first_ts
                if self.first_ts is not None
                else 0.0
            ),

            "initiator_ip": self.initiator_ip,
            "responder_ip": self.responder_ip,

            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,

            "duration": duration,

            # -----------------------------------------------------------
            # IKE
            # -----------------------------------------------------------

            "ike_version": (
                self.ike_version
                if self.ike_version is not None
                else 0
            ),

            "ike_exchange_type": (
                self.ike_exchange_type
                if self.ike_exchange_type is not None
                else 0
            ),

            "ike_initiator_spi": self.ike_initiator_spi,

            "sa_proposal_count": self.sa_proposal_count,

            "ke_dh_group": (
                self.ke_dh_group
                if self.ke_dh_group is not None
                else 0
            ),

            "ike_nat_traversal": self.ike_nat_traversal,

            "ike_packet_count": self.ike_packet_count,

            "ike_handshake_duration": handshake_duration,

            # -----------------------------------------------------------
            # Inferred configuration
            # -----------------------------------------------------------

            "mode": self.mode,

            "cipher_suite": self.cipher_suite,

            "auth_algo": self.auth_algo,

            "dh_group": self.dh_group,

            "pfs_enabled": self.pfs_enabled,

            "key_lifetime_sec": self.key_lifetime_sec,

            "esp_spi": self.esp_spi,
        }

        return result

    # -------------------------------------------------------------------
    # ESP
    # -------------------------------------------------------------------

    def _process_esp_packet(self, pkt: Any) -> None:
        """
        Extract ESP SPI from an ESP packet.

        ESP payload remains encrypted, so this only extracts metadata.
        """

        esp_layer = pkt[ESP]

        try:
            spi_val = int(esp_layer.spi)
        except Exception:
            return

        if spi_val not in self._seen_esp_spis:

            self._seen_esp_spis.append(spi_val)

            if self.esp_spi == "0x0":
                self.esp_spi = f"0x{spi_val:08x}"

    # -------------------------------------------------------------------
    # IKE packet
    # -------------------------------------------------------------------

    def _process_ike_packet(
        self,
        pkt: Any,
        sport: int,
        dport: int,
        ts: float,
    ) -> None:
        """Process one IKE UDP packet."""

        self.ike_packet_count += 1

        if self.ike_first_ts is None:
            self.ike_first_ts = ts

        self.ike_last_ts = ts

        # ---------------------------------------------------------------
        # Endpoint information
        # ---------------------------------------------------------------

        if self.initiator_ip == "0.0.0.0":

            if pkt.haslayer(IP):

                self.initiator_ip = pkt[IP].src
                self.responder_ip = pkt[IP].dst

            elif pkt.haslayer(IPv6):

                self.initiator_ip = pkt[IPv6].src
                self.responder_ip = pkt[IPv6].dst

            self.initiator_port = sport
            self.responder_port = dport

        # ---------------------------------------------------------------
        # Native Scapy IKEv2
        # ---------------------------------------------------------------

        if pkt.haslayer(ikev2.IKEv2):

            self._parse_ikev2_layer(
                pkt[ikev2.IKEv2]
            )
            return

        # ---------------------------------------------------------------
        # Native IKEv1
        # ---------------------------------------------------------------

        if pkt.haslayer(isakmp.ISAKMP):

            self._parse_isakmp_layer(
                pkt[isakmp.ISAKMP]
            )
            return

        # ---------------------------------------------------------------
        # Raw UDP payload
        #
        # Particularly useful for UDP/4500 with:
        #
        #     4-byte non-ESP marker
        #
        # followed by IKE.
        # ---------------------------------------------------------------

        try:
            udp_payload = bytes(pkt[UDP].payload)
        except Exception:
            return

        if len(udp_payload) < 28:
            return

        # NAT-T IKE packet begins with four zero bytes.
        if udp_payload[:4] == b"\x00\x00\x00\x00":
            sub_payload = udp_payload[4:]
        else:
            sub_payload = udp_payload

        if len(sub_payload) < 28:
            return

        # Try IKEv2.
        try:

            v2 = ikev2.IKEv2(sub_payload)

            self._parse_ikev2_layer(v2)

            return

        except Exception:
            pass

        # Try IKEv1.
        try:

            v1 = isakmp.ISAKMP(sub_payload)

            self._parse_isakmp_layer(v1)

        except Exception:
            pass

    # -------------------------------------------------------------------
    # IKEv2
    # -------------------------------------------------------------------

    def _parse_ikev2_layer(self, v2_hdr: Any) -> None:
        """Parse an IKEv2 message."""

        self.ike_version = 2

        # ---------------------------------------------------------------
        # Initiator SPI
        # ---------------------------------------------------------------

        if hasattr(v2_hdr, "init_SPI"):

            spi_bytes = v2_hdr.init_SPI

            if isinstance(spi_bytes, (bytes, bytearray)):

                self.ike_initiator_spi = (
                    f"0x{spi_bytes.hex()}"
                )

            elif isinstance(spi_bytes, int):

                self.ike_initiator_spi = (
                    f"0x{spi_bytes:016x}"
                )

        # ---------------------------------------------------------------
        # Exchange type
        # ---------------------------------------------------------------

        exch = getattr(v2_hdr, "exch_type", None)

        if exch is not None:

            exch = int(exch)

            # First observed IKE exchange.
            if self.ike_exchange_type is None:
                self.ike_exchange_type = exch

        # ---------------------------------------------------------------
        # Walk the payload chain
        # ---------------------------------------------------------------

        curr = getattr(v2_hdr, "payload", None)

        while curr:

            # -----------------------------------------------------------
            # Security Association
            # -----------------------------------------------------------

            if isinstance(curr, ikev2.IKEv2_SA):

                self._extract_ikev2_sa(curr)

            # -----------------------------------------------------------
            # Key Exchange
            # -----------------------------------------------------------

            elif isinstance(curr, ikev2.IKEv2_KE):

                self._extract_ikev2_ke(curr)

                # PFS:
                #
                # A KE payload in CREATE_CHILD_SA is evidence of a
                # rekey/Child-SA DH exchange and therefore PFS.
                #
                # We ONLY mark this true when the current exchange is
                # CREATE_CHILD_SA.
                if exch == 36:

                    self.pfs_enabled = True
                    self._observed_child_sa_ke = True

            # -----------------------------------------------------------
            # Traffic Selectors
            # -----------------------------------------------------------

            elif isinstance(
                curr,
                (
                    ikev2.IKEv2_TSi,
                    ikev2.IKEv2_TSr,
                ),
            ):

                self._extract_ikev2_traffic_selectors(curr)

            # -----------------------------------------------------------
            # Notify
            # -----------------------------------------------------------

            elif isinstance(curr, ikev2.IKEv2_Notify):

                self._process_ikev2_notify(curr)

            # -----------------------------------------------------------
            # Continue payload chain
            # -----------------------------------------------------------

            curr = getattr(curr, "payload", None)

    # -------------------------------------------------------------------
    # IKEv2 KE
    # -------------------------------------------------------------------

    def _extract_ikev2_ke(self, ke_payload: Any) -> None:
        """
        Extract the DH group from an IKEv2 KE payload.
        """

        group = getattr(ke_payload, "group", None)

        if group is None:
            return

        try:
            group = int(group)
        except (TypeError, ValueError):
            return

        self.ke_dh_group = group

    # -------------------------------------------------------------------
    # IKEv2 Notify
    # -------------------------------------------------------------------

    def _process_ikev2_notify(self, notify: Any) -> None:
        """Process IKEv2 Notify payloads."""

        notify_type = getattr(notify, "type", None)

        if notify_type is None:
            return

        try:
            notify_type = int(notify_type)
        except (TypeError, ValueError):
            return

        if notify_type in (
            NAT_DETECTION_SOURCE_IP,
            NAT_DETECTION_DESTINATION_IP,
        ):
            self.ike_nat_traversal = True

    # -------------------------------------------------------------------
    # IKEv2 SA
    # -------------------------------------------------------------------

    def _extract_ikev2_sa(self, sa_payload: Any) -> None:
        """
        Extract:

            - proposal count
            - encryption algorithm
            - integrity algorithm
            - DH group
            - ESP SPI

        from an IKEv2 SA payload.
        """

        proposal_count = 0

        curr_prop = getattr(
            sa_payload,
            "prop",
            None,
        )

        while curr_prop:

            proposal_count += 1

            # -----------------------------------------------------------
            # Proposal SPI
            # -----------------------------------------------------------

            spi_value = getattr(
                curr_prop,
                "SPI",
                None,
            )

            if spi_value and self.esp_spi == "0x0":

                try:

                    if isinstance(
                        spi_value,
                        (bytes, bytearray),
                    ) and len(spi_value) == 4:

                        self.esp_spi = (
                            f"0x{int.from_bytes(spi_value, 'big'):08x}"
                        )

                except Exception:
                    pass

            # -----------------------------------------------------------
            # Transforms
            # -----------------------------------------------------------

            curr_trans = getattr(
                curr_prop,
                "trans",
                None,
            )

            key_len = None
            encr_id = None
            integ_id = None

            while curr_trans:

                trans_type = getattr(
                    curr_trans,
                    "transform_type",
                    None,
                )

                trans_id = getattr(
                    curr_trans,
                    "transform_id",
                    None,
                )

                if trans_type is not None:
                    try:
                        trans_type = int(trans_type)
                    except (TypeError, ValueError):
                        trans_type = None

                if trans_id is not None:
                    try:
                        trans_id = int(trans_id)
                    except (TypeError, ValueError):
                        trans_id = None

                # -------------------------------------------------------
                # Encryption
                # -------------------------------------------------------

                if trans_type == 1 and trans_id is not None:

                    encr_id = trans_id

                # -------------------------------------------------------
                # Integrity
                # -------------------------------------------------------

                elif trans_type == 3 and trans_id is not None:

                    integ_id = trans_id

                # -------------------------------------------------------
                # DH
                # -------------------------------------------------------

                elif trans_type == 4 and trans_id is not None:

                    self.ke_dh_group = trans_id

                # -------------------------------------------------------
                # Key length
                # -------------------------------------------------------

                candidate_key_len = getattr(
                    curr_trans,
                    "key_length",
                    None,
                )

                if candidate_key_len:

                    try:
                        key_len = int(candidate_key_len)
                    except (TypeError, ValueError):
                        pass

                next_trans = getattr(
                    curr_trans,
                    "payload",
                    None,
                )

                if isinstance(
                    next_trans,
                    ikev2.IKEv2_Transform,
                ):
                    curr_trans = next_trans
                else:
                    curr_trans = None

            # -----------------------------------------------------------
            # Resolve encryption
            # -----------------------------------------------------------

            if encr_id is not None:

                if encr_id == 12:

                    # AES-CBC
                    if key_len == 128:
                        self.cipher_suite = "aes128_cbc"

                    elif key_len == 256:
                        self.cipher_suite = "aes256_cbc"

                elif encr_id == 18:

                    self.cipher_suite = "aes128_gcm"
                    self.auth_algo = "aes_gcm"

                elif encr_id == 19:

                    self.cipher_suite = "aes192_gcm"
                    self.auth_algo = "aes_gcm"

                elif encr_id == 20:

                    if key_len == 128:
                        self.cipher_suite = "aes128_gcm"

                    elif key_len == 256:
                        self.cipher_suite = "aes256_gcm"

                    else:
                        self.cipher_suite = "aes_gcm"

                    self.auth_algo = "aes_gcm"

                elif encr_id in ENCR_TRANSFORM_IDS:

                    self.cipher_suite = (
                        ENCR_TRANSFORM_IDS[encr_id]
                    )

            # -----------------------------------------------------------
            # Resolve integrity
            # -----------------------------------------------------------

            if (
                integ_id is not None
                and self.cipher_suite not in (
                    "aes128_gcm",
                    "aes192_gcm",
                    "aes256_gcm",
                    "aes_gcm",
                )
            ):

                self.auth_algo = INTEG_TRANSFORM_IDS.get(
                    integ_id
                )

            # -----------------------------------------------------------
            # Next proposal
            # -----------------------------------------------------------

            next_prop = getattr(
                curr_prop,
                "payload",
                None,
            )

            if isinstance(
                next_prop,
                ikev2.IKEv2_Proposal,
            ):
                curr_prop = next_prop
            else:
                curr_prop = None

        if proposal_count > 0:
            self.sa_proposal_count = proposal_count

    # -------------------------------------------------------------------
    # Traffic Selector parsing
    # -------------------------------------------------------------------

    def _extract_ikev2_traffic_selectors(
        self,
        ts_payload: Any,
    ) -> None:
        """
        Determine tunnel vs transport mode from actual Traffic Selector
        fields.

        We DO NOT search raw bytes for zeroes.

        Typical interpretation:

            0.0.0.0/0 or ::/0
                -> tunnel mode

            specific host/range selectors
                -> transport mode

        NOTE:
            This function only runs when Scapy actually exposes a
            Traffic Selector payload. If IKE_AUTH is encrypted, this
            information may simply be unavailable.
        """

        self._observed_traffic_selector = True

        # ---------------------------------------------------------------
        # Try to inspect individual Traffic Selector entries.
        # ---------------------------------------------------------------

        selectors_found = False

        curr = getattr(
            ts_payload,
            "ts",
            None,
        )

        while curr:

            selectors_found = True

            start_addr = self._normalise_address(
                getattr(curr, "start_addr", None)
            )

            end_addr = self._normalise_address(
                getattr(curr, "end_addr", None)
            )

            # -----------------------------------------------------------
            # Any-to-any selector:
            #
            # 0.0.0.0 -> 255.255.255.255
            #
            # or:
            #
            # :: -> ffff:ffff:...
            #
            # strongly indicates tunnel-mode selectors.
            # -----------------------------------------------------------

            if self._is_wildcard_selector(
                start_addr,
                end_addr,
            ):
                self.mode = "tunnel"
                return

            # Continue to next selector.
            next_selector = getattr(
                curr,
                "payload",
                None,
            )

            # Scapy's exact selector class can vary by version.
            # Stop if the next payload is not another TS-like object.
            if next_selector is None:
                break

            curr = next_selector

        # ---------------------------------------------------------------
        # If selectors were present but weren't wildcard selectors,
        # treat them as host/range-specific transport selectors.
        # ---------------------------------------------------------------

        if selectors_found:
            self.mode = "transport"

    # -------------------------------------------------------------------
    # Address helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _normalise_address(value: Any) -> Optional[str]:
        """
        Convert Scapy address representations into strings.
        """

        if value is None:
            return None

        if isinstance(value, bytes):

            try:
                if len(value) == 4:
                    return ".".join(
                        str(x)
                        for x in value
                    )

                if len(value) == 16:

                    import ipaddress

                    return str(
                        ipaddress.ip_address(value)
                    )

            except Exception:
                return None

        return str(value)

    @staticmethod
    def _is_wildcard_selector(
        start_addr: Optional[str],
        end_addr: Optional[str],
    ) -> bool:
        """
        Check whether a Traffic Selector represents the entire address
        space.
        """

        if start_addr is None or end_addr is None:
            return False

        # IPv4 wildcard.
        if (
            start_addr == "0.0.0.0"
            and end_addr == "255.255.255.255"
        ):
            return True

        # IPv6 wildcard.
        if (
            start_addr == "::"
            and end_addr.lower()
            == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        ):
            return True

        return False

    # -------------------------------------------------------------------
    # IKEv1
    # -------------------------------------------------------------------

    def _parse_isakmp_layer(
        self,
        v1_hdr: Any,
    ) -> None:
        """Parse an IKEv1 / ISAKMP message."""

        self.ike_version = 1

        # ---------------------------------------------------------------
        # Initiator cookie
        # ---------------------------------------------------------------

        if hasattr(v1_hdr, "init_cookie"):

            cookie = v1_hdr.init_cookie

            if isinstance(
                cookie,
                (bytes, bytearray),
            ):

                self.ike_initiator_spi = (
                    f"0x{cookie.hex()}"
                )

            elif isinstance(cookie, int):

                self.ike_initiator_spi = (
                    f"0x{cookie:016x}"
                )

        # ---------------------------------------------------------------
        # Exchange type
        # ---------------------------------------------------------------

        if hasattr(v1_hdr, "exch_type"):

            self.ike_exchange_type = int(
                v1_hdr.exch_type
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_ike_pcap(
    pcap_path: str,
) -> Dict[str, Any]:
    """
    Parse an IPsec PCAP and return IKE features.
    """

    parser = IKEParser(pcap_path)

    return parser.parse()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:

    cli_parser = argparse.ArgumentParser(
        description=(
            "SIH 2026 IKE Dissector - "
            "Extracts packet-derived IKE features."
        )
    )

    cli_parser.add_argument(
        "pcap",
        help="Path to input PCAP file.",
    )

    cli_parser.add_argument(
        "--json",
        action="store_true",
        help="Print output as formatted JSON.",
    )

    args = cli_parser.parse_args()

    try:

        features = parse_ike_pcap(
            args.pcap
        )

        if args.json:

            print(
                json.dumps(
                    features,
                    indent=2,
                    default=str,
                )
            )

        else:

            print(
                f"[+] IKE Features extracted for "
                f"{features['session_id']}:"
            )

            for key, value in features.items():

                print(
                    f"    {key:24s}: {value}"
                )

    except Exception as e:

        print(
            f"[-] Error parsing {args.pcap}: {e}",
            file=sys.stderr,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()

