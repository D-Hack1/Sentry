"""
api/report_generator.py — PDF security assessment report generator.
Renders reports/template.html with Jinja2 and converts it with WeasyPrint.
Called by GET /report/{id}.

Report sections: executive summary, session metadata, security score gauge
(inline SVG), risk flags (severity colour-coded), threat matrix (MITRE ATT&CK
for ICS techniques relevant to the weaknesses found), AI confidence,
recommendations (highest impact first), SHAP evidence and IP correlation.
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from features.security_rules import score_to_severity

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}

# MITRE ATT&CK for ICS techniques an adversary could use against each weakness.
# Keys are substrings of the risk-flag texts in features/security_rules.py.
_TECHNIQUES = {
    "T0842": ("Network Sniffing", "Discovery"),
    "T0830": ("Adversary-in-the-Middle", "Collection"),
    "T0859": ("Valid Accounts", "Persistence / Lateral Movement"),
}
_MITRE_MAPPING = [
    ("DH Group 2", "T0842",
     "1024-bit DH is within reach of Logjam-style precomputation: recorded traffic can be decrypted passively."),
    ("DH Group 5", "T0842",
     "1536-bit DH is below current guidance and weakens long-term confidentiality of captured traffic."),
    ("Perfect Forward Secrecy", "T0842",
     "Without PFS a single key compromise lets an eavesdropper decrypt every recorded session."),
    ("Key lifetime", "T0842",
     "Long key lifetimes increase the volume of traffic exposed by one compromised key."),
    ("AES-128-CBC", "T0830",
     "CBC mode without AEAD is exposed to padding-oracle attacks by an on-path attacker."),
    ("AES-256-CBC", "T0830",
     "CBC mode without AEAD is exposed to padding-oracle attacks by an on-path attacker."),
    ("HMAC-SHA1", "T0830",
     "Deprecated integrity protection weakens tamper detection for an on-path attacker."),
    ("HMAC-MD5", "T0830",
     "Broken integrity protection allows an on-path attacker to tamper with traffic."),
    ("IKEv1", "T0859",
     "IKEv1 Aggressive Mode exposes a PSK hash that can be cracked offline into valid VPN credentials."),
    ("NAT-T", "T0842",
     "UDP encapsulation exposes extra flow metadata to passive observers."),
]


def _score_gauge_svg(score: float) -> str:
    """
    Inline SVG semicircular gauge for security_score (0–100), coloured by severity.
    Solid strokes only: WeasyPrint's SVG renderer drops gradient strokes on
    degenerate paths (score 0) and everything drawn after them.
    """
    score = max(0.0, min(100.0, float(score)))
    radius, cx, cy = 80, 100, 100
    angle = math.pi - math.pi * (score / 100)
    x = cx + radius * math.cos(angle)
    y = cy - radius * math.sin(angle)
    color = SEVERITY_COLORS[score_to_severity(score)]
    progress = (
        f'<path d="M 20 100 A 80 80 0 0 1 {x:.2f} {y:.2f}" fill="none" stroke="{color}" '
        f'stroke-width="12" stroke-linecap="round"/>'
        if score >= 0.5 else ""
    )
    return f"""
<svg viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg" width="220" height="132">
  <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e5e7eb" stroke-width="12" stroke-linecap="round"/>
  {progress}
  <circle cx="{x:.2f}" cy="{y:.2f}" r="6" fill="{color}"/>
  <text x="100" y="95" text-anchor="middle" font-family="sans-serif" font-size="28" font-weight="bold" fill="{color}">{score:.0f}</text>
  <text x="100" y="112" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#6b7280">/ 100</text>
</svg>
""".strip()


def _flag_severity(flag: str) -> str:
    """Rule flags start with their severity, e.g. 'HIGH: Perfect Forward Secrecy ...'."""
    prefix = flag.split(":", 1)[0].strip().lower()
    return prefix if prefix in SEVERITY_COLORS else "info"


def _mitre_threats(risk_flags: list[str]) -> list[dict]:
    threats: dict[str, dict] = {}
    for flag in risk_flags:
        for needle, technique_id, reason in _MITRE_MAPPING:
            if needle.lower() in flag.lower():
                name, tactic = _TECHNIQUES[technique_id]
                entry = threats.setdefault(
                    technique_id, {"id": technique_id, "name": name, "tactic": tactic, "reasons": []}
                )
                if reason not in entry["reasons"]:
                    entry["reasons"].append(reason)
    return list(threats.values())


def _executive_summary(session: dict) -> str:
    score = float(session.get("security_score") or 0)
    severity = session.get("severity") or score_to_severity(score)
    cipher = session.get("cipher_suite") or "an unidentified cipher"
    dh = session.get("dh_group") or "an unidentified DH group"
    pfs = session.get("pfs_enabled")
    pfs_text = "enabled" if pfs is True else "disabled" if pfs is False else "undetermined"
    traffic = (session.get("traffic_class") or "unknown").replace("_", " ")
    flags = session.get("risk_flags") or []

    risk_phrase = {
        "critical": "presents critical security weaknesses that require immediate remediation",
        "high": "has significant security weaknesses that should be addressed promptly",
        "medium": "meets minimum requirements but has notable weaknesses",
        "low": "is reasonably configured with minor improvements available",
    }.get(severity, "is configured securely")
    flag_summary = (
        f"{len(flags)} security rule(s) fired; the most severe is: {flags[0].split('.')[0]}."
        if flags else "No security rule violations were detected."
    )
    return (
        f"The analysed IPsec VPN session {session.get('session_id', 'N/A')} {risk_phrase}, "
        f"scoring {score:.0f}/100 ({severity.upper()}). It negotiated {cipher} with {dh} key exchange; "
        f"Perfect Forward Secrecy was {pfs_text}. Encrypted-traffic analysis classified the tunnel "
        f"payload as {traffic} ({float(session.get('traffic_confidence') or 0):.0%} confidence). "
        f"{flag_summary}"
    )


def _evidence_lists(session: dict) -> tuple[list[str], list[str]]:
    evidence = session.get("evidence") or []
    if isinstance(evidence, dict):  # legacy documents stored {"config": [...], "traffic": [...]}
        return list(evidence.get("traffic", [])), list(evidence.get("config", []))
    return list(evidence), list(session.get("config_evidence") or [])


def render_report_html(session: dict[str, Any]) -> str:
    template_path = os.path.join(_TEMPLATE_DIR, "template.html")
    if not os.path.exists(template_path):
        raise RuntimeError(f"Report template not found at {template_path}")

    risk_flags = list(session.get("risk_flags") or [])
    traffic_evidence, config_evidence = _evidence_lists(session)
    score = float(session.get("security_score") or 0)
    severity = session.get("severity") or score_to_severity(score)
    context = {
        "session": session,
        "severity": severity,
        "score": score,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "executive_summary": _executive_summary(session),
        "gauge_svg": _score_gauge_svg(score),
        "risk_flags": [{"text": f, "severity": _flag_severity(f)} for f in risk_flags],
        "mitre_threats": _mitre_threats(risk_flags),
        "recommendations": list(session.get("recommendations") or []),
        "traffic_evidence": traffic_evidence,
        "config_evidence": config_evidence,
        "correlation": session.get("correlation") or {},
        "severity_color": SEVERITY_COLORS,
    }
    return _jinja_env.get_template("template.html").render(**context)


def generate_pdf_report(session: dict[str, Any]) -> bytes:
    """Render the session report and return PDF bytes."""
    from weasyprint import HTML  # imported lazily: needs system Pango libraries

    return HTML(string=render_report_html(session), base_url=_TEMPLATE_DIR).write_pdf()
