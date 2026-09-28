"""
api/report_generator.py — PDF security assessment report generator
Uses Jinja2 + WeasyPrint.  Called by GET /report/{id}.
"""

import os
import math
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

# ── Template directory ────────────────────────────────────────────────────────
_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "reports"
)

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


# ── MITRE ATT&CK for ICS — relevant techniques per risk flag ─────────────────
_MITRE_MAPPING = {
    "DEPRECATED: DH Group 2": {
        "id":          "T0869",
        "name":        "Standard Application Layer Protocol",
        "tactic":      "Command and Control",
        "description": "Weak key exchange exposes session negotiation to passive interception "
                       "and potential Logjam-style downgrade attacks.",
    },
    "WEAK: DH Group 5": {
        "id":          "T0869",
        "name":        "Standard Application Layer Protocol",
        "tactic":      "Command and Control",
        "description": "Sub-2048-bit DH is considered weak under NIST SP 800-131A.",
    },
    "WEAK: AES-128-CBC": {
        "id":          "T0830",
        "name":        "Adversary-in-the-Middle",
        "tactic":      "Collection",
        "description": "CBC mode without authenticated encryption is vulnerable to "
                       "padding oracle attacks.",
    },
    "HIGH RISK: No Perfect Forward Secrecy": {
        "id":          "T0831",
        "name":        "Data Destruction",
        "tactic":      "Inhibit Response Function",
        "description": "Without PFS, compromise of the long-term key allows retrospective "
                       "decryption of all recorded sessions.",
    },
    "LEGACY: IKEv1": {
        "id":          "T0869",
        "name":        "Standard Application Layer Protocol",
        "tactic":      "Command and Control",
        "description": "IKEv1 lacks built-in DoS protection and has known Main Mode "
                       "identity exposure issues.",
    },
}


# ── Gauge SVG ─────────────────────────────────────────────────────────────────
def _score_gauge_svg(score: float) -> str:
    """
    Returns an inline SVG semicircular gauge for security_score (0–100).
    Red → Yellow → Green across the arc.
    """
    score   = max(0.0, min(100.0, float(score)))
    radius  = 80
    cx, cy  = 100, 100
    # Arc from 180° (left) to 0° (right) — progress = score/100
    start_angle = math.pi          # left
    end_angle   = 0.0              # right
    angle = start_angle - (start_angle - end_angle) * (score / 100)

    x = cx + radius * math.cos(angle)
    y = cy - radius * math.sin(angle)   # SVG y-axis is inverted

    # Sweep: large arc flag = 0 (always < 180°), sweep-flag = 0 (counter-clockwise)
    if score < 50:
        needle_color = "#ef4444"   # red
    elif score < 75:
        needle_color = "#f59e0b"   # amber
    else:
        needle_color = "#22c55e"   # green

    return f"""
<svg viewBox="0 0 200 120" xmlns="http://www.w3.org/2000/svg" width="200" height="120">
  <defs>
    <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%"   stop-color="#ef4444"/>
      <stop offset="50%"  stop-color="#f59e0b"/>
      <stop offset="100%" stop-color="#22c55e"/>
    </linearGradient>
  </defs>
  <!-- Background arc -->
  <path d="M 20 100 A 80 80 0 0 1 180 100"
        fill="none" stroke="#e5e7eb" stroke-width="12" stroke-linecap="round"/>
  <!-- Coloured progress arc -->
  <path d="M 20 100 A 80 80 0 0 1 {x:.2f} {y:.2f}"
        fill="none" stroke="url(#arcGrad)" stroke-width="12" stroke-linecap="round"/>
  <!-- Needle dot -->
  <circle cx="{x:.2f}" cy="{y:.2f}" r="6" fill="{needle_color}"/>
  <!-- Score text -->
  <text x="100" y="95" text-anchor="middle"
        font-family="sans-serif" font-size="28" font-weight="bold"
        fill="{needle_color}">{int(score)}</text>
  <text x="100" y="112" text-anchor="middle"
        font-family="sans-serif" font-size="11" fill="#6b7280">/ 100</text>
</svg>
""".strip()


# ── Risk flag → severity colour ───────────────────────────────────────────────
def _flag_severity(flag: str) -> str:
    upper = flag.upper()
    if "DEPRECATED" in upper or "BROKEN" in upper:
        return "critical"
    if "HIGH RISK" in upper or "WEAK" in upper:
        return "high"
    if "LEGACY" in upper or "LONG" in upper:
        return "medium"
    return "info"


# ── MITRE threats relevant to this session ───────────────────────────────────
def _mitre_threats(risk_flags: list[str]) -> list[dict]:
    seen = set()
    threats = []
    for flag in risk_flags:
        for key, threat in _MITRE_MAPPING.items():
            if key in flag and threat["id"] not in seen:
                threats.append(threat)
                seen.add(threat["id"])
    return threats


# ── Executive summary ─────────────────────────────────────────────────────────
def _executive_summary(session: dict) -> str:
    score    = session.get("security_score", 0)
    severity = session.get("severity", "unknown")
    cipher   = session.get("cipher_suite", "unknown")
    dh       = session.get("dh_group", "unknown")
    pfs      = "enabled" if session.get("pfs_enabled") else "disabled"
    traffic  = session.get("traffic_class", "unknown")
    flags    = session.get("risk_flags", [])

    risk_phrase = (
        "presents critical security weaknesses that require immediate remediation"
        if severity == "critical"
        else "has significant security concerns that should be addressed promptly"
        if severity == "high"
        else "meets minimum security requirements but has room for improvement"
        if severity == "medium"
        else "is configured securely"
    )

    flag_summary = (
        f"Key concerns include: {', '.join(flags[:3])}{'...' if len(flags) > 3 else ''}."
        if flags else "No critical rule violations were detected."
    )

    return (
        f"The analysed IPsec VPN session (ID: {session.get('session_id', 'N/A')}) "
        f"{risk_phrase}, achieving a security score of {score}/100 ({severity.upper()}). "
        f"The session used {cipher} encryption with {dh} key exchange and PFS was {pfs}. "
        f"Traffic analysis classified the payload as {traffic}. "
        f"{flag_summary}"
    )


# ── Public interface ──────────────────────────────────────────────────────────
def generate_pdf_report(session: dict[str, Any]) -> bytes:
    """
    Render the Jinja2 HTML template with session data and convert to PDF bytes.
    Raises RuntimeError if the template file is missing.
    """
    template_path = os.path.join(_TEMPLATE_DIR, "template.html")
    if not os.path.exists(template_path):
        raise RuntimeError(
            f"Report template not found at {template_path}. "
            "Ensure reports/template.html exists."
        )

    risk_flags = session.get("risk_flags", [])
    decorated_flags = [
        {"text": f, "severity": _flag_severity(f)}
        for f in risk_flags
    ]

    template_context = {
        "session":           session,
        "generated_at":      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "executive_summary": _executive_summary(session),
        "gauge_svg":         _score_gauge_svg(session.get("security_score", 0)),
        "risk_flags":        decorated_flags,
        "mitre_threats":     _mitre_threats(risk_flags),
        "recommendations":   session.get("recommendations", []),
        "evidence":          session.get("evidence", {}),
        # Severity colour helpers
        "severity_color": {
            "critical": "#dc2626",
            "high":     "#ea580c",
            "medium":   "#ca8a04",
            "low":      "#16a34a",
            "info":     "#2563eb",
        },
    }

    template = _jinja_env.get_template("template.html")
    html_str = template.render(**template_context)

    pdf_bytes = HTML(string=html_str, base_url=_TEMPLATE_DIR).write_pdf()
    return pdf_bytes