"""
api/correlator.py — Track and correlate repeated weak-config VPN sessions from the same IP
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Tuple
from collections import defaultdict
import json

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
WEAK_SCORE_THRESHOLD = 60          # Sessions with score < 60 are "weak"
CORRELATION_WINDOW_MINUTES = 60    # Look back this far for correlations
MIN_WEAK_SESSIONS_FOR_PATTERN = 3  # Need at least 3 weak sessions to flag a pattern
ATTACK_PATTERN_SCORE_REDUCTION = 15  # Reduce score by this much if pattern detected


# ══════════════════════════════════════════════════════════════════════════════
# Correlator
# ══════════════════════════════════════════════════════════════════════════════
class SessionCorrelator:
    """
    Tracks weak configurations across sessions, detects patterns from repeated
    IPs attempting weak ciphers or DH groups, and enriches session metadata
    with correlation insights.
    """

    def __init__(self, es_client: AsyncElasticsearch, index_name: str = "ipsec_sessions"):
        """
        Args:
            es_client: AsyncElasticsearch client
            index_name: Name of the ES index storing sessions
        """
        self.es = es_client
        self.index_name = index_name
        # In-memory cache: initiator_ip -> [weak session docs from recent window]
        self._weak_session_cache: Dict[str, List[Dict]] = defaultdict(list)

    async def correlate(self, session: Dict) -> Dict:
        """
        Analyze a session for repeated weak-config patterns from the same initiator IP.

        Args:
            session: The full session document (output from /analyze, before ES storage)

        Returns:
            Enriched session dict with correlation metadata added:
            - correlation: {
                "initiator_ip": str,
                "weak_session_count": int,
                "recent_weak_sessions": [list of recent weak session summaries],
                "pattern_detected": bool,
                "pattern_description": str (if detected),
                "correlation_confidence": float (0–1),
                "recommended_action": str,
              }
            - adjusted_security_score: int (reduced if pattern detected)
            - adjusted_severity: str
        """
        initiator_ip = session.get("initiator_ip", "unknown")
        security_score = session.get("security_score", 100)
        is_weak = security_score < WEAK_SCORE_THRESHOLD

        # Always add correlation metadata, even if this session isn't weak
        correlation_data = await self._analyze_ip_pattern(initiator_ip, session, is_weak)

        # Adjust score if a pattern is detected
        adjusted_score = security_score
        adjusted_severity = session.get("severity", "info")

        if correlation_data["pattern_detected"]:
            adjusted_score = max(0, security_score - ATTACK_PATTERN_SCORE_REDUCTION)
            adjusted_severity = self._map_score_to_severity(adjusted_score)
            logger.warning(
                f"Correlation pattern detected for IP {initiator_ip}: "
                f"original score={security_score}, adjusted={adjusted_score}"
            )

        session["correlation"] = correlation_data
        session["adjusted_security_score"] = adjusted_score
        session["adjusted_severity"] = adjusted_severity

        return session

    async def _analyze_ip_pattern(
        self, initiator_ip: str, current_session: Dict, is_weak: bool
    ) -> Dict:
        """
        Query ES for recent weak sessions from the same initiator IP
        and determine if a suspicious pattern exists.
        """
        # Query ES for recent weak sessions from this IP
        recent_weak = await self._query_recent_weak_sessions(initiator_ip)

        # If current session is weak, add it to the list for pattern analysis
        if is_weak:
            recent_weak.append({
                "session_id":     current_session.get("session_id"),
                "timestamp":      current_session.get("timestamp"),
                "security_score": current_session.get("security_score"),
                "cipher_suite":   current_session.get("cipher_suite"),
                "dh_group":       current_session.get("dh_group"),
            })

        # Analyze for patterns
        pattern_detected, pattern_desc, confidence = self._detect_pattern(
            initiator_ip, recent_weak, current_session
        )

        recommended_action = self._recommend_action(
            initiator_ip, recent_weak, pattern_detected, pattern_desc
        )

        return {
            "initiator_ip":            initiator_ip,
            "weak_session_count":      len(recent_weak),
            "recent_weak_sessions":    recent_weak,
            "pattern_detected":        pattern_detected,
            "pattern_description":     pattern_desc,
            "correlation_confidence":  confidence,
            "recommended_action":      recommended_action,
        }

    async def _query_recent_weak_sessions(self, initiator_ip: str) -> List[Dict]:
        """
        Query ES for weak sessions (score < WEAK_SCORE_THRESHOLD) from initiator_ip
        within the last CORRELATION_WINDOW_MINUTES.
        """
        cutoff_time = (
            datetime.now(timezone.utc) - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        ).isoformat()

        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"initiator_ip": initiator_ip}},
                        {"range": {"security_score": {"lt": WEAK_SCORE_THRESHOLD}}},
                        {"range": {"timestamp": {"gte": cutoff_time}}},
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 100,  # Cap at 100 for memory safety
        }

        try:
            resp = await self.es.search(index=self.index_name, body=es_query)
            return [
                {
                    "session_id":     hit["_source"].get("session_id"),
                    "timestamp":      hit["_source"].get("timestamp"),
                    "security_score": hit["_source"].get("security_score"),
                    "cipher_suite":   hit["_source"].get("cipher_suite"),
                    "dh_group":       hit["_source"].get("dh_group"),
                }
                for hit in resp.get("hits", {}).get("hits", [])
            ]
        except Exception as exc:
            logger.error(f"Error querying recent weak sessions for {initiator_ip}: {exc}")
            return []

    def _detect_pattern(
        self, initiator_ip: str, weak_sessions: List[Dict], current_session: Dict
    ) -> Tuple[bool, str, float]:
        """
        Detect suspicious patterns in weak sessions from this IP.

        Returns:
            (pattern_detected: bool, description: str, confidence: float 0–1)

        Patterns:
          1. Frequency: ≥3 weak sessions in the window → "High Frequency Attack"
          2. Same cipher repeatedly: ≥2 weak sessions with same weak cipher → "Repeated Weak Cipher"
          3. Same weak DH repeatedly: ≥2 weak sessions with same weak DH → "Repeated Weak DH"
          4. Escalation: current session weak + ≥1 prior weak in window → "Escalation"
        """
        if len(weak_sessions) < MIN_WEAK_SESSIONS_FOR_PATTERN:
            return False, "", 0.0

        confidence = 0.0
        descriptions = []

        # ── Pattern 1: High Frequency ───────────────────────────────────────
        if len(weak_sessions) >= MIN_WEAK_SESSIONS_FOR_PATTERN:
            descriptions.append(
                f"High Frequency: {len(weak_sessions)} weak sessions from {initiator_ip} "
                f"in the last {CORRELATION_WINDOW_MINUTES} minutes"
            )
            confidence = min(1.0, confidence + 0.4)

        # ── Pattern 2: Repeated Weak Cipher ────────────────────────────────
        weak_ciphers = {
            "aes128_cbc": True,
            "aes128_gcm": True,  # 128-bit is weak
        }
        cipher_counts = defaultdict(int)
        for sess in weak_sessions:
            cipher = sess.get("cipher_suite")
            if cipher and cipher in weak_ciphers:
                cipher_counts[cipher] += 1

        for cipher, count in cipher_counts.items():
            if count >= 2:
                descriptions.append(
                    f"Repeated Weak Cipher: {count} sessions attempted {cipher} "
                    "(a known-weak cipher)"
                )
                confidence = min(1.0, confidence + 0.3)

        # ── Pattern 3: Repeated Weak DH ────────────────────────────────────
        weak_dh_groups = {
            "group2": True,   # 1024-bit, broken by Logjam
            "group5": True,   # 1536-bit, below recommended
        }
        dh_counts = defaultdict(int)
        for sess in weak_sessions:
            dh = sess.get("dh_group")
            if dh and dh in weak_dh_groups:
                dh_counts[dh] += 1

        for dh, count in dh_counts.items():
            if count >= 2:
                descriptions.append(
                    f"Repeated Weak DH: {count} sessions attempted {dh} "
                    "(a deprecated DH group)"
                )
                confidence = min(1.0, confidence + 0.3)

        # ── Pattern 4: Escalation (current session weak + prior weak) ──────
        current_score = current_session.get("security_score", 100)
        if (current_score < WEAK_SCORE_THRESHOLD and 
            len(weak_sessions) >= 2):  # at least one prior weak
            descriptions.append(
                f"Escalation: Current weak session + {len(weak_sessions) - 1} prior "
                f"weak sessions from {initiator_ip} indicate escalating attack pattern"
            )
            confidence = min(1.0, confidence + 0.3)

        pattern_detected = confidence > 0.0
        pattern_text = " | ".join(descriptions) if descriptions else ""

        return pattern_detected, pattern_text, confidence

    def _recommend_action(
        self, initiator_ip: str, weak_sessions: List[Dict], pattern_detected: bool, pattern_desc: str
    ) -> str:
        """
        Generate a recommended security action based on the detected pattern.
        """
        if not pattern_detected:
            return "Monitor. No suspicious pattern detected."

        if not weak_sessions:
            return "No action needed."

        weak_count = len(weak_sessions)

        if weak_count >= 5:
            return (
                f"CRITICAL: Block {initiator_ip} at firewall. IP shows high-frequency "
                f"weak-config attempts ({weak_count} in window). Likely reconnaissance or attack."
            )
        elif weak_count >= 3:
            return (
                f"HIGH: Review firewall rules for {initiator_ip}. Multiple weak-config "
                f"attempts suggest intentional probing. Consider rate-limiting or blocking."
            )
        else:
            return (
                f"MEDIUM: Investigate {initiator_ip}. Repeated weak cipher/DH attempts "
                f"suggest either misconfigured client or active probing. Contact administrator."
            )

    @staticmethod
    def _map_score_to_severity(score: int) -> str:
        """Map numeric score (0–100) back to severity label."""
        if score < 40:
            return "critical"
        elif score < 60:
            return "high"
        elif score < 75:
            return "medium"
        elif score < 90:
            return "low"
        else:
            return "info"


# ══════════════════════════════════════════════════════════════════════════════
# Helper: Correlator Factory (for FastAPI lifespan)
# ══════════════════════════════════════════════════════════════════════════════
def create_correlator(es_client: AsyncElasticsearch, index_name: str = "ipsec_sessions") -> SessionCorrelator:
    """
    Factory function to instantiate a correlator with an ES client.
    Called during app startup.
    """
    return SessionCorrelator(es_client, index_name)