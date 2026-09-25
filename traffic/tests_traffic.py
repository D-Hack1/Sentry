"""
traffic/tests_traffic.py
Unit tests verifying profile diversity, parameter variation, and manifest compliance.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic.common import TrafficRNG
from traffic.web_traffic import AVAILABLE_PROFILES as WEB_PROFILES, execute_web_session
from traffic.voip_sim import AVAILABLE_PROFILES as VOIP_PROFILES, execute_voip_session
from traffic.video_stream import AVAILABLE_PROFILES as VIDEO_PROFILES, execute_video_session

def test_web_profiles():
    print("Testing Web Traffic Profiles:")
    assert len(WEB_PROFILES) >= 6, f"Expected >= 6 profiles, got {len(WEB_PROFILES)}"
    
    for profile in WEB_PROFILES:
        rng = TrafficRNG(seed=42)
        manifest, pkts, total_bytes = execute_web_session(
            target_host="127.0.0.1",
            target_port=80,
            profile=profile,
            duration=35.0,
            start_delay=1.0,
            rng=rng,
            session_id=f"test_web_{profile}",
            dry_run=True,
        )
        assert manifest.traffic_class == "web"
        assert manifest.profile == profile
        assert manifest.seed == 42
        assert len(manifest.generation_params["phases"]) >= 2
        assert pkts > 0
        assert total_bytes > 0
        print(f"  [PASS] {profile}: {pkts} pkts, {total_bytes} bytes, {len(manifest.generation_params['phases'])} phases")

def test_voip_profiles():
    print("\nTesting VoIP Traffic Profiles:")
    assert len(VOIP_PROFILES) >= 6, f"Expected >= 6 profiles, got {len(VOIP_PROFILES)}"

    for profile in VOIP_PROFILES:
        rng = TrafficRNG(seed=99)
        manifest, pkts, total_bytes = execute_voip_session(
            target_host="127.0.0.1",
            target_port=5004,
            profile=profile,
            duration=35.0,
            start_delay=1.0,
            rng=rng,
            session_id=f"test_voip_{profile}",
            dry_run=True,
        )
        assert manifest.traffic_class == "voip"
        assert manifest.profile == profile
        assert manifest.seed == 99
        assert len(manifest.generation_params["phases"]) >= 2
        assert pkts > 0
        assert total_bytes > 0
        print(f"  [PASS] {profile}: {pkts} pkts, {total_bytes} bytes, {len(manifest.generation_params['phases'])} phases")

def test_video_profiles():
    print("\nTesting Video Streaming Traffic Profiles:")
    assert len(VIDEO_PROFILES) >= 6, f"Expected >= 6 profiles, got {len(VIDEO_PROFILES)}"

    for profile in VIDEO_PROFILES:
        rng = TrafficRNG(seed=777)
        manifest, pkts, total_bytes = execute_video_session(
            target_host="127.0.0.1",
            target_port=8080,
            profile=profile,
            duration=35.0,
            start_delay=1.0,
            rng=rng,
            session_id=f"test_video_{profile}",
            dry_run=True,
        )
        assert manifest.traffic_class == "video_stream"
        assert manifest.profile == profile
        assert manifest.seed == 777
        assert len(manifest.generation_params["phases"]) >= 2
        assert pkts > 0
        assert total_bytes > 0
        print(f"  [PASS] {profile}: {pkts} pkts, {total_bytes} bytes, {len(manifest.generation_params['phases'])} phases")

if __name__ == "__main__":
    test_web_profiles()
    test_voip_profiles()
    test_video_profiles()
    print("\nAll web, VoIP, and video streaming profile tests passed successfully!")
