import importlib.util
from pathlib import Path

import pytest

from features.kafka_serde import JsonValueSerializer, SafeJsonDeserializer, StrKeySerializer

ROOT = Path(__file__).resolve().parents[1]


def _consumer_module():
    # kafka/consumer.py must be loaded by path: `kafka` is the kafka-python package
    spec = importlib.util.spec_from_file_location("sentry_kafka_consumer", ROOT / "kafka" / "consumer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_json_round_trip():
    data = {"a": 1, "b": [1.5, None], "c": "x"}
    raw = JsonValueSerializer().serialize("t", [], data)
    assert SafeJsonDeserializer().deserialize("t", [], raw) == data
    assert StrKeySerializer().serialize("t", [], "sid") == b"sid"


def test_bad_json_never_raises():
    value = SafeJsonDeserializer().deserialize("t", [], b"\xff{not json")
    assert "__undecodable__" in value and "__raw__" in value


@pytest.mark.parametrize("envelope", [
    None,
    ["not", "a", "dict"],
    {"__undecodable__": "JSONDecodeError", "__raw__": "x"},
    {"feature_row": None},
    {"feature_row": {"session_id": "only-an-id"}},
])
def test_consumer_rejects_bad_envelopes_with_value_or_type_error(envelope):
    consumer = _consumer_module()
    with pytest.raises((TypeError, ValueError)):
        consumer._deserialise(envelope)


def test_end_to_end_latency_uses_publish_stamp():
    from datetime import datetime, timedelta, timezone
    import time

    consumer = _consumer_module()
    stamp = (datetime.now(timezone.utc) - timedelta(milliseconds=250)).isoformat()
    latency = consumer._end_to_end_latency_ms({"published_at": stamp}, time.monotonic())
    assert 240 <= latency < 5000
    assert consumer._end_to_end_latency_ms({}, time.monotonic()) < 50
