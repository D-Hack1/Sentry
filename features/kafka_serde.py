"""
features/kafka_serde.py — kafka-python (3.x) serializers shared by the pipeline.

Lives here rather than in kafka/ because that directory name is shadowed by
the kafka-python package itself.
"""

from __future__ import annotations

import json
from typing import Any

from kafka.serializer import Deserializer, Serializer


class JsonValueSerializer(Serializer):
    """dict -> UTF-8 JSON; non-JSON types (datetime, numpy scalars...) via str()."""

    def serialize(self, topic, headers, data: Any):
        if data is None:
            return None
        return json.dumps(data, default=str).encode("utf-8")


class StrKeySerializer(Serializer):
    def serialize(self, topic, headers, data: Any):
        if data is None:
            return None
        return data if isinstance(data, bytes) else str(data).encode("utf-8")


class SafeJsonDeserializer(Deserializer):
    """
    UTF-8 JSON -> object. Never raises: a malformed message becomes
    {"__undecodable__": <error>, "__raw__": <text>} so the consumer can
    dead-letter it instead of crashing the poll loop.
    """

    def deserialize(self, topic, headers, data: bytes):
        if data is None:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {"__undecodable__": f"{type(exc).__name__}: {exc}",
                    "__raw__": data[:2000].decode("utf-8", errors="replace")}
