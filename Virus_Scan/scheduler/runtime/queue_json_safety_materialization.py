"""Bounded materialization helpers for scheduler queue JSON safety."""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
import json
import math

from Virus_Scan.scheduler.internal.immutable_outputs import (
    materialize_scheduler_mapping,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS, record_queue_json_degraded

JsonSafeConverter = Callable[[object, str | None], object]
BULKY_QUEUE_JSON_KEYS = frozenset(
    {
        "strings_blob",
        "string_blob",
        "raw_strings",
        "decoded_text",
        "text",
        "raw_sample",
        "content",
        "blob",
        "decompiled_source",
        "ilspy_output",
    }
)
LIMITED_SEQUENCE_KEYS = frozenset({"decoded_payloads", "decode_records", "evidence_links"})


def queue_json_safe_mapping(
    value: dict[object, object],
    *,
    key_text: str,
    safe_value: JsonSafeConverter,
) -> dict[str, object]:
    """Convert an exact dict into deterministic JSON-safe scheduler data."""
    del key_text
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(dict.items(value)):
        key_s = materialize_scheduler_mapping(key)
        if type(key_s) is not str:
            key_s = "unsupported_scheduler_key_" + int.__str__(index)
        if key_s.lower() in BULKY_QUEUE_JSON_KEYS and type(item) is str and len(item) > 2048:
            out[key_s] = {"truncated": True, "chars": len(item), "sample": item[:2048]}
        else:
            out[key_s] = safe_value(item, key_s)
    return out


def queue_json_safe_sequence(
    value: list[object] | tuple[object, ...],
    *,
    key_text: str,
    safe_value: JsonSafeConverter,
) -> list[object]:
    """Convert bounded queue JSON sequences while preserving truncation evidence."""
    limit = 64 if key_text.lower() in LIMITED_SEQUENCE_KEYS else None
    seq = list(value)[:limit] if limit else list(value)
    sequence_out: list[object] = [safe_value(item, key_text or None) for item in seq]
    if limit and len(value) > limit:
        sequence_out.append({"truncated": True, "items": len(value) - limit})
    return sequence_out


def queue_json_safe_set(
    value: set[object] | frozenset[object],
    *,
    key_text: str,
    safe_value: JsonSafeConverter,
) -> list[object]:
    """Convert scheduler set values into a stable JSON-safe list."""
    safe_items = [safe_value(item, key_text or None) for item in value]
    return sorted(safe_items, key=queue_json_safe_order_key)


def queue_json_safe_order_key(value: object) -> tuple[str, str]:
    """Return a deterministic ordering key for JSON-safe set members."""
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except QUEUE_JSON_EXCEPTIONS:
        payload = json.dumps(unsupported_scheduler_value_evidence(value), sort_keys=True, separators=(",", ":"))
    return (type(value).__name__, payload)


def queue_json_unsupported_collection(value: object, *, field_name: str) -> object:
    """Return unsupported evidence for dict subclasses with implicit behavior."""
    if isinstance(value, Counter):
        return unsupported_scheduler_value_evidence(value, field_name=field_name)
    if isinstance(value, defaultdict):
        return unsupported_scheduler_value_evidence(value, field_name=field_name)
    return None


def queue_json_scalar_value(value: object) -> object:
    """Return exact JSON scalar values or None when non-scalar handling is needed."""
    if type(value) is str and len(value) > 8192:
        return {"truncated": True, "chars": len(value), "sample": value[:4096]}
    if type(value) is str or value is None or type(value) in {bool, int}:
        return value
    return None


def queue_json_float_value(value: float, *, field_name: str) -> object:
    """Return finite floats or unsupported evidence for non-finite/hostile values."""
    try:
        if math.isfinite(value):
            return value
    except QUEUE_JSON_EXCEPTIONS as exc:
        record_queue_json_degraded("queue_json_float_check_failed", exc, domain="telemetry")
    return unsupported_scheduler_value_evidence(value, field_name=field_name)
