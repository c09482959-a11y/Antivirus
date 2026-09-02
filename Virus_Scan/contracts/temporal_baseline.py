"""Canonical v5 persisted schema for profile-owned temporal dwell baselines."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import PurePath
from typing import Final

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.temporal_learning import (
    TEMPORAL_BASELINE_MODEL_VERSION,
    TEMPORAL_PROFILE_BASELINE_SCHEMA,
)

TEMPORAL_DWELL_BINS_SEC: Final[tuple[float, ...]] = (
    0.001, 0.01, 0.1, 1.0, 5.0, 30.0, 300.0, 3600.0, 86400.0,
)
TEMPORAL_DWELL_MAX_RECORDS: Final[int] = 4096
TEMPORAL_DWELL_MAX_APPLIED_KEYS: Final[int] = 4096
TEMPORAL_CONTEXT_LEVELS: Final[tuple[str, ...]] = (
    "exact", "engine", "global",
)
_HEX: Final[frozenset[str]] = frozenset("0123456789abcdef")
_RECORD_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version", "model_version", "context_level", "engine",
    "extension", "previous_stage", "current_stage", "source_behavior",
    "target_behavior", "count", "mean", "m2", "minimum", "maximum",
    "histogram_bins_sec", "histogram_counts", "last_update_ordinal",
})
_STORE_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version", "model_version", "records", "applied_learning_keys",
})


def temporal_context_extension(node_id: str) -> str:
    if type(node_id) is not str:
        raise ValueError("temporal baseline node invalid")
    suffix = PurePath(node_id).suffix.lower()
    return suffix if suffix else "<no_ext>"


def temporal_baseline_record_key(
    *, level: str, engine: str, extension: str, previous_stage: str,
    current_stage: str, source_behavior: str, target_behavior: str,
) -> str:
    if level not in TEMPORAL_CONTEXT_LEVELS:
        raise ValueError("temporal baseline context invalid")
    for value in (
        engine, extension, previous_stage, current_stage,
        source_behavior, target_behavior,
    ):
        if type(value) is not str or value == "":
            raise ValueError("temporal baseline identity invalid")
    payload = (
        level,
        engine if level != "global" else "trusted_benign",
        extension if level == "exact" else "*",
        previous_stage,
        current_stage,
        source_behavior,
        target_behavior,
    )
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def empty_temporal_baselines() -> dict[str, object]:
    return {
        "schema_version": TEMPORAL_PROFILE_BASELINE_SCHEMA,
        "model_version": TEMPORAL_BASELINE_MODEL_VERSION,
        "records": {},
        "applied_learning_keys": {},
    }


def new_temporal_baseline_record(
    *, level: str, engine: str, extension: str, previous_stage: str,
    current_stage: str, source_behavior: str, target_behavior: str,
) -> dict[str, object]:
    temporal_baseline_record_key(
        level=level, engine=engine, extension=extension,
        previous_stage=previous_stage, current_stage=current_stage,
        source_behavior=source_behavior, target_behavior=target_behavior,
    )
    return {
        "schema_version": TEMPORAL_PROFILE_BASELINE_SCHEMA,
        "model_version": TEMPORAL_BASELINE_MODEL_VERSION,
        "context_level": level,
        "engine": engine if level != "global" else "trusted_benign",
        "extension": extension if level == "exact" else "*",
        "previous_stage": previous_stage,
        "current_stage": current_stage,
        "source_behavior": source_behavior,
        "target_behavior": target_behavior,
        "count": 0,
        "mean": 0.0,
        "m2": 0.0,
        "minimum": None,
        "maximum": None,
        "histogram_bins_sec": list(TEMPORAL_DWELL_BINS_SEC),
        "histogram_counts": [0] * (len(TEMPORAL_DWELL_BINS_SEC) + 1),
        "last_update_ordinal": 0,
    }


def _finite_nonnegative(value: object, name: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(name + " invalid")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise ValueError(name + " invalid")
    return number


def _owned_mapping(value: object, name: str) -> dict[object, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise ValueError(name + " invalid")
    return dict(items)


def _record_identity(value: dict[object, object]) -> tuple[str, ...]:
    fields = (
        "context_level", "engine", "extension", "previous_stage",
        "current_stage", "source_behavior", "target_behavior",
    )
    output: list[str] = []
    for field in fields:
        child = value.get(field)
        if type(child) is not str or child == "":
            raise ValueError("temporal baseline identity invalid")
        output.append(child)
    return tuple(output)


def _validate_record(key: object, value: object) -> dict[str, object]:
    if type(key) is not str or len(key) != 64 or any(char not in _HEX for char in key):
        raise ValueError("temporal baseline key invalid")
    record = _owned_mapping(value, "temporal baseline record")
    if frozenset(record) != _RECORD_FIELDS:
        raise ValueError("temporal baseline record invalid")
    if record.get("schema_version") != TEMPORAL_PROFILE_BASELINE_SCHEMA:
        raise ValueError("temporal baseline schema invalid")
    if record.get("model_version") != TEMPORAL_BASELINE_MODEL_VERSION:
        raise ValueError("temporal baseline model invalid")
    identity = _record_identity(record)
    level, engine, extension, previous, current, source, target = identity
    if level not in TEMPORAL_CONTEXT_LEVELS:
        raise ValueError("temporal baseline context invalid")
    if level == "global" and (engine != "trusted_benign" or extension != "*"):
        raise ValueError("temporal global context invalid")
    if level == "engine" and extension != "*":
        raise ValueError("temporal engine context invalid")
    expected_key = temporal_baseline_record_key(
        level=level, engine=engine, extension=extension,
        previous_stage=previous, current_stage=current,
        source_behavior=source, target_behavior=target,
    )
    if key != expected_key:
        raise ValueError("temporal baseline identity mismatch")
    count = record.get("count")
    ordinal = record.get("last_update_ordinal")
    if type(count) is not int or isinstance(count, bool) or count < 0:
        raise ValueError("temporal baseline count invalid")
    if type(ordinal) is not int or isinstance(ordinal, bool) or ordinal < 0:
        raise ValueError("temporal baseline ordinal invalid")
    mean = _finite_nonnegative(record.get("mean"), "temporal baseline mean")
    m2 = _finite_nonnegative(record.get("m2"), "temporal baseline m2")
    minimum = record.get("minimum")
    maximum = record.get("maximum")
    if count == 0:
        if minimum is not None or maximum is not None or mean != 0.0 or m2 != 0.0:
            raise ValueError("temporal empty baseline statistics invalid")
    else:
        low = _finite_nonnegative(minimum, "temporal baseline minimum")
        high = _finite_nonnegative(maximum, "temporal baseline maximum")
        if low > mean or mean > high:
            raise ValueError("temporal baseline bounds invalid")
    bins = record.get("histogram_bins_sec")
    counts = record.get("histogram_counts")
    if type(bins) not in (list, tuple) or tuple(bins) != TEMPORAL_DWELL_BINS_SEC:
        raise ValueError("temporal baseline bins invalid")
    if type(counts) not in (list, tuple) or len(counts) != len(TEMPORAL_DWELL_BINS_SEC) + 1:
        raise ValueError("temporal baseline histogram invalid")
    if any(type(item) is not int or isinstance(item, bool) or item < 0 for item in counts):
        raise ValueError("temporal baseline histogram invalid")
    if sum(counts) != count:
        raise ValueError("temporal baseline histogram support mismatch")
    clean = deepcopy(record)
    clean["histogram_bins_sec"] = list(bins)
    clean["histogram_counts"] = list(counts)
    return clean


def validate_temporal_baselines(value: object) -> dict[str, object]:
    store = _owned_mapping(value, "temporal baseline store")
    if frozenset(store) != _STORE_FIELDS:
        raise ValueError("temporal baseline store invalid")
    if store.get("schema_version") != TEMPORAL_PROFILE_BASELINE_SCHEMA:
        raise ValueError("temporal baseline store schema invalid")
    if store.get("model_version") != TEMPORAL_BASELINE_MODEL_VERSION:
        raise ValueError("temporal baseline store model invalid")
    records = _owned_mapping(store.get("records"), "temporal baseline records")
    applied = _owned_mapping(
        store.get("applied_learning_keys"), "temporal baseline applied keys",
    )
    if len(records) > TEMPORAL_DWELL_MAX_RECORDS:
        raise ValueError("temporal baseline records invalid")
    if len(applied) > TEMPORAL_DWELL_MAX_APPLIED_KEYS:
        raise ValueError("temporal baseline applied keys invalid")
    clean_records = {
        key: _validate_record(key, record)
        for key, record in sorted(records.items())
    }
    clean_applied: dict[str, int] = {}
    for key, ordinal in sorted(applied.items()):
        if type(key) is not str or len(key) != 64 or any(char not in _HEX for char in key):
            raise ValueError("temporal baseline replay key invalid")
        if type(ordinal) is not int or isinstance(ordinal, bool) or ordinal < 0:
            raise ValueError("temporal baseline replay ordinal invalid")
        clean_applied[key] = ordinal
    return {
        "schema_version": TEMPORAL_PROFILE_BASELINE_SCHEMA,
        "model_version": TEMPORAL_BASELINE_MODEL_VERSION,
        "records": clean_records,
        "applied_learning_keys": clean_applied,
    }


__all__ = (
    "TEMPORAL_CONTEXT_LEVELS",
    "TEMPORAL_DWELL_BINS_SEC",
    "TEMPORAL_DWELL_MAX_APPLIED_KEYS",
    "TEMPORAL_DWELL_MAX_RECORDS",
    "empty_temporal_baselines",
    "new_temporal_baseline_record",
    "temporal_baseline_record_key",
    "temporal_context_extension",
    "validate_temporal_baselines",
)
