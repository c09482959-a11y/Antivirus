"""Compact per-record final JSON materialization."""
from __future__ import annotations

import json
from typing import Mapping

from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.publication.json_finalization.error_fields import build_compact_error_record
from Virus_Scan.publication.json_finalization.normalization import normalize_compact_result_record
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_items,
    final_json_compact_sort_unavailable_text,
    final_json_duplicate_key_text,
    final_json_type_name,
    projection_failure,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    json_key_result,
)
from Virus_Scan.publication.json_finalization.success_fields import build_compact_success_record


def _compact_json_default(value: object) -> dict[str, object]:
    return {
        "model_signal_projection_failed": True,
        "reason": "compact_json_materialization_failed",
        "value_type": final_json_type_name(value),
    }


def _compact_sort_key(item: object) -> str:
    try:
        return json.dumps(make_json_safe(item), sort_keys=True, default=_compact_json_default)
    except TELEMETRY_FAILURE_ERRORS:
        return final_json_compact_sort_unavailable_text(item)


def _compact_mapping_record(
    items: tuple[tuple[object, object], ...],
) -> dict[str, object]:
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(items):
        key_text, key_reason = json_key_result(key, index)
        if key_text in out:
            key_text = final_json_duplicate_key_text(key_text, index)
        if key_reason:
            out[key_text] = {
                "key_unavailable_reason": key_reason,
                "value": compact_json_serializable_record(item),
            }
        else:
            out[key_text] = compact_json_serializable_record(item)
    return out


def _compact_collection_record(value: object) -> object:
    if type(value) is tuple:
        compacted: object = tuple(
            compact_json_serializable_record(item) for item in value
        )
    elif type(value) is list:
        compacted = [compact_json_serializable_record(item) for item in value]
    else:
        materialized = [compact_json_serializable_record(item) for item in value]
        compacted = tuple(sorted(materialized, key=_compact_sort_key))
    return compacted


def _compact_scalar_record(value: object) -> object:
    if isinstance(value, str) or type(value) in (int, float, bool) or value is None:
        compacted: object = str.__str__(value) if isinstance(value, str) else value
    elif type(value) in (bytes, bytearray):
        compacted = bytes(value).decode("utf-8", errors="replace")
    else:
        compacted = projection_failure("compact_value_unavailable", value)
    return compacted


def _compact_nonmapping_record(value: object) -> object:
    if isinstance(value, Mapping):
        compacted = projection_failure("compact_mapping_unavailable", value)
    elif type(value) in (tuple, list, set, frozenset):
        compacted = _compact_collection_record(value)
    else:
        compacted = _compact_scalar_record(value)
    return compacted


def compact_json_serializable_record(value: object) -> object:
    """Detach mapping views in compact records while preserving contract tuples."""
    items = final_json_mapping_items(value)
    if items is not None:
        return _compact_mapping_record(items)
    return _compact_nonmapping_record(value)


def compact_result_record(record: object) -> object:
    """Return a bounded, audit-useful scan record without deep stringification.

    Stage 35 removes the previous ``len(str(record))`` decision point. Some
    historical result records contain very large nested replay/calibration objects;
    recursively stringifying every record during finalization was the confirmed
    5k/10k stall source.  Final output now compacts every record through an
    explicit allow-list of fields and bounded summaries.
    """
    normalized = normalize_compact_result_record(record)
    try:
        compact = build_compact_success_record(normalized)
    except TELEMETRY_FAILURE_ERRORS as exc:
        compact = build_compact_error_record(normalized, exc)
    return compact_json_serializable_record(compact)


__all__ = (
    'compact_json_serializable_record',
    'compact_result_record',
)
