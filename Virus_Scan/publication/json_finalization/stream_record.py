"""Deterministic final-record ordering and compact materialization."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_type_name,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import projection_text_result
from Virus_Scan.publication.json_finalization.compact_record import compact_result_record
from Virus_Scan.publication.json_finalization.stream_identity import record_with_stream_identity
from Virus_Scan.runtime.api import VOLATILE_RESULT_KEYS, deterministic_mode_enabled
from Virus_Scan.contracts.retained_scan_result import (
    retained_publication_record,
    retained_result_marker_present,
)


def _key_text(key: object) -> str:
    text, reason = projection_text_result(key)
    if reason:
        return "<" + no_hook_type_name(key) + ":" + reason + ">"
    return text


def _key_order_text(key: object) -> str:
    return _key_text(key).replace("\\", "/").lower()


def deterministic_streaming_enabled(value: bool | None) -> bool:
    if value is None:
        return deterministic_mode_enabled()
    if type(value) is bool:
        return value
    raise TypeError("unsupported_final_json_deterministic_mode:" + no_hook_type_name(value))


def drop_volatile_result_fields(value: object) -> object:
    if type(value) is dict:
        keyed = [
            (str.__str__(key) if type(key) is str else _key_text(key), item)
            for key, item in dict.items(value)
        ]
        return {
            key: drop_volatile_result_fields(item)
            for key, item in sorted(keyed, key=lambda pair: pair[0].lower())
            if key.lower() not in VOLATILE_RESULT_KEYS
        }
    if type(value) is list:
        return [drop_volatile_result_fields(item) for item in value]
    return value


def stream_result_items(
    results: object,
    *,
    deterministic: bool,
) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(results, allow_dict_subclass=True)
    if items is None:
        raise TypeError("final_json_stream_mapping_unsupported:" + no_hook_type_name(results))
    ordered = sorted(items, key=lambda pair: _key_order_text(pair[0]))
    if not deterministic:
        return tuple((_key_text(key), value) for key, value in ordered)
    canonical: dict[str, object] = {}
    for key, value in ordered:
        key_text = _key_text(key)
        if key_text.lower() not in VOLATILE_RESULT_KEYS:
            if retained_result_marker_present(value):
                retained_publication_record(value)
                canonical[key_text] = value
                continue
            materialized = no_hook_materialize(value, reason_prefix="final_json_stream")
            canonical[key_text] = drop_volatile_result_fields(materialized)
    return tuple(canonical.items())


def json_safe_record(
    value: object,
    make_json_safe: object | None,
    *,
    key_text: str = "",
    compact_records: bool = True,
) -> object:
    """Apply the JSON-safe converter once to one authoritative result record."""
    if retained_result_marker_present(value):
        return make_json_safe(retained_publication_record(value))
    record = record_with_stream_identity(value, key_text)
    if compact_records:
        record = compact_result_record(record)
    return make_json_safe(record)


__all__ = (
    "deterministic_streaming_enabled",
    "drop_volatile_result_fields",
    "json_safe_record",
    "stream_result_items",
)
