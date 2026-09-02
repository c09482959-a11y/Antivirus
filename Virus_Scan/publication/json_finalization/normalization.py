"""Finalizer input normalization before compact JSON projection."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import exact_finite_float_or_none
from Virus_Scan.contracts.result_record import normalize_result_record, result_has_scan_evidence
from Virus_Scan.publication.json_finalization.record_fields import record_errors
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_items,
    final_json_type_name,
    projection_failure,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    duplicate_json_key_text,
    json_key_result,
)


from Virus_Scan.publication.json_finalization.truthiness import first_present_value

_HIGH_RISK_CLASSIFICATIONS = frozenset((
    "malicious",
    "high",
    "high_confidence",
    "suspicious_high",
))
_ERROR_CLASSIFICATIONS = frozenset(("error", "timeout", "incomplete_scan"))
_UNVERIFIED_CLEAN_CLASSIFICATIONS = frozenset(("clean", "clean_score"))


def _exact_text_field(record: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = dict.get(record, key)
        if type(value) is str and str.strip(str.__str__(value)):
            return str.strip(str.__str__(value))
    return ""


def _compact_score(record: dict[str, object]) -> float:
    value = dict.get(record, "score")
    metric = exact_finite_float_or_none(value)
    return metric if metric is not None else 0.0


def _compact_requires_result_normalization(record: dict[str, object]) -> bool:
    classification = _exact_text_field(record, "classification", "class", "verdict").lower()
    if not classification:
        return True
    has_evidence = result_has_scan_evidence(record)
    if classification in _ERROR_CLASSIFICATIONS:
        return not has_evidence
    if classification in _UNVERIFIED_CLEAN_CLASSIFICATIONS:
        return not has_evidence
    if classification in _HIGH_RISK_CLASSIFICATIONS or _compact_score(record) >= 70.0:
        return not has_evidence
    return False


def _compact_snapshot_with_identity(record: dict[str, object]) -> dict[str, object]:
    snapshot = dict(record)
    file_path = first_present_value(snapshot, "file", "path", "node")
    if file_path is not None:
        dict.setdefault(snapshot, "file", file_path)
        dict.setdefault(snapshot, "path", file_path)
        dict.setdefault(snapshot, "node", file_path)
    return snapshot



def _compact_outer_record_snapshot(record: object) -> dict[str, object] | None:
    """Detach outer record mappings through descriptor-based reads only."""
    items = final_json_mapping_items(record)
    if items is None:
        return None
    snapshot: dict[str, object] = {}
    for index, (key, value) in enumerate(items):
        key_text, key_reason = json_key_result(key, index)
        if key_text in snapshot:
            key_text = duplicate_json_key_text(key_text, index)
        if key_reason:
            snapshot[key_text] = projection_failure(key_reason, key)
            continue
        snapshot[key_text] = value
    return snapshot


def normalize_compact_result_record(record: object) -> dict[str, object]:
    """Normalize an arbitrary result object before final JSON compaction."""
    record_snapshot = _compact_outer_record_snapshot(record)
    if record_snapshot is None:
        normalized = normalize_result_record(record, source="finalizer_compact")
    elif _compact_requires_result_normalization(record_snapshot):
        normalized = normalize_result_record(
            record_snapshot,
            file_path=first_present_value(record_snapshot, "file", "path", "node"),
            source="finalizer_compact",
        )
    else:
        normalized = _compact_snapshot_with_identity(record_snapshot)
    if isinstance(normalized, dict):
        raw_error_items = record_errors(normalized)
        normalized["_finalizer_raw_errors"] = raw_error_items
        return normalized
    return {
        "input_file_path": "",
        "_finalizer_raw_errors": [
            {
                "final_json_projection_failed": True,
                "reason": "result_record_normalization_failed",
                "value_type": final_json_type_name(normalized),
            }
        ],
    }


__all__ = (
    'normalize_compact_result_record',
)
