"""Canonical scheduler ownership for obtaining and publishing one YARA result.

This module does not load, compile, or execute a second YARA implementation.
It receives the existing canonical scan callable through dependency injection,
reuses an exact immutable result when one already exists, and publishes that
same result to scheduler records.
"""
from __future__ import annotations

from Virus_Scan.contracts.scan_cache_fingerprint import ScanCacheExecutionIdentity
from Virus_Scan.contracts.yara_hits import (
    YaraScanResult,
    normalize_yara_hits,
    unavailable_yara_scan_result,
    yara_scan_result_record,
)


def _materialize_yara_result(value: object) -> YaraScanResult | None:
    if type(value) is YaraScanResult:
        return value
    if type(value) is not dict:
        return None
    try:
        return YaraScanResult.from_record(value)
    except (TypeError, ValueError):
        return None


def obtain_scheduler_yara_result(
    *,
    path: object,
    yara_enabled: bool,
    compiled_rules: object,
    yara_scan_with_optional_zip: object,
    existing_result: object = None,
) -> YaraScanResult:
    """Reuse an exact result or invoke the existing canonical YARA owner once."""
    if type(yara_enabled) is not bool:
        raise TypeError("scheduler_yara_enabled_exact_bool_required")
    materialized = _materialize_yara_result(existing_result)
    if materialized is not None:
        return materialized
    if not yara_enabled:
        return unavailable_yara_scan_result(
            "yara_disabled_by_request",
            status="disabled",
        )
    result = yara_scan_with_optional_zip(
        path,
        compiled_rules=compiled_rules,
    )
    if type(result) is not YaraScanResult:
        raise TypeError("scheduler_yara_scan_result_invalid")
    return result


def _remove_executed_yara_from_skipped_layers(
    record: dict[str, object],
    yara_result: YaraScanResult,
) -> None:
    if yara_result.status in ("disabled", "unavailable"):
        return
    explanation = dict.get(record, "explanation")
    if type(explanation) is not dict:
        return
    constraints = dict.get(explanation, "constraints")
    if type(constraints) is not dict:
        return
    skipped = dict.get(constraints, "heavy_layers_skipped")
    if type(skipped) not in (list, tuple):
        return
    filtered = [
        item
        for item in skipped
        if type(item) is str and item != "full_yara"
    ]
    dict.__setitem__(constraints, "heavy_layers_skipped", filtered)


def publish_scheduler_yara_result(
    record: object,
    yara_result: object,
) -> dict[str, object]:
    """Attach one exact immutable YARA result to a final scheduler record."""
    if type(record) is not dict:
        raise TypeError("scheduler_yara_publication_record_invalid")
    if type(yara_result) is not YaraScanResult:
        raise TypeError("scheduler_yara_publication_result_invalid")
    dict.__setitem__(record, "yara_hits", normalize_yara_hits(yara_result))
    dict.__setitem__(record, "yara_evidence", yara_scan_result_record(yara_result))
    _remove_executed_yara_from_skipped_layers(record, yara_result)
    return record


def cached_scheduler_yara_result(
    record: object,
    execution_identity: object,
) -> YaraScanResult | None:
    """Return a cache result only when its current YARA contract is exact."""
    if type(record) is not dict or type(execution_identity) is not ScanCacheExecutionIdentity:
        return None
    raw_result = dict.get(record, "yara_evidence")
    materialized = _materialize_yara_result(raw_result)
    if materialized is None:
        return None
    if execution_identity.yara_state == "disabled":
        return materialized if materialized.status == "disabled" else None
    if execution_identity.yara_state != "verified":
        return None
    if materialized.status not in ("complete", "complete_no_match"):
        return None
    if materialized.package_kind != execution_identity.yara_package_kind:
        return None
    if materialized.rule_source_digest != execution_identity.yara_source_digest:
        return None
    if materialized.compiled_cache_digest != execution_identity.yara_compiled_cache_digest:
        return None
    if materialized.rule_catalog_digest != execution_identity.yara_rule_catalog_digest:
        return None
    return materialized


__all__ = (
    "cached_scheduler_yara_result",
    "obtain_scheduler_yara_result",
    "publish_scheduler_yara_result",
)
