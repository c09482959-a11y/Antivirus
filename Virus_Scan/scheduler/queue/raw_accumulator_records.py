"""Immutable raw accumulator record transformations owned by queue domain."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
import time
from typing import Mapping

from Virus_Scan.scheduler.queue.raw_accumulator_append_steps import (
    accumulator_result_mapping,
    append_accumulator_errors,
    append_accumulator_events,
    append_accumulator_failure,
    append_accumulator_status,
    append_accumulator_strings,
    append_accumulator_tags,
    append_accumulator_yara_hits,
)
from Virus_Scan.scheduler.queue.raw_accumulator_yara_evidence import (
    append_accumulator_yara_evidence,
)
from Virus_Scan.scheduler.queue.raw_accumulator_value_support import (
    coerce_nonnegative_int,
    no_hook_mapping_items,
    raw_accumulator_failure_record,
    raw_mapping,
    raw_sequence,
    raw_text,
    unique_text,
)

def empty_raw_accumulator(file_id: object) -> dict[str, object]:
    return {
        "file_id": raw_text(file_id, field_name="raw_accumulator_file_id"),
        "expected": 0,
        "completed": 0,
        "failed": 0,
        "retried": 0,
        "degraded": False,
        "raw_failures": [],
        "tags": [],
        "yara_hits": [],
        "yara_evidence": None,
        "strings_parts": [],
        "ordered_events": [],
        "errors": [],
        "suspicious": False,
    }


def normalize_counts(data: object, deps: object) -> dict[str, object]:
    """Normalize raw accumulator counters without hiding reconciliation drift."""
    items = no_hook_mapping_items(data)
    if items is None:
        return raw_accumulator_failure_record(data, reason="raw_accumulator_record_not_mapping")
    data = scheduler_str_key_mapping_from_items(items)
    expected = coerce_nonnegative_int(dict.get(data, "expected"), 0)
    completed = coerce_nonnegative_int(dict.get(data, "completed"), 0)
    failed = coerce_nonnegative_int(dict.get(data, "failed"), 0)
    retried = coerce_nonnegative_int(dict.get(data, "retried"), 0)
    repaired = False
    if completed > expected > 0:
        expected = completed
        repaired = True
    if failed > completed:
        completed = failed
        expected = max(expected, completed)
        repaired = True
    data["expected"] = expected
    data["completed"] = completed
    data["failed"] = failed
    data["retried"] = retried
    if repaired:
        data["degraded"] = True
        tags = raw_sequence(dict.get(data, "tags"), field_name="raw_accumulator_tags")
        tags.append("raw_accumulator_count_reconciled")
        try:
            data["tags"] = deps.ordered_unique_tags(tags)
        except deps.recoverable_exceptions:
            data["tags"] = unique_text(tags)
        errs = raw_sequence(dict.get(data, "errors"), field_name="raw_accumulator_errors")
        errs.append("raw accumulator counters required deterministic reconciliation")
        data["errors"] = unique_text(errs)[-128:]
    return data


def initialized_record(
    path: object,
    file_id: object,
    expected: int,
    initial_tags: list[object] | None,
    effective_stage: str,
    ext_stage: str,
    identity: Mapping[str, object] | None,
    deps: object,
) -> dict[str, object]:
    now = time.time()
    return {
        "file_id": raw_text(file_id, field_name="raw_accumulator_file_id"),
        "file": raw_text(path, field_name="raw_accumulator_path"),
        "expected": coerce_nonnegative_int(expected, 0),
        "completed": 0,
        "failed": 0,
        "retried": 0,
        "degraded": False,
        "raw_failures": [],
        "tags": deps.ordered_unique_tags(raw_sequence(initial_tags, field_name="raw_accumulator_initial_tags")),
        "yara_hits": [],
        "yara_evidence": None,
        "strings_parts": [],
        "ordered_events": [],
        "errors": [],
        "suspicious": False,
        "effective_stage": raw_text(effective_stage, field_name="raw_accumulator_effective_stage"),
        "ext_stage": raw_text(ext_stage, field_name="raw_accumulator_ext_stage"),
        "identity": raw_mapping(identity, field_name="raw_accumulator_identity"),
        "published_at": now,
        "updated_at": now,
    }


def append_result_record(
    data: dict[str, object],
    result: Mapping[str, object] | None,
    deps: object,
) -> dict[str, object]:
    result_data, result_rejected = accumulator_result_mapping(result)
    data = normalize_counts(data, deps)
    append_accumulator_tags(data, result_data, deps)
    append_accumulator_yara_hits(data, result_data, deps)
    append_accumulator_yara_evidence(data, result_data)
    append_accumulator_strings(data, result_data)
    append_accumulator_events(data, result_data)
    result_error, error_text = append_accumulator_errors(data, result_data)
    append_accumulator_status(data, result_data)
    append_accumulator_failure(
        data,
        result_data,
        result_error=result_error,
        result_rejected=result_rejected,
        error_text=error_text,
    )
    data["updated_at"] = time.time()
    return normalize_counts(data, deps)


def reconciled_expected_record(
    data: dict[str, object],
    expected: int,
    *,
    reason: str,
    deps: object,
) -> dict[str, object]:
    data = normalize_counts(data, deps)
    new_expected = coerce_nonnegative_int(expected, 0)
    old_expected = coerce_nonnegative_int(dict.get(data, "expected"), 0)
    completed = coerce_nonnegative_int(dict.get(data, "completed"), 0)
    new_expected = max(new_expected, completed)
    if new_expected != old_expected:
        data["expected"] = new_expected
        data["degraded"] = True
        tags = raw_sequence(dict.get(data, "tags"), field_name="raw_accumulator_tags")
        tags.extend(["raw_accumulator_expected_reconciled", "scanner_degraded", "scan_incomplete"])
        try:
            data["tags"] = deps.ordered_unique_tags(tags)
        except deps.recoverable_exceptions:
            data["tags"] = unique_text(tags)
        reason_text = raw_text(reason, field_name="raw_accumulator_reconcile_reason")
        failures = raw_sequence(dict.get(data, "raw_failures"), field_name="raw_accumulator_raw_failures")
        message = reason_text + ": expected " + str(old_expected) + " -> " + str(new_expected)
        failures.append({"collector": "raw_publish", "seq": None, "attempt": None, "error": message})
        data["raw_failures"] = failures[-64:]
        errors = raw_sequence(dict.get(data, "errors"), field_name="raw_accumulator_errors")
        errors.append(message)
        data["errors"] = unique_text(errors)[-128:]
    data["updated_at"] = time.time()
    return normalize_counts(data, deps)


__all__ = (
    "append_result_record",
    "coerce_nonnegative_int",
    "empty_raw_accumulator",
    "initialized_record",
    "normalize_counts",
    "reconciled_expected_record",
)
