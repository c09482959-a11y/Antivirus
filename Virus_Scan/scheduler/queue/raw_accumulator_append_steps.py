"""Bounded raw accumulator result append transformations."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from typing import Mapping

from Virus_Scan.scheduler.queue.raw_accumulator_value_support import (
    coerce_nonnegative_int,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_text,
    raw_sequence,
    unique_text,
    unsupported_scheduler_value_evidence,
)


def accumulator_result_mapping(result: Mapping[str, object] | None) -> tuple[dict[str, object], bool]:
    result_items = no_hook_mapping_items(result)
    result_rejected = result is not None and result_items is None
    if result_rejected:
        return {
            "error": "raw_accumulator_result_not_mapping",
            "errors": (
                unsupported_scheduler_value_evidence(
                    result,
                    field_name="raw_accumulator_result",
                ),
            ),
            "tags": (
                "raw_accumulator_result_rejected",
                "scanner_degraded",
                "scan_incomplete",
            ),
        }, True
    if result_items is None:
        return {}, False
    return scheduler_str_key_mapping_from_items(result_items), False


def append_accumulator_tags(
    data: dict[str, object],
    result_data: Mapping[str, object],
    deps: object,
) -> None:
    tags = raw_sequence(
        dict.get(data, "tags"),
        field_name="raw_accumulator_tags",
    )
    tags += raw_sequence(
        dict.get(result_data, "tags"),
        field_name="raw_accumulator_result_tags",
    )
    try:
        data["tags"] = deps.ordered_unique_tags(tags)
    except deps.recoverable_exceptions:
        data["tags"] = unique_text(tags)


def append_accumulator_yara_hits(
    data: dict[str, object],
    result_data: Mapping[str, object],
    deps: object,
) -> None:
    hits = raw_sequence(
        dict.get(data, "yara_hits"),
        field_name="raw_accumulator_yara_hits",
    )
    hits += raw_sequence(
        dict.get(result_data, "yara_hits"),
        field_name="raw_accumulator_result_yara_hits",
    )
    try:
        data["yara_hits"] = deps.normalize_yara_hits(hits)
    except deps.recoverable_exceptions:
        data["yara_hits"] = unique_text(hits)



def append_accumulator_strings(data: dict[str, object], result_data: Mapping[str, object]) -> None:
    strings_parts = raw_sequence(
        dict.get(data, "strings_parts"),
        field_name="raw_accumulator_strings_parts",
    )
    part = dict.get(result_data, "strings_blob")
    if part is None:
        part = dict.get(result_data, "strings")
    part_text, part_reason = no_hook_text(
        part,
        missing_reason="missing_raw_accumulator_strings",
        unsupported_reason="unsafe_raw_accumulator_strings_rejected",
    )
    if not part_reason and part_text:
        if sum(len(item) for item in strings_parts if type(item) is str) < 32768:
            strings_parts.append(part_text[:2048])
        data["strings_parts"] = strings_parts[-8:]


def append_accumulator_events(data: dict[str, object], result_data: Mapping[str, object]) -> None:
    events = raw_sequence(
        dict.get(data, "ordered_events"),
        field_name="raw_accumulator_ordered_events",
    )
    events.extend(
        raw_sequence(
            dict.get(result_data, "ordered_events"),
            field_name="raw_accumulator_result_ordered_events",
        )
    )
    data["ordered_events"] = events[-4096:]


def append_accumulator_errors(
    data: dict[str, object],
    result_data: Mapping[str, object],
) -> tuple[object, str]:
    errors = raw_sequence(
        dict.get(data, "errors"),
        field_name="raw_accumulator_errors",
    )
    result_error = dict.get(result_data, "error")
    error_text, error_reason = no_hook_text(
        result_error,
        missing_reason="missing_raw_accumulator_error",
        unsupported_reason="unsafe_raw_accumulator_error_rejected",
    )
    if not error_reason and error_text:
        errors.append(error_text)
    errors.extend(
        raw_sequence(
            dict.get(result_data, "errors"),
            field_name="raw_accumulator_result_errors",
        )
    )
    data["errors"] = unique_text(errors)[-128:]
    return result_error, error_text


def append_accumulator_status(data: dict[str, object], result_data: Mapping[str, object]) -> None:
    data["suspicious"] = (
        dict.get(data, "suspicious") is True
        or dict.get(result_data, "suspicious") is True
    )
    data["completed"] = coerce_nonnegative_int(dict.get(data, "completed"), 0) + 1
    attempt = coerce_nonnegative_int(dict.get(result_data, "attempt"), 0)
    if dict.get(result_data, "retried") is True or attempt > 0:
        data["retried"] = coerce_nonnegative_int(dict.get(data, "retried"), 0) + 1


def append_accumulator_failure(
    data: dict[str, object],
    result_data: Mapping[str, object],
    *,
    result_error: object,
    result_rejected: bool,
    error_text: str,
) -> None:
    if result_error is None and not result_rejected:
        return
    data["failed"] = coerce_nonnegative_int(dict.get(data, "failed"), 0) + 1
    data["degraded"] = True
    failures = raw_sequence(
        dict.get(data, "raw_failures"),
        field_name="raw_accumulator_raw_failures",
    )
    failures.append({
        "collector": no_hook_materialize(
            dict.get(result_data, "collector"),
            reason_prefix="raw_accumulator_collector",
        ),
        "seq": no_hook_materialize(
            dict.get(result_data, "seq"),
            reason_prefix="raw_accumulator_seq",
        ),
        "attempt": no_hook_materialize(
            dict.get(result_data, "attempt"),
            reason_prefix="raw_accumulator_attempt",
        ),
        "error": error_text[:500] if error_text else "raw_accumulator_result_not_mapping",
    })
    data["raw_failures"] = failures[-64:]


__all__ = (
    "accumulator_result_mapping",
    "append_accumulator_errors",
    "append_accumulator_events",
    "append_accumulator_failure",
    "append_accumulator_status",
    "append_accumulator_strings",
    "append_accumulator_tags",
    "append_accumulator_yara_hits",
)
