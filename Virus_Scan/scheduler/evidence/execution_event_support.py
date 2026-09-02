"""No-hook support for scheduler execution events."""
from __future__ import annotations

import math
from collections.abc import Mapping


from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value as mapping_item_value
from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_mapping,
    immutable_tuple,
    materialize_scheduler_mapping,
    unsupported_scheduler_value_evidence,
)

ExecutionIssue = dict[str, object]
ExecutionItems = tuple[tuple[object, object], ...]
ExecutionMapping = Mapping[str, object]


def field_issue(field_name: str, value: object, reason: str) -> ExecutionIssue:
    return {
        "scheduler_execution_field_rejected": True,
        "field_name": field_name,
        "reason": reason,
        "value_type": no_hook_type_name(value),
        "evidence": unsupported_scheduler_value_evidence(value, field_name=field_name),
    }


def scheduler_text_value(
    value: object,
    *,
    field_name: str,
    default_text: str | None,
    allow_none: bool = False,
) -> tuple[str | None, ExecutionIssue | None]:
    if value is None:
        return (None if allow_none else default_text), None
    text, reason = no_hook_text(
        value,
        missing_reason="scheduler_execution_text_missing",
        unsupported_reason="scheduler_execution_text_rejected",
    )
    if reason == "":
        if text != "":
            return text, None
        return (None if allow_none else default_text), None
    return (None if allow_none else default_text), field_issue(field_name, value, reason)


def scheduler_attempt_value(value: object) -> tuple[int, ExecutionIssue | None]:
    if value is None:
        return 0, None
    if type(value) is bool:
        return 0, field_issue("attempt", value, "scheduler_execution_attempt_rejected")
    if type(value) is int:
        if value < 0:
            return 0, field_issue("attempt", value, "scheduler_execution_attempt_negative")
        return value, None
    if type(value) is float:
        if math.isfinite(value) and value >= 0 and value.is_integer():
            return int(value), None
        reason = (
            "scheduler_execution_attempt_non_finite"
            if not math.isfinite(value)
            else "scheduler_execution_attempt_non_integral"
        )
        return 0, field_issue("attempt", value, reason)
    if type(value) is str:
        text = str.__str__(value).strip()
        if text.isdigit():
            return int(text), None
        return 0, field_issue("attempt", value, "scheduler_execution_attempt_text_invalid")
    return 0, field_issue("attempt", value, "scheduler_execution_attempt_rejected")


def scheduler_bool_metadata_value(value: object, *, field_name: str) -> bool | ExecutionIssue:
    if value is None:
        return False
    if type(value) is bool:
        return value
    if type(value) is int:
        return value != 0
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "y"}:
            return True
        if text in {"", "0", "false", "no", "n"}:
            return False
    return unsupported_scheduler_value_evidence(value, field_name=field_name)


def immutable_execution_mapping(value: ExecutionMapping | None) -> ExecutionMapping:
    return immutable_mapping({} if value is None else value)


def immutable_execution_tuple(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) in {list, tuple, set, frozenset}:
        return immutable_tuple(value)
    return (unsupported_scheduler_value_evidence(value, field_name="scheduler_execution_sequence"),)


def metadata_with_field_issues(metadata: ExecutionMapping | None, issues: ExecutionMapping) -> ExecutionMapping:
    frozen = immutable_execution_mapping(metadata)
    if not issues:
        return frozen
    materialized = materialize_scheduler_mapping(frozen)
    if type(materialized) is not dict:
        materialized = {"metadata_unavailable": unsupported_scheduler_value_evidence(metadata, field_name="metadata")}
    materialized["scheduler_execution_field_rejections"] = materialize_scheduler_mapping(issues)
    return immutable_mapping(materialized)



def first_text_mapping_value(items: ExecutionItems | None, *keys: str) -> object | None:
    if items is None:
        return None
    for key in keys:
        value = mapping_item_value(items, key)
        text, reason = no_hook_text(
            value,
            missing_reason="",
            unsupported_reason="scheduler_execution_text_rejected",
        )
        if reason == "" and text != "":
            return value
    return None


def raw_job_items(job: object) -> ExecutionItems | None:
    return no_hook_mapping_items(job)


__all__ = (
    "field_issue",
    "first_text_mapping_value",
    "immutable_execution_mapping",
    "immutable_execution_tuple",
    "mapping_item_value",
    "metadata_with_field_issues",
    "raw_job_items",
    "scheduler_attempt_value",
    "scheduler_bool_metadata_value",
    "scheduler_text_value",
)
