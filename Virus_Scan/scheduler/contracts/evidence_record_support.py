"""No-hook support helpers for scheduler evidence record contracts."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, TypeVar, overload

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.contracts.bool_field_parsing import parse_scheduler_bool_field
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.mapping_item_lookup import first_scheduler_mapping_item_value, scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence


def merge_field_issue(out: dict[str, object], issue: tuple[str, object] | None) -> None:
    if issue is None:
        return
    key, value = issue
    out[key] = value


_T = TypeVar("_T")


def scheduler_text_field(value: object, *, field_name: str, default_text: str) -> tuple[str, tuple[str, object] | None]:
    text, reason = no_hook_text(
        value,
        missing_reason="",
        unsupported_reason="scheduler_evidence_text_rejected",
    )
    if reason == "" and text != "":
        return text, None
    if reason == "" and text == "":
        return default_text, None
    return default_text, (
        scheduler_field_issue_key(field_name),
        {
            "scheduler_evidence_field_rejected": True,
            "field_name": field_name,
            "reason": reason,
            "value_type": no_hook_type_name(value),
        },
    )


def scheduler_bool_field(value: object, *, field_name: str, default: bool) -> tuple[bool, tuple[str, object] | None]:
    parsed = parse_scheduler_bool_field(
        value,
        text_invalid_reason="scheduler_evidence_bool_text_unrecognized",
        rejected_reason="scheduler_evidence_bool_rejected",
    )
    if parsed.accepted:
        return parsed.value, None
    if parsed.reason == "":
        return default, None
    return default, (
        scheduler_field_issue_key(field_name),
        {
            "scheduler_evidence_field_rejected": True,
            "field_name": field_name,
            "reason": parsed.reason,
            "value_type": no_hook_type_name(value),
        },
    )


def scheduler_mapping_items(value: object) -> tuple[tuple[object, object], ...] | None:
    frozen_decision = frozen_scheduler_items_decision(value)
    if frozen_decision.accepted:
        return frozen_decision.items
    if type(value) is dict or type(value) is MappingProxyType:
        return no_hook_mapping_items(value)
    return None


@overload
def scheduler_mapping_value(value: object, key: str) -> object | None: ...


@overload
def scheduler_mapping_value(value: object, key: str, *, default: _T) -> _T: ...


def scheduler_mapping_value(value: object, key: str, *, default: object = None) -> object:
    return scheduler_mapping_item_value(scheduler_mapping_items(value), key, default)


@overload
def first_scheduler_mapping_value(value: object, *keys: str) -> object | None: ...


@overload
def first_scheduler_mapping_value(value: object, *keys: str, default: _T) -> _T: ...


def first_scheduler_mapping_value(value: object, *keys: str, default: object = None) -> object:
    return first_scheduler_mapping_item_value(scheduler_mapping_items(value), keys, default)


def scheduler_context_with_issues(context: object, issues: Mapping[str, object]) -> Mapping[str, object]:
    merged: dict[str, object] = {}
    items = scheduler_mapping_items(context)
    if items is not None:
        for key, value in items:
            if type(key) is str:
                merged[str.__str__(key)] = value
    elif context is not None:
        merged["context_materialization"] = unsupported_scheduler_value_evidence(
            context,
            field_name="context",
        )
    issue_items = scheduler_mapping_items(issues)
    if issue_items is None:
        merged["context_issues_materialization"] = unsupported_scheduler_value_evidence(
            issues,
            field_name="context_issues",
        )
        return merged
    for key, value in issue_items:
        if type(key) is str:
            merged[str.__str__(key)] = value
        else:
            merged["context_issue_key_" + int.__str__(len(merged))] = unsupported_scheduler_value_evidence(
                key,
                field_name="context_issue_key",
            )
    return merged


def scheduler_field_issue_key(field_name: object) -> str:
    if type(field_name) is str and field_name != "":
        return str.__str__(field_name) + "_materialization"
    return "scheduler_field_materialization"



__all__ = (
    "first_scheduler_mapping_value",
    "merge_field_issue",
    "scheduler_bool_field",
    "scheduler_context_with_issues",
    "scheduler_mapping_items",
    "scheduler_mapping_value",
    "scheduler_text_field",
)
