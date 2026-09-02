"""No-hook support for in-memory scheduler result timeout evidence."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.mapping_item_lookup import first_scheduler_mapping_value, scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.evidence.inmemory_result_timeout_bool_decisions import timeout_bool_decision, timeout_tags_decision


def first_mapping_value(source: object, keys: tuple[str, ...], default_value: object = None) -> object:
    return first_scheduler_mapping_value(source, keys, default_value)


def timeout_float(value: object, *, default_value: float, field: str, rejections: list[dict[str, object]]) -> float:
    metric, reason = no_hook_finite_float(value, default=default_value, reason=str.__add__("unsafe_", field))
    if reason:
        rejections.append({"field": field, "reason": reason})
    return metric


def timeout_int(value: object, *, default_value: int, field: str, rejections: list[dict[str, object]]) -> int:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default_value,
        reason=str.__add__("unsafe_", field),
        non_finite_reason="non_finite_scheduler_integer_rejected",
        allow_exact_text=True,
    )
    if reason:
        rejections.append({"field": field, "reason": reason})
    return parsed


def timeout_text(value: object, *, default_value: str, field: str, rejections: list[dict[str, object]]) -> str:
    text, reason = no_hook_text(value, missing_reason="missing_scheduler_timeout_text")
    if reason:
        if value is not None:
            rejections.append({"field": field, "reason": reason})
        return default_value
    return text


def timeout_bool(value: object, *, field: str, rejections: list[dict[str, object]]) -> bool:
    decision = timeout_bool_decision(value, field=field)
    if decision.rejected:
        rejections.append({"field": decision.field, "reason": decision.reason})
    return decision.value


def timeout_mapping(value: object, *, field: str, rejections: list[dict[str, object]]) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        if value is None:
            return {}
        rejections.append({"field": field, "reason": "unsafe_scheduler_mapping_rejected"})
        return {
            _timeout_field_key(field, "_unavailable"): True,
            _timeout_field_key(field, "_unavailable_reason"): "unsafe_scheduler_mapping_rejected",
            _timeout_field_key(field, "_failure"): unsupported_scheduler_value_evidence(value, field_name=field),
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        }
    return scheduler_str_key_mapping_from_items(items)


def timeout_tags(value: object, *, rejections: list[dict[str, object]]) -> tuple[object, ...]:
    decision = timeout_tags_decision(value)
    if decision.rejected:
        rejections.append({"field": "tags", "reason": decision.reason})
    return decision.value



def _timeout_field_key(field: str, suffix: str) -> str:
    return str.__add__(field, suffix)


__all__ = (
    "first_mapping_value",
    "timeout_bool",
    "timeout_float",
    "timeout_int",
    "timeout_mapping",
    "timeout_tags",
    "timeout_text",
)
