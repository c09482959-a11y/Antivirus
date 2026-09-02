"""Canonical no-hook inputs for runtime governance and replay."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)


def _runtime_field_name(field_name: str) -> str:
    if type(field_name) is str:
        return str.__str__(field_name)
    return "runtime_input"


def _runtime_reason(field_name: str, suffix: str) -> str:
    return _runtime_field_name(field_name) + "_" + str.__str__(suffix)


def runtime_input_rejection(
    field_name: str, value: object, reason: str
) -> Mapping[str, object]:
    safe_field = _runtime_field_name(field_name)
    return {
        "runtime_input_rejected": True,
        "field_name": safe_field,
        "reason": reason,
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }


def runtime_mapping(
    value: object, *, field_name: str
) -> tuple[dict[object, object], tuple[Mapping[str, object], ...]]:
    if value is None:
        return {}, ()
    items = no_hook_mapping_items(value)
    if items is None:
        reason = _runtime_reason(field_name, "mapping_rejected")
        return {}, (runtime_input_rejection(field_name, value, reason),)
    return dict(items), ()


def runtime_sequence(
    value: object, *, field_name: str
) -> tuple[tuple[object, ...], tuple[Mapping[str, object], ...]]:
    if value is None:
        return (), ()
    if type(value) not in (tuple, list, set, frozenset):
        reason = _runtime_reason(field_name, "sequence_rejected")
        return (), (runtime_input_rejection(field_name, value, reason),)
    return no_hook_sequence_items(value), ()


def runtime_object_state(
    value: object, *, field_name: str
) -> tuple[dict[object, object], tuple[Mapping[str, object], ...]]:
    items = no_hook_mapping_items(value)
    if items is not None:
        return dict(items), ()
    state = no_hook_plain_instance_dict(value)
    if state is not None:
        return state, ()
    reason = _runtime_reason(field_name, "object_rejected")
    return {}, (runtime_input_rejection(field_name, value, reason),)


def runtime_text(
    value: object, *, field_name: str, default: str
) -> tuple[str, tuple[Mapping[str, object], ...]]:
    text, reason = no_hook_text(
        value,
        missing_reason=_runtime_reason(field_name, "missing"),
        unsupported_reason=_runtime_reason(field_name, "rejected"),
    )
    if reason or text == "":
        issue = reason or _runtime_reason(field_name, "blank")
        return default, (runtime_input_rejection(field_name, value, issue),)
    return text, ()


def runtime_int(
    value: object, *, field_name: str, default: int = 0
) -> tuple[int, tuple[Mapping[str, object], ...]]:
    parsed, reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason=_runtime_reason(field_name, "rejected"),
        allow_exact_text=True,
    )
    return (
        (parsed, ())
        if not reason
        else (parsed, (runtime_input_rejection(field_name, value, reason),))
    )


def runtime_float(
    value: object,
    *,
    field_name: str,
    default: float = 0.0,
    minimum: float | None = None,
    maximum: float | None = None,
) -> tuple[float, tuple[Mapping[str, object], ...]]:
    parsed, reason = no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason=_runtime_reason(field_name, "rejected"),
        non_finite_reason=_runtime_reason(field_name, "non_finite"),
        allow_exact_text=True,
    )
    return (
        (parsed, ())
        if not reason
        else (parsed, (runtime_input_rejection(field_name, value, reason),))
    )


def runtime_bool(
    value: object, *, field_name: str, default: bool = False
) -> tuple[bool, tuple[Mapping[str, object], ...]]:
    if type(value) is bool:
        return value, ()
    if type(value) is int and type(value) is not bool:
        return value != 0, ()
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True, ()
        if text in {"0", "false", "no", "off", ""}:
            return False, ()
    reason = _runtime_reason(field_name, "rejected")
    return default, (runtime_input_rejection(field_name, value, reason),)


__all__ = (
    "runtime_bool",
    "runtime_float",
    "runtime_input_rejection",
    "runtime_int",
    "runtime_mapping",
    "runtime_object_state",
    "runtime_sequence",
    "runtime_text",
)
