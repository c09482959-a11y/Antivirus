"""Primitive no-hook helpers for model-evidence publication."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeGuard

from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key, no_hook_type_name


def model_evidence_type_marker(value: object) -> str:
    return "<" + no_hook_type_name(value) + ">"


def model_evidence_unavailable_repr(value: object) -> str:
    return "<" + no_hook_type_name(value) + " repr unavailable>"


def model_evidence_child_path(parent: str, child: str) -> str:
    if parent == "":
        return child
    return parent + "." + child


def model_evidence_field_path(parent: str, field: str) -> str:
    return model_evidence_child_path(parent, field)


def model_evidence_index_path(parent: str, index: int) -> str:
    return parent + "[" + int.__str__(index) + "]"


def model_evidence_unavailable_field(field: str) -> str:
    return field + "_unavailable_reason"


def model_evidence_unavailable_reasons_field(field: str) -> str:
    return field + "_unavailable_reasons"


def model_evidence_probability_model_name(field: str) -> str:
    return field + "_probability"


def model_evidence_non_boolean_flag_reason(field_name: str) -> str:
    return "non_boolean_" + field_name + "_flag"


def model_evidence_blank_key(index: int) -> str:
    return "_blank_key_" + int.__str__(index)


def model_evidence_duplicate_key(name: str, index: int) -> str:
    return no_hook_duplicate_key(name, index, rejection="model_evidence_duplicate_key_rejected")


def model_evidence_missing_field_reason(field_name: str) -> str:
    return "missing_" + field_name


def model_evidence_is_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    return isinstance(value, Mapping)


def model_evidence_is_sequence(value: object) -> bool:
    return type(value) in (list, tuple)


def model_evidence_is_container(value: object) -> bool:
    return model_evidence_is_mapping(value) or model_evidence_is_sequence(value)


def model_evidence_sequence_items(value: object) -> tuple[object, ...]:
    items: tuple[object, ...] = ()
    if type(value) is tuple:
        items = value
    elif type(value) is list:
        items = tuple(value)
    return items


__all__ = (
    "model_evidence_blank_key",
    "model_evidence_child_path",
    "model_evidence_duplicate_key",
    "model_evidence_field_path",
    "model_evidence_index_path",
    "model_evidence_is_container",
    "model_evidence_is_mapping",
    "model_evidence_is_sequence",
    "model_evidence_missing_field_reason",
    "model_evidence_non_boolean_flag_reason",
    "model_evidence_probability_model_name",
    "model_evidence_sequence_items",
    "model_evidence_type_marker",
    "model_evidence_unavailable_field",
    "model_evidence_unavailable_reasons_field",
    "model_evidence_unavailable_repr",
)
