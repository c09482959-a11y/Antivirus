"""Reasoned text/key helpers for bounded final JSON projection."""
from __future__ import annotations

from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_duplicate_key_text,
    final_json_unavailable_reason_key,
    final_json_unavailable_text,
    projection_failure,
    safe_bounded_text_value,
    safe_json_key_text,
    safe_projection_path_text,
    safe_projection_sort_key,
    safe_projection_text,
)


FinalJsonBoundaryValue = object
FinalJsonBoundaryRecord = dict[str, FinalJsonBoundaryValue]
FinalJsonBoundaryPair = tuple[FinalJsonBoundaryValue, FinalJsonBoundaryValue]


def projection_text_result(value: FinalJsonBoundaryValue) -> tuple[str, str]:
    return safe_projection_text(value)


def projection_path_result(value: FinalJsonBoundaryValue) -> tuple[str, str]:
    return safe_projection_path_text(value)


def projection_unavailable_text(value: FinalJsonBoundaryValue, reason: str = "final_json_text_unavailable") -> str:
    return final_json_unavailable_text(value, reason)


def projection_text_or_marker(value: FinalJsonBoundaryValue, *, reason_text: str = "final_json_text_unavailable", width: int | None = None) -> str:
    text, reason = projection_text_result(value)
    if reason:
        text = projection_unavailable_text(value, reason_text)
    if width is not None:
        return text[:width]
    return text


def projection_text_or_failure(value: FinalJsonBoundaryValue, width: int = 512) -> str | FinalJsonBoundaryRecord:
    text, reason = projection_text_result(value)
    if reason:
        return projection_failure(reason, value)
    return text[:width]


def projection_value_sort_key(value: FinalJsonBoundaryValue) -> tuple[str, str, str]:
    return safe_projection_sort_key(value)


def mapping_pair_sort_key(pair: FinalJsonBoundaryPair) -> tuple[str, str, str]:
    return projection_value_sort_key(pair[0])


def json_key_result(key: FinalJsonBoundaryValue, index: int) -> tuple[str, str]:
    return safe_json_key_text(key, index)


def duplicate_json_key_text(key_text: str, index: int) -> str:
    return final_json_duplicate_key_text(key_text, index)


def unavailable_reason_field(key_text: str) -> str:
    return final_json_unavailable_reason_key(key_text)


def bounded_text_value(value: FinalJsonBoundaryValue, width: int = 512) -> str | FinalJsonBoundaryRecord:
    return safe_bounded_text_value(value, width)


__all__ = (
    "bounded_text_value",
    "duplicate_json_key_text",
    "json_key_result",
    "mapping_pair_sort_key",
    "projection_path_result",
    "projection_text_or_failure",
    "projection_text_or_marker",
    "projection_text_result",
    "projection_unavailable_text",
    "projection_value_sort_key",
    "unavailable_reason_field",
)
