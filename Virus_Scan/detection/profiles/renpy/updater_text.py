"""Ren'Py updater text/path predicates owned by the Ren'Py profile."""
from __future__ import annotations

import re
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
)


def _renpy_profile_text(value: object, *, missing_reason: str = "missing_renpy_profile_text") -> tuple[str, str]:
    return no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason="unsafe_renpy_profile_text_rejected",
    )


def profile_text_or_empty(value: object) -> str:
    """Return stable profile text without invoking caller-owned hooks."""
    text, _reason = _renpy_profile_text(value)
    return text


def _plain_sequence_field(values: object) -> tuple[object, ...] | None:
    data = no_hook_plain_instance_dict(values)
    if data is None:
        return None
    raw = dict.get(data, "_values")
    if type(raw) is tuple:
        return raw
    if type(raw) is list:
        return tuple(raw)
    return None


def _renpy_profile_sequence(values: Iterable[object] | object | None) -> tuple[tuple[object, ...], str]:
    if values is None:
        return (), ""
    items = no_hook_sequence_items(values)
    if items != () or type(values) in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool):
        return items, ""
    plain_items = _plain_sequence_field(values)
    if plain_items is not None:
        return plain_items, ""
    return (), "unsafe_renpy_profile_iterable_rejected"


def profile_tuple_or_empty(values: Iterable[object] | object | None) -> tuple[object, ...]:
    """Freeze profile sequences without caller-owned iteration hooks."""
    items, _reason = _renpy_profile_sequence(values)
    return items


def profile_iterable_has_items(values: Iterable[object] | object | None) -> bool:
    """Return whether a supported sequence has items without caller-owned iteration hooks."""
    items, _reason = _renpy_profile_sequence(values)
    return len(items) > 0


def has_any_text(text: object, needles: object) -> object:
    low, text_reason = _renpy_profile_text(text)
    if text_reason != "":
        return False
    needle_items, _needle_reason = _renpy_profile_sequence(needles)
    for needle in needle_items:
        needle_text, needle_reason = _renpy_profile_text(needle)
        if needle_reason == "" and needle_text.lower() in low.lower():
            return True
    return False


def high_gate_norm(tags: object) -> object:
    normalized = set()
    items, sequence_reason = _renpy_profile_sequence(tags)
    if sequence_reason != "":
        normalized.add(TAG_NORMALIZATION_FAILURE_EVIDENCE)
        normalized.add(DETECTION_STAGE_DEGRADED_TAG)
        return normalized
    for tag in items:
        text, text_reason = _renpy_profile_text(tag)
        if text_reason != "":
            normalized.add(TAG_NORMALIZATION_FAILURE_EVIDENCE)
            normalized.add(DETECTION_STAGE_DEGRADED_TAG)
            continue
        text = text.strip().lower()
        if text != "":
            normalized.add(text)
    return normalized


def sanitize_tag_part(value: object) -> object:
    text, reason = _renpy_profile_text(value)
    if reason != "":
        return "unknown"
    cleaned = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    if cleaned == "":
        return "unknown"
    return cleaned


def is_renpy_bytecode_path(path: object) -> object:
    path_text = profile_text_or_empty(path).lower()
    normalized = path_text.replace("\\", "/")
    return path_text.endswith((".rpyc", ".rpyb")) or "/renpy/" in normalized


__all__ = (
    "has_any_text",
    "high_gate_norm",
    "is_renpy_bytecode_path",
    "profile_iterable_has_items",
    "profile_text_or_empty",
    "profile_tuple_or_empty",
    "sanitize_tag_part",
)
