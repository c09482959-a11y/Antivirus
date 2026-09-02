"""No-hook scheduler diagnostic text and scalar helpers."""
from __future__ import annotations

import math
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail, scheduler_exception_text
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping, unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.exact_int_text_decision import ExactIntTextDecision, exact_int_text_decision
from Virus_Scan.scheduler.internal.exact_integer_bounds import clamp_exact_int
from Virus_Scan.scheduler.internal.no_hook_int_parsing import parse_scheduler_int_value
from Virus_Scan.scheduler.internal.evidence_projection import (
    scheduler_evidence_path,
    scheduler_evidence_text,
)

if TYPE_CHECKING:
    import os

_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)
_FILESYSTEM_PATH_TYPES = (type(Path(".")),)


def scheduler_value_snapshot(value: object, *, field_name: str = "scheduler_value") -> object:
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return unsupported_scheduler_value_evidence(value, field_name=field_name)
    if type(value) in {dict, list, tuple, set, frozenset}:
        return materialize_scheduler_mapping(value)
    return unsupported_scheduler_value_evidence(value, field_name=field_name)


def scheduler_text(value: object, *, replacement_text: str = "", unsupported_reason: str = "scheduler_text_rejected") -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="scheduler_text_missing", unsupported_reason=unsupported_reason)
    if reason == "" and text:
        return text, ""
    return replacement_text, reason


def scheduler_bool(value: object, *, default: bool = False, reason: str = "scheduler_bool_rejected") -> tuple[bool, str]:
    if type(value) is bool:
        return value, ""
    if type(value) is int:
        return value != 0, ""
    if type(value) is str:
        text = str.__str__(value).strip().lower()
        if text in {"1", "true", "yes", "on", "enabled"}:
            return True, ""
        if text in {"0", "false", "no", "off", "disabled", ""}:
            return False, ""
    return default, reason


def scheduler_float(value: object, *, default: float = 0.0, minimum: float | None = None, maximum: float | None = None, reason: str = "scheduler_numeric_rejected", non_finite_reason: str = "non_finite_number") -> tuple[float, str]:
    return no_hook_finite_float(value, default=default, minimum=minimum, maximum=maximum, reason=reason, non_finite_reason=non_finite_reason, allow_exact_text=True)


def _exact_scheduler_int_text_decision(value: str) -> ExactIntTextDecision:
    return exact_int_text_decision(
        value,
        empty_reason="scheduler_integer_text_empty",
        sign_only_reason="scheduler_integer_text_sign_only",
        digit_reason="scheduler_integer_text_digits_rejected",
    )


def scheduler_int(value: object, *, default: int = 0, minimum: int | None = None, maximum: int | None = None, reason: str = "scheduler_integer_rejected") -> tuple[int, str]:
    default_value = default if type(default) is int and type(default) is not bool else 0
    safe_default = clamp_exact_int(default_value, minimum=minimum, maximum=maximum)
    parsed = parse_scheduler_int_value(value, reason=reason)
    if not parsed.accepted:
        return safe_default, parsed.reason
    return clamp_exact_int(parsed.value, minimum=minimum, maximum=maximum), ""


def scheduler_nonnegative_int(value: object, *, reason: str = "scheduler_integer_rejected") -> int:
    """Return an exact no-hook non-negative scheduler integer, falling back to zero."""
    parsed, _reason = scheduler_int(value, default=0, minimum=0, reason=reason)
    return parsed


def scheduler_minimum_int(value: object, *, minimum: int = 1, reason: str = "scheduler_integer_rejected") -> tuple[int, str]:
    minimum_value = minimum if type(minimum) is int and type(minimum) is not bool else 1
    parsed = parse_scheduler_int_value(value, reason=reason)
    if not parsed.accepted:
        return minimum_value, parsed.reason
    if parsed.value < minimum_value:
        return minimum_value, ""
    return parsed.value, ""


def scheduler_path_text(path: object) -> tuple[str, str]:
    if path is None:
        return "", "scheduler_path_missing"
    if type(path) is str:
        return str.__str__(path), ""
    if type(path) in _PATH_TYPES:
        try:
            return PurePath.__str__(path), ""
        except (RuntimeError, TypeError, ValueError):
            return "", "scheduler_path_text_failed"
    return "", "scheduler_path_rejected"


def scheduler_filesystem_path(path: object) -> tuple[str | os.PathLike[str], str]:
    if path is None:
        return "", ""
    if type(path) is str:
        return str.__str__(path), ""
    if type(path) in _FILESYSTEM_PATH_TYPES:
        return path, ""
    return "", "scheduler_path_rejected"


def scheduler_join_texts(*values: object) -> str:
    parts: list[str] = []
    for value in values:
        text, reason = scheduler_text(value)
        if reason == "" and text:
            parts.append(text)
    return " ".join(parts)


def scheduler_tag_texts(tags: object) -> tuple[str, ...]:
    items = no_hook_sequence_items(tags)
    out: list[str] = []
    for item in items:
        text, reason = scheduler_text(item, unsupported_reason="scheduler_tag_text_rejected")
        if reason == "" and text:
            out.append(text)
    return tuple(out)


__all__ = (
    "scheduler_bool",
    "scheduler_error_detail",
    "scheduler_evidence_path",
    "scheduler_evidence_text",
    "scheduler_exception_text",
    "scheduler_filesystem_path",
    "scheduler_float",
    "scheduler_int",
    "scheduler_join_texts",
    "scheduler_nonnegative_int",
    "scheduler_path_text",
    "scheduler_tag_texts",
    "scheduler_text",
    "scheduler_value_snapshot",
)
