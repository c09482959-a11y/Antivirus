"""Text normalization helpers for CLI evidence line rendering."""

from __future__ import annotations

import re
from pathlib import Path, PosixPath, WindowsPath
from types import MappingProxyType
from Virus_Scan.contracts.no_hook_materialization import (
    exact_finite_float_or_none,
    exact_int_or_none,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure

_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))
_REPORTING_STDOUT_ENCODING = "utf-8"
_OWNED_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _record_report_text_failure(where: str, exc: BaseException) -> bool:
    try:
        record_suppressed_failure(where, exc, domain="reporting")
    except TELEMETRY_FAILURE_ERRORS:
        return False
    return True


def safe_report_text(value: object, *, limit: int | None = None) -> str:
    """Return display-safe text without invoking caller-owned hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_report_text",
        unsupported_reason="unsafe_report_text_rejected",
    )
    if reason:
        return ""
    try:
        text = re.sub("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        enc = _REPORTING_STDOUT_ENCODING
        text = text.encode(enc, errors="backslashreplace").decode(enc, errors="replace")
        safe_limit = exact_int_or_none(limit)
        if safe_limit is not None and safe_limit >= 0 and len(text) > safe_limit:
            return text[: max(20, safe_limit)].rstrip() + "..."
        return text
    except TELEMETRY_FAILURE_ERRORS as exc:
        _record_report_text_failure("safe_report_text_normalize_failed", exc)
        return ""


def safe_report_path_text(value: object) -> str:
    text = safe_report_text(value)
    if text:
        return text
    if type(value) in _OWNED_PATH_TYPES:
        try:
            return str(value)
        except TELEMETRY_FAILURE_ERRORS as exc:
            _record_report_text_failure("safe_report_path_text_failed", exc)
    return ""


def safe_report_int(value: object, default: int) -> int:
    metric = exact_int_or_none(value)
    if metric is None:
        return default
    return metric


def safe_report_float(value: object, default: float = 0.0) -> float:
    metric = exact_finite_float_or_none(value)
    if metric is None:
        return default
    return metric


def safe_report_sequence(value: object, *, max_items: int = 128) -> tuple[object, ...]:
    """Detach exact builtin sequences without invoking unknown iteration hooks."""
    if type(value) is tuple:
        return tuple(value[:max_items])
    if type(value) is list:
        return tuple(value[:max_items])
    if type(value) is frozenset:
        return tuple(value)[:max_items]
    if type(value) is set:
        return tuple(value)[:max_items]
    return ()


def safe_report_mapping_items(value: object, *, max_items: int = 512) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return tuple(items[:max_items])


def safe_report_mapping_get(mapping: object, key: str, default: object = None) -> object:
    if type(key) is not str:
        return default
    if type(mapping) is dict:
        try:
            return dict.get(mapping, key, default)
        except TELEMETRY_FAILURE_ERRORS:
            return default
    if type(mapping) is _MAPPING_PROXY_TYPE:
        for candidate_key, value in safe_report_mapping_items(mapping):
            if type(candidate_key) is str and str.__eq__(candidate_key, key):
                return value
    return default


def safe_report_mapping(value: object) -> dict[object, object]:
    if type(value) is dict:
        return value
    return {}


def clip_evidence_text(value: object, limit: object=170) -> object:
    safe_limit = safe_report_int(limit, 170)
    return safe_report_text(value, limit=safe_limit)


def add_unique_line(lines: object, seen: object, prefix: object, detail: object, limit: object=170) -> None:
    detail = clip_evidence_text(detail, limit)
    if not detail:
        return
    prefix_text = safe_report_text(prefix, limit=80) or "Evidence"
    line = str.__add__(str.__add__(prefix_text, ": "), detail)
    key = line.lower()
    if key not in seen:
        seen.add(key)
        lines.append(line)


def context_around(text: object, pattern: object, radius: object=70) -> object:
    try:
        if type(pattern) is not str:
            return ""
        haystack = safe_report_text(text)
        if not haystack:
            return ""
        match = re.search(pattern, haystack, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        safe_radius = safe_report_int(radius, 70)
        start = max(0, match.start() - safe_radius)
        end = min(len(haystack), match.end() + safe_radius)
        return haystack[start:end]
    except TELEMETRY_FAILURE_ERRORS as exc:
        _record_report_text_failure("report_context_extract_failed", exc)
        return ""


def first_regex(text: object, patterns: object, radius: object=80) -> object:
    for pattern in safe_report_sequence(patterns, max_items=128):
        if type(pattern) is not str:
            continue
        ctx = context_around(text, pattern, radius=radius)
        if ctx:
            return ctx
    return ""


def looks_like_tag_name(value: object) -> object:
    normalized = safe_report_text(value, limit=120).strip().lower()
    return bool(normalized) and bool(re.fullmatch("[a-z0-9_:-]{3,80}", normalized))


def raw_sample_text(evidence: object, strings_blob: object) -> object:
    raw = safe_report_mapping_get(evidence, "raw_sample")
    if type(raw) in (bytes, bytearray):
        try:
            return bytes(raw[:512000]).decode("latin1", errors="ignore")
        except TELEMETRY_FAILURE_ERRORS as exc:
            _record_report_text_failure("report_raw_sample_decode_failed", exc)
            return ""
    return safe_report_text(strings_blob)


__all__ = (
    "add_unique_line",
    "clip_evidence_text",
    "context_around",
    "first_regex",
    "looks_like_tag_name",
    "raw_sample_text",
    "safe_report_float",
    "safe_report_int",
    "safe_report_mapping",
    "safe_report_mapping_get",
    "safe_report_mapping_items",
    "safe_report_path_text",
    "safe_report_sequence",
    "safe_report_text",
)
