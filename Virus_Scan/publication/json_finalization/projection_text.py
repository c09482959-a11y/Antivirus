"""Exact-text helpers for final JSON publication boundaries."""
from __future__ import annotations

import gc
import math
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from types import MappingProxyType

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key, no_hook_plain_instance_dict, no_hook_type_name

_FINAL_JSON_TEXT_ATTRS = ("text", "_text", "value")
_MISSING_TEXT_ATTR = object()
FinalJsonValue = object
FinalJsonRecord = dict[str, FinalJsonValue]
FinalJsonMappingItems = tuple[tuple[FinalJsonValue, FinalJsonValue], ...]
_MAPPING_PROXY_TYPE: type[FinalJsonValue] = type(MappingProxyType({}))
_NO_MAPPING_VALUE = None
_FINAL_JSON_STDLIB_PATH_TYPES = (
    PurePosixPath,
    PureWindowsPath,
    PosixPath,
    WindowsPath,
)


def _mapping_proxy_backing_dict(value: FinalJsonValue) -> dict[FinalJsonValue, FinalJsonValue] | None:
    """Return a mapping-proxy backing dict without invoking mapping hooks."""
    if type(value) is not _MAPPING_PROXY_TYPE:
        return _NO_MAPPING_VALUE
    try:
        referents = gc.get_referents(value)
    except TELEMETRY_FAILURE_ERRORS:
        return _NO_MAPPING_VALUE
    if len(referents) != 1:
        return _NO_MAPPING_VALUE
    backing = referents[0]
    if isinstance(backing, dict):
        return backing
    return _NO_MAPPING_VALUE


def final_json_mapping_items(value: FinalJsonValue) -> FinalJsonMappingItems | None:
    """Return mapping items through built-in dict descriptors only.

    Final JSON may receive dict subclasses and mapping proxies from scheduler or
    worker boundaries. Reading those through caller mapping methods or indexing
    would execute caller-owned hooks. Built-in dict descriptors preserve the
    stored mapping facts while bypassing subclass method overrides.
    """
    backing: dict[FinalJsonValue, FinalJsonValue] | None = value if isinstance(value, dict) else _mapping_proxy_backing_dict(value)
    if backing is None:
        return _NO_MAPPING_VALUE
    try:
        items = dict.items(backing)
        return tuple(items)
    except TELEMETRY_FAILURE_ERRORS:
        return _NO_MAPPING_VALUE


def final_json_mapping_get(value: FinalJsonValue, key: FinalJsonValue, default: FinalJsonValue = None) -> FinalJsonValue:
    backing: dict[FinalJsonValue, FinalJsonValue] | None = value if isinstance(value, dict) else _mapping_proxy_backing_dict(value)
    if backing is None:
        return default
    try:
        return dict.get(backing, key, default)
    except TELEMETRY_FAILURE_ERRORS:
        try:
            return dict.__getitem__(backing, key)
        except (*TELEMETRY_FAILURE_ERRORS, KeyError):
            return default


def final_json_type_name(value: FinalJsonValue) -> str:
    return no_hook_type_name(value)


def final_json_unavailable_text(value: FinalJsonValue, reason: str) -> str:
    return "<" + final_json_type_name(value) + " " + reason + ">"


def final_json_unavailable_sort_text(value: FinalJsonValue) -> str:
    return "<" + final_json_type_name(value) + ">"


def final_json_indexed_key(prefix: str, index: int) -> str:
    return prefix + int.__str__(index)


def final_json_duplicate_key_text(key_text: str, index: int) -> str:
    return no_hook_duplicate_key(key_text, index, rejection="final_json_duplicate_key_rejected")


def final_json_unavailable_reason_key(key_text: str) -> str:
    return key_text + "_unavailable_reason"


def final_json_compact_sort_unavailable_text(value: FinalJsonValue) -> str:
    return "compact_sort_unavailable:" + final_json_type_name(value)


def final_json_error_tag(prefix: str, exc: BaseException) -> str:
    return prefix + ":" + final_json_type_name(exc)


def final_json_projection_text_result(value: FinalJsonValue) -> tuple[str, str]:
    return safe_projection_text(value)


def _plain_instance_text_attr(value: FinalJsonValue, attr: str) -> FinalJsonValue:
    """Read exact-instance wrapper text from a proven instance dict only.

    Final JSON text projection may accept plain internal wrappers that store
    ``text``, ``_text``, or ``value`` directly on the instance.  It must not
    perform normal attribute lookup for unknown objects, and it must not call
    ``object.__getattribute__(value, "__dict__")`` until the canonical no-hook
    helper proves that ``__dict__`` is Python's built-in instance-dict
    descriptor rather than a caller-owned property or descriptor.
    """
    instance_dict = no_hook_plain_instance_dict(value)
    if instance_dict is None:
        return _MISSING_TEXT_ATTR
    return dict.__getitem__(instance_dict, attr) if attr in instance_dict else _MISSING_TEXT_ATTR


def _safe_scalar_projection_text(value: FinalJsonValue) -> tuple[bool, str, str]:
    handled = True
    if value is None:
        text, reason = "", "missing_final_json_text"
    elif isinstance(value, str):
        text, reason = str.__str__(value), ""
    elif type(value) is bytes:
        text, reason = value.decode("utf-8", errors="replace"), ""
    elif type(value) is bytearray:
        text, reason = bytes(value).decode("utf-8", errors="replace"), ""
    elif type(value) is bool:
        text, reason = ("true" if value else "false"), ""
    elif type(value) is int:
        text, reason = int.__str__(value), ""
    elif type(value) is float:
        if math.isfinite(value):
            text, reason = float.__str__(value), ""
        else:
            text, reason = "", "non_finite_final_json_text"
    else:
        handled, text, reason = False, "", ""
    return handled, text, reason


def safe_projection_text(value: FinalJsonValue) -> tuple[str, str]:
    """Return final-JSON boundary text without trusting caller-owned hooks."""
    handled, text, reason = _safe_scalar_projection_text(value)
    if handled:
        return text, reason
    for attr in _FINAL_JSON_TEXT_ATTRS:
        attr_value = _plain_instance_text_attr(value, attr)
        if attr_value is _MISSING_TEXT_ATTR:
            continue
        text, reason = final_json_projection_text_result(attr_value)
        if reason == "":
            return text, ""
    return "", "final_json_text_unavailable"


def safe_projection_path_text(value: FinalJsonValue) -> tuple[str, str]:
    """Return an owned final-JSON path without caller path hooks."""
    if isinstance(value, str):
        return str.__str__(value), ""
    if (
        type(value) is PurePosixPath
        or type(value) is PureWindowsPath
        or type(value) is PosixPath
        or type(value) is WindowsPath
    ):
        return PurePath.as_posix(value), ""
    return "", "unsupported_final_json_path"


def present_text(value: FinalJsonValue) -> str:
    """Return stripped display text or an explicit unavailable marker."""
    text, reason = final_json_projection_text_result(value)
    if reason == "missing_final_json_text":
        return ""
    if reason:
        return final_json_unavailable_text(value, reason)
    return text.strip()


def safe_projection_sort_key(value: FinalJsonValue) -> tuple[str, str, str]:
    text, reason = final_json_projection_text_result(value)
    if reason:
        return (final_json_unavailable_sort_text(value), reason, "")
    return (text.lower(), text, "")


def projection_failure(reason: str, value: FinalJsonValue | None = None) -> FinalJsonRecord:
    record: FinalJsonRecord = {"model_signal_projection_failed": True, "reason": reason}
    if value is not None:
        record["value_type"] = final_json_type_name(value)
    return record


def safe_json_key_text(key: FinalJsonValue, index: int) -> tuple[str, str]:
    text, reason = final_json_projection_text_result(key)
    if reason:
        return final_json_indexed_key("_unavailable_key_", index), "final_json_key_text_unavailable"
    if text == "":
        return final_json_indexed_key("_blank_key_", index), "blank_final_json_key"
    return text[:256], ""


def safe_bounded_text_value(value: FinalJsonValue, width: int = 512) -> str | FinalJsonRecord:
    text, reason = final_json_projection_text_result(value)
    if reason:
        return projection_failure(reason, value)
    return text[:width]


__all__ = (
    "final_json_compact_sort_unavailable_text",
    "final_json_duplicate_key_text",
    "final_json_error_tag",
    "final_json_indexed_key",
    "final_json_mapping_get",
    "final_json_mapping_items",
    "final_json_projection_text_result",
    "final_json_type_name",
    "final_json_unavailable_reason_key",
    "final_json_unavailable_sort_text",
    "final_json_unavailable_text",
    "present_text",
    "projection_failure",
    "safe_bounded_text_value",
    "safe_json_key_text",
    "safe_projection_path_text",
    "safe_projection_sort_key",
    "safe_projection_text",
)
