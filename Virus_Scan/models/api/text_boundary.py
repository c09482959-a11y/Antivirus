"""Exact public model-API text boundary helpers.

Public model contracts publish evidence that can flow into final JSON and replay.
Those boundaries must detach exact built-in text without invoking caller-owned
``str`` subclass hooks or arbitrary object ``__str__`` implementations.
"""
from __future__ import annotations

from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key, no_hook_plain_instance_dict, no_hook_type_name

_PUBLIC_SCALAR_TYPES = (int, float, bool)
_TEXT_FIELDS = ("text", "_text", "value", "_value")
_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def _is_stdlib_path(raw: object) -> bool:
    return type(raw) in _STDLIB_PATH_TYPES


def _detached_text(raw: object) -> str | None:
    if isinstance(raw, str):
        return str.__str__(raw)
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).decode("utf-8", errors="replace")
    if isinstance(raw, _PUBLIC_SCALAR_TYPES):
        return repr(raw)
    if _is_stdlib_path(raw):
        return PurePath.as_posix(raw)
    return None


def _plain_instance_text(raw: object) -> str | None:
    data = no_hook_plain_instance_dict(raw)
    if data is None:
        return None
    for field_name in _TEXT_FIELDS:
        field_value = dict.get(data, field_name)
        detached = _detached_text(field_value)
        if detached is not None:
            return detached
    return None


def public_unreadable_value_label(value: object) -> str:
    """Return a deterministic unreadable-value label without caller hooks."""
    return "<unreadable_" + no_hook_type_name(value) + ">"


def public_unreadable_mapping_key_label(index: int) -> str:
    """Return a deterministic unreadable mapping-key label."""
    return "<unreadable_mapping_key_" + int.__str__(index) + ">"


def public_blank_mapping_key_label(index: int) -> str:
    """Return a deterministic blank mapping-key label."""
    return "<blank_mapping_key_" + int.__str__(index) + ">"


def public_duplicate_mapping_key_label(text: str, index: int) -> str:
    """Return a deterministic duplicate-key label for exact text."""
    return no_hook_duplicate_key(text, index, rejection="public_duplicate_mapping_key_rejected")


def public_unavailable_contract_mapping(reason: str, *, evidence_type: str) -> Mapping[str, object]:
    """Return the canonical public-contract unavailable evidence mapping."""
    reason_text = str.__str__(reason) if type(reason) is str and reason else "public_contract_value_unavailable"
    evidence_text = (
        str.__str__(evidence_type)
        if type(evidence_type) is str and evidence_type
        else "public_contract_value_unavailable"
    )
    return MappingProxyType({
        "ready": False,
        "degraded": True,
        "unavailable_reason": reason_text,
        "evidence_type": evidence_text,
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def public_first_unavailable_reason(*reasons: str | None) -> str | None:
    for reason in reasons:
        if reason is not None:
            return reason
    return None


def public_api_contract_text(
    value: object,
    *,
    default_text: str = "",
    strip: bool = True,
    allow_path: bool = True,
) -> tuple[str, str | None]:
    """Return detached public-contract text plus an unavailable reason.

    Supported values are exact/built-in strings, bytes-like values, scalar
    primitives, and filesystem path protocol values. Unsupported objects are
    not coerced with raw ``str(value)`` because model evidence from these public
    APIs may be published to final JSON and replay comparisons.
    """
    replacement_text = _detached_text(default_text)
    if replacement_text is None and default_text is not None:
        replacement_text = _plain_instance_text(default_text)
    if replacement_text is None:
        replacement_text = ""
    try:
        if value is None:
            text = replacement_text
        else:
            detached = _detached_text(value)
            if detached is not None:
                text = detached
            elif allow_path and _is_stdlib_path(value):
                text = PurePath.as_posix(value)
            elif allow_path:
                attr_text = _plain_instance_text(value)
                if attr_text is None:
                    return replacement_text, "unreadable_public_contract_text"
                text = attr_text
            else:
                return replacement_text, "unreadable_public_contract_text"
        if strip:
            text = str.strip(text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return replacement_text, "unreadable_public_contract_text"
    else:
        return text, None


def public_api_sort_key(value: object) -> tuple[str, str, str]:
    """Sort public evidence keys without raw object string coercion."""
    default_text = public_unreadable_value_label(value)
    text, reason = public_api_contract_text(value, default_text=default_text)
    if reason is not None:
        return (default_text, reason, "")
    return (text.lower(), text, "")


__all__ = (
    "public_api_contract_text",
    "public_api_sort_key",
    "public_blank_mapping_key_label",
    "public_duplicate_mapping_key_label",
    "public_first_unavailable_reason",
    "public_unavailable_contract_mapping",
    "public_unreadable_mapping_key_label",
    "public_unreadable_value_label",
)
