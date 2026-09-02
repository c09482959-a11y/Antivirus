"""Temporal model text-boundary materialization.

Temporal anomaly/validation evidence can be published to final JSON and replay
comparison.  Those paths must detach caller-owned strings without invoking
subclass hooks and must avoid arbitrary object ``__str__`` where unsupported
objects would otherwise become fake clean evidence.
"""
from __future__ import annotations

import math
from pathlib import PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_plain_instance_dict

TEMPORAL_TEXT_UNAVAILABLE = "temporal_text_unavailable"
_TEXT_FIELDS = ("text", "_text", "value", "_value")
_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


def _detach_text_value(raw: object) -> str | None:
    if isinstance(raw, str):
        return str.__str__(raw)
    if type(raw) is bytes:
        return bytes.decode(raw, "latin1", errors="ignore")
    if type(raw) is bytearray:
        return bytes(raw).decode("latin1", errors="ignore")
    if type(raw) is memoryview:
        return raw.tobytes().decode("latin1", errors="ignore")
    if type(raw) is bool:
        return "true" if raw else "false"
    if type(raw) is int:
        return int.__str__(raw)
    if type(raw) is float and math.isfinite(raw):
        return float.__str__(raw)
    if type(raw) is PurePosixPath:
        return PurePath.as_posix(raw)
    if type(raw) is PureWindowsPath:
        return PurePath.as_posix(raw)
    if type(raw) is PosixPath:
        return PurePath.as_posix(raw)
    if type(raw) is WindowsPath:
        return PurePath.as_posix(raw)
    return None


def _attribute_text(value: object) -> str | None:
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return None
    for field_name in _TEXT_FIELDS:
        detached = _detach_text_value(dict.get(data, field_name))
        if detached is not None:
            return detached
    return None


def temporal_boundary_text(
    value: object,
    *,
    default: str = "",
    strip: bool = True,
    allow_object_str: bool = False,
) -> str:
    """Return deterministic temporal evidence text.

    Supported boundary values are exact strings, bytes-like values, stdlib
    paths, primitive scalars, and plain instance text fields. Unsupported
    objects become explicit temporal-unavailable evidence without object string
    protocol coercion.
    """
    del allow_object_str  # Explicitly unused contract parameters.
    try:
        if value is None:
            text = str.__str__(default) if isinstance(default, str) else ""
        else:
            detached = _detach_text_value(value)
            if detached is not None:
                text = detached
            else:
                attr_text = _attribute_text(value)
                if attr_text is not None:
                    text = attr_text
                else:
                    text = TEMPORAL_TEXT_UNAVAILABLE if default == "" else str.__str__(default)
        if strip:
            text = str.strip(text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return str.__str__(default) if isinstance(default, str) else ""
    else:
        return text


def temporal_boundary_stage(value: object, *, default: str = "unknown") -> str:
    text = temporal_boundary_text(value, default=default, strip=True, allow_object_str=False)
    return text if text != "" else default


__all__ = (
    "TEMPORAL_TEXT_UNAVAILABLE",
    "temporal_boundary_stage",
    "temporal_boundary_text",
)
