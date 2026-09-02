"""No-hook text projection for detection enrichment boundaries."""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS

_TEXT_FIELDS = ("text", "_text", "value", "_value")


def detection_enrichment_text_or_empty(value: object, *, default: str = "") -> str:
    """Return detached enrichment text without caller-owned string hooks.

    Detection enrichment consumers need text for regex/tag extraction, but unknown
    objects must not be converted with ``str(value)``. Exact built-in scalars and
    plain instance dictionaries with exact scalar text fields are accepted; all
    other objects become the caller-provided default.
    """
    if value is None:
        return default
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bytes:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is memoryview:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value) if math.isfinite(value) else default
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return default
    try:
        for field_name in _TEXT_FIELDS:
            field_value = dict.get(data, field_name)
            if type(field_value) is str:
                return str.__str__(field_value)
            if type(field_value) is bytes:
                return bytes(field_value).decode("utf-8", errors="replace")
            if type(field_value) is bytearray:
                return bytes(field_value).decode("utf-8", errors="replace")
            if type(field_value) is memoryview:
                return bytes(field_value).decode("utf-8", errors="replace")
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return default
    return default


__all__ = ("detection_enrichment_text_or_empty",)
