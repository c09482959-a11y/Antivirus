from __future__ import annotations

from types import MappingProxyType
from typing import Callable, TYPE_CHECKING

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import exact_text_or_none

if TYPE_CHECKING:
    from collections.abc import Mapping

def _adaptive_exact_text(value: object) -> str:
    if type(value) is str:
        return value
    if isinstance(value, str):
        return str.__str__(value)
    exception_message = "unsupported adaptive reason text value"
    raise TypeError(exception_message)


def adaptive_reason_text(value: object, *, unreadable_reason: str = "unreadable_model_signal_reason") -> str | None:
    """Return explicit reason text without truth-testing caller-owned values."""
    if value is None:
        return None
    try:
        text = _adaptive_exact_text(value).strip()
    except RECOVERABLE_RUNTIME_ERRORS:
        return unreadable_reason
    if text == "":
        return None
    return text


def adaptive_reason_or_default(reason: object, default: str) -> str:
    text = adaptive_reason_text(reason)
    if text is not None:
        return text
    return default


def adaptive_mapping_get(record: Mapping[str, object], key: object, default: object = None) -> object:
    """Read exact/builtin mapping evidence without caller-owned mapping/key hooks."""
    key_text = exact_text_or_none(key)
    if key_text is None:
        return default
    if type(record) is dict:
        return dict.get(record, key_text, default)
    if isinstance(record, dict):
        return dict.get(record, key_text, default)
    if isinstance(record, MappingProxyType):
        try:
            return record[key_text]
        except RECOVERABLE_RUNTIME_ERRORS:
            return default
    return default


def adaptive_invalid_flag_reason(value: object, field_name: object) -> str | None:
    if value is None or value is False or value is True:
        return None
    field_text = exact_text_or_none(field_name)
    if field_text is None or field_text == "":
        field_text = "unknown"
    return "invalid_" + field_text + "_flag"


def first_adaptive_probability_reason(reason_reader: Callable[..., str | None], *values: object) -> str | None:
    """Return the first explicit probability reason without boolean fallback chains."""
    for value in values:
        reason = reason_reader({}, "reason_probe", value)
        if reason is not None:
            return reason
    return None


def first_adaptive_reason_text(*values: object, unreadable_reason: str = "unreadable_model_signal_reason") -> str | None:
    """Return the first readable reason text without boolean fallback chains."""
    for value in values:
        text = adaptive_reason_text(value, unreadable_reason=unreadable_reason)
        if text is not None:
            return text
    return None


__all__ = (
    "adaptive_invalid_flag_reason",
    "adaptive_mapping_get",
    "adaptive_reason_or_default",
    "adaptive_reason_text",
    "first_adaptive_probability_reason",
    "first_adaptive_reason_text",
)
