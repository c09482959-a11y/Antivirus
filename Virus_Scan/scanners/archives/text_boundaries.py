"""Archive scanner-owned no-hook text and primitive boundaries."""
from __future__ import annotations

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field_status, no_hook_finite_float, no_hook_text, no_hook_type_name


def archive_owned_text(value: object, *, default_text: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="archive_text_missing",
        unsupported_reason="archive_text_unsafe",
    )
    if reason:
        return str.__str__(default_text) if type(default_text) is str else ""
    return str.strip(text)


def archive_lower_text(value: object, *, default_text: str = "") -> str:
    return str.lower(archive_owned_text(value, default_text=default_text))


def archive_delimited_join(delimiter: str, *parts: object) -> str:
    sep = str.__str__(delimiter) if type(delimiter) is str else ""
    out = ""
    first = True
    for part in parts:
        text = str.__str__(part) if type(part) is str else archive_owned_text(part)
        if first:
            out = text
            first = False
        else:
            out = str.__add__(str.__add__(out, sep), text)
    return out


def archive_colon_join(*parts: object) -> str:
    return archive_delimited_join(":", *parts)


def archive_prefixed(prefix: str, value: object) -> str:
    return str.__add__(str.__str__(prefix), archive_owned_text(value))


def archive_type_diagnostic(prefix: str, value: object) -> str:
    safe_prefix = str.__str__(prefix) if type(prefix) is str else "archive_type_rejected:"
    safe_type = no_hook_type_name(value)
    return str.__add__(safe_prefix, safe_type)


def archive_metric(value: object, *, default_value: float = 0.0, minimum: float | None = None, maximum: float | None = None) -> float:
    metric, reason = no_hook_finite_float(
        value,
        default=default_value,
        minimum=minimum,
        maximum=maximum,
        reason="archive_metric_unsafe",
        non_finite_reason="archive_metric_unsafe",
        allow_exact_text=True,
    )
    if reason:
        return default_value
    return metric


def archive_nonnegative_int(value: object, *, default_value: int = 0) -> int:
    metric = archive_metric(value, default_value=float(default_value), minimum=0.0)
    if not math.isfinite(metric):
        return default_value
    return int(metric)


def archive_exact_attr_text(value: object, expected_type: type, attr_name: str) -> str:
    unavailable = "unsafe_archive_member_text_attr"
    if type(value) is not expected_type or type(attr_name) is not str:
        return "unsafe_archive_member_text_record"
    attr, reason = no_hook_exact_owner_field_status(value, expected_type, attr_name)
    if reason:
        attr = unavailable
    text = archive_owned_text(attr, default_text=unavailable)
    return text or unavailable


def archive_exact_attr_int(value: object, expected_type: type, attr_name: str) -> int:
    if type(value) is not expected_type or type(attr_name) is not str:
        raise TypeError("unsafe_archive_member_numeric_record")
    attr, reason = no_hook_exact_owner_field_status(value, expected_type, attr_name)
    if reason:
        raise TypeError("unsafe_archive_member_numeric_attr") from TypeError(reason)
    if type(attr) is int and type(attr) is not bool:
        return max(0, attr)
    if type(attr) is float and math.isfinite(attr):
        return max(0, int(attr))
    raise TypeError("unsafe_archive_member_numeric_attr")
