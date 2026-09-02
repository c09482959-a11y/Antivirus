"""No-hook scalar helpers for raw work execution."""
from __future__ import annotations

import math


from Virus_Scan.contracts.no_hook_materialization import no_hook_text


def raw_execution_text(value: object, default_text: str, *, field_name: str) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="raw_execution_" + field_name + "_missing", unsupported_reason="raw_execution_" + field_name + "_rejected")
    if reason == "" and text:
        return text, ""
    return default_text, reason


def raw_execution_attempt(value: object) -> tuple[int, str]:
    if value is None:
        return 0, ""
    if type(value) is bool:
        return 0, "raw_execution_attempt_rejected"
    if type(value) is int:
        return max(value, 0), ""
    if type(value) is float and math.isfinite(value) and value.is_integer():
        parsed = int(value)
        return max(parsed, 0), ""
    if type(value) is str:
        text = str.__str__(value).strip()
        if text.isdecimal():
            parsed = int(text, 10)
            return max(parsed, 0), ""
    return 0, "raw_execution_attempt_rejected"


def raw_result_error_text(value: object) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason="raw_result_error_missing", unsupported_reason="raw_result_error_rejected")
    if reason == "" and text:
        return text, ""
    return "", reason


__all__ = ("raw_execution_attempt", "raw_execution_text", "raw_result_error_text")
