"""Exact primitive value helpers for in-memory parent runtime setup."""
from __future__ import annotations

import json
import math


from Virus_Scan.scheduler.internal.exact_integer_text import scheduler_int_text
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def positive_process_count(value: object) -> int:
    if value is None:
        return 1
    if type(value) is bool:
        return 1
    if type(value) is int:
        return value if value > 0 else 1
    if type(value) is float:
        if math.isfinite(value) and value.is_integer():
            parsed = int(value)
            return parsed if parsed > 0 else 1
        return 1
    if type(value) is str:
        text = str.__str__(value).strip()
        if text == "":
            return 1
        sign = 1
        digits = text
        if text[0] in {"+", "-"}:
            if len(text) == 1:
                return 1
            sign = -1 if text[0] == "-" else 1
            digits = text[1:]
        if not digits.isdecimal():
            return 1
        parsed = sign * int(digits, 10)
        return parsed if parsed > 0 else 1
    return 1


int_log_value = scheduler_int_text


def optional_float_log_value(value: object) -> str:
    if value is None:
        return "n/a"
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    if type(value) is float and math.isfinite(value):
        return float.__repr__(value)
    return "n/a"


def stage_limits_log_value(stage_limits: object) -> str:
    materialized = materialize_scheduler_mapping(stage_limits)
    return json.dumps(materialized, sort_keys=True, separators=(",", ":"), allow_nan=False)


__all__ = (
    "int_log_value",
    "optional_float_log_value",
    "positive_process_count",
    "stage_limits_log_value",
)
