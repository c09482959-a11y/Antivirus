"""No-hook snapshot support for scheduler recovery contracts."""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_mapping,
    materialize_scheduler_mapping,
    unsupported_scheduler_value_evidence,
)


def record_snapshot(value: object) -> dict[str, object]:
    materialized = materialize_scheduler_mapping(immutable_mapping(value))
    return materialized if type(materialized) is dict else {}


def transition_mapping(value: Mapping[str, object] | None) -> Mapping[str, object]:
    return MappingProxyType(record_snapshot(value))


def bounded_history_with_item(
    record: Mapping[str, object],
    item: Mapping[str, object],
) -> tuple[object, ...]:
    source = record_snapshot(record)
    existing = source.get("history")
    existing_records: tuple[object, ...]
    if type(existing) is list:
        existing_records = tuple(existing)
    elif type(existing) is tuple:
        existing_records = existing
    else:
        existing_records = ()
    history = (*existing_records, record_snapshot(item))
    return history[-64:]


@dataclass(frozen=True, slots=True)
class RecoveryIntegerParseDecision:
    value: int
    accepted: bool
    reason: str



def _exact_recovery_integer_text(value: str) -> RecoveryIntegerParseDecision:
    text = str.__str__(value).strip()
    if text == "":
        return RecoveryIntegerParseDecision(value=0, accepted=False, reason="empty_integer_text")
    sign = 1
    digits = text
    if text[0] in {"+", "-"}:
        if len(text) == 1:
            return RecoveryIntegerParseDecision(value=0, accepted=False, reason="sign_without_digits")
        sign = -1 if text[0] == "-" else 1
        digits = text[1:]
    if not digits.isdecimal():
        return RecoveryIntegerParseDecision(value=0, accepted=False, reason="non_decimal_integer_text")
    return RecoveryIntegerParseDecision(value=sign * int(digits, 10), accepted=True, reason="accepted")


def recovery_integer_result(
    value: object,
    *,
    replacement: int = 0,
    field_name: str = "recovery_integer",
) -> tuple[int, dict[str, object] | None]:
    safe_field_name = str.__str__(field_name) if type(field_name) is str and field_name else "recovery_integer"
    safe_replacement = replacement if type(replacement) is int and type(replacement) is not bool else 0
    if type(value) is int and type(value) is not bool:
        parsed = RecoveryIntegerParseDecision(value=value, accepted=True, reason="accepted")
    elif type(value) is float:
        if math.isfinite(value) and value.is_integer():
            parsed = RecoveryIntegerParseDecision(value=int(value), accepted=True, reason="accepted")
        else:
            parsed = RecoveryIntegerParseDecision(value=0, accepted=False, reason="non_integral_float")
    elif type(value) is str:
        parsed = _exact_recovery_integer_text(value)
    elif type(value) is bytes:
        parsed = _exact_recovery_integer_text(bytes(value).decode("utf-8", "replace"))
    elif type(value) is bytearray:
        parsed = _exact_recovery_integer_text(bytes(value).decode("utf-8", "replace"))
    else:
        parsed = RecoveryIntegerParseDecision(value=0, accepted=False, reason="unsupported_integer_type")
    if parsed.accepted:
        no_issue: dict[str, object] | None = None
        return parsed.value, no_issue
    reason = safe_field_name + ("_missing" if value is None else "_rejected")
    evidence = unsupported_scheduler_value_evidence(value, field_name=safe_field_name)
    evidence["error_category"] = reason
    evidence["message"] = "scheduler recovery integer rejected; deterministic replacement recorded with explicit evidence"
    evidence["recovery_integer_replacement"] = safe_replacement
    evidence["recovery_integer_value"] = safe_replacement
    return safe_replacement, evidence


def recovery_timestamp(now: float | None = None) -> tuple[float, str]:
    ts = float(now if now is not None else time.time())
    return ts, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


__all__ = (
    "RecoveryIntegerParseDecision",
    "bounded_history_with_item",
    "record_snapshot",
    "recovery_integer_result",
    "recovery_timestamp",
    "transition_mapping",
)
