"""No-hook raw queue JSON policy helpers."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.scheduler.internal.exact_integer_bounds import clamp_exact_int
from Virus_Scan.scheduler.internal.exact_integer_text import parse_exact_integer_text


_POLICY_PREFIX = "GLOBAL_"
_POLICY_ISSUE_SUFFIX = "_policy_issue"
_POLICY_REJECTED_SUFFIX = "_policy_rejected"


@dataclass(frozen=True, slots=True)
class RawPolicyIntegerDecision:
    value: int
    reason: str
    replacement_used: bool


def raw_policy_label(name: str) -> str:
    return str.removeprefix(name, _POLICY_PREFIX).lower()


def raw_policy_issue_label(label: str) -> str:
    return str.__add__(label, _POLICY_ISSUE_SUFFIX)


def raw_policy_rejected_reason(label: str) -> str:
    return str.__add__(label, _POLICY_REJECTED_SUFFIX)


def _exact_int_text_decision(value: str) -> RawPolicyIntegerDecision:
    parsed = parse_exact_integer_text(
        value,
        empty_reason="raw_policy_int_text_missing",
        sign_without_digits_reason="raw_policy_int_sign_without_digits",
        not_decimal_reason="raw_policy_int_text_rejected",
    )
    return RawPolicyIntegerDecision(parsed.value, parsed.reason, parsed.reason != "")


def raw_policy_int(value: object, *, default_value: int, minimum: int, rejected_reason: str) -> tuple[int, str]:
    safe_default = clamp_exact_int(default_value if type(default_value) is int and type(default_value) is not bool else minimum, minimum=minimum)
    if value is None:
        return safe_default, ""
    parsed: int
    if type(value) is bool:
        return safe_default, rejected_reason
    if type(value) is int:
        parsed = value
    elif type(value) is float:
        if not math.isfinite(value) or not value.is_integer():
            return safe_default, rejected_reason
        parsed = int(value)
    elif type(value) is str:
        decision = _exact_int_text_decision(value)
        if decision.reason:
            return safe_default, rejected_reason
        parsed = decision.value
    elif type(value) is bytes:
        decision = _exact_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return safe_default, rejected_reason
        parsed = decision.value
    elif type(value) is bytearray:
        decision = _exact_int_text_decision(bytes(value).decode("utf-8", "replace"))
        if decision.reason:
            return safe_default, rejected_reason
        parsed = decision.value
    else:
        return safe_default, rejected_reason
    return clamp_exact_int(parsed, minimum=minimum), ""


__all__ = (
    "RawPolicyIntegerDecision",
    "raw_policy_int",
    "raw_policy_issue_label",
    "raw_policy_label",
    "raw_policy_rejected_reason",
)
