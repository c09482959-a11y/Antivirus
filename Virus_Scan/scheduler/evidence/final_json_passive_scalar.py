"""Exact scalar classification for passive scheduler status fields."""
from __future__ import annotations



from Virus_Scan.scheduler.evidence.final_json_exact_fields import (
    exact_flag_value,
    exact_has_content,
)
from Virus_Scan.scheduler.evidence.final_json_passive_decisions import (
    ScalarFailureCategoryDecision,
)

_FAILURE_MARKERS = (
    "failed", "failure", "error", "fatal", "degraded", "timeout", "timed_out",
    "exhaust", "dead", "invalid", "corrupt", "missing", "orphan", "unwritten",
    "suppressed",
)
_OK_STATUSES = ("", "ok", "clean", "success", "passed", "complete", "completed")


def scalar_failure_category(key: str, value: object) -> str:
    return scalar_failure_category_decision(key, value).category


def _suppressed_failures_count(value: object) -> tuple[bool, int]:
    if value is None:
        return True, 0
    if type(value) is int and type(value) is not bool:
        return True, max(value, 0)
    if type(value) is not str:
        return False, 0
    stripped_count = str.strip(value)
    if stripped_count == "":
        return False, 0
    count_sign = 1
    count_digits = stripped_count
    if stripped_count[0] in {"+", "-"}:
        if len(stripped_count) == 1:
            return False, 0
        count_sign = -1 if stripped_count[0] == "-" else 1
        count_digits = stripped_count[1:]
    if not str.isdecimal(count_digits):
        return False, 0
    return True, max(0, count_sign * int(count_digits, 10))


def _suppressed_failures_decision(key: str, value: object) -> ScalarFailureCategoryDecision:
    if value is None:
        return ScalarFailureCategoryDecision.no_failure("suppressed_failures_missing")
    accepted, count = _suppressed_failures_count(value)
    if not accepted:
        return ScalarFailureCategoryDecision.unsupported_category(
            str.__add__(key, "_unsupported"),
            "suppressed_failures_count_rejected",
        )
    if count > 0:
        return ScalarFailureCategoryDecision.failure(
            str.__add__(key, "_failure"),
            "suppressed_failures_positive_count",
        )
    return ScalarFailureCategoryDecision.no_failure("suppressed_failures_zero_count")


def _empty_scalar_decision(key: str, value: object) -> ScalarFailureCategoryDecision | None:
    if exact_has_content(value):
        return None
    if value is None or type(value) in {str, bool, int, dict, list, tuple, set, frozenset}:
        return ScalarFailureCategoryDecision.no_failure("passive_scalar_empty_exact_value")
    return ScalarFailureCategoryDecision.unsupported_category(
        str.__add__(key, "_unsupported"),
        "passive_scalar_empty_unsupported_value",
    )


def _failure_suffix_decision(
    key: str,
    text: str,
    value: object,
) -> ScalarFailureCategoryDecision | None:
    if not text.endswith(("_failed", "_failure", "_fatal")):
        return None
    if exact_flag_value(value):
        return ScalarFailureCategoryDecision.failure(
            str.__add__(key, "_failure"),
            "passive_scalar_failure_flag_true",
        )
    if type(value) in {str, bool, int}:
        return ScalarFailureCategoryDecision.no_failure("passive_scalar_failure_suffix_false")
    return ScalarFailureCategoryDecision.unsupported_category(
        str.__add__(key, "_unsupported"),
        "passive_scalar_failure_suffix_unsupported",
    )


def _status_state_decision(
    key: str,
    text: str,
    value: object,
) -> ScalarFailureCategoryDecision | None:
    if not any(fragment in text for fragment in ("status", "state")):
        return None
    if type(value) is not str:
        return ScalarFailureCategoryDecision.unsupported_category(
            str.__add__(key, "_unsupported"),
            "passive_scalar_status_value_type_rejected",
        )
    status_text = str.lower(value)
    if status_text not in _OK_STATUSES and any(marker in status_text for marker in _FAILURE_MARKERS):
        return ScalarFailureCategoryDecision.failure(
            str.__add__(key, "_failure"),
            "passive_scalar_status_failure_marker",
        )
    return None


def _classified_scalar_decision(
    key: str,
    text: str,
    value: object,
) -> ScalarFailureCategoryDecision | None:
    if text == "suppressed_failures":
        return _suppressed_failures_decision(key, value)
    decision = _empty_scalar_decision(key, value)
    if decision is not None:
        return decision
    if text == "scheduler":
        return ScalarFailureCategoryDecision.unsupported_category(
            str.__add__(key, "_unsupported"),
            "passive_scalar_scheduler_root_unsupported",
        )
    decision = _failure_suffix_decision(key, text, value)
    if decision is not None:
        return decision
    return _status_state_decision(key, text, value)


def scalar_failure_category_decision(key: str, value: object) -> ScalarFailureCategoryDecision:
    if type(key) is not str:
        return ScalarFailureCategoryDecision.unsupported_category(
            "scheduler_passive_scalar_unsupported_key",
            "passive_scalar_key_type_rejected",
        )
    decision = _classified_scalar_decision(key, str.lower(key), value)
    if decision is not None:
        return decision
    return ScalarFailureCategoryDecision.no_failure("passive_scalar_no_failure_marker")


__all__ = ("scalar_failure_category", "scalar_failure_category_decision")
