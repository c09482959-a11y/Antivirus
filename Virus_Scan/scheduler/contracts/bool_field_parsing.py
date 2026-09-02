"""No-hook scheduler contract boolean parsing support."""
from __future__ import annotations

from dataclasses import dataclass

_TRUE_BOOL_TEXTS = frozenset(
    {"1", "true", "yes", "y", "failed", "failure", "fatal", "degraded", "timeout"}
)
_FALSE_BOOL_TEXTS = frozenset(
    {"0", "false", "no", "n", "ok", "clean", "success", "passed", "written"}
)


@dataclass(frozen=True, slots=True)
class SchedulerBoolParseResult:
    """Boolean parse result with explicit no-hook rejection reason."""

    accepted: bool
    value: bool
    reason: str



def parse_scheduler_bool_field(
    value: object,
    *,
    text_invalid_reason: str,
    rejected_reason: str,
) -> SchedulerBoolParseResult:
    """Parse scheduler boolean field values without invoking caller hooks."""

    if value is None:
        return SchedulerBoolParseResult(accepted=False, value=False, reason="")
    if type(value) is bool:
        return SchedulerBoolParseResult(accepted=True, value=value, reason="")
    if type(value) is int:
        return SchedulerBoolParseResult(accepted=True, value=value != 0, reason="")
    if type(value) is str:
        normalized = str.__str__(value).strip().lower()
        accepted = normalized in _TRUE_BOOL_TEXTS or normalized in _FALSE_BOOL_TEXTS
        return SchedulerBoolParseResult(
            accepted=accepted,
            value=normalized in _TRUE_BOOL_TEXTS,
            reason="" if accepted else text_invalid_reason,
        )
    return SchedulerBoolParseResult(accepted=False, value=False, reason=rejected_reason)


__all__ = ("SchedulerBoolParseResult", "parse_scheduler_bool_field")
