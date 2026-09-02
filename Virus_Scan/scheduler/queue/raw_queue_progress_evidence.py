"""Replayable evidence helpers for raw queue progress checks."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.status_predicates import scheduler_reason_empty
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
)
from Virus_Scan.scheduler.queue.raw_queue_path_support import raw_queue_accepted_path_extra
from pathlib import Path


@dataclass(frozen=True)
class RawProgressMappingEvidence:
    value: dict[str, object] | None
    reason: str

    @property
    def available(self) -> bool:
        return scheduler_reason_empty(self.reason)

    def as_extra(self) -> dict[str, str | bool]:
        return {
            "raw_progress_mapping_available": self.available,
            "raw_progress_mapping_reason": self.reason,
        }


@dataclass(frozen=True)
class RawProgressBoolDecision:
    value: bool
    reason: str
    field_name: str

    @property
    def accepted(self) -> bool:
        return scheduler_reason_empty(self.reason)

    def as_extra(self) -> dict[str, str | bool]:
        return {
            "raw_progress_bool_field": self.field_name,
            "raw_progress_bool_accepted": self.accepted,
            "raw_progress_bool_reason": self.reason,
            "raw_progress_bool_value": self.value,
        }


@dataclass(frozen=True)
class RawProgressMtimeEvidence:
    value: float
    reason: str
    path_text: str
    path_reason: str = ""
    error_type: str = ""
    error_detail: str = ""

    @property
    def available(self) -> bool:
        return scheduler_reason_empty(self.reason)

    def as_extra(self) -> dict[str, str | float | bool]:
        return {
            "raw_progress_mtime_available": self.available,
            "raw_progress_mtime_reason": self.reason,
            "path": self.path_text,
            "path_reason": self.path_reason,
            "error_type": self.error_type,
            "error_detail": self.error_detail,
            "mtime_value": self.value,
        }


raw_progress_path_extra = raw_queue_accepted_path_extra


def raw_progress_extra(queue_dir: object, file_path: object) -> dict[str, str]:
    extra = raw_progress_path_extra("queue_dir", queue_dir)
    extra.update(raw_progress_path_extra("file_path", file_path))
    return extra


def raw_progress_mapping(value: object) -> RawProgressMappingEvidence:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return RawProgressMappingEvidence(value=None, reason="raw_progress_mapping_rejected")
    return RawProgressMappingEvidence(value=scheduler_str_key_mapping_from_items(items), reason="")


def raw_progress_expected(value: object) -> int:
    if type(value) is bool:
        return 1 if value else 0
    parsed, _reason = scheduler_int(value, default=0, minimum=0, reason="raw_progress_expected_rejected")
    return parsed


def raw_progress_float(value: object, default: float = 0.0) -> float:
    parsed, reason = scheduler_float(value, default=default, minimum=0.0, reason="raw_progress_float_rejected")
    return parsed if reason == "" else default


def raw_progress_bool(
    value: object,
    *,
    field_name: str = "raw_progress_bool",
    reason: str = "raw_progress_bool_rejected",
) -> RawProgressBoolDecision:
    parsed, parse_reason = scheduler_bool(value, default=False, reason=reason)
    return RawProgressBoolDecision(value=parsed, reason=parse_reason, field_name=field_name)


def raw_progress_quiet_seconds(value: object) -> float:
    quiet = raw_progress_float(value, 120.0)
    return max(15.0, quiet)


def unavailable_raw_progress_mtime(
    *,
    reason: str,
    path_text: str = "",
    path_reason: str = "",
    error_type: str = "",
    error_detail: str = "",
) -> RawProgressMtimeEvidence:
    return RawProgressMtimeEvidence(
        value=0.0,
        reason=reason,
        path_text=path_text,
        path_reason=path_reason,
        error_type=error_type,
        error_detail=error_detail,
    )


def raw_progress_path_mtime(path: object) -> RawProgressMtimeEvidence:
    text, reason = scheduler_path_text(path)
    if reason != "" or text == "":
        return unavailable_raw_progress_mtime(
            reason=reason or "raw_progress_mtime_path_missing",
            path_text=text,
            path_reason=reason or "raw_progress_mtime_path_missing",
        )
    try:
        parsed, parse_reason = scheduler_float(
            Path(text).stat().st_mtime,
            default=0.0,
            minimum=0.0,
            reason="raw_progress_mtime_rejected",
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return unavailable_raw_progress_mtime(
            reason="raw_progress_mtime_stat_failed",
            path_text=text,
            error_type=type(exc).__name__,
            error_detail=scheduler_error_detail(exc, max_length=500),
        )
    if parse_reason:
        return unavailable_raw_progress_mtime(reason=parse_reason, path_text=text)
    return RawProgressMtimeEvidence(value=parsed, reason="", path_text=text)


__all__ = (
    "RawProgressBoolDecision",
    "RawProgressMappingEvidence",
    "RawProgressMtimeEvidence",
    "raw_progress_bool",
    "raw_progress_expected",
    "raw_progress_extra",
    "raw_progress_float",
    "raw_progress_mapping",
    "raw_progress_path_mtime",
    "raw_progress_quiet_seconds",
)
