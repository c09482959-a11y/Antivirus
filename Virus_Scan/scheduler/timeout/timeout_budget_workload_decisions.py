"""Typed timeout workload decisions with replayable rejection reasons."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TYPE_CHECKING

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_path_text
from Virus_Scan.scheduler.internal.status_predicates import scheduler_status_equals, scheduler_status_not

if TYPE_CHECKING:
    import os

ConfiguredTimeoutStatus = Literal["not_configured", "blank", "accepted", "rejected"]
TimeoutSizeStatus = Literal["accepted", "rejected"]
WorkloadExtensionStatus = Literal["accepted", "rejected"]


@dataclass(frozen=True, slots=True)
class ConfiguredTimeoutErrorDecision:
    """Replayable outcome for configured timeout validation."""

    status: ConfiguredTimeoutStatus
    configured_timeout_seconds: float
    error: str | None
    reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_not(self.status, "rejected")


@dataclass(frozen=True, slots=True)
class TimeoutSizeMegabytesDecision:
    """Replayable timeout workload size conversion."""

    status: TimeoutSizeStatus
    size_bytes: float
    megabytes: float
    reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_equals(self.status, "accepted")


@dataclass(frozen=True, slots=True)
class WorkloadExtensionDecision:
    """Replayable suffix materialization for timeout workload classification."""

    status: WorkloadExtensionStatus
    extension: str
    reason: str

    @property
    def accepted(self) -> bool:
        return scheduler_status_equals(self.status, "accepted")


def configured_timeout_error_decision(
    configured_timeout_seconds: float | str | None,
) -> ConfiguredTimeoutErrorDecision:
    if configured_timeout_seconds is None:
        return ConfiguredTimeoutErrorDecision("not_configured", 0.0, None, "configured_timeout_seconds_not_configured")
    if type(configured_timeout_seconds) is str and str.__str__(configured_timeout_seconds) == "":
        return ConfiguredTimeoutErrorDecision("blank", 0.0, None, "configured_timeout_seconds_blank")
    configured, reason = scheduler_float(
        configured_timeout_seconds,
        default=0.0,
        reason="configured_timeout_seconds_rejected",
    )
    if reason:
        return ConfiguredTimeoutErrorDecision("rejected", 0.0, "configured_timeout_seconds " + str.__str__(reason), reason)
    if configured < 0.0:
        return ConfiguredTimeoutErrorDecision(
            "rejected",
            configured,
            "configured_timeout_seconds ValueError: configured timeout below minimum 0.0",
            "configured_timeout_seconds_below_minimum",
        )
    return ConfiguredTimeoutErrorDecision("accepted", configured, None, "configured_timeout_seconds_accepted")


def workload_size_megabytes_decision(size_bytes: float | None) -> TimeoutSizeMegabytesDecision:
    value, reason = scheduler_float(size_bytes, default=0.0, minimum=0.0, reason="timeout_size_rejected")
    if reason:
        return TimeoutSizeMegabytesDecision("rejected", 0.0, 0.0, str.__str__(reason))
    return TimeoutSizeMegabytesDecision("accepted", value, value / 1048576.0, "timeout_size_accepted")


def workload_extension_decision(path: str | os.PathLike[str] | None) -> WorkloadExtensionDecision:
    path_text, reason = scheduler_path_text(path)
    if reason:
        return WorkloadExtensionDecision("rejected", "", str.__str__(reason))
    return WorkloadExtensionDecision("accepted", Path(path_text).suffix.lower(), "workload_extension_accepted")


__all__ = (
    "ConfiguredTimeoutErrorDecision",
    "ConfiguredTimeoutStatus",
    "TimeoutSizeMegabytesDecision",
    "TimeoutSizeStatus",
    "WorkloadExtensionDecision",
    "WorkloadExtensionStatus",
    "configured_timeout_error_decision",
    "workload_extension_decision",
    "workload_size_megabytes_decision",
)
