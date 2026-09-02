"""Typed global raw-queue scan outcome contract."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.status_predicates import scheduler_status_equals


@dataclass(frozen=True)
class GlobalRawQueueScanOutcome:
    """Replayable scheduler result for global raw-queue execution."""

    status: str
    reason: str
    result: Mapping[str, object] | None = None
    exception_type: str = ""

    @property
    def ok(self) -> bool:
        return scheduler_status_equals(self.status, "completed")

    def get(self, key: str, default: object = None) -> object:
        if self.result is None:
            return default
        return self.result.get(key, default)

    def require_result(self) -> Mapping[str, object]:
        if self.result is None:
            raise RuntimeError("global_raw_queue_result_unavailable:" + self.reason)
        return self.result


def raw_queue_scan_completed(result: Mapping[str, object]) -> GlobalRawQueueScanOutcome:
    return GlobalRawQueueScanOutcome(status="completed", reason="completed", result=result)


def raw_queue_scan_skipped(reason: str) -> GlobalRawQueueScanOutcome:
    return GlobalRawQueueScanOutcome(status="skipped", reason=reason)


def raw_queue_scan_rejected(reason: str) -> GlobalRawQueueScanOutcome:
    return GlobalRawQueueScanOutcome(status="rejected", reason=reason)


def raw_queue_scan_failed(reason: str, exc: BaseException) -> GlobalRawQueueScanOutcome:
    return GlobalRawQueueScanOutcome(status="failed", reason=reason, exception_type=type(exc).__name__)


__all__ = (
    "GlobalRawQueueScanOutcome",
    "raw_queue_scan_completed",
    "raw_queue_scan_failed",
    "raw_queue_scan_rejected",
    "raw_queue_scan_skipped",
)
