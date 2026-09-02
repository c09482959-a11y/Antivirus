"""Immutable process-queue pending publication contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
    scheduler_text,
)


@dataclass(frozen=True, slots=True)
class ProcessQueuePublishAttempt:
    """Validated payload for one process-queue pending publication."""

    order: int
    original_index: int
    file_path: str
    workload_class: str
    queue_file_id: str
    weight: float

    def __post_init__(self) -> None:
        order, order_reason = scheduler_int(
            self.order,
            minimum=0,
            reason="process_queue_publish_order_rejected",
        )
        original_index, index_reason = scheduler_int(
            self.original_index,
            minimum=0,
            reason="process_queue_publish_index_rejected",
        )
        file_path, file_reason = scheduler_path_text(self.file_path)
        workload_class, workload_reason = scheduler_text(
            self.workload_class,
            unsupported_reason="process_queue_publish_workload_rejected",
        )
        queue_file_id, identity_reason = scheduler_text(
            self.queue_file_id,
            unsupported_reason="process_queue_publish_identity_rejected",
        )
        weight, weight_reason = scheduler_float(
            self.weight,
            minimum=0.0,
            reason="process_queue_publish_weight_rejected",
        )
        reasons = tuple(
            reason
            for reason in (
                order_reason,
                index_reason,
                file_reason,
                workload_reason,
                identity_reason,
                weight_reason,
            )
            if reason
        )
        if reasons or not file_path or not workload_class or not queue_file_id:
            raise ValueError(
                "invalid process queue publish attempt:"
                + ",".join(reasons or ("missing_required_field",))
            )
        object.__setattr__(self, "order", order)
        object.__setattr__(self, "original_index", original_index)
        object.__setattr__(self, "file_path", file_path)
        object.__setattr__(self, "workload_class", workload_class)
        object.__setattr__(self, "queue_file_id", queue_file_id)
        object.__setattr__(self, "weight", weight)

    @property
    def job(self) -> dict[str, object]:
        return {
            "index": self.original_index,
            "order": self.order,
            "file": self.file_path,
            "queue_file_id": self.queue_file_id,
            "weight": self.weight,
            "workload_class": self.workload_class,
        }

    @property
    def pending_name(self) -> str:
        return str(self.order).zfill(8) + "_" + str(self.original_index).zfill(8) + ".json"


@dataclass(frozen=True, slots=True)
class ProcessQueuePublishResult:
    """Validated result for one pending-job publication attempt."""

    published: bool
    guard_blocked: bool = False
    guard_exception: bool = False
    durable_write_failed: bool = False
    identity_index_failed: bool = False
    release_failed: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "published",
            "guard_blocked",
            "guard_exception",
            "durable_write_failed",
            "identity_index_failed",
            "release_failed",
        ):
            value, reason = scheduler_bool(
                scheduler_exact_attr(self, field_name, owner_type=ProcessQueuePublishResult),
                reason="process_queue_publish_" + field_name + "_rejected",
            )
            if reason:
                raise ValueError(reason)
            object.__setattr__(self, field_name, value)


@dataclass(frozen=True, slots=True)
class ProcessQueuePublishAttemptRequest:
    """Immutable construction request for one pending queue job."""

    order: int
    original_index: int
    file_path: object
    workload_class: object
    queue_file_identity_for_path: Callable[[object], object]
    process_weight_for_path: Callable[[object], object]


def build_process_queue_publish_attempt(
    request: ProcessQueuePublishAttemptRequest,
) -> ProcessQueuePublishAttempt:
    """Build a validated pending-job payload from the canonical request."""
    safe_path, path_reason = scheduler_path_text(request.file_path)
    if path_reason or not safe_path:
        reason = path_reason or "missing_path"
        raise ValueError("invalid process queue publish path:" + reason)
    return ProcessQueuePublishAttempt(
        order=request.order,
        original_index=request.original_index,
        file_path=safe_path,
        workload_class=request.workload_class,
        queue_file_id=request.queue_file_identity_for_path(safe_path),
        weight=request.process_weight_for_path(safe_path),
    )



__all__ = (
    'ProcessQueuePublishAttempt',
    'ProcessQueuePublishAttemptRequest',
    'ProcessQueuePublishResult',
    'build_process_queue_publish_attempt',
)
