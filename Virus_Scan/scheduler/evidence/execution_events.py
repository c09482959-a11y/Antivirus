"""Immutable scheduler execution event ownership.

This module owns construction of execution-scoped scheduler evidence.  Durable
JSON publication is owned by :mod:`scheduler_json_writer`; this module must not
perform persistence or mutate execution state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Tuple

from Virus_Scan.scheduler.evidence.execution_event_support import (
    first_text_mapping_value,
    immutable_execution_mapping,
    immutable_execution_tuple,
    mapping_item_value,
    metadata_with_field_issues,
    raw_job_items,
    scheduler_attempt_value,
    scheduler_bool_metadata_value,
    scheduler_text_value,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping, unsupported_scheduler_value_evidence


@dataclass(frozen=True)
class SchedulerExecutionEvent:
    """Replay-safe evidence for one scheduler execution transition."""

    event_type: str
    file_id: str | None = None
    worker_id: str | None = None
    attempt: int = 0
    status: str = "unknown"
    tags: Tuple[object, ...] = ()
    errors: Tuple[object, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        field_issues: dict[str, object] = {}
        event_type, issue = scheduler_text_value(
            self.event_type,
            field_name="event_type",
            default_text="scheduler_execution_event",
        )
        if issue is not None:
            field_issues["event_type"] = issue
        file_id, issue = scheduler_text_value(self.file_id, field_name="file_id", default_text=None, allow_none=True)
        if issue is not None:
            field_issues["file_id"] = issue
        worker_id, issue = scheduler_text_value(self.worker_id, field_name="worker_id", default_text=None, allow_none=True)
        if issue is not None:
            field_issues["worker_id"] = issue
        attempt, issue = scheduler_attempt_value(self.attempt)
        if issue is not None:
            field_issues["attempt"] = issue
        status, issue = scheduler_text_value(self.status, field_name="status", default_text="unknown")
        if issue is not None:
            field_issues["status"] = issue

        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "file_id", file_id)
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "attempt", attempt)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "tags", immutable_execution_tuple(self.tags))
        object.__setattr__(self, "errors", immutable_execution_tuple(self.errors))
        object.__setattr__(self, "metadata", metadata_with_field_issues(self.metadata, field_issues))

    def as_dict(self) -> dict[str, object]:
        return {
            "event_type": self.event_type,
            "file_id": self.file_id,
            "worker_id": self.worker_id,
            "attempt": self.attempt,
            "status": self.status,
            "tags": list(materialize_scheduler_mapping(self.tags)),
            "errors": list(materialize_scheduler_mapping(self.errors)),
            "metadata": materialize_scheduler_mapping(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SchedulerExecutionEventRequest:
    """Immutable construction request for scheduler execution evidence."""

    event_type: object
    file_id: object = None
    worker_id: object = None
    attempt: object = 0
    status: object = "unknown"
    tags: object = None
    errors: object = None
    metadata: Mapping[str, object] | None = None


def build_execution_event(
    request: SchedulerExecutionEventRequest,
) -> SchedulerExecutionEvent:
    """Construct immutable execution evidence from the canonical request."""
    return SchedulerExecutionEvent(
        event_type=request.event_type,
        file_id=request.file_id,
        worker_id=request.worker_id,
        attempt=request.attempt,
        status=request.status,
        tags=immutable_execution_tuple(request.tags),
        errors=immutable_execution_tuple(request.errors),
        metadata=immutable_execution_mapping(request.metadata),
    )



def build_raw_job_execution_event(job: Mapping[str, object], *, status: object, worker_id: object = None) -> SchedulerExecutionEvent:
    """Build immutable evidence from a raw-stage job mapping."""
    items = raw_job_items(job)
    metadata: dict[str, object]
    if items is None:
        metadata = {"raw_job_mapping_rejected": unsupported_scheduler_value_evidence(job, field_name="raw_job")}
    else:
        metadata = {
            "seq": mapping_item_value(items, "seq"),
            "collector": mapping_item_value(items, "collector"),
            "retried": scheduler_bool_metadata_value(mapping_item_value(items, "retried"), field_name="retried"),
        }
    return build_execution_event(
        SchedulerExecutionEventRequest(
            event_type="raw_job_execution",
            file_id=first_text_mapping_value(items, "file_id", "path", "file"),
            worker_id=worker_id,
            attempt=mapping_item_value(items, "attempt", 0),
            status=status,
            tags=mapping_item_value(items, "tags"),
            errors=mapping_item_value(items, "errors"),
            metadata=metadata,
        )
    )


__all__ = (
    'SchedulerExecutionEvent',
    'SchedulerExecutionEventRequest',
    'build_execution_event',
    'build_raw_job_execution_event',
)
