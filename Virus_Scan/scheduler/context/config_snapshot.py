"""Context-owned immutable scheduler configuration snapshots."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.context_no_hook import (
    context_float,
    context_int,
    context_text,
    merge_context_evidence,
)
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value


@dataclass(frozen=True, slots=True)
class SchedulerConfigSnapshot:
    """Immutable scheduler configuration crossing the context boundary."""

    scheduler: str = "process"
    max_workers: int = 0
    per_file_timeout_sec: float = 20.0
    progress_every: int = 10
    workload_limits: Mapping[str, object] = field(default_factory=immutable_mapping)
    environment: Mapping[str, object] = field(default_factory=immutable_mapping)
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        scheduler, scheduler_evidence = context_text(self.scheduler, field_name="scheduler", default="process")
        max_workers, max_workers_evidence = context_int(self.max_workers, field_name="max_workers", default=0, minimum=0)
        timeout, timeout_evidence = context_float(self.per_file_timeout_sec, field_name="per_file_timeout_sec", default=0.0, minimum=0.0)
        progress, progress_evidence = context_int(self.progress_every, field_name="progress_every", default=1, minimum=1)
        object.__setattr__(self, "scheduler", scheduler.lower())
        object.__setattr__(self, "max_workers", max_workers)
        object.__setattr__(self, "per_file_timeout_sec", timeout)
        object.__setattr__(self, "progress_every", progress)
        object.__setattr__(self, "workload_limits", immutable_mapping(self.workload_limits))
        object.__setattr__(self, "environment", immutable_mapping(self.environment))
        object.__setattr__(self, "evidence", merge_context_evidence(self.evidence, scheduler_evidence, max_workers_evidence, timeout_evidence, progress_evidence))

    def as_dict(self) -> dict[str, object]:
        return {
            "scheduler": self.scheduler,
            "max_workers": self.max_workers,
            "per_file_timeout_sec": self.per_file_timeout_sec,
            "progress_every": self.progress_every,
            "workload_limits": materialize_scheduler_mapping(self.workload_limits),
            "environment": materialize_scheduler_mapping(self.environment),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }

    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerConfigSnapshot":
        return cls(
            scheduler=scheduler_mapping_value(value, "scheduler", "process"),
            max_workers=scheduler_mapping_value(value, "max_workers", 0),
            per_file_timeout_sec=scheduler_mapping_value(value, "per_file_timeout_sec", 20.0),
            progress_every=scheduler_mapping_value(value, "progress_every", 10),
            workload_limits=scheduler_mapping_value(value, "workload_limits", {}),
            environment=scheduler_mapping_value(value, "environment", {}),
            evidence=scheduler_mapping_value(value, "evidence", ()),
        )


@dataclass(frozen=True, slots=True)
class SchedulerConfigSnapshotRequest:
    """Internal request for one scheduler configuration snapshot."""

    scheduler: object = "process"
    max_workers: object = 0
    per_file_timeout_sec: object = 20.0
    progress_every: object = 10
    workload_limits: Mapping[str, object] | None = None
    environment: Mapping[str, object] | None = None


def build_scheduler_config_snapshot(
    request: SchedulerConfigSnapshotRequest,
) -> SchedulerConfigSnapshot:
    """Build one immutable scheduler configuration snapshot."""
    return SchedulerConfigSnapshot(
        scheduler=request.scheduler,
        max_workers=request.max_workers,
        per_file_timeout_sec=request.per_file_timeout_sec,
        progress_every=request.progress_every,
        workload_limits={} if request.workload_limits is None else request.workload_limits,
        environment={} if request.environment is None else request.environment,
    )



__all__ = (
    'SchedulerConfigSnapshot',
    'SchedulerConfigSnapshotRequest',
    'build_scheduler_config_snapshot',
)
