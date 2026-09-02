"""Context-owned immutable scheduler runtime snapshots."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.context_no_hook import (
    context_bool,
    context_text,
    merge_context_evidence,
)
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value


@dataclass(frozen=True, slots=True)
class SchedulerRuntimeSnapshot:
    """Immutable runtime state visible to scheduler domains."""

    root: str = ""
    runtime_dir: str = ""
    queue_dir: str = ""
    frozen: bool = False
    onefile: bool = False
    process_policy: Mapping[str, object] = field(default_factory=immutable_mapping)
    worker_capacity: Mapping[str, object] = field(default_factory=immutable_mapping)
    active_flags: tuple[object, ...] = ()
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        root, root_evidence = context_text(self.root, field_name="root", default="")
        runtime_dir, runtime_dir_evidence = context_text(self.runtime_dir, field_name="runtime_dir", default="")
        queue_dir, queue_dir_evidence = context_text(self.queue_dir, field_name="queue_dir", default="")
        frozen, frozen_evidence = context_bool(self.frozen, field_name="frozen", default=False)
        onefile, onefile_evidence = context_bool(self.onefile, field_name="onefile", default=False)
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "runtime_dir", runtime_dir)
        object.__setattr__(self, "queue_dir", queue_dir)
        object.__setattr__(self, "frozen", frozen)
        object.__setattr__(self, "onefile", onefile)
        object.__setattr__(self, "process_policy", immutable_mapping(self.process_policy))
        object.__setattr__(self, "worker_capacity", immutable_mapping(self.worker_capacity))
        object.__setattr__(self, "active_flags", immutable_tuple(self.active_flags))
        object.__setattr__(self, "evidence", merge_context_evidence(self.evidence, root_evidence, runtime_dir_evidence, queue_dir_evidence, frozen_evidence, onefile_evidence))

    def as_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "runtime_dir": self.runtime_dir,
            "queue_dir": self.queue_dir,
            "frozen": self.frozen,
            "onefile": self.onefile,
            "process_policy": materialize_scheduler_mapping(self.process_policy),
            "worker_capacity": materialize_scheduler_mapping(self.worker_capacity),
            "active_flags": materialize_scheduler_mapping(self.active_flags),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }


    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerRuntimeSnapshot":
        return cls(
            root=scheduler_mapping_value(value, "root", ""),
            runtime_dir=scheduler_mapping_value(value, "runtime_dir", ""),
            queue_dir=scheduler_mapping_value(value, "queue_dir", ""),
            frozen=scheduler_mapping_value(value, "frozen", default=False),
            onefile=scheduler_mapping_value(value, "onefile", default=False),
            process_policy=scheduler_mapping_value(value, "process_policy", {}),
            worker_capacity=scheduler_mapping_value(value, "worker_capacity", {}),
            active_flags=scheduler_mapping_value(value, "active_flags", ()),
            evidence=scheduler_mapping_value(value, "evidence", ()),
        )


__all__ = ("SchedulerRuntimeSnapshot",)
