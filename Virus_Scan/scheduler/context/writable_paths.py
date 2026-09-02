"""Context-owned immutable writable path snapshots."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.context_no_hook import context_text, merge_context_evidence
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_value


@dataclass(frozen=True, slots=True)
class SchedulerWritablePaths:
    """Explicit writable scheduler paths owned outside onefile extraction state."""

    runtime_dir: str = ""
    queue_dir: str = ""
    checkpoint_dir: str = ""
    evidence_dir: str = ""
    temp_dir: str = ""
    metadata: Mapping[str, object] = field(default_factory=immutable_mapping)
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        runtime_dir, runtime_dir_evidence = context_text(self.runtime_dir, field_name="runtime_dir", default="")
        queue_dir, queue_dir_evidence = context_text(self.queue_dir, field_name="queue_dir", default="")
        checkpoint_dir, checkpoint_dir_evidence = context_text(self.checkpoint_dir, field_name="checkpoint_dir", default="")
        evidence_dir, evidence_dir_evidence = context_text(self.evidence_dir, field_name="evidence_dir", default="")
        temp_dir, temp_dir_evidence = context_text(self.temp_dir, field_name="temp_dir", default="")
        object.__setattr__(self, "runtime_dir", runtime_dir)
        object.__setattr__(self, "queue_dir", queue_dir)
        object.__setattr__(self, "checkpoint_dir", checkpoint_dir)
        object.__setattr__(self, "evidence_dir", evidence_dir)
        object.__setattr__(self, "temp_dir", temp_dir)
        object.__setattr__(self, "metadata", immutable_mapping(self.metadata))
        object.__setattr__(self, "evidence", merge_context_evidence(self.evidence, runtime_dir_evidence, queue_dir_evidence, checkpoint_dir_evidence, evidence_dir_evidence, temp_dir_evidence))

    def as_dict(self) -> dict[str, object]:
        return {
            "runtime_dir": self.runtime_dir,
            "queue_dir": self.queue_dir,
            "checkpoint_dir": self.checkpoint_dir,
            "evidence_dir": self.evidence_dir,
            "temp_dir": self.temp_dir,
            "metadata": materialize_scheduler_mapping(self.metadata),
            "evidence": materialize_scheduler_mapping(self.evidence),
        }


    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerWritablePaths":
        return cls(
            runtime_dir=scheduler_mapping_value(value, "runtime_dir", ""),
            queue_dir=scheduler_mapping_value(value, "queue_dir", ""),
            checkpoint_dir=scheduler_mapping_value(value, "checkpoint_dir", ""),
            evidence_dir=scheduler_mapping_value(value, "evidence_dir", ""),
            temp_dir=scheduler_mapping_value(value, "temp_dir", ""),
            metadata=scheduler_mapping_value(value, "metadata", {}),
            evidence=scheduler_mapping_value(value, "evidence", ()),
        )


__all__ = ("SchedulerWritablePaths",)
