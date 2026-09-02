"""Worker-owned process-queue spawn/scaling failure evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping


@dataclass(frozen=True)
class ProcessQueueWorkerSpawnFailureEvidence:
    """Immutable evidence that a process-queue worker spawn/scale action failed."""

    stage: str
    action: str
    worker_id: int | None
    error_category: str
    error_source: str
    detail: str
    fatal: bool = False
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        """Return a JSON/checkpoint/replay-safe immutable evidence record."""
        return immutable_mapping(
            {
                "stage": self.stage,
                "action": self.action,
                "worker_id": self.worker_id,
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail,
                "fatal": bool(self.fatal),
                "final_json_must_record": bool(self.final_json_must_record),
                "checkpoint_must_record": bool(self.checkpoint_must_record),
                "replay_must_reproduce": bool(self.replay_must_reproduce),
            }
        )


__all__ = ("ProcessQueueWorkerSpawnFailureEvidence",)
