"""Immutable queue-owned evidence for orphan-recovery action failures."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_evidence_text,
    scheduler_exception_text,
)

@dataclass(frozen=True, slots=True)
class OrphanRecoveryActionEvidence:
    """Replay-visible evidence for reclaim/recovery publication failures."""

    stage: str
    action: str
    source_path: str
    destination_path: str
    error_category: str
    error_source: str
    detail: str
    job_id: str = ""
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "stage": self.stage,
                "action": self.action,
                "source_path": self.source_path,
                "destination_path": self.destination_path,
                "job_id": self.job_id,
                "error_category": self.error_category,
                "error_source": self.error_source,
                "detail": self.detail[:1000],
                "timeout_failure": True,
                "retry_failure": True,
                "queue_recovery_failure": True,
                "final_json_must_record": bool(self.final_json_must_record),
                "checkpoint_must_record": bool(self.checkpoint_must_record),
                "replay_must_reproduce": bool(self.replay_must_reproduce),
            }
        )


@dataclass(frozen=True, slots=True)
class OrphanRecoveryActionEvidenceRequest:
    """Immutable construction request for one orphan-recovery action record."""

    stage: str
    action: str
    source_path: object
    error: BaseException
    error_source: str
    destination_path: object = ""
    job_id: object = ""


def orphan_recovery_action_evidence(
    request: OrphanRecoveryActionEvidenceRequest,
) -> OrphanRecoveryActionEvidence:
    """Build queue-owned evidence from the canonical immutable request."""
    return OrphanRecoveryActionEvidence(
        stage=request.stage,
        action=request.action,
        source_path=scheduler_evidence_path(
            request.source_path, field_name="orphan_source_path"
        ),
        destination_path=scheduler_evidence_path(
            request.destination_path, field_name="orphan_destination_path"
        ),
        job_id=scheduler_evidence_text(
            request.job_id,
            missing_text="missing_orphan_job_id",
            field_name="orphan_job_id",
        ),
        error_category=no_hook_type_name(request.error),
        error_source=request.error_source,
        detail=scheduler_exception_text(request.error),
    )



@dataclass(frozen=True, slots=True)
class OrphanRecoveryActionEvidenceAppendRequest:
    """One immutable request for appending reclaim action evidence to a caller sink."""

    evidence_records: list[Mapping[str, object]] | None
    stage: str
    action: str
    source_path: object
    error: BaseException
    error_source: str
    destination_path: object = ""
    job_id: object = ""


__all__ = (
    'OrphanRecoveryActionEvidence',
    'OrphanRecoveryActionEvidenceAppendRequest',
    'OrphanRecoveryActionEvidenceRequest',
    'orphan_recovery_action_evidence',
)
