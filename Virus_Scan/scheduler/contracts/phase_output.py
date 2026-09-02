"""Immutable scheduler phase-output contracts.

Phase 9 requires scheduler domains to communicate through explicit immutable
records instead of loose mutable partial dictionaries.  This module provides the
narrow cross-phase envelope: each phase output names its owning phase/domain and
carries exactly one typed immutable scheduler payload.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol

from Virus_Scan.scheduler.context.config_snapshot import SchedulerConfigSnapshot
from Virus_Scan.scheduler.context.dependency_snapshot import SchedulerDependencySnapshot
from Virus_Scan.scheduler.context.runtime_snapshot import SchedulerRuntimeSnapshot
from Virus_Scan.scheduler.context.writable_paths import SchedulerWritablePaths
from Virus_Scan.scheduler.contracts.contract_fields import (
    contract_int,
    contract_mapping_value,
    contract_sequence,
    contract_text,
    merge_contract_issues,
)
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.queue_claim import QueueClaim
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueIntegrityResult, QueueMergeResult, QueueRecoveryResult, QueueSnapshot
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision, RetryExhaustionResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerIdentity, WorkerResult, WorkerSnapshot
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


_PHASE_PAYLOAD_TYPES = (
    SchedulerConfigSnapshot,
    SchedulerRuntimeSnapshot,
    SchedulerDependencySnapshot,
    SchedulerWritablePaths,
    QueueSnapshot,
    QueueClaim,
    QueueIntegrityResult,
    QueueRecoveryResult,
    QueueMergeResult,
    WorkerSnapshot,
    WorkerIdentity,
    WorkerResult,
    TimeoutResult,
    RetryDecision,
    RetryExhaustionResult,
    ReplaySnapshot,
    ReplayComparisonResult,
)

_PHASE_PAYLOAD_BY_NAME = MappingProxyType({payload_type.__name__: payload_type for payload_type in _PHASE_PAYLOAD_TYPES})
_PHASE_OUTPUT_EVIDENCE_REQUIRES_EVIDENCE_RECORD = "SchedulerPhaseOutput evidence requires SchedulerEvidenceRecord"
_PHASE_OUTPUT_LEDGER_REQUIRES_OUTPUT_ENTRIES = "SchedulerPhaseOutputLedger requires SchedulerPhaseOutput entries"


def _require_scheduler_phase_evidence_record(record: object) -> SchedulerEvidenceRecord:
    if not isinstance(record, SchedulerEvidenceRecord):
        raise TypeError(_PHASE_OUTPUT_EVIDENCE_REQUIRES_EVIDENCE_RECORD)
    return record


def _require_scheduler_phase_output(output: object) -> "SchedulerPhaseOutput":
    if not isinstance(output, SchedulerPhaseOutput):
        raise TypeError(_PHASE_OUTPUT_LEDGER_REQUIRES_OUTPUT_ENTRIES)
    return output


class _PhasePayloadMapping(Protocol):
    def as_dict(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class SchedulerPhaseOutput:
    """Typed immutable output emitted by one scheduler phase boundary."""

    phase: str
    domain: str
    status: str
    payload: _PhasePayloadMapping
    sequence: int = 0
    evidence: tuple[SchedulerEvidenceRecord, ...] = ()

    def __post_init__(self) -> None:
        phase, phase_issue = contract_text(self.phase, field_name="phase", default="scheduler")
        domain, domain_issue = contract_text(self.domain, field_name="domain", default="scheduler")
        status, status_issue = contract_text(self.status, field_name="status", default="ok")
        sequence, sequence_issue = contract_int(self.sequence, field_name="sequence", default=0, minimum=0)
        if not isinstance(self.payload, _PHASE_PAYLOAD_TYPES):
            allowed = ", ".join(payload_type.__name__ for payload_type in _PHASE_PAYLOAD_TYPES)
            raise TypeError("SchedulerPhaseOutput payload must be one of: " + allowed)
        evidence_items, evidence_issue = contract_sequence(self.evidence, field_name="evidence")
        evidence = [_require_scheduler_phase_evidence_record(record) for record in evidence_items]
        evidence.extend(
            SchedulerEvidenceRecord(
                stage="scheduler_phase_output_contract",
                state="degraded",
                error_category="scheduler_contract_field_rejected",
                error_source="scheduler.contracts.phase_output",
                message="scheduler phase output field rejected without caller hooks",
                context=issue,
                final_json_must_record=True,
                checkpoint_must_record=True,
                replay_must_record=True,
            )
            for issue in merge_contract_issues(
                phase_issue,
                domain_issue,
                status_issue,
                sequence_issue,
                evidence_issue,
            )
            if type(issue) is dict
        )
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "evidence", tuple(evidence))

    @property
    def payload_type(self) -> str:
        return type(self.payload).__name__

    def as_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "domain": self.domain,
            "status": self.status,
            "sequence": self.sequence,
            "payload_type": self.payload_type,
            "payload": self.payload.as_dict(),
            "evidence": [record.as_dict() for record in self.evidence],
        }

    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerPhaseOutput":
        payload_type_text, _payload_type_issue = contract_text(contract_mapping_value(value, "payload_type", default=""), field_name="payload_type", default="")
        payload_type = _PHASE_PAYLOAD_BY_NAME.get(payload_type_text)
        if payload_type is None:
            raise TypeError("unknown SchedulerPhaseOutput payload_type: " + payload_type_text)
        payload = payload_type.from_mapping(contract_mapping_value(value, "payload", default={}) or {})
        evidence_items, _evidence_issue = contract_sequence(contract_mapping_value(value, "evidence", default=()), field_name="evidence")
        return cls(
            phase=contract_mapping_value(value, "phase", default="scheduler"),
            domain=contract_mapping_value(value, "domain", default="scheduler"),
            status=contract_mapping_value(value, "status", default="ok"),
            sequence=contract_mapping_value(value, "sequence", default=0),
            payload=payload,
            evidence=tuple(SchedulerEvidenceRecord.from_mapping(record) for record in evidence_items),
        )


@dataclass(frozen=True, slots=True)
class SchedulerPhaseOutputLedger:
    """Ordered immutable collection of typed phase outputs for replay."""

    outputs: tuple[SchedulerPhaseOutput, ...] = ()

    def __post_init__(self) -> None:
        outputs, _outputs_issue = contract_sequence(self.outputs, field_name="outputs")
        typed_outputs = [_require_scheduler_phase_output(output) for output in outputs]
        object.__setattr__(self, "outputs", tuple(sorted(typed_outputs, key=lambda item: (item.sequence, item.phase, item.domain))))

    def as_dict(self) -> dict[str, object]:
        return {"outputs": [output.as_dict() for output in self.outputs]}

    def as_replay_records(self) -> tuple[Mapping[str, object], ...]:
        return tuple(materialize_scheduler_mapping(output.as_dict()) for output in self.outputs)

    @classmethod
    def from_mapping(cls, value: object) -> "SchedulerPhaseOutputLedger":
        outputs, _outputs_issue = contract_sequence(contract_mapping_value(value, "outputs", default=()), field_name="outputs")
        return cls(outputs=tuple(SchedulerPhaseOutput.from_mapping(item) for item in outputs))


__all__ = ("SchedulerPhaseOutput", "SchedulerPhaseOutputLedger")
