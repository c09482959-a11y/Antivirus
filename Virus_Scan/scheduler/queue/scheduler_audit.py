"""Queue-owned scheduler behavior audit telemetry ownership.

This module owns immutable scheduler behavior/audit reports derived from
reconciliation and replay snapshots. It does not mutate queue state.
"""

from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items

from Virus_Scan.scheduler.queue.publication_state import QueueRunFinalizationState
from Virus_Scan.scheduler.replay.replay_validator import (
    QueueReplayComparisonSnapshot,
    normalize_scheduler_replay_results,
)


_HARDENING_REPORT_MISSING_FINALIZATION_STATE = "scheduler hardening report missing canonical finalization state"
_HARDENING_REPORT_MISSING_REPLAY_SNAPSHOT = "scheduler hardening report missing canonical replay snapshot"
_HARDENING_REPORT_REPLAY_COUNT_MISMATCH = (
    "scheduler hardening report replay count does not match finalized publication count"
)
_BEHAVIOR_RATING_OUT_OF_RANGE = "scheduler behavior rating must be between 0 and 10"
_OVERALL_FORENSIC_RATING_OUT_OF_RANGE = "overall forensic rating must be between 0 and 10"
_BEHAVIOR_AUDIT_MISSING_HARDENING_REPORT = "scheduler behavior audit missing canonical hardening report"
_BEHAVIOR_AUDIT_MISSING_QUEUE_PHASES_PREFIX = "scheduler behavior audit missing queue phases: "
_BEHAVIOR_AUDIT_MISSING_QUEUE_PHASES = "scheduler behavior audit missing queue phases"
_BEHAVIOR_AUDIT_MUST_END_AT_FINALIZE = "scheduler behavior audit must end at finalize"
_BEHAVIOR_AUDIT_REQUEUE_WITHOUT_RECOVERY = "scheduler behavior audit has requeue accounting without replay recovery count"
_BEHAVIOR_AUDIT_FAILED_COUNT_BELOW_ACCOUNTING = (
    "scheduler behavior audit failed replay count is below worker failure accounting"
)


@dataclass(frozen=True, slots=True)
class QueueBehaviorHardeningReport:
    """Immutable scheduler hardening report for finalization plus replay evidence."""

    finalization_state: QueueRunFinalizationState
    replay_snapshot: QueueReplayComparisonSnapshot
    scheduler_behavior_rating: float
    overall_forensic_rating: float

    def assert_valid(self) -> None:
        if not isinstance(self.finalization_state, QueueRunFinalizationState):
            raise TypeError(_HARDENING_REPORT_MISSING_FINALIZATION_STATE)
        if not isinstance(self.replay_snapshot, QueueReplayComparisonSnapshot):
            raise TypeError(_HARDENING_REPORT_MISSING_REPLAY_SNAPSHOT)
        self.finalization_state.assert_valid()
        if self.replay_snapshot.emitted_result_count != self.finalization_state.emitted_result_count:
            raise RuntimeError(_HARDENING_REPORT_REPLAY_COUNT_MISMATCH)
        if self.scheduler_behavior_rating < 0 or self.scheduler_behavior_rating > 10:
            exception_message = _BEHAVIOR_RATING_OUT_OF_RANGE
            raise RuntimeError(exception_message)
        if self.overall_forensic_rating < 0 or self.overall_forensic_rating > 10:
            exception_message = _OVERALL_FORENSIC_RATING_OUT_OF_RANGE
            raise RuntimeError(exception_message)

    def as_dict(self) -> dict[str, object]:
        self.assert_valid()
        return {
            "finalization_state": self.finalization_state.as_dict(),
            "replay_snapshot": self.replay_snapshot.as_dict(),
            "scheduler_behavior_rating": self.scheduler_behavior_rating,
            "overall_forensic_rating": self.overall_forensic_rating,
        }


def _build_scheduler_behavior_hardening_report(
    finalization_state: object,
    replay_results: object,
    *,
    scheduler_behavior_rating: object,
    overall_forensic_rating: object,
) -> object:
    """Build the canonical immutable scheduler behavior report after validation."""
    replay_snapshot = normalize_scheduler_replay_results(replay_results)
    report = QueueBehaviorHardeningReport(
        finalization_state=finalization_state,
        replay_snapshot=replay_snapshot,
        scheduler_behavior_rating=float(scheduler_behavior_rating),
        overall_forensic_rating=float(overall_forensic_rating),
    )
    report.assert_valid()
    return report


_QUEUE_MAJOR_BEHAVIOR_PHASES = ("planning", "enqueue", "dispatch", "claim", "collect", "recover", "publish", "finalize")


@dataclass(frozen=True, slots=True)
class QueueSchedulerBehaviorAudit:
    """Immutable final scheduler behavior audit tying phase coverage, replay, and failure accounting."""

    hardening_report: QueueBehaviorHardeningReport
    required_phases: tuple[str, ...] = _QUEUE_MAJOR_BEHAVIOR_PHASES

    def assert_valid(self) -> None:
        if not isinstance(self.hardening_report, QueueBehaviorHardeningReport):
            raise TypeError(_BEHAVIOR_AUDIT_MISSING_HARDENING_REPORT)
        self.hardening_report.assert_valid()
        phases = tuple(
            str.__str__(snapshot.phase)
            if type(snapshot.phase) is str and snapshot.phase
            else "unknown"
            for snapshot in self.hardening_report.finalization_state.phase_ledger.snapshots
        )
        required = tuple(
            str.__str__(phase) if type(phase) is str and phase else "unknown"
            for phase in no_hook_sequence_items(self.required_phases)
        )
        missing = tuple(phase for phase in required if phase not in phases)
        if missing:
            safe_missing = tuple(str.__str__(item) for item in missing if type(item) is str and item)
            if safe_missing:
                exception_message = _BEHAVIOR_AUDIT_MISSING_QUEUE_PHASES_PREFIX + str.join(", ", safe_missing)
                raise RuntimeError(exception_message)
            exception_message = _BEHAVIOR_AUDIT_MISSING_QUEUE_PHASES
            raise RuntimeError(exception_message)
        if phases[-1] != "finalize":
            exception_message = _BEHAVIOR_AUDIT_MUST_END_AT_FINALIZE
            raise RuntimeError(exception_message)
        worker_failure_actions = tuple(record.final_scheduler_action for record in self.hardening_report.finalization_state.worker_failures)
        if any(action == "requeue" for action in worker_failure_actions) and self.hardening_report.replay_snapshot.recovery_count <= 0:
            exception_message = _BEHAVIOR_AUDIT_REQUEUE_WITHOUT_RECOVERY
            raise RuntimeError(exception_message)
        failed_actions = sum(1 for action in worker_failure_actions if action in {"fail", "quarantine"})
        if failed_actions and self.hardening_report.replay_snapshot.failed_count < failed_actions:
            exception_message = _BEHAVIOR_AUDIT_FAILED_COUNT_BELOW_ACCOUNTING
            raise RuntimeError(exception_message)

    def as_dict(self) -> dict[str, object]:
        self.assert_valid()
        return {
            "hardening_report": self.hardening_report.as_dict(),
            "required_phases": list(self.required_phases),
        }


def _build_scheduler_behavior_audit(
    finalization_state: object,
    replay_results: object,
    *,
    scheduler_behavior_rating: object,
    overall_forensic_rating: object,
) -> object:
    """Build the strict final scheduler behavior audit after complete phase/replay validation."""
    report = _build_scheduler_behavior_hardening_report(
        finalization_state,
        replay_results,
        scheduler_behavior_rating=scheduler_behavior_rating,
        overall_forensic_rating=overall_forensic_rating,
    )
    audit = QueueSchedulerBehaviorAudit(report)
    audit.assert_valid()
    return audit

