from collections import deque
from dataclasses import dataclass, field
import time
from typing import Callable, Mapping, MutableMapping, MutableSet

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.queue.inmemory_lifecycle_decisions import terminal_transition_decision
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import InMemoryRetryDecision
from Virus_Scan.scheduler.queue.inmemory_lifecycle_requests import (
    LifecycleJournalRecorder,
    LifecycleRecorderMixin,
)
from Virus_Scan.scheduler.queue.inmemory_retry_recovery import (
    replace_with_history_transition,
    retry_or_fail,
)
from Virus_Scan.scheduler.queue.inmemory_cancel import (
    InMemoryCancelRequest,
    request_cancel_only,
)
from Virus_Scan.scheduler.queue.inmemory_cancel_evidence import cancel_publication_evidence_from_record
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal
from Virus_Scan.scheduler.queue.inmemory_empty_drain import (
    InMemoryEmptyDrainRecoveryDecision,
    requeue_missing_after_empty_drain,
)


def _retry_decision_delta_and_evidence(decision: object) -> tuple[int, tuple[Mapping[str, object], ...]]:
    if type(decision) is InMemoryRetryDecision:
        return decision.completed_delta, tuple(decision.evidence)
    return 0, ()


def _empty_drain_delta_evidence_and_result(decision: object) -> tuple[int, tuple[Mapping[str, object], ...], tuple[int, int]]:
    if type(decision) is InMemoryEmptyDrainRecoveryDecision:
        return decision.completed_delta, tuple(decision.evidence), (decision.retried, decision.failed_now)
    return 0, (), (0, 0)


def _cancel_stall_poison_mask(value: object) -> int:
    parsed, _reason = scheduler_int(value, default=0, reason="cancel_stall_poison_mask_rejected")
    return parsed


@dataclass
class InMemoryRecoveryCoordinator(LifecycleRecorderMixin):
    """Reconciliation-owned coordinator for in-memory retry/cancel/drain state.

    This object is constructed by the scheduler runtime and owns the reconciliation
    transitions for one scheduler run. It centralizes the previously nested retry/cancel/drain decisions and
    exposes only deterministic transition methods.
    """

    job_records: MutableMapping[int, dict[str, object]]
    active: MutableMapping[int, object]
    pending: deque[tuple[int, object, int]]
    results: MutableMapping[object, object]
    failed: MutableSet[int]
    terminal: MutableSet[int]
    lifecycle_journal: LifecycleJournalRecorder
    state_index: object
    max_job_retries: int
    cancel_table: object
    cancel_generation: object
    cancel_flags: object
    cancel_stall_poison_mask: int
    total_files: int
    worker_error_result: Callable[[object, BaseException | str], dict[str, object]]
    partial_checkpoint_cache: PartialCheckpointCache = field(default_factory=PartialCheckpointCache)
    evidence_journal: InMemoryRecoveryEvidenceJournal = field(default_factory=InMemoryRecoveryEvidenceJournal)
    completed: int = 0

    def retry_evidence_count(self) -> int:
        return self.evidence_journal.retry_count()

    def retry_evidence_since(self, cursor: object) -> tuple[Mapping[str, object], ...]:
        return self.evidence_journal.retry_since(cursor)

    def retry_evidence_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return self.evidence_journal.retry_snapshot()

    def cancel_evidence_count(self) -> int:
        return self.evidence_journal.cancel_count()

    def cancel_evidence_since(self, cursor: object) -> tuple[Mapping[str, object], ...]:
        return self.evidence_journal.cancel_since(cursor)

    def cancel_evidence_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return self.evidence_journal.cancel_snapshot()

    def empty_drain_evidence_snapshot(self) -> tuple[Mapping[str, object], ...]:
        return self.evidence_journal.empty_drain_snapshot()

    def append_empty_drain_evidence(self, records: object) -> int:
        return self.evidence_journal.append_empty_drain(records)


    def terminal_transition(self, record: dict[str, object], *, state: str, attempt: object, now: float | None) -> bool:
        return terminal_transition_decision(record, state=state, attempt=attempt, now=now).accepted

    def replace_with_history_transition(
        self,
        job_id: int,
        record: MutableMapping[str, object],
        reason: object,
        *,
        pid: object = None,
        now: float | None = None,
        action: str = 'history',
        extra: object = None,
    ) -> dict[str, object]:
        return replace_with_history_transition(
            job_records=self.job_records,
            job_id=job_id,
            record=record,
            reason=reason,
            pid=pid,
            now=now,
            action=action,
            extra=extra,
        )

    def retry_or_fail(self, job_id: int, reason: object, *, pid: object = None) -> bool:
        decision = retry_or_fail(
            job_records=self.job_records,
            active=self.active,
            pending=self.pending,
            results=self.results,
            failed=self.failed,
            terminal=self.terminal,
            job_id=job_id,
            reason=reason,
            max_job_retries=self.max_job_retries,
            cancel_table=self.cancel_table,
            cancel_generation=self.cancel_generation,
            cancel_flags=self.cancel_flags,
            worker_error_result=self.worker_error_result,
            lifecycle_recorder=self.record_lifecycle_request,
            pid=pid,
        )
        self.state_index.sync_record(job_id, self.job_records.get(job_id), due_at=None)
        completed_delta, retry_evidence = _retry_decision_delta_and_evidence(decision)
        self.completed += completed_delta
        if retry_evidence:
            self.evidence_journal.append_retry(retry_evidence)
        return decision.retried if type(decision) is InMemoryRetryDecision else False

    def request_cancel_only(self, job_id: int, reason: object, *, pid: object = None) -> bool:
        requested = request_cancel_only(
            InMemoryCancelRequest(
                job_records=self.job_records,
                terminal=self.terminal,
                job_id=job_id,
                reason=reason,
                cancel_table=self.cancel_table,
                cancel_generation=self.cancel_generation,
                cancel_flags=self.cancel_flags,
                cancel_stall_poison_mask=_cancel_stall_poison_mask(
                    self.cancel_stall_poison_mask
                ),
                pid=pid,
            )
        )
        if requested:
            self.state_index.sync_record(job_id, self.job_records.get(job_id), due_at=time.time())
            self.evidence_journal.append_cancel(
                cancel_publication_evidence_from_record(self.job_records.get(job_id))
            )
        return requested

    def requeue_missing_after_empty_drain(self) -> tuple[int, int]:
        decision = requeue_missing_after_empty_drain(
            total_files=self.total_files,
            terminal=self.terminal,
            retry_callable=lambda _jid, _reason: self.retry_or_fail(_jid, _reason),
        )
        completed_delta, empty_evidence, result = _empty_drain_delta_evidence_and_result(decision)
        self.completed += completed_delta
        self.evidence_journal.replace_empty_drain(empty_evidence, mirror_retry=True)
        return result
