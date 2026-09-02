"""Canonical immutable queue recovery and worker-failure contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.queue.exact_bool_support import exact_bool


_WORKER_ACCOUNTING_REQUEUE_INCONSISTENT = "scheduler worker failure accounting must choose requeue or fail exactly once; requeue action is inconsistent"
_WORKER_ACCOUNTING_FAIL_INCONSISTENT = "scheduler worker failure accounting must choose requeue or fail exactly once; fail action is inconsistent"
_WORKER_ACCOUNTING_QUARANTINE_INCONSISTENT = "scheduler worker failure accounting quarantine action is inconsistent"
_WORKER_ACCOUNTING_FINALIZE_INCONSISTENT = "scheduler worker failure accounting finalize action is inconsistent"


def _raise_worker_accounting_requeue_inconsistent() -> NoReturn:
    raise RuntimeError(_WORKER_ACCOUNTING_REQUEUE_INCONSISTENT)


def _raise_worker_accounting_fail_inconsistent() -> NoReturn:
    raise RuntimeError(_WORKER_ACCOUNTING_FAIL_INCONSISTENT)


def _raise_worker_accounting_quarantine_inconsistent() -> NoReturn:
    raise RuntimeError(_WORKER_ACCOUNTING_QUARANTINE_INCONSISTENT)


def _raise_worker_accounting_finalize_inconsistent() -> NoReturn:
    raise RuntimeError(_WORKER_ACCOUNTING_FINALIZE_INCONSISTENT)


_RECOVERY_ACTIONS = frozenset(("requeue", "fail", "quarantine", "finalize"))


def _exact_required_text(value: object, *, missing_message: str) -> str:
    if type(value) is str:
        text = str.__str__(value)
        if text.strip():
            return text
    raise RuntimeError(missing_message)


def _exact_recovery_action(value: object, *, message_prefix: str) -> str:
    if type(value) is str:
        text = str.__str__(value)
        if text in _RECOVERY_ACTIONS:
            return text
        raise RuntimeError(message_prefix + text)
    raise RuntimeError(message_prefix + no_hook_type_name(value))


def _exact_non_negative_int(value: object, *, missing_message: str) -> int:
    if type(value) is int and type(value) is not bool and value >= 0:
        return value
    raise RuntimeError(missing_message)


@dataclass(frozen=True)
class QueueRecoveryDecision:
    """Immutable scheduler recovery decision for one failed worker/job boundary."""

    job_id: str
    worker_id: str
    file_path: str
    failure_reason: str
    final_action: str
    reason_text: str
    attempt_count: int
    source_event: str

    def assert_valid(self) -> None:
        _exact_required_text(self.job_id, missing_message="scheduler recovery decision missing job id")
        _exact_required_text(self.worker_id, missing_message="scheduler recovery decision missing worker id")
        _exact_required_text(self.file_path, missing_message="scheduler recovery decision missing file path")
        _exact_required_text(self.failure_reason, missing_message="scheduler recovery decision missing failure reason")
        _exact_recovery_action(self.final_action, message_prefix="invalid scheduler recovery action: ")
        _exact_required_text(self.reason_text, missing_message="scheduler recovery decision missing reason text")
        _exact_non_negative_int(self.attempt_count, missing_message="scheduler recovery decision has negative attempt count")
        _exact_required_text(self.source_event, missing_message="scheduler recovery decision missing source event")

    def as_dict(self) -> dict[str, object]:
        self.assert_valid()
        return {
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "file_path": self.file_path,
            "failure_reason": self.failure_reason,
            "final_action": self.final_action,
            "reason_text": self.reason_text,
            "attempt_count": self.attempt_count,
            "source_event": self.source_event,
        }


@dataclass(frozen=True)
class QueueWorkerFailureAccounting:
    """Immutable timeout/kill accounting record for one scheduler worker failure."""

    worker_id: str
    job_id: str
    file_path: str
    failure_reason: str
    requeued: bool
    failed: bool
    attempt_count: int
    final_scheduler_action: str

    def assert_valid(self) -> None:
        _exact_required_text(self.worker_id, missing_message="scheduler worker failure accounting missing worker id")
        _exact_required_text(self.job_id, missing_message="scheduler worker failure accounting missing job id")
        _exact_required_text(self.file_path, missing_message="scheduler worker failure accounting missing file path")
        _exact_required_text(self.failure_reason, missing_message="scheduler worker failure accounting missing failure reason")
        action = _exact_recovery_action(self.final_scheduler_action, message_prefix="invalid scheduler worker failure action: ")
        _exact_non_negative_int(self.attempt_count, missing_message="scheduler worker failure accounting has negative attempt count")
        requeued = exact_bool(self.requeued)
        failed = exact_bool(self.failed)
        if action == "requeue" and (not requeued or failed):
            _raise_worker_accounting_requeue_inconsistent()
        if action == "fail" and (requeued or not failed):
            _raise_worker_accounting_fail_inconsistent()
        if action == "quarantine" and (requeued or not failed):
            _raise_worker_accounting_quarantine_inconsistent()
        if action == "finalize" and (requeued or failed):
            _raise_worker_accounting_finalize_inconsistent()

    def as_dict(self) -> dict[str, object]:
        return {
            "worker_id": self.worker_id,
            "job_id": self.job_id,
            "file_path": self.file_path,
            "failure_reason": self.failure_reason,
            "requeued": self.requeued,
            "failed": self.failed,
            "attempt_count": self.attempt_count,
            "final_scheduler_action": self.final_scheduler_action,
        }
