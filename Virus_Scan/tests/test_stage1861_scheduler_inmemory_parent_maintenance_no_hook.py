"""Stage1861 in-memory parent maintenance no-hook regressions."""
from pathlib import Path

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import (
    _empty_drain_completed_count,
    _recovery_completed_count,
)
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import (
    InMemoryRecoveryEvidenceJournal,
)


class HostileRecoveryEvidence:
    touched = False

    @property
    def retry_recovery_evidence(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("retry evidence property hook executed")

    @property
    def cancel_only_evidence(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("cancel evidence property hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("recovery bool hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("recovery repr hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("recovery format hook executed")


class OwnedRecoveryEvidence:
    def __init__(self):
        self.completed = "4"


class HostileCompleted:
    touched = False

    def __int__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("completed int hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("completed bool hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("completed str hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("completed repr hook executed")

    def __format__(self, format_spec):  # pragma: no cover - must not execute
        type(self).touched = True
        raise AssertionError("completed format hook executed")


def test_initial_evidence_counts_are_owned_by_recovery_journal():
    journal = InMemoryRecoveryEvidenceJournal()
    journal.append_retry(({"stage": "retry"}, {"stage": "retry2"}))
    journal.append_cancel(({"stage": "cancel"},))

    assert journal.retry_count() == 2
    assert journal.cancel_count() == 1


def test_empty_drain_completed_count_rejects_unknown_values_without_hooks():
    HostileCompleted.touched = False

    assert _empty_drain_completed_count(HostileCompleted()) == 0
    assert HostileCompleted.touched is False


def test_recovery_completed_count_uses_no_hook_plain_state():
    recovery = OwnedRecoveryEvidence()

    assert _recovery_completed_count(recovery) == (4, True)


def test_recovery_completed_count_rejects_hostile_property_without_hooks():
    HostileRecoveryEvidence.touched = False
    recovery = HostileRecoveryEvidence()

    assert _recovery_completed_count(recovery) == (0, True)
    assert HostileRecoveryEvidence.touched is False


def test_stage1861_parent_maintenance_uses_canonical_recovery_journal_api():
    source = read_python_file(Path("Virus_Scan/scheduler/orchestration/inmemory_parent_maintenance.py"))

    assert 'getattr(request.recovery, "retry_recovery_evidence"' not in source
    assert 'getattr(request.recovery, "cancel_only_evidence"' not in source
    assert "request.recovery.retry_evidence_count()" in source
    assert "request.recovery.cancel_evidence_count()" in source
    assert 'log_error(f"in-memory worker-death retry sweep failed:' not in source
    assert 'log_error(f"in-memory worker memory-toxicity sweep failed:' not in source
    assert "safe_inmemory_accounting_count(completed, fallback=0" not in source
    assert "safe_inmemory_accounting_count(value, fallback=0" not in source
