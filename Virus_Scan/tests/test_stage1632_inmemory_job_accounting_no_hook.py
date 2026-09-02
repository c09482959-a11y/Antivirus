from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from Virus_Scan.scheduler.orchestration.inmemory_parent_iteration import reconcile_or_wait_for_empty_drain
from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import empty_drain_reconciliation_decision, should_reconcile_empty_drain
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex
from Virus_Scan.scheduler.queue.inmemory_recovery_evidence_journal import InMemoryRecoveryEvidenceJournal


class HostileRecord:
    touched = 0

    def get(self, _name, _default=None):
        HostileRecord.touched += 1
        raise RuntimeError("record get hook must not run")

    def items(self):
        HostileRecord.touched += 1
        raise RuntimeError("record items hook must not run")

    @property
    def state(self):
        HostileRecord.touched += 1
        raise RuntimeError("state property must not run")


class HostileNumber:
    touched = 0

    def __int__(self):
        HostileNumber.touched += 1
        raise RuntimeError("int hook must not run")

    def __float__(self):
        HostileNumber.touched += 1
        raise RuntimeError("float hook must not run")

    def __bool__(self):
        HostileNumber.touched += 1
        raise RuntimeError("bool hook must not run")


class HostileContainer:
    touched = 0

    def __len__(self):
        HostileContainer.touched += 1
        raise RuntimeError("len hook must not run")

    def __bool__(self):
        HostileContainer.touched += 1
        raise RuntimeError("bool hook must not run")

    def __iter__(self):
        HostileContainer.touched += 1
        raise RuntimeError("iter hook must not run")


@dataclass
class PlainRecovery:
    completed: int = 0


def test_scheduler_state_index_rejects_hostile_identity_without_numeric_hooks():
    HostileNumber.touched = 0
    index = InMemorySchedulerStateIndex()

    with pytest.raises(ValueError, match="inmemory_state_index_job_id_rejected"):
        index.sync_record(HostileNumber(), {"state": "queued"}, due_at=1.0)

    assert HostileNumber.touched == 0
    assert index.queued_or_active_count() == 0


def test_scheduler_state_index_rejects_hostile_record_entries_without_mapping_hooks():
    HostileRecord.touched = 0
    index = InMemorySchedulerStateIndex()

    index.sync_record(1, HostileRecord(), due_at=None)

    assert HostileRecord.touched == 0
    assert index.queued_or_active_count() == 0
    assert index.active_heavy_weight() == 0


def test_scheduler_state_index_counts_exact_records_and_exact_numeric_weight():
    index = InMemorySchedulerStateIndex()
    records = {
        1: {"state": "running", "file": "a", "cost": {"heavy": True, "weight": 3}},
        2: {"state": "assigned", "file": "b", "cost": {"heavy": 1, "weight": "2"}},
        3: {"state": "queued", "file": "c"},
        4: {"state": "done", "file": "d"},
        5: {"state": "running", "file": None, "cost": {"heavy": True, "weight": 9}},
    }
    for job_id, record in records.items():
        index.sync_record(job_id, record, due_at=1.0)

    assert index.logical_inflight_count() == 3
    assert index.queued_unstarted_count() == 1
    assert index.queued_or_active_count() == 4
    assert index.active_heavy_weight() == 14


def test_should_reconcile_empty_drain_rejects_hostile_containers_and_recovery_without_hooks():
    HostileContainer.touched = 0
    HostileNumber.touched = 0
    index = InMemorySchedulerStateIndex()

    assert should_reconcile_empty_drain(
        pending=HostileContainer(),
        active=HostileContainer(),
        state_index=index,
        recovery=HostileContainer(),
        submitted=HostileNumber(),
        total_files=HostileNumber(),
    ) is False

    assert HostileContainer.touched == 0
    assert HostileNumber.touched == 0


def test_should_reconcile_empty_drain_uses_transition_owned_state_index_only():
    index = InMemorySchedulerStateIndex()
    assert should_reconcile_empty_drain(
        pending={},
        active={},
        state_index=index,
        recovery=PlainRecovery(completed=1),
        submitted=2,
        total_files=2,
    ) is True

    index.sync_record(1, {"state": "running"}, due_at=1.0)
    assert should_reconcile_empty_drain(
        pending={},
        active={},
        state_index=index,
        recovery=PlainRecovery(completed=1),
        submitted=2,
        total_files=2,
    ) is False


def test_stage2191_empty_drain_unsupported_state_is_replayable_without_container_hooks():
    HostileContainer.touched = 0
    decision = empty_drain_reconciliation_decision(
        pending=HostileContainer(),
        active={},
        state_index=InMemorySchedulerStateIndex(),
        recovery=PlainRecovery(completed=0),
        submitted=1,
        total_files=1,
    )

    assert decision.should_reconcile is False
    assert decision.replayable is True
    assert decision.unsupported_fields == ("pending",)
    assert tuple(decision.evidence)[0]["stage"] == "inmemory_empty_drain_reconciliation_gate"
    assert tuple(decision.evidence)[0]["unsupported_fields"] == ("pending",)
    assert tuple(decision.evidence)[0]["final_json_must_record"] is True
    assert HostileContainer.touched == 0


def test_stage2191_empty_drain_reconciliation_evidence_reaches_recovery_projection():
    journal = InMemoryRecoveryEvidenceJournal()
    recovery = SimpleNamespace(
        completed=0,
        append_empty_drain_evidence=lambda records: journal.append_empty_drain(records),
    )
    setup = SimpleNamespace(
        pending=HostileContainer(),
        active={},
        state_index=InMemorySchedulerStateIndex(),
        recovery=recovery,
    )

    assert reconcile_or_wait_for_empty_drain(setup, submitted=1, total_files=1) == (False, False)
    assert journal.empty_drain_snapshot()
    assert journal.retry_snapshot()
    assert journal.empty_drain_snapshot()[0]["reason"] == "unsupported_empty_drain_state"
