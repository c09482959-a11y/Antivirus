from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.snapshot_behavior import QueueBehaviorSnapshot
from Virus_Scan.scheduler.queue.snapshots import QueuePhaseLedger


class _Stage1929HostileValue:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __bool__ executed")

    def __str__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __format__ executed")

    def __int__(self):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ executed")

    def __lt__(self, other):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __lt__ executed")

    def __add__(self, other):  # pragma: no cover - must not run
        type(self).touched += 1
        raise AssertionError("caller-owned __add__ executed")


def _snapshot(phase, *, completed: int = 0, failed: int = 0, total: int | None = 1) -> QueueBehaviorSnapshot:
    return QueueBehaviorSnapshot(
        phase=phase,
        pending=0,
        claimed=0,
        running=0,
        completed=completed,
        failed=failed,
        quarantined=0,
        duplicate_count=0,
        invalid_record_count=0,
        orphan_lock_count=0,
        emitted_result_count=0,
        finalized_count=0,
        total=total,
    )


def test_stage1929_queue_snapshot_error_messages_reject_hostile_phase_without_hooks() -> None:
    hostile = _Stage1929HostileValue()
    _Stage1929HostileValue.touched = 0

    before = _snapshot("collect", completed=5, failed=0, total=10)
    after = _snapshot(hostile, completed=4, failed=0, total=10)

    with pytest.raises(RuntimeError, match="files_done decreased during unknown"):
        after.assert_valid(before)
    assert _Stage1929HostileValue.touched == 0


def test_stage1929_queue_snapshot_finalize_mismatch_uses_owned_int_text() -> None:
    hostile = _Stage1929HostileValue()
    _Stage1929HostileValue.touched = 0
    snapshot = QueueBehaviorSnapshot(
        phase="finalize",
        pending=hostile,
        claimed=hostile,
        running=hostile,
        completed=0,
        failed=0,
        quarantined=0,
        duplicate_count=0,
        invalid_record_count=0,
        orphan_lock_count=0,
        emitted_result_count=1,
        finalized_count=2,
        total=2,
    )

    with pytest.raises(RuntimeError, match="finalization mismatch during finalize"):
        snapshot.assert_valid(None)
    assert _Stage1929HostileValue.touched == 0


def test_stage1929_phase_ledger_missing_phase_message_rejects_hostile_required_phase() -> None:
    hostile = _Stage1929HostileValue()
    _Stage1929HostileValue.touched = 0
    ledger = QueuePhaseLedger((_snapshot("planning"),))

    with pytest.raises(RuntimeError, match="phase ledger missing phases"):
        ledger.assert_contains(("planning", "finalize", hostile))
    assert _Stage1929HostileValue.touched == 0


def test_stage1929_scheduler_snapshot_sources_remove_old_hook_routes() -> None:
    snapshot_source = read_python_file(Path("Virus_Scan/scheduler/queue/snapshot_behavior.py"))
    audit_source = read_python_file(Path("Virus_Scan/scheduler/queue/scheduler_audit.py"))
    ledger_source = read_python_file(Path("Virus_Scan/scheduler/queue/snapshots.py"))
    state_source = read_python_file(Path("Virus_Scan/scheduler/queue/state_io.py"))

    assert 'reason=f"queue_snapshot_{field_name}_rejected"' not in snapshot_source
    assert 'fallback="unknown"' not in snapshot_source
    assert "for field_name, keys in aliases.items():" not in snapshot_source
    assert "during {self.phase}" not in snapshot_source
    assert "scheduler behavior audit missing queue phases: {', '.join(missing)}" not in audit_source
    assert "scheduler queue phase ledger missing phases: {', '.join(missing)}" not in ledger_source
    assert "str(key): _freeze_queue_json_value(item)" not in state_source
    assert 'context=f"queue_state_read:{queue_path.name}"' not in state_source
    assert 'raise ValueError(f"queue JSON payload must be an object: {queue_path}")' not in state_source
