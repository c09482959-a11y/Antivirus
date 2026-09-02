"""Stage 2189: scheduler durable JSON cleanup decisions."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from Virus_Scan.scheduler.evidence.scheduler_json_writer import raw_unlink_quiet
from Virus_Scan.scheduler.queue import raw_accumulator_store as raw_store


class HostileCleanupPath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - touching proves unsafe path coercion
        type(self).touched += 1
        raise AssertionError("cleanup path __fspath__ must not be invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup path __str__ must not be invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("cleanup path __repr__ must not be invoked")


def test_stage2189_raw_unlink_quiet_rejects_bad_path_with_typed_decision() -> None:
    HostileCleanupPath.touched = 0
    events: list[tuple[str, BaseException]] = []
    deps = replace(
        raw_store.raw_json_dependencies(),
        record_suppressed=lambda where, exc: events.append((where, exc)),
    )

    decision = raw_unlink_quiet(
        HostileCleanupPath(),
        log_context="stage2189_cleanup",
        deps=deps,
    )

    assert decision is False
    assert HostileCleanupPath.touched == 0
    assert events
    assert events[0][0] == "raw_json_cleanup_path_rejected"
    assert isinstance(events[0][1], ValueError)
    assert str(events[0][1]) == "scheduler_path_rejected"


def test_stage2189_raw_unlink_quiet_reports_successful_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "cleanup.json"
    target.write_text("{}", encoding="utf-8")

    decision = raw_unlink_quiet(
        target,
        log_context="stage2189_cleanup",
        deps=raw_store.raw_json_dependencies(),
    )

    assert decision is True
    assert not target.exists()


def test_stage2189_scheduler_json_durable_uses_canonical_runtime_owners() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "scheduler/evidence/scheduler_json_durable.py"
    ).read_text(encoding="utf-8")

    assert "typing import Any" not in source
    assert "_queue_safe_unlink" not in source
    assert "_queue_atomic_replace" not in source
    assert "queue_safe_unlink as" not in source
    assert "queue_atomic_replace as" not in source
