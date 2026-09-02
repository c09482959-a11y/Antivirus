from __future__ import annotations

from Virus_Scan.scheduler.workers.process_snapshots import (
    ProcessQueueWorkerSnapshot,
    snapshot_active_process_queue_workers,
)
from Virus_Scan.scheduler.workers.process_snapshots_evidence import (
    process_suppressed_failure_report_decision,
    process_suppressed_failures_decision,
    process_worker_entries_decision,
)


def test_stage2156_missing_worker_entries_are_replayable_decision() -> None:
    decision = process_worker_entries_decision(None)

    assert decision.entries == ()
    assert decision.reason == "process_worker_entries_missing"
    assert decision.accepted is False
    assert decision.missing is True
    assert ProcessQueueWorkerSnapshot(0, None).active_processes == ()


def test_stage2156_missing_suppressed_failures_are_replayable_decision() -> None:
    decision = process_suppressed_failures_decision(None)

    assert decision.entries == ()
    assert decision.reason == "process_worker_snapshot_suppressed_failures_missing"
    assert decision.accepted is False
    assert decision.missing is True
    assert ProcessQueueWorkerSnapshot(0, (), None).suppressed_failures == ()


def test_stage2156_successful_suppressed_report_is_replayable_decision() -> None:
    calls: list[tuple[str, str]] = []

    def reporter(label: str, exc: BaseException) -> None:
        calls.append((label, type(exc).__name__))

    decision = process_suppressed_failure_report_decision(
        reporter,
        "monitor_loop_suppressed",
        RuntimeError("poll failed"),
        (RuntimeError,),
    )

    assert decision.issue == ""
    assert decision.reason == "monitor_loop_suppressed_report_recorded"
    assert decision.reported is True
    assert decision.accepted is True
    assert calls == [("monitor_loop_suppressed", "RuntimeError")]


def test_stage2156_snapshot_records_reporter_rejection_without_hook() -> None:
    class DoneProcess:
        def poll(self) -> int:
            return 0

    snapshot = snapshot_active_process_queue_workers(
        ((0, DoneProcess(), "out", ("cmd",)),),
        recoverable_exceptions=(RuntimeError,),
        report_suppressed=object(),
    )

    assert snapshot.live_count == 0
    assert snapshot.active_processes == ()
    assert snapshot.suppressed_failures == ()
