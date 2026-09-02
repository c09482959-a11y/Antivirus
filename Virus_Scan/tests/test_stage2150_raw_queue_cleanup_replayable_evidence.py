from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_cleanup import cleanup_diagnostic_tmp_files
from Virus_Scan.scheduler.queue.raw_queue_cleanup_evidence import (
    raw_queue_cleanup_name_decision,
    raw_queue_cleanup_path_decision,
    raw_queue_diagnostic_cleanup_decision,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileCleanupPath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - invoking this is the defect
        type(self).touched += 1
        raise AssertionError("fspath hook invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str hook invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook invoked")


class HostileCleanupName:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str hook invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook invoked")


def test_stage2150_cleanup_path_rejection_is_replayable_without_hooks() -> None:
    HostileCleanupPath.touched = 0

    decision = raw_queue_cleanup_path_decision(HostileCleanupPath())

    assert decision.path is None
    assert decision.accepted is False
    assert decision.reason == "unsafe_cleanup_path_rejected"
    assert ("decision", "raw_queue_cleanup_path") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileCleanupPath.touched == 0


def test_stage2150_cleanup_name_rejection_is_replayable_without_hooks() -> None:
    HostileCleanupName.touched = 0

    decision = raw_queue_cleanup_name_decision(HostileCleanupName(), field_name="queue_diagnostic_tmp_name")

    assert decision.text == ""
    assert decision.accepted is False
    assert decision.reason == "unsafe_queue_diagnostic_tmp_name_rejected"
    assert ("decision", "raw_queue_cleanup_name") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileCleanupName.touched == 0


def test_stage2150_diagnostic_cleanup_rejected_directory_returns_typed_decision() -> None:
    reports = []

    decision = cleanup_diagnostic_tmp_files(
        Path("queue"),
        failure_diagnostics_dir=lambda _queue_dir: HostileCleanupPath(),
        safe_listdir=lambda _path: [],
        safe_unlink=lambda *_args, **_kwargs: True,
        report=lambda *args, **kwargs: reports.append((args, kwargs)),
    )

    assert decision == raw_queue_diagnostic_cleanup_decision(
        0,
        completed=False,
        reason="queue_diagnostic_directory_rejected",
    )
    assert reports[0][0][0] == "queue_diagnostic_tmp_cleanup_failed"
    assert HostileCleanupPath.touched == 0


def test_stage2150_raw_queue_cleanup_hidden_default_returns_removed_from_owner() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_cleanup.py"))

    assert "return None" not in source
    assert "return \"\"" not in source
    assert "return" + "\n" not in source
    assert "raw_queue_cleanup_path_decision(value).path" in source
    assert "raw_queue_cleanup_name_decision(value, field_name=field_name).text" in source
    assert "raw_queue_diagnostic_cleanup_decision(" in source
