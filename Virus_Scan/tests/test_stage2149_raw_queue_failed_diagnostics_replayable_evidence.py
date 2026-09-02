from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics import repair_failed_queue_job_diagnostics
from Virus_Scan.scheduler.queue.raw_queue_failed_diagnostics_evidence import (
    failed_queue_mapping_decision,
    failed_queue_name_decision,
    failed_queue_repair_count_decision,
)
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileFailedQueueName:
    touched = 0

    def __bool__(self):  # pragma: no cover - invoking this is the defect
        type(self).touched += 1
        raise AssertionError("bool hook invoked")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("str hook invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter hook invoked")


class HostileFailedQueueMapping:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("bool hook invoked")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("iter hook invoked")

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("items hook invoked")


class DictSubclass(dict):
    pass


def _job_dirs(root: Path) -> tuple[Path, Path, Path, Path]:
    paths = tuple(root / name for name in ("pending", "active", "done", "failed"))
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    return paths  # type: ignore[return-value]


def test_stage2149_failed_queue_name_rejection_is_replayable_without_hooks() -> None:
    HostileFailedQueueName.touched = 0

    decision = failed_queue_name_decision(HostileFailedQueueName())

    assert decision.text == ""
    assert decision.accepted is False
    assert decision.reason == "unsafe_failed_queue_name_rejected"
    assert ("decision", "failed_queue_name") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileFailedQueueName.touched == 0


def test_stage2149_failed_queue_mapping_rejection_is_replayable_without_hooks() -> None:
    HostileFailedQueueMapping.touched = 0

    decision = failed_queue_mapping_decision(HostileFailedQueueMapping())

    assert decision.mapping == {}
    assert decision.accepted is False
    assert ("decision", "failed_queue_mapping") in decision.evidence
    assert ("accepted", False) in decision.evidence
    assert HostileFailedQueueMapping.touched == 0


def test_stage2149_failed_queue_mapping_records_filtered_keys() -> None:
    decision = failed_queue_mapping_decision(DictSubclass({"ok": 1, 3: "bad"}))

    assert decision.mapping == {"ok": 1}
    assert decision.accepted is True
    assert decision.reason == "non_text_failed_queue_mapping_keys_rejected"
    assert ("accepted_keys", 1) in decision.evidence
    assert ("rejected_keys", 1) in decision.evidence


def test_stage2149_missing_failed_directory_returns_recorded_zero_count(tmp_path: Path) -> None:
    pending = tmp_path / "pending"
    active = tmp_path / "active"
    done = tmp_path / "done"
    failed = tmp_path / "failed"
    for path in (pending, active, done):
        path.mkdir(parents=True, exist_ok=True)

    repaired = repair_failed_queue_job_diagnostics(
        tmp_path,
        queue_job_dirs=lambda _root: (pending, active, done, failed),
        safe_queue_listdir=lambda _path: [],
        is_job_json_name=lambda _name: True,
        read_json_file=lambda _path, default=None: {},
        default_failure_info=lambda **kwargs: kwargs,
        make_json_safe=lambda value: value,
        queue_safe_unlink=lambda *_args, **_kwargs: True,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        log_error=lambda _message: None,
    )
    decision = failed_queue_repair_count_decision(repaired, reason="failed_queue_directory_missing")

    assert repaired == 0
    assert decision.count == 0
    assert decision.reason == "failed_queue_directory_missing"
    assert ("decision", "failed_queue_repair_count") in decision.evidence


def test_stage2149_failed_diagnostics_hidden_default_returns_removed_from_owner() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/queue/raw_queue_failed_diagnostics.py"))

    assert "return \"\"" not in source
    assert "return {}" not in source
    assert "return 0" not in source
    assert "failed_queue_name_decision(value).text" in source
    assert "failed_queue_mapping_decision(value).mapping" in source
    assert "failed_queue_repair_count_decision(" in source
