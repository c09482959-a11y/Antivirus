from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.child_failure_metadata import (
    build_safe_exception_info,
    safe_exception_info,
    worker_error_result,
)


class Stage2139HostileKey:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __hash__(self) -> int:
        return hash("attempt")

    def __eq__(self, other: object) -> bool:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile key equality executed")

    def __str__(self) -> str:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile key string executed")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile key repr executed")


class Stage2139HostileText:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile text executed")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile repr executed")

    def __format__(self, spec: str) -> str:
        type(self).touched += 1
        raise AssertionError("stage2139 hostile format executed")


class Stage2139HostileMapping:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def items(self):
        type(self).touched += 1
        raise AssertionError("stage2139 hostile items executed")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("stage2139 hostile iter executed")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("stage2139 hostile bool executed")


def _reset() -> None:
    Stage2139HostileKey.reset()
    Stage2139HostileText.reset()
    Stage2139HostileMapping.reset()


def test_stage2139_child_failure_metadata_source_uses_typed_decisions() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler" / "workers" / "child_failure_metadata.py").read_text(encoding="utf-8")
    support = (root / "scheduler" / "workers" / "child_failure_metadata_types.py").read_text(encoding="utf-8")

    assert "Any" not in source
    assert "return None" not in source
    assert "ChildAttemptDecision" in support
    assert "ChildResultSnapshotDecision" in support
    assert "child_failure_job_attempt_missing" in support
    assert "non_materializable_worker_error_result" in source


def test_stage2139_safe_exception_info_rejects_hostile_job_keys_without_hooks() -> None:
    _reset()
    hostile_key = Stage2139HostileKey()
    info = safe_exception_info(
        RuntimeError(Stage2139HostileText()),
        stage="stage2139",
        job={hostile_key: 5},
        exception_info_builder=build_safe_exception_info,
        report=lambda _label, _exc: None,
        recoverable_exceptions=(Exception,),
    )

    assert Stage2139HostileKey.touched == 0
    assert Stage2139HostileText.touched == 0
    assert info["attempt"] == 0
    assert info["attempt_unavailable_reason"] == "child_failure_job_attempt_missing"
    assert info["error"] == "RuntimeError"


def test_stage2139_worker_error_result_rejects_hostile_result_mapping_without_hooks() -> None:
    _reset()

    def make_error_result(_path: object, _exc: BaseException) -> object:
        return Stage2139HostileMapping()

    snapshot, failure_info = worker_error_result(
        Stage2139HostileText(),
        RuntimeError(Stage2139HostileText()),
        stage="stage2139",
        job=Stage2139HostileMapping(),
        make_error_result=make_error_result,
        exception_info_builder=build_safe_exception_info,
        report=lambda _label, _exc: None,
        recoverable_exceptions=(Exception,),
    )

    assert Stage2139HostileText.touched == 0
    assert Stage2139HostileMapping.touched == 0
    assert failure_info["attempt_unavailable_reason"] == "child_failure_job_attempt_mapping_unavailable"
    assert failure_info["worker_error_result_unavailable_reason"] == "non_materializable_worker_error_result"
    assert snapshot["file"] == ""
    assert snapshot["queue_failure"] is True
    assert snapshot["scan_integrity"]["failure_info"] is failure_info
