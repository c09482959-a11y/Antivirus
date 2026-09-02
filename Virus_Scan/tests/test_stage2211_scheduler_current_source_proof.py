from __future__ import annotations

from pathlib import Path

_TARGET_FILES = (
    Path("Virus_Scan/scheduler/context/inmemory_raw_dependency_factory.py"),
    Path("Virus_Scan/scheduler/orchestration/process_queue_completion_evidence.py"),
    Path("Virus_Scan/scheduler/queue/raw_accumulator_value_support.py"),
    Path("Virus_Scan/scheduler/queue/raw_queue_quarantine.py"),
    Path("Virus_Scan/scheduler/workers/inmemory_raw_finalization.py"),
    Path("Virus_Scan/scheduler/workers/lifecycle_boundary.py"),
)


def test_stage2211_scheduler_current_source_removes_dynamic_any_surfaces() -> None:
    for path in _TARGET_FILES:
        source = path.read_text(encoding="utf-8")
        assert "from typing import Any" not in source
        assert "typing.Any" not in source
        assert " Any" not in source
        assert ": Any" not in source
        assert "[Any" not in source
        assert ", Any" not in source
        assert "Any]" not in source
        assert len(source.splitlines()) <= 200


def test_stage2211_scheduler_current_source_keeps_boundary_entrypoints() -> None:
    dependency_factory = _TARGET_FILES[0].read_text(encoding="utf-8")
    completion_evidence = _TARGET_FILES[1].read_text(encoding="utf-8")
    raw_accumulator = _TARGET_FILES[2].read_text(encoding="utf-8")
    quarantine = _TARGET_FILES[3].read_text(encoding="utf-8")
    raw_finalization = _TARGET_FILES[4].read_text(encoding="utf-8")
    lifecycle = _TARGET_FILES[5].read_text(encoding="utf-8")

    assert "def execute_inmemory_raw_stage_job(job: dict[str, object]) -> dict[str, object]" in dependency_factory
    assert "def collect_nonclean_worker_exit_evidence(worker_exit_evidence: tuple[Mapping[str, object], ...])" in completion_evidence
    assert "def raw_accumulator_failure_record(value: object, *, reason: str) -> dict[str, object]" in raw_accumulator
    assert "def quarantine_sidecar_payload(" in quarantine
    assert "def finalize_inmemory_raw_scan_result(" in raw_finalization
    assert "def transition(self, event: WorkerLifecycleEvent | Mapping[str, object]) -> Mapping[str, object]" in lifecycle
