from __future__ import annotations

from pathlib import Path

_TARGET_FILES = (
    Path("Virus_Scan/scheduler/workers/inmemory_worker_heartbeat_boundary.py"),
    Path("Virus_Scan/scheduler/internal/worker_result_boundary.py"),
    Path("Virus_Scan/scheduler/internal/context_no_hook.py"),
    Path("Virus_Scan/scheduler/queue/inmemory_lifecycle_contracts.py"),
    Path("Virus_Scan/scheduler/queue/raw_queue_failed_diagnostics.py"),
)


def test_stage2210_scheduler_current_source_removes_dynamic_any_surfaces() -> None:
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


def test_stage2210_scheduler_current_source_keeps_object_no_hook_contracts() -> None:
    heartbeat = _TARGET_FILES[0].read_text(encoding="utf-8")
    worker_result = _TARGET_FILES[1].read_text(encoding="utf-8")
    context = _TARGET_FILES[2].read_text(encoding="utf-8")
    lifecycle = _TARGET_FILES[3].read_text(encoding="utf-8")
    failed_diagnostics = _TARGET_FILES[4].read_text(encoding="utf-8")

    assert "def safe_worker_heartbeat_inputs(" in heartbeat
    assert "dict[str, object] | None" in heartbeat
    assert "def build_worker_result_schema_failure(" in worker_result
    assert "dict[str, object]" in worker_result
    assert "def context_text(" in context
    assert "tuple[dict[str, object], ...]" in context
    assert "def lifecycle_transition_snapshot(" in lifecycle
    assert "dict[str, object] | None" in lifecycle
    assert "def repair_failed_queue_job_diagnostics(" in failed_diagnostics
    assert "Mapping[str, object]" in failed_diagnostics
