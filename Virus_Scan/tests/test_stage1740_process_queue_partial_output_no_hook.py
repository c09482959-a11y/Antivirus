"""Stage 1740: process-queue partial output rejects hostile paths before hooks."""

from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputDependencies,
    ProcessQueuePartialOutputRequest,
    publish_process_queue_partial_output,
)


class HostilePartialPath:
    touched = 0

    def __bool__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned bool hook must not execute")

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str hook must not execute")

    def __fspath__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook must not execute")


class HostileSourcePath:
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str hook must not execute")

    def __fspath__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook must not execute")


def _deps(logs: list[str]):
    def read_json_file(path, *, default):
        return json.loads(Path(path).read_text())

    return ProcessQueuePartialOutputDependencies(
        read_json_file=read_json_file,
        log_error=logs.append,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )


def test_stage1740_process_queue_partial_output_rejects_hostile_target_path_without_hooks() -> None:
    HostilePartialPath.touched = 0
    logs: list[str] = []

    result = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(outputs=(), partial_output_path=HostilePartialPath()),
        _deps(logs),
    )

    assert result.published is False
    assert result.merged == {}
    assert len(result.evidence) == 1
    assert result.evidence[0].error_category == "scheduler_path_rejected"
    assert result.evidence[0].final_json_must_record is True
    assert HostilePartialPath.touched == 0
    assert any("partial_output_path" in item and "scheduler_path_rejected" in item for item in logs)


def test_stage1740_process_queue_partial_output_rejects_hostile_source_path_without_hooks() -> None:
    HostileSourcePath.touched = 0
    logs: list[str] = []

    result = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(outputs=(HostileSourcePath(),), partial_output_path="partial.json"),
        _deps(logs),
    )

    assert result.published is False
    assert result.merged == {}
    assert len(result.evidence) == 1
    assert result.evidence[0].context["field"] == "partial_output_source"
    assert HostileSourcePath.touched == 0
    assert any("partial_output_source" in item and "scheduler_path_rejected" in item for item in logs)


def test_stage1740_process_queue_partial_output_preserves_success_path(tmp_path: Path) -> None:
    logs: list[str] = []
    output = tmp_path / "worker.json"
    output.write_text(json.dumps({"sample.exe": {"status": "done"}}))
    target = tmp_path / "partial.json"

    result = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(outputs=(str(output),), partial_output_path=target, context="monitor"),
        _deps(logs),
    )

    assert result.published is True
    assert result.merged["sample.exe"]["status"] == "done"
    assert result.evidence == ()
    assert json.loads((tmp_path / "partial.json.partial").read_text(encoding="utf-8")) == {
        "sample.exe": {"status": "done"}
    }
    assert logs == []
