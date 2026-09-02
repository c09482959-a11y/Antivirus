"""Stage 1842: partial-output and progress-count fallback closure."""

from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputDependencies,
    ProcessQueuePartialOutputRequest,
    publish_process_queue_partial_output,
)
from Virus_Scan.scheduler.evidence.process_queue_partial_output_support import (
    process_queue_partial_output_failure,
)
from Virus_Scan.scheduler.evidence.process_queue_progress_counts import snapshot_process_queue_progress_counts


class HostileContext:
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned context text hook must not execute")

    def __repr__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned context repr hook must not execute")


class HostileCount:
    touched = 0

    def __int__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned int hook must not execute")

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned str hook must not execute")


class HostileSourcePath:
    touched = 0

    def __str__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned path text hook must not execute")

    def __fspath__(self):  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned path hook must not execute")


def _deps(logs: list[str]):
    return ProcessQueuePartialOutputDependencies(
        read_json_file=lambda _path, *, default: default,
        log_error=logs.append,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
    )


def test_stage1842_partial_output_context_rejection_records_reason_without_fallback_or_hooks() -> None:
    HostileContext.touched = 0
    evidence = process_queue_partial_output_failure(
        reason="scheduler_path_rejected",
        field="partial_output_source",
        value=object(),
        context=HostileContext(),  # type: ignore[arg-type]
    )

    assert evidence.context["context_reason"] == "partial_output_context_rejected"
    assert "context" not in evidence.context
    assert evidence.message == "process queue partial output partial_output_source was unavailable"
    assert HostileContext.touched == 0


def test_stage1842_partial_output_rejection_log_uses_owned_context_without_fstring_hooks() -> None:
    HostileContext.touched = 0
    HostileSourcePath.touched = 0
    logs: list[str] = []

    result = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(
            outputs=(HostileSourcePath(),),
            partial_output_path="partial.json",
            context=HostileContext(),  # type: ignore[arg-type]
        ),
        _deps(logs),
    )

    assert result.published is False
    assert result.evidence[0].context["context_reason"] == "partial_output_context_rejected"
    assert logs == [
        "process_queue_partial_output: partial_output_source rejected without caller hooks: "
        "scheduler_path_rejected context_reason=partial_output_context_rejected"
    ]
    assert HostileContext.touched == 0
    assert HostileSourcePath.touched == 0


def test_stage1842_progress_counts_preserve_missing_counts_and_reject_hostile_present_values_without_hooks() -> None:
    counts = snapshot_process_queue_progress_counts(
        "queue",
        progress_counts=lambda _queue_dir: {"file_done": "2", "raw_active": b"3"},
    )
    assert counts.file_done_count == 2
    assert counts.file_failed_count == 0
    assert counts.file_active_count == 0
    assert counts.file_pending_count == 0
    assert counts.raw_live == 3

    HostileCount.touched = 0
    with pytest.raises(ValueError, match="scheduler_progress_count_file_done_rejected"):
        snapshot_process_queue_progress_counts(
            "queue",
            progress_counts=lambda _queue_dir: {"file_done": HostileCount()},
        )
    assert HostileCount.touched == 0


def test_stage1842_sources_remove_repaired_fallback_and_fstring_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = (
        root / "scheduler" / "evidence" / "process_queue_partial_output.py",
        root / "scheduler" / "evidence" / "process_queue_partial_output_support.py",
        root / "scheduler" / "evidence" / "process_queue_progress_counts.py",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in targets)
    forbidden = (
        'fallback="partial_monitor"',
        'fallback=0,',
        'f"{context_text}: {field} rejected without caller hooks: {reason}"',
        'message=f"process queue partial output {field} was unavailable"',
        'reason=f"scheduler_progress_count_{key}_rejected"',
    )
    for snippet in forbidden:
        assert snippet not in source
