"""Stage 1741: partial-output failures propagate to production scheduler evidence."""

from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.scheduler.evidence.process_queue_monitor_progress import (
    ProcessQueueMonitorProgressDependencies,
    ProcessQueueMonitorProgressRequest,
    publish_process_queue_monitor_progress,
)
from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputDependencies,
    ProcessQueuePartialOutputRequest,
    publish_process_queue_partial_output,
)
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import (
    attach_scheduler_evidence_to_merged_results,
)


class HostilePartialTarget:
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


def test_stage1741_partial_writer_failure_emits_evidence(tmp_path) -> None:
    output = tmp_path / "worker.json"
    output.write_text('{"sample.exe": {"status": "done"}}')
    logs: list[str] = []
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    result = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(
            outputs=(str(output),),
            partial_output_path=blocked_parent / "partial.json",
        ),
        ProcessQueuePartialOutputDependencies(
            read_json_file=lambda path, *, default: json.loads(Path(path).read_text(encoding="utf-8")),
            log_error=logs.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )

    assert result.published is False
    assert result.merged == {}
    assert result.evidence[0].error_category == "partial_output_publication_failed"
    assert result.evidence[0].context["value_type"] == "OSError"
    assert logs == ["process queue monitor partial JSON publication failed"]


def test_stage1741_monitor_progress_returns_partial_output_evidence_without_hooks() -> None:
    HostilePartialTarget.touched = 0
    output = publish_process_queue_monitor_progress(
        ProcessQueueMonitorProgressRequest(
            outputs=(),
            partial_output_path=HostilePartialTarget(),
            file_done_count=0,
            file_failed_count=0,
            file_active_count=0,
            file_pending_count=1,
            raw_live=0,
            raw_done=0,
            raw_failed=0,
            live_workers=1,
            total_files=1,
            progress_every=1,
            last_done_count=-1,
            last_progress_time=0.0,
            progress_interval_sec=1.0,
            last_monitor_heartbeat_time=0.0,
            monitor_heartbeat_sec=1.0,
            accounted_total=0,
            elastic_cpu_sample=None,
            now=1.0,
        ),
        ProcessQueueMonitorProgressDependencies(
            log_info=lambda _message: None,
            read_json_file=lambda _path, *, default: default,
            log_error=lambda _message: None,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )

    assert len(output.partial_output_evidence) == 1
    evidence = output.partial_output_evidence[0]
    assert evidence.stage == "process_queue_partial_output"
    assert evidence.error_category == "scheduler_path_rejected"
    assert HostilePartialTarget.touched == 0


def test_stage1741_partial_output_evidence_attaches_to_final_json_source_records() -> None:
    publication = publish_process_queue_partial_output(
        ProcessQueuePartialOutputRequest(outputs=(), partial_output_path=HostilePartialTarget()),
        ProcessQueuePartialOutputDependencies(
            read_json_file=lambda _path, *, default: default,
            log_error=lambda _message: None,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )
    merged = {"sample.exe": {"status": "done"}}

    attach_scheduler_evidence_to_merged_results(merged, publication.evidence)

    evidence = merged["sample.exe"]["scheduler_evidence"][0]
    assert evidence["stage"] == "process_queue_partial_output"
    assert evidence["error_category"] == "scheduler_path_rejected"
    assert evidence["final_json_must_record"] is True
