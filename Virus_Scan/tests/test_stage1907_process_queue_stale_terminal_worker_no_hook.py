from pathlib import Path
from typing import Any, cast

import pytest

from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryDependencies,
    ProcessQueueStaleRecoveryEvidence,
    ProcessQueueStaleRecoveryRequest,
    reconcile_process_queue_stale_recovery,
)
from Virus_Scan.scheduler.queue.process_queue_terminal_counts import terminal_queue_counts
from Virus_Scan.scheduler.queue.process_queue_worker_output_merge import merge_process_queue_worker_outputs


class HostileValue:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")

    def __format__(self, spec):
        raise AssertionError("format hook executed")

    def __float__(self):
        raise AssertionError("float hook executed")

    def __iter__(self):
        raise AssertionError("iter hook executed")

    def __fspath__(self):
        raise AssertionError("fspath hook executed")

    def exists(self):
        raise AssertionError("exists hook executed")


def test_stale_recovery_evidence_rejects_hostile_scalars_without_hooks():
    hostile = HostileValue()
    record = cast(Any, ProcessQueueStaleRecoveryEvidence)(
        stage="stage",
        queue_dir="queue",
        progress_stall_sec=hostile,
        per_file_timeout_sec=hostile,
        error_category="category",
        error_source="source",
        detail="detail",
        final_json_must_record=hostile,
        checkpoint_must_record=hostile,
        replay_must_reproduce=hostile,
    ).as_record()

    assert record["progress_stall_sec"] == 0.0
    assert record["per_file_timeout_sec"] == 0.0
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stale_recovery_failure_uses_no_hook_path_exception_and_recovered_record():
    hostile = HostileValue()
    logs = []
    result = reconcile_process_queue_stale_recovery(
        cast(Any, ProcessQueueStaleRecoveryRequest)(
            queue_dir=hostile,
            progress_stall_sec=hostile,
            per_file_timeout_sec=hostile,
            raw_stage_progress_state={},
        ),
        ProcessQueueStaleRecoveryDependencies(
            raw_stage_progress_recent=lambda *_args, **_kwargs: False,
            file_has_recent_raw_owner_progress=lambda *_args, **_kwargs: False,
            worker_liveness_checker=lambda *_args, **_kwargs: None,
            worker_terminator=lambda *_args, **_kwargs: None,
            log_error=logs.append,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError, OSError),
        ),
    )

    assert result.evidence
    evidence = dict(result.evidence[0])
    assert cast(str, evidence["queue_dir"]).startswith("<HostileValue unsupported_process_queue_stale_queue_dir")
    assert evidence["progress_stall_sec"] == 0.0
    assert evidence["timeout_failure"] is True
    assert evidence["queue_recovery_failure"] is True
    assert logs == []


def test_terminal_counts_rejects_hostile_directory_before_listdir_or_exists():
    calls = []
    with pytest.raises(TypeError, match="process_queue_terminal_count_directory_rejected"):
        terminal_queue_counts(
            HostileValue(),
            Path("active"),
            Path("failed"),
            safe_listdir=lambda directory: calls.append(directory) or [],
            is_job_name=lambda _name: True,
        )
    assert calls == []


def test_worker_output_merge_rejects_hostile_output_and_logs_without_formatting_hooks():
    logs = []
    issues = []

    class Deps:
        def record_issue(self, stage, exc, **extra):
            issues.append((stage, extra))

        def log_error(self, message):
            logs.append(message)

        def read_json_file(self, *_args, **_kwargs):
            return {}

    merged, had_error = merge_process_queue_worker_outputs((HostileValue(),), deps=Deps())

    assert merged == {}
    assert had_error is True
    assert issues and issues[0][0] == "process_queue_worker_output_path_rejected"
    assert logs and logs[0].startswith("process queue worker output path rejected: <HostileValue")
