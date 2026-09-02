"""Stage2060 scheduler sentinel publication evidence closure."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.evidence.process_queue_partial_output import (
    ProcessQueuePartialOutputDependencies,
    ProcessQueuePartialOutputRequest,
    publish_process_queue_partial_output,
)
from Virus_Scan.scheduler.queue import claim_destination as claim_owner
from Virus_Scan.scheduler.queue import terminal_accounting_evidence as terminal_owner
from Virus_Scan.scheduler.runtime import process_worker_capacity as capacity_owner
from Virus_Scan.scheduler.workers import inmemory_scan_progress as progress_owner
from Virus_Scan.scheduler.workers.inmemory_scan_progress import InMemoryScanProgressEmitter


def test_stage2060_scan_progress_recorder_failure_publishes_fallback():
    recorded: list[tuple[str, str, dict[str, object]]] = []

    def fallback(where, exc, **kwargs):
        recorded.append((where, type(exc).__name__, dict(kwargs.get("context") or {})))
        return "failure-id"

    def callback(_stage, _inc, _bytes_delta):
        raise RuntimeError("callback unavailable")

    def recorder(_where, _exc):
        raise ValueError("recorder unavailable")

    original = progress_owner.record_suppressed_failure
    progress_owner.record_suppressed_failure = fallback
    try:
        emitter = InMemoryScanProgressEmitter(
            progress_callback=callback,
            cancel_error_type=KeyboardInterrupt,
            recoverable_exceptions=(RuntimeError, ValueError),
            record_suppressed=recorder,
        )
        assert emitter("scan") is False
    finally:
        progress_owner.record_suppressed_failure = original
    assert recorded == [
        (
            "inmemory_scan_progress_callback_failed",
            "ValueError",
            {
                "inmemory_scan_progress_failed": True,
                "stage": "scan",
                "reason": "progress_callback_failure_recorder_failed",
                "callback_error_type": "RuntimeError",
                "recorder_failed": True,
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            },
        )
    ]


def test_stage2060_claim_destination_recorder_failure_publishes_fallback():
    recorded: list[tuple[str, str, dict[str, object], bool]] = []

    def fallback(where, exc, **kwargs):
        recorded.append((where, type(exc).__name__, dict(kwargs.get("context") or {}), kwargs.get("fatal") is True))
        return "failure-id"

    def recorder(*_args, **_kwargs):
        raise ValueError("claim recorder unavailable")

    original = claim_owner.record_suppressed_failure
    claim_owner.record_suppressed_failure = fallback
    try:
        name = claim_owner.claim_destination_name(
            "worker/one",
            "pending/name.json",
            worker_pid=object(),
            record_suppressed=recorder,
        )
    finally:
        claim_owner.record_suppressed_failure = original

    assert name == "worker_one_0_pending_name.json"
    assert recorded == [
        (
            "queue_claim_destination_component_rejection_recorder_failed",
            "ValueError",
            {
                "queue_claim_destination_component_rejected": True,
                "queue_claim_destination_component_rejection_recorder_failed": True,
                "component_issue_count": 3,
                "final_json_must_record": True,
                "checkpoint_must_record": True,
                "replay_must_record": True,
            },
            True,
        )
    ]


def test_stage2060_terminal_report_callback_failure_publishes_fallback():
    recorded: list[tuple[str, str, dict[str, object]]] = []

    def fallback(where, exc, **kwargs):
        recorded.append((where, type(exc).__name__, dict(kwargs.get("context") or {})))
        return "failure-id"

    def report(*_args, **_kwargs):
        raise ValueError("terminal reporter unavailable")

    original = terminal_owner.record_suppressed_failure
    terminal_owner.record_suppressed_failure = fallback
    try:
        assert terminal_owner.report_terminal_accounting_failure(
            report,
            "terminal_marker",
            RuntimeError("terminal failure"),
            extra={"queue": "done"},
        ) is False
    finally:
        terminal_owner.record_suppressed_failure = original
    assert recorded[0][0] == "queue_terminal_accounting_report_callback_failed"
    assert recorded[0][1] == "ValueError"
    assert recorded[0][2]["queue_terminal_accounting_failed"] is True
    assert recorded[0][2]["queue_terminal_accounting_report_callback_failed"] is True
    assert recorded[0][2]["marker"] == "terminal_marker"
    assert recorded[0][2]["final_json_must_record"] is True


def test_stage2060_partial_output_log_failure_is_returned_as_evidence(tmp_path: Path):
    request = ProcessQueuePartialOutputRequest(
        outputs=(object(),),
        partial_output_path=str(tmp_path / "partial-output"),
        context="partial-monitor",
    )
    deps = ProcessQueuePartialOutputDependencies(
        read_json_file=lambda *_args, **_kwargs: {},
        log_error=lambda _message: (_ for _ in ()).throw(ValueError("log unavailable")),
        recoverable_exceptions=(ValueError,),
    )

    result = publish_process_queue_partial_output(request, deps)

    assert result.published is False
    assert [record.error_category for record in result.evidence] == [
        "scheduler_path_rejected",
        "partial_output_rejection_log_failed",
    ]
    assert all(record.final_json_must_record for record in result.evidence)
    assert all(record.checkpoint_must_record for record in result.evidence)
    assert all(record.replay_must_record for record in result.evidence)


def test_stage2060_capacity_environment_fallback_is_explicit_empty_mapping():
    recorded: list[tuple[str, object, str]] = []

    def snapshot(_env):
        raise RuntimeError("environment unavailable")

    def record(*, setting, value, policy_default, reason):
        recorded.append((setting, policy_default, reason))

    original_snapshot = capacity_owner.scheduler_environment_snapshot
    original_record = capacity_owner._record_capacity_rejection
    capacity_owner.scheduler_environment_snapshot = snapshot
    capacity_owner._record_capacity_rejection = record
    try:
        assert capacity_owner.process_queue_is_child_shard({}) is False
    finally:
        capacity_owner.scheduler_environment_snapshot = original_snapshot
        capacity_owner._record_capacity_rejection = original_record
    assert recorded == [("scheduler_process_environment", {}, "RuntimeError")]
