from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path


import pytest

from Virus_Scan.scheduler.queue.publish_durable import _write_queue_job_json_durable
from Virus_Scan.scheduler.queue.publish_job_contract import (
    ProcessQueuePublishAttempt,
    ProcessQueuePublishAttemptRequest,
    ProcessQueuePublishResult,
    build_process_queue_publish_attempt,
)
from Virus_Scan.scheduler.queue.publish_job_execution import publish_locked_process_queue_job
from Virus_Scan.scheduler.queue.identity_lock import IdentityLockReleaseDecision


class HostileValue:
    def __bool__(self):
        raise AssertionError("bool hook executed")

    def __str__(self):
        raise AssertionError("str hook executed")

    def __format__(self, spec):
        raise AssertionError("format hook executed")

    def __fspath__(self):
        raise AssertionError("fspath hook executed")


def _attempt() -> ProcessQueuePublishAttempt:
    return ProcessQueuePublishAttempt(
        order=3,
        original_index=7,
        file_path="sample.bin",
        workload_class="scan",
        queue_file_id="qid",
        weight=1.5,
    )


def test_durable_writer_rejects_hostile_log_context_without_format_hooks(tmp_path):
    tmp = tmp_path / "pending.tmp"
    final = tmp_path / "pending.json"

    assert _write_queue_job_json_durable(
        tmp,
        final,
        {"file": "sample.bin", "index": 7, "order": 3},
        log_context=HostileValue(),
    ) is True
    assert final.exists()


def test_publish_attempt_pending_name_uses_validated_primitives_without_format_hooks():
    assert _attempt().pending_name == "00000003_00000007.json"


def test_publish_result_rejects_hostile_bool_without_bool_hook():
    with pytest.raises(ValueError) as excinfo:
        ProcessQueuePublishResult(published=HostileValue())
    assert str(excinfo.value) == "process_queue_publish_published_rejected"


def test_build_publish_attempt_rejects_hostile_path_without_fspath_or_format_hooks():
    with pytest.raises(ValueError) as excinfo:
        build_process_queue_publish_attempt(ProcessQueuePublishAttemptRequest(
            order=0,
            original_index=0,
            file_path=HostileValue(),
            workload_class="scan",
            queue_file_identity_for_path=lambda path: "qid",
            process_weight_for_path=lambda path: 1.0,
        ))
    assert str(excinfo.value) == "invalid process queue publish path:scheduler_path_rejected"


def test_publish_execution_rejects_hostile_identity_and_pending_dir_without_hooks(tmp_path):
    suppressed = []
    attempt = _attempt()

    with pytest.raises(ValueError) as identity_exc:
        publish_locked_process_queue_job(
            queue_dir=tmp_path,
            pending_dir=tmp_path,
            attempt=attempt,
            identity=HostileValue(),
            lock=object(),
            enqueue_guard=lambda *_args, **_kwargs: True,
            write_queue_job_json_durable=lambda *_args, **_kwargs: True,
            identity_index_note=lambda *_args, **_kwargs: None,
            release_identity_lock_decision=lambda _lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
            record_scheduler_suppressed=lambda *args, **kwargs: suppressed.append((args, kwargs)),
            guard_failure_stage="guard_failed",
            identity_index_failure_stage="identity_failed",
            release_failure_stage="release_failed",
        )
    assert str(identity_exc.value) == "invalid process queue publication identity:process_queue_publish_lock_identity_rejected"

    with pytest.raises(ValueError) as pending_exc:
        publish_locked_process_queue_job(
            queue_dir=tmp_path,
            pending_dir=HostileValue(),
            attempt=attempt,
            identity="qid",
            lock=object(),
            enqueue_guard=lambda *_args, **_kwargs: True,
            write_queue_job_json_durable=lambda *_args, **_kwargs: True,
            identity_index_note=lambda *_args, **_kwargs: None,
            release_identity_lock_decision=lambda _lock: IdentityLockReleaseDecision(True, "process_queue_identity_lock_released"),
            record_scheduler_suppressed=lambda *args, **kwargs: suppressed.append((args, kwargs)),
            guard_failure_stage="guard_failed",
            identity_index_failure_stage="identity_failed",
            release_failure_stage="release_failed",
        )
    assert str(pending_exc.value) == "invalid process queue pending directory:scheduler_path_rejected"


def test_publish_execution_preserves_release_failure_in_typed_result(tmp_path):
    suppressed = []

    result = publish_locked_process_queue_job(
        queue_dir=tmp_path,
        pending_dir=tmp_path,
        attempt=_attempt(),
        identity="qid",
        lock=tmp_path / "identity.lock",
        enqueue_guard=lambda *_args, **_kwargs: True,
        write_queue_job_json_durable=lambda *_args, **_kwargs: True,
        identity_index_note=lambda *_args, **_kwargs: None,
        release_identity_lock_decision=lambda _lock: IdentityLockReleaseDecision(False, "process_queue_identity_lock_release_failed"),
        record_scheduler_suppressed=lambda *args, **kwargs: suppressed.append((args, kwargs)),
        guard_failure_stage="guard_failed",
        identity_index_failure_stage="identity_failed",
        release_failure_stage="release_failed",
    )

    assert result.published is True
    assert result.release_failed is True
    assert suppressed[0][0][0] == "release_failed"


def test_stage1910_source_guard_removed_publish_durable_contract_hooks_and_sentinels():
    durable_source = read_python_file(Path("Virus_Scan/scheduler/queue/publish_durable.py"))
    contract_source = read_python_file(Path("Virus_Scan/scheduler/queue/publish_job_contract.py"))
    execution_source = read_python_file(Path("Virus_Scan/scheduler/queue/publish_job_execution.py"))
    forbidden = (
        'context=f"{log_context}_tmp"',
        'log_context=f"{log_context}_tmp_cleanup"',
        'log_context=f"{log_context}_durability_cleanup"',
        'extra={"tmp": str(tmp), "final": str(final)}',
        'return f"{self.order:08d}_{self.original_index:08d}.json"',
        'reason=f"process_queue_publish_{field_name}_rejected"',
        'f"invalid process queue publish path:',
        'f"invalid process queue publication identity:',
        'f"invalid process queue pending directory:',
    )
    joined = durable_source + contract_source + execution_source
    for pattern in forbidden:
        assert pattern not in joined
    assert "return False" not in durable_source
