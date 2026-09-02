"""Stage798 Phase 10 queue JSON bounded ownership decomposition tests."""
from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

from Virus_Scan.scheduler.runtime import queue_json

from Virus_Scan.scheduler.runtime import queue_json_cleanup as queue_json_cleanup_module
from Virus_Scan.scheduler.runtime import queue_json_failures as queue_json_failures_module
from Virus_Scan.scheduler.runtime import queue_json_locks as queue_json_locks_module
from Virus_Scan.scheduler.runtime import queue_json_publication as queue_json_publication_module
from Virus_Scan.scheduler.runtime import queue_json_safety as queue_json_safety_module
from Virus_Scan.scheduler.runtime import queue_json_schema as queue_json_schema_module
from Virus_Scan.scheduler.runtime.queue_json_cleanup import queue_json_orphan_cleanup_due
from Virus_Scan.scheduler.runtime.queue_json_failures import queue_default_failure_info
from Virus_Scan.scheduler.runtime.queue_json_publication import read_json_file, queue_write_json_replace
from Virus_Scan.scheduler.runtime.queue_json_safety import make_json_safe
from Virus_Scan.scheduler.runtime.queue_json_schema import validate_persistent_record_semantics
from Virus_Scan.scheduler.runtime import queue_filesystem
from Virus_Scan.scheduler.runtime import queue_filesystem_common as queue_filesystem_common_module
from Virus_Scan.scheduler.runtime import queue_filesystem_dirs as queue_filesystem_dirs_module
from Virus_Scan.scheduler.runtime import queue_filesystem_identity as queue_filesystem_identity_module
from Virus_Scan.scheduler.runtime import queue_filesystem_operations as queue_filesystem_operations_module
from Virus_Scan.scheduler.runtime import queue_filesystem_process as queue_filesystem_process_module
from Virus_Scan.scheduler.runtime.queue_filesystem_operations import queue_atomic_replace, queue_safe_unlink
from Virus_Scan.scheduler.queue.inmemory_retry_result_evidence import InMemoryRetryPendingPublicationEvidence
from Virus_Scan.scheduler.queue import inmemory_retry_cancel_evidence as inmemory_retry_cancel_evidence_module
from Virus_Scan.scheduler.queue import inmemory_retry_lifecycle_evidence as inmemory_retry_lifecycle_evidence_module
from Virus_Scan.scheduler.queue import inmemory_retry_result_evidence as inmemory_retry_result_evidence_module
from Virus_Scan.scheduler.queue import inmemory_retry_recovery as inmemory_retry_recovery_module
from Virus_Scan.scheduler.queue import inmemory_retry_recovery_requeue as inmemory_retry_recovery_requeue_module
from Virus_Scan.scheduler.queue import inmemory_retry_recovery_exhausted as inmemory_retry_recovery_exhausted_module


def _module_file(module: ModuleType) -> str:
    path = module.__file__
    assert path is not None
    return path


def test_stage798_queue_json_facade_preserves_canonical_publication_surface(tmp_path):
    target = tmp_path / "job.json"
    payload = {"file": "sample.bin", "result": {"file": "sample.bin", "classification": "benign", "score": 0.0}}

    assert queue_json._queue_write_json_replace(target, payload, verify=True, log_context="stage798") is True
    loaded = queue_json.read_json_file(target, default={})

    assert loaded["file"] == "sample.bin"
    assert loaded["schema_version"] == 1
    assert loaded == read_json_file(target, default={})


def test_stage798_queue_json_decomposition_keeps_bounded_owners_below_phase10_limit():
    modules = [
        queue_json,
        queue_json_safety_module,
        queue_json_schema_module,
        queue_json_locks_module,
        queue_json_cleanup_module,
        queue_json_publication_module,
        queue_json_failures_module,
    ]
    for module in modules:
        with open(_module_file(module), "r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        assert line_count < 220, f"{module.__name__} remains oversized: {line_count} lines"


def test_stage798_queue_json_bounded_modules_keep_failure_semantics(tmp_path):
    failure_info = queue_default_failure_info("stage798", exception_type="InjectedFailure", error="boom")
    payload = {"file": "failed.bin", "queue_failure": True, "failure_info": failure_info}
    target = tmp_path / "failure.json"

    assert queue_write_json_replace(target, payload, verify=True, log_context="stage798_failure") is True
    loaded = json.loads(target.read_text(encoding="utf-8"))

    assert loaded["queue_failure"] is True
    validate_persistent_record_semantics(loaded, context="stage798_failure")
    assert make_json_safe({"decoded_text": "x" * 3000})["decoded_text"]["truncated"] is True
    assert isinstance(queue_json_orphan_cleanup_due(target), bool)


def test_stage798_queue_filesystem_facade_preserves_bounded_runtime_operations(tmp_path):
    src = tmp_path / "src.json"
    dst = tmp_path / "dst.json"
    src.write_text("{}", encoding="utf-8")

    assert queue_filesystem.queue_atomic_replace(src, dst, retries=1) is True
    assert dst.exists()
    assert queue_atomic_replace(dst, src, retries=1) is True
    assert queue_safe_unlink(src, retries=1) is True
    assert queue_filesystem.queue_file_results_dir(tmp_path).is_dir()


def test_stage798_queue_filesystem_decomposition_keeps_bounded_owners_below_phase10_limit():
    modules = [
        queue_filesystem,
        queue_filesystem_common_module,
        queue_filesystem_dirs_module,
        queue_filesystem_identity_module,
        queue_filesystem_operations_module,
        queue_filesystem_process_module,
    ]
    for module in modules:
        with open(_module_file(module), "r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        assert line_count < 220, f"{module.__name__} remains oversized: {line_count} lines"


def test_stage798_inmemory_retry_evidence_decomposition_preserves_canonical_result_contract():
    evidence = InMemoryRetryPendingPublicationEvidence(
        job_id=7,
        generation=2,
        reason="retry",
        file="sample.bin",
        error_category="RetryPublicationFailure",
        error_source="pending.appendleft",
        detail="boom",
    )

    record = dict(evidence.as_record())
    integrity = evidence.as_scan_integrity()

    assert record["stage"] == "inmemory_retry_pending_publication"
    assert record["final_json_must_record"] is True
    assert integrity["queue_failure"] is True
    assert integrity["retry_pending_publication_failed"] is True


def test_stage798_inmemory_retry_evidence_decomposition_keeps_bounded_owners_below_phase10_limit():
    modules = [
        inmemory_retry_cancel_evidence_module,
        inmemory_retry_lifecycle_evidence_module,
        inmemory_retry_result_evidence_module,
    ]
    for module in modules:
        with open(_module_file(module), "r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        assert line_count < 220, f"{module.__name__} remains oversized: {line_count} lines"


def test_stage1792_inmemory_retry_evidence_facade_stays_deleted():
    facade = Path(__file__).parents[1] / "scheduler" / "queue" / "inmemory_retry_evidence.py"

    assert not facade.exists()


def test_stage798_inmemory_retry_recovery_decomposition_keeps_bounded_owners_below_phase10_limit():
    modules = [
        inmemory_retry_recovery_module,
        inmemory_retry_recovery_requeue_module,
        inmemory_retry_recovery_exhausted_module,
    ]
    for module in modules:
        with open(_module_file(module), "r", encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        assert line_count < 220, f"{module.__name__} remains oversized: {line_count} lines"
