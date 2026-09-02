"""Stage2213 current-source proof for scheduler Class-A sentinel rows.

These tests lock the current-source behavior used to close the Stage2213
scheduler sentinel/default-return proof cluster.  The rows are closed only where
runtime behavior or source shape proves a local control/absence sentinel, an
explicit recorded rejection, or a typed unavailable-evidence replacement rather
than a hidden externally observable failure.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.scheduler.internal.exception_projection import _scheduler_owned_exception_args_rejection
from Virus_Scan.scheduler.internal.immutable_snapshots import immutable_snapshot_tuple
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.internal.scheduler_config_values import process_queue_env_float
from Virus_Scan.scheduler.orchestration.inmemory_parent_dispatch import _submitted_count
from Virus_Scan.scheduler.queue.admission_fairness import _buckets_have_items
from Virus_Scan.scheduler.queue.claim_candidates import pending_claim_names
from Virus_Scan.scheduler.queue.claim_destination import _record_claim_destination_component_rejections
from Virus_Scan.scheduler.queue.claim_meta import read_claim_meta
from Virus_Scan.scheduler.queue.claim_protection import _queue_missing_worker_liveness
from Virus_Scan.scheduler.queue.claim_sidecar_policy_support import policy_first_present
from Virus_Scan.scheduler.queue.inmemory_cancel import (
    InMemoryCancelRequest,
    request_cancel_only,
)
from Virus_Scan.scheduler.queue.inmemory_cancel_evidence import cancel_publication_evidence_from_record
from Virus_Scan.scheduler.queue.inmemory_retry_failure_result import InMemoryRetryFailureResult
from Virus_Scan.scheduler.queue.orphan_recovery import _queue_reclaim_path_text
from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import _owned_mapping
from Virus_Scan.scheduler.queue.orphan_recovery_gates import _job_value
from Virus_Scan.scheduler.queue.process_queue_terminal_counts import _job_count
from Virus_Scan.scheduler.queue.publish_controls import queue_slice_item
from Virus_Scan.scheduler.queue.recovery_contract import retry_already_pending
from Virus_Scan.scheduler.queue.snapshot_behavior_support import snapshot_optional_message_int
from Virus_Scan.scheduler.runtime.queue_filesystem_dirs import _state_tokens
from Virus_Scan.scheduler.runtime.queue_filesystem_process import scheduler_windows_creationflags
from Virus_Scan.scheduler.runtime.queue_json_failures import _queue_failure_extra
from Virus_Scan.scheduler.runtime.stage_cost import _size_weight_delta
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_progress_preexecution import handle_pre_execution_progress_wait
from Virus_Scan.scheduler.timeout.longtask_controller import per_file_timeout
from Virus_Scan.scheduler.timeout.timeout_budget_policy_workloads import _archive_ratio_complexity
from Virus_Scan.scheduler.workers.initial_spawn import _initial_spawn_log_int
from Virus_Scan.scheduler.workers.inmemory_worker_job_publication import _request_field
from Virus_Scan.scheduler.workers.inmemory_worker_submission import _owned_task_meta_value
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress import InMemoryWorkerThreadProgress

_REPO_ROOT = Path(__file__).resolve().parents[2]

_STAGE2213_SOURCE_PROOFS: tuple[tuple[str, str, str, str], ...] = (
    ("STAGE1945-SCHEDULER-01490", "Virus_Scan/scheduler/execution/scheduler_file_terminal.py", "maybe_return_terminal_result", "return None"),
    ("STAGE1945-SCHEDULER-01561", "Virus_Scan/scheduler/internal/exception_projection.py", "_scheduler_owned_exception_args_rejection", 'return ""'),
    ("STAGE1945-SCHEDULER-01637", "Virus_Scan/scheduler/internal/immutable_snapshots.py", "immutable_snapshot_tuple", "return ()"),
    ("STAGE1945-SCHEDULER-01644", "Virus_Scan/scheduler/internal/live_path_entries.py", "freeze_live_scheduler_paths", "return ()"),
    ("STAGE1945-SCHEDULER-01732", "Virus_Scan/scheduler/internal/scheduler_config_values.py", "_config_name", "_record_rejection"),
    ("STAGE1945-SCHEDULER-01802", "Virus_Scan/scheduler/orchestration/inmemory_parent_dispatch.py", "_submitted_count", "return 0"),
    ("STAGE1945-SCHEDULER-02455", "Virus_Scan/scheduler/queue/admission_fairness.py", "_buckets_have_items", "return False"),
    ("STAGE1945-SCHEDULER-02520", "Virus_Scan/scheduler/queue/claim_candidates.py", "pending_claim_names", "return []"),
    ("STAGE1945-SCHEDULER-02536", "Virus_Scan/scheduler/queue/claim_destination.py", "_record_claim_destination_component_rejections", "if not issues or record_suppressed is None"),
    ("STAGE1945-SCHEDULER-02590", "Virus_Scan/scheduler/queue/claim_heartbeat.py", "_umige_read_claim_heartbeat_meta", "return {}"),
    ("STAGE1945-SCHEDULER-02597", "Virus_Scan/scheduler/queue/claim_meta.py", "read_claim_meta", "Returns an empty dict for absent metadata"),
    ("STAGE1945-SCHEDULER-02621", "Virus_Scan/scheduler/queue/claim_protection.py", "_queue_missing_worker_liveness", "queue_active_claim_worker_liveness_dependency_missing"),
    ("STAGE1945-SCHEDULER-02652", "Virus_Scan/scheduler/queue/claim_sidecar_policy_support.py", "policy_first_present", "return None"),
    ("STAGE1945-SCHEDULER-02840", "Virus_Scan/scheduler/queue/inmemory_cancel.py", "request_cancel_only", "return False"),
    ("STAGE1945-SCHEDULER-02852", "Virus_Scan/scheduler/queue/inmemory_cancel_evidence.py", "cancel_publication_evidence_from_record", "return ()"),
    ("STAGE1945-SCHEDULER-03052", "Virus_Scan/scheduler/queue/inmemory_retry_failure_result.py", "evidence_dict", "return None"),
    ("STAGE1945-SCHEDULER-03254", "Virus_Scan/scheduler/queue/orphan_recovery.py", "_queue_reclaim_path_text", 'return ""'),
    ("STAGE1945-SCHEDULER-03337", "Virus_Scan/scheduler/queue/orphan_recovery_failure_info.py", "_owned_mapping", '"_unavailable"'),
    ("STAGE1945-SCHEDULER-03363", "Virus_Scan/scheduler/queue/orphan_recovery_gates.py", "_job_value", 'return ""'),
    ("STAGE1945-SCHEDULER-03601", "Virus_Scan/scheduler/queue/process_queue_terminal_counts.py", "_job_count", "return 0"),
    ("STAGE1945-SCHEDULER-03673", "Virus_Scan/scheduler/queue/publish_controls.py", "queue_slice_item", "return None"),
    ("STAGE1945-SCHEDULER-04192", "Virus_Scan/scheduler/queue/recovery_contract.py", "retry_already_pending", "return False"),
    ("STAGE1945-SCHEDULER-04472", "Virus_Scan/scheduler/queue/snapshot_behavior_support.py", "snapshot_optional_message_int", "return None"),
    ("STAGE1945-SCHEDULER-04498", "Virus_Scan/scheduler/queue/terminal_accounting_evidence.py", "report_terminal_accounting_failure", "return False"),
    ("STAGE1945-SCHEDULER-04808", "Virus_Scan/scheduler/runtime/process_worker_capacity.py", "_scheduler_environment", "return _empty_scheduler_environment()"),
    ("STAGE1945-SCHEDULER-04823", "Virus_Scan/scheduler/runtime/queue_filesystem_dirs.py", "_state_tokens", "return ()"),
    ("STAGE1945-SCHEDULER-04861", "Virus_Scan/scheduler/runtime/queue_filesystem_process.py", "scheduler_windows_creationflags", "return 0"),
    ("STAGE1945-SCHEDULER-04864", "Virus_Scan/scheduler/runtime/queue_json_failures.py", "_queue_failure_extra", "return ()"),
    ("STAGE1945-SCHEDULER-04973", "Virus_Scan/scheduler/runtime/stage_cost.py", "_size_weight_delta", "return 0"),
    ("STAGE1945-SCHEDULER-05375", "Virus_Scan/scheduler/timeout/inmemory_timeout_sweep_progress_preexecution.py", "handle_pre_execution_progress_wait", "return False"),
    ("STAGE1945-SCHEDULER-05469", "Virus_Scan/scheduler/timeout/longtask_controller.py", "__exit__", "return False"),
    ("STAGE1945-SCHEDULER-05558", "Virus_Scan/scheduler/timeout/timeout_budget_policy_workloads.py", "_archive_ratio_complexity", "return 0.0"),
    ("STAGE1945-SCHEDULER-05741", "Virus_Scan/scheduler/workers/initial_spawn.py", "_initial_spawn_log_int", "return 0"),
    ("STAGE1945-SCHEDULER-06231", "Virus_Scan/scheduler/workers/inmemory_worker_job_publication.py", "_request_field", "InMemoryWorkerRequestField"),
    ("STAGE1945-SCHEDULER-06288", "Virus_Scan/scheduler/workers/inmemory_worker_submission.py", "_owned_task_meta_value", "return None"),
    ("STAGE1945-SCHEDULER-06308", "Virus_Scan/scheduler/workers/inmemory_worker_thread_progress.py", "__call__", "return False"),
)


def _source_for_symbol(relative_path: str, symbol: str) -> str:
    path = _REPO_ROOT / relative_path
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            return ast.get_source_segment(source, node) or ""
    raise AssertionError(f"{symbol} not found in {relative_path}")


def test_stage2213_closed_scheduler_sentinel_rows_still_map_to_current_source() -> None:
    for defect_id, relative_path, symbol, expected_text in _STAGE2213_SOURCE_PROOFS:
        source = _source_for_symbol(relative_path, symbol)
        assert expected_text in source, defect_id


def test_stage2213_local_absence_sentinels_have_distinguished_runtime_meaning(tmp_path: Path) -> None:
    assert immutable_snapshot_tuple(None) == ()
    assert freeze_live_scheduler_paths(None) == ()
    OwnedSchedulerError = type("OwnedSchedulerError", (Exception,), {"__module__": "Virus_Scan.scheduler.stage2213"})
    assert _scheduler_owned_exception_args_rejection(OwnedSchedulerError("owned")) == ""
    assert _submitted_count(object()) == 0
    assert _buckets_have_items({"light": [], "heavy": []}, ("light", "heavy")) is False
    assert pending_claim_names(tmp_path, listdir=lambda _path: [], is_job_name=lambda name: name.endswith(".json"), limit=10) == []
    assert request_cancel_only(InMemoryCancelRequest(
        job_records={},
        terminal=set(),
        job_id=10,
        reason="not-present",
        cancel_table={},
        cancel_generation={},
        cancel_flags=SimpleNamespace(value=0),
        cancel_stall_poison_mask=1,
    )) is False
    assert cancel_publication_evidence_from_record({}) == ()
    assert InMemoryRetryFailureResult({"ok": True}).evidence_dict() is None
    assert _queue_reclaim_path_text(object()) == ""
    assert _owned_mapping(None, field="timeout_evidence") == {}
    assert _job_value({}, "file", "path") == ""
    assert _job_count(tmp_path / "missing", safe_listdir=lambda _path: [], is_job_name=lambda _name: True) == 0
    assert queue_slice_item(object()) is None
    assert retry_already_pending(None) is False
    assert snapshot_optional_message_int(None, "pending") is None
    assert _state_tokens(None) == ()
    assert _queue_failure_extra(None) == ()
    assert _size_weight_delta(1024) == 0
    assert _archive_ratio_complexity(19.9, 100.0) == 0.0
    assert _initial_spawn_log_int(object(), "initial_spawn_target_rejected") == 0
    assert _owned_task_meta_value(object(), "job_id") is None


def test_stage2213_recorded_rejection_and_typed_unavailable_replacements() -> None:
    recorded: list[tuple[str, str, dict[str, object] | None]] = []

    def record_suppressed(stage: str, exc: BaseException, *, extra=None, fatal=False):
        del fatal
        recorded.append((stage, type(exc).__name__, extra))

    assert process_queue_env_float("", 7.5, minimum=1.0, record_suppressed=record_suppressed, env_get=lambda *_args: "99") == 7.5
    assert recorded and recorded[-1][0] == "process_queue_env_float_name_invalid"
    assert recorded[-1][2] and recorded[-1][2]["reason"] == "scheduler_config_name_blank"

    _record_claim_destination_component_rejections((), record_suppressed=record_suppressed)
    assert recorded[-1][0] == "process_queue_env_float_name_invalid"

    field = _request_field(SimpleNamespace(), "job_id", unavailable_value=0)
    assert field.value == 0
    assert field.unavailable_reason == "missing_inmemory_worker_request_job_id"


def test_stage2213_metadata_absence_and_progress_control_paths_are_explicit(tmp_path: Path) -> None:
    missing_claim = tmp_path / "missing.claim"
    assert read_claim_meta(
        missing_claim,
        claim_meta_path=lambda path: path,
        now=lambda: 1.0,
        report=lambda *_args, **_kwargs: None,
    ) == {}

    assert policy_first_present({}, ("policy", "fallback")) is None
    assert _queue_missing_worker_liveness("1234") is False
    assert scheduler_windows_creationflags() == 0

    class Recovery:
        def replace_with_history_transition(self, *_args, **_kwargs):  # pragma: no cover - not called on False branch
            raise AssertionError("recovery should not run for non-pre-execution stages")

    failures: list[dict[str, object]] = []
    assert handle_pre_execution_progress_wait(
        jid="job",
        rec={"stage": "raw_scan"},
        now=1.0,
        pid=1,
        budget_info={},
        recovery=Recovery(),
        stage_is_pre_execution=lambda _stage: True,
        timeout_retry_evidence=failures,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(RuntimeError,),
    ) is False
    assert failures == []

    assert per_file_timeout(0).__exit__(None, None, None) is False

    progress = InMemoryWorkerThreadProgress(
        cfg={"worker_rss_limit_mb": 0.0},
        job_id="job",
        generation=1,
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags=SimpleNamespace(running=1, cancel_request=2, poisoned_or_retire_mask=4),
        completed_jobs=0,
        task_meta={},
        cancel_requested=lambda *_args: True,
        update_shared_heartbeat=lambda *_args, **_kwargs: True,
        recoverable_exceptions=(RuntimeError,),
    )
    assert progress() is False
