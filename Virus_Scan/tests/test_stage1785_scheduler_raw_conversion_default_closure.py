from __future__ import annotations

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.scheduler.api.contracts import QueueResultMergeError
from Virus_Scan.scheduler.contracts.replay_result import ReplaySnapshot
from Virus_Scan.scheduler.evidence.process_queue_monitor_progress import (
    ProcessQueueMonitorProgressRequest,
)
from Virus_Scan.scheduler.evidence.process_queue_progress_counts import (
    snapshot_process_queue_progress_counts,
)
from Virus_Scan.scheduler.execution.target_collection import collect_target_files
from Virus_Scan.scheduler.execution.triage_escalation import should_escalate_after_triage
from Virus_Scan.scheduler.execution.scheduler_file_analysis import (
    execute_scheduler_file_analysis,
)
from Virus_Scan.scheduler.execution.scheduler_file_terminal import (
    maybe_return_terminal_result,
)
from Virus_Scan.scheduler.orchestration.scheduler_mode_dispatch import run_scheduler_mode
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import (
    SchedulerModeDispatchDependencies,
    SchedulerModeDispatchRequest,
)
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import (
    SchedulerTargetPlanningRequest,
    plan_scheduler_targets,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup import (
    ProcessQueueStartupRequest,
)
from Virus_Scan.scheduler.ownership.raw_stage_eligibility import global_raw_eligible
from Virus_Scan.scheduler.queue import identity_index
from Virus_Scan.scheduler.queue.claim_meta import (
    merge_claim_meta_into_job,
    unreadable_claim_meta_info,
)
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState
from Virus_Scan.scheduler.queue.publish import _write_process_queue_jobs_slice
from Virus_Scan.scheduler.queue.publish_job import (
    ProcessQueuePublishAttemptRequest,
    ProcessQueuePublishResult,
    build_process_queue_publish_attempt,
)
from Virus_Scan.scheduler.queue.result_merge import load_queue_file_results
from Virus_Scan.scheduler.queue.inmemory_retry_missing_record import (
    retry_missing_record_evidence,
)
from Virus_Scan.scheduler.queue.integrity_contracts import QueueIdentityRecord
from Virus_Scan.scheduler.replay.replay_mismatch import build_replay_mismatches
from Virus_Scan.scheduler.replay.replay_snapshot import hybrid_queue_key
from Virus_Scan.scheduler.runtime import raw_escalation_policy, stage_cost
from Virus_Scan.scheduler.runtime.stage_budget_tables import (
    stage_budget_failure_evidence,
)
from Virus_Scan.scheduler.runtime.startup_defaults import SchedulerStartupSnapshot
from Virus_Scan.scheduler.timeout.timeout_workload_inspection import (
    archive_metrics,
    image_pixel_count,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")

    def __fspath__(self):
        type(self).fspath_calls += 1
        raise RuntimeError("must not execute")


class HostileError(RuntimeError):
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")


def _reset_hostile_counters() -> None:
    for owner in (HostileValue, HostileError):
        for name in tuple(vars(owner)):
            if name.endswith("_calls"):
                setattr(owner, name, 0)


def _assert_no_hostile_hooks() -> None:
    for owner in (HostileValue, HostileError):
        for name, value in vars(owner).items():
            if name.endswith("_calls"):
                assert value == 0, f"{owner.__name__}.{name} executed"


def test_stage1785_target_and_escalation_boundaries_reject_without_hooks():
    _reset_hostile_counters()
    hostile = HostileValue()
    with pytest.raises(ValueError, match="scheduler_target_root"):
        collect_target_files(hostile)

    recorded = []
    assert should_escalate_after_triage(
        "sample.bin",
        hostile,
        False,
        {},
        "scan",
        get_scan_extension=lambda _path: ".bin",
        deep_scan_thorough=lambda: False,
        contextual_dangerous_anchor_hits=lambda _tags: False,
        record_suppressed_failure=lambda where, error: recorded.append((where, error)),
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
    ) is True
    with patch.object(
        raw_escalation_policy,
        "record_suppressed_failure",
        lambda where, error, **kwargs: recorded.append((where, error)),
    ):
        assert raw_escalation_policy.should_escalate_after_inmemory_triage(
            "sample.bin",
            hostile,
            False,
            {},
            "scan",
        ) is True
    assert recorded
    _assert_no_hostile_hooks()


def test_stage1785_claim_and_publication_evidence_reject_without_hooks():
    _reset_hostile_counters()
    info = unreadable_claim_meta_info(
        HostileError("unsafe"),
        now=HostileValue(),
        marker=HostileValue(),
    )
    queue_info = info["queue_info"]
    assert queue_info["claim_meta_unreadable"] is True
    assert queue_info["claim_meta_time_unavailable"]
    assert queue_info["claim_meta_marker_unavailable"]

    merged = merge_claim_meta_into_job(
        "claim.json",
        HostileValue(),
        read_claim_meta=lambda _path: HostileValue(),
    )
    assert merged["queue_info"]["claim_meta_job_rejected"] is True
    assert merged["queue_info"]["claim_meta_result_rejected"] is True

    with pytest.raises(RuntimeError, match="scheduler_publication_job_id_rejected"):
        QueuePublicationState.empty().with_publication({
            "job_id": HostileValue(),
            "file": "sample.bin",
        })
    exact = QueuePublicationState.empty().with_publication({
        "job_id": "job-1",
        "file": "sample.bin",
    })
    assert exact.job_identities == frozenset({"job-1"})
    _assert_no_hostile_hooks()


def test_stage1785_identity_publish_and_result_merge_reject_without_hooks(
    tmp_path,
):
    _reset_hostile_counters()
    recorded = []
    with patch.object(
        identity_index,
        "record_scheduler_suppressed",
        lambda where, error: recorded.append((where, error)),
    ):
        identity_index.set_index_entry(
            (tmp_path, "pending"),
            {HostileValue()},
        )
    assert not tuple((tmp_path / "identity_index").glob("*.json"))

    cursor, enqueued, skipped = _write_process_queue_jobs_slice(
        tmp_path / "queue",
        [],
        0,
        HostileValue(),
        record_suppressed=lambda where, error, **kwargs: recorded.append((where, error)),
    )
    assert (cursor, enqueued, skipped) == (0, 0, 0)

    reports = []
    with pytest.raises(QueueResultMergeError):
        load_queue_file_results(
            tmp_path,
            file_results_dir=lambda _queue_dir: tmp_path,
            safe_listdir=lambda _path: [HostileValue()],
            read_json=lambda _path, default=None: default,
            report=lambda *args, **kwargs: reports.append((args, kwargs)),
        )
    assert recorded
    assert reports
    _assert_no_hostile_hooks()


def test_stage1785_cost_and_timeout_inspection_emit_explicit_rejection_evidence():
    _reset_hostile_counters()
    hostile = HostileValue()
    cost = stage_cost.estimate_stage_file_cost(hostile)
    assert cost["stage"] == "unknown"
    assert cost["heavy"] is True
    assert cost["cost_evidence"]["scheduler_stage_cost_degraded"] is True

    pixels, pixel_error = image_pixel_count(hostile)
    assert pixels is None
    assert pixel_error.startswith("image_path_unavailable:")
    metrics = archive_metrics(hostile, 100)
    assert metrics["inspection_error"].startswith("archive_path_unavailable:")
    assert metrics["nested_archive_count"] is None
    _assert_no_hostile_hooks()


def test_stage1785_execution_and_orchestration_producers_reject_without_hooks():
    _reset_hostile_counters()
    hostile = HostileValue()
    request = SimpleNamespace(
        per_file_timeout_sec=20,
        use_signal_timeout=False,
        yara_enabled=False,
        compiled_rules=None,
        previous_stage="previous",
        root=".",
        routing_evidence_context=None,
        artifact_read_snapshot=None,
        slow_file_warn_sec=0.0,
    )
    deps = SimpleNamespace(
        should_escalate_after_triage=lambda *args, **kwargs: False,
        get_scan_extension=lambda _path: ".bin",
        deep_scan_thorough=lambda: False,
        contextual_dangerous_anchor_hits=lambda _tags: False,
        record_runtime_suppressed=lambda *args, **kwargs: None,
        recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        compute_timeout_budget=lambda *args, **kwargs: SimpleNamespace(
            hard_timeout_seconds=20,
        ),
        nullcontext_factory=nullcontext,
        normalize_yara_hits=lambda hits: hits,
    )
    with pytest.raises(
        ValueError,
        match="scheduler_execution_global_raw_info_mapping_rejected",
    ):
        execute_scheduler_file_analysis(
            request=request,
            deps=deps,
            path="sample.bin",
            started_file=0.0,
            tags=(),
            suspicious=False,
            curr_stage="binary",
            router_identity=None,
            route_tag_evidence=TagEvidence(),
            prefilter_info={},
            global_raw_info=hostile,
        )

    terminal_deps = SimpleNamespace(
        terminal_asset_triage=lambda _tags, suspicious=False: True,
        make_terminal_asset_result=lambda *args, **kwargs: {
            "trusted_benign": hostile,
        },
        attach_routing_evidence_to_record=lambda result, *args, **kwargs: result,
    )
    with pytest.raises(
        ValueError,
        match="scheduler_execution_trusted_benign_bool_rejected",
    ):
        maybe_return_terminal_result(
            request=request,
            deps=terminal_deps,
            path="sample.bin",
            started_file=0.0,
            tags=(),
            suspicious=False,
            curr_stage="binary",
            router_identity=None,
            active_timeout_budget=SimpleNamespace(as_evidence=lambda: {}),
            cache_sha256="abc",
        )

    with pytest.raises(ValueError, match="scheduler_requested_mode_rejected"):
        plan_scheduler_targets(
            SchedulerTargetPlanningRequest(
                root=".",
                scheduler_requested=hostile,
            ),
            log_error=lambda _message: None,
            logging_module=SimpleNamespace(info=lambda *args, **kwargs: None),
        )

    dispatch_request = SchedulerModeDispatchRequest(
        scheduler=hostile,
        workers=1,
        root=".",
        all_files=(),
        total_files=0,
        scan_started_at=0.0,
        strict=False,
        yara_enabled=False,
        progress_every=1,
        throttle_sec=0.0,
        partial_output_path=None,
        partial_output_every=1,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=20.0,
        work_queue_dir=None,
        worker_output_path=None,

        scan_session_snapshot=scan_session_snapshot_fixture(),    )
    with pytest.raises(ValueError, match="scheduler_mode_rejected"):
        run_scheduler_mode(
            dispatch_request,
            SchedulerModeDispatchDependencies(
                worker=lambda _path: None,
                write_partial=lambda: None,
                result_retainer=lambda _path, result: result,
                derived_cache_writer=lambda _result: False,
            ),
        )
    _assert_no_hostile_hooks()


def test_stage1785_startup_raw_eligibility_and_budget_evidence_reject_without_hooks():
    _reset_hostile_counters()
    hostile = HostileValue()
    with pytest.raises(ValueError, match="scheduler_startup_mode_rejected"):
        SchedulerStartupSnapshot(hostile, False)
    with pytest.raises(ValueError, match="raw_queue_enabled_flag_rejected"):
        global_raw_eligible(
            "sample.bin",
            raw_queue_enabled=lambda: hostile,
            raw_queue_min_bytes=lambda: 1,
            get_size=lambda _path: 100,
            get_scan_extension=lambda _path: ".bin",
            normalize_stage=lambda _ext: "binary",
            runtime_value=lambda *args: False,
        )
    evidence = stage_budget_failure_evidence(hostile, hostile, hostile)
    assert evidence["state"] == "failed"
    assert evidence["context"]["boundary_reasons"]
    _assert_no_hostile_hooks()


def test_stage1785_progress_and_replay_boundaries_reject_without_hooks():
    _reset_hostile_counters()
    hostile = HostileValue()
    with pytest.raises(ValueError, match="scheduler_progress_counts_mapping_rejected"):
        snapshot_process_queue_progress_counts(
            "queue",
            progress_counts=lambda _queue_dir: hostile,
        )
    with pytest.raises(
        ValueError,
        match="scheduler_monitor_progress_every_rejected",
    ):
        ProcessQueueMonitorProgressRequest(
            outputs=(),
            partial_output_path=None,
            file_done_count=0,
            file_failed_count=0,
            file_active_count=0,
            file_pending_count=0,
            raw_live=0,
            raw_done=0,
            raw_failed=0,
            live_workers=0,
            total_files=0,
            progress_every=hostile,
            last_done_count=0,
            last_progress_time=0.0,
            progress_interval_sec=1.0,
            last_monitor_heartbeat_time=0.0,
            monitor_heartbeat_sec=1.0,
            accounted_total=0,
            elastic_cpu_sample=None,
            now=0.0,
        )
    with pytest.raises(Exception, match="invalid hybrid queue directory"):
        hybrid_queue_key(hostile)
    with pytest.raises(TypeError, match="exact ReplaySnapshot"):
        build_replay_mismatches(hostile, ReplaySnapshot())

    expected = ReplaySnapshot(
        replay_id="expected",
        records=({"job_id": "job-1", "status": "ok"},),
    )
    actual = ReplaySnapshot(
        replay_id="actual",
        records=({"job_id": "job-1", "status": "failed"},),
    )
    mismatches = build_replay_mismatches(expected, actual)
    assert mismatches[0]["field"] == "status"
    _assert_no_hostile_hooks()


def test_stage1785_startup_integrity_retry_and_publish_boundaries_reject_without_hooks():
    _reset_hostile_counters()
    hostile = HostileValue()
    with pytest.raises(
        ValueError,
        match="process_queue_startup_file_rejected",
    ):
        ProcessQueueStartupRequest(
            root=".",
            all_files=(hostile,),
            process_count=1,
            strict=False,
            progress_every=1,
            throttle_sec=0.0,
            partial_output_every=1,
            slow_file_warn_sec=0.0,
            per_file_timeout_sec=1.0,
            scan_session_snapshot=scan_session_snapshot_fixture(),
        )
    with pytest.raises(ValueError, match="missing state"):
        QueueIdentityRecord.from_observation(
            state=hostile,
            path="job.json",
            name="job.json",
            job={},
        )
    with pytest.raises(ValueError, match="inmemory_retry_job_id_rejected"):
        retry_missing_record_evidence(
            job_id=hostile,
            reason="retry",
            record=None,
        )
    callback_calls = []
    with pytest.raises(ValueError, match="invalid process queue publish path"):
        build_process_queue_publish_attempt(
            ProcessQueuePublishAttemptRequest(
                order=0,
                original_index=0,
                file_path=hostile,
                workload_class="generic",
                queue_file_identity_for_path=lambda _path: callback_calls.append(
                    "identity"
                ),
                process_weight_for_path=lambda _path: callback_calls.append(
                    "weight"
                ),
            )
        )
    assert callback_calls == []
    with pytest.raises(
        ValueError,
        match="process_queue_publish_published_rejected",
    ):
        ProcessQueuePublishResult(published=hostile)
    _assert_no_hostile_hooks()


def test_stage1785_repaired_scheduler_routes_forbid_old_raw_patterns():
    forbidden = {
        "execution/target_collection.py": (
            "str(root)",
            "str(item)",
            "if file_list_path:",
        ),
        "execution/triage_escalation.py": (
            "str(t)",
            "(tags or ())",
            "bool(suspicious)",
            "prefilter_info or {}",
        ),
        "runtime/raw_escalation_policy.py": (
            "str(tag)",
            "tags or []",
            "bool(suspicious)",
        ),
        "queue/claim_meta.py": (
            '"claim_meta_error": str(exc)',
            '"progress_marker": str(marker)',
            '"heartbeat_time": float(now)',
        ),
        "queue/identity_index.py": (
            "os.fspath(key[0])",
            "[str(part)",
            "{str(item)",
            "float(payload.get",
        ),
        "queue/publication_state.py": (
            "str(value or",
            "str(result.get",
            "frozenset(str(item)",
        ),
        "queue/publish.py": (
            "repr(max_new)",
            "int(max_new or 0)",
            "int(cursor or 0)",
        ),
        "queue/result_merge.py": (
            "str(file_key)",
            "str(file_path)",
            "str(name)",
        ),
        "runtime/stage_cost.py": (
            "str(path or",
            "float(duration_sec or",
            "float(rss_mb or",
        ),
        "execution/scheduler_file_analysis.py": (
            "str((global_raw_info or {})",
            "bool(global_raw_info)",
            "bool(result.get",
            "str(path)",
        ),
        "execution/scheduler_file_terminal.py": (
            "bool(result.get",
            "str(path)",
        ),
        "orchestration/scheduler_mode_dispatch.py": (
            "str(request.scheduler or",
            "int(value or 0)",
        ),
        "orchestration/scheduler_target_planning.py": (
            "str(request.scheduler_requested or",
            "int(request.max_files)",
        ),
        "ownership/raw_stage_eligibility.py": (
            "bool(runtime_value",
            "str(effective_stage or",
        ),
        "runtime/startup_defaults.py": (
            "str(self.scheduler_mode or",
            "bool(self.process_requested)",
        ),
        "runtime/stage_budget_tables.py": (
            "str(category or",
            "str(message or",
            "type(exc).__name__",
        ),
        "evidence/process_queue_progress_counts.py": (
            "dict(progress_counts(queue_dir))",
            'int(counts["file_done"])',
        ),
        "evidence/process_queue_monitor_progress.py": (
            "int(request.progress_every or 10)",
        ),
        "evidence/records.py": (
            "bool(record.get",
            "bool(self.records)",
        ),
        "replay/replay_snapshot.py": (
            "os.fspath(queue_dir)",
            "{queue_dir!r}",
        ),
        "replay/replay_mismatch.py": (
            "snapshot.as_dict()",
            "str(record.get",
        ),
        "timeout/timeout_workload_inspection.py": (
            "os.fspath(path or",
        ),
    }
    scheduler_root = Path(stage_cost.__file__).parents[1]
    for relative_path, patterns in forbidden.items():
        source = (scheduler_root / relative_path).read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern not in source, f"{relative_path}: {pattern}"
