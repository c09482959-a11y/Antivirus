from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext
import pytest
from typing import Any, cast

from Virus_Scan.scheduler.orchestration.process_queue_child_mode import ProcessQueueChildModeResult
from Virus_Scan.scheduler.orchestration.process_queue_completion import ProcessQueueCompletionResult
from Virus_Scan.scheduler.ownership.process_queue_dynamic_feed import (
    ProcessQueueDynamicFeedOutput,
    ProcessQueueDynamicFeedRequest,
)
from Virus_Scan.scheduler.queue.process_queue_result_merge import ProcessQueueResultMergeOutput
from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryOutput,
    ProcessQueueStaleRecoveryRequest,
)
from Virus_Scan.scheduler.workers.inmemory_runtime_config import InMemoryRuntimeConfigSnapshot
from Virus_Scan.scheduler.workers.inmemory_heartbeat_flags import build_inmemory_heartbeat_flags


from Virus_Scan.orchestration.yara_initialization import initialize_yara_worker_runtime
from Virus_Scan.orchestration.worker_runtime_descriptors import (
    WorkerYaraRuntimeDescriptor,
)

def _disabled_yara_descriptor() -> WorkerYaraRuntimeDescriptor:
    return WorkerYaraRuntimeDescriptor(
        initializer=initialize_yara_worker_runtime,
        root="/tmp/yara",
        enabled=False,
        available=False,
        scan_mode="auto",
        package_kind="",
        source_path="",
        source_digest="",
        compiled_cache_digest="",
        rule_catalog_digest="",
        unavailable_reason="yara_disabled",
    )


def test_phase9_process_queue_result_boundaries_freeze_mutable_inputs():
    merged = {"file.exe": {"tags": ["a"]}}
    exit_evidence = ({"stage": "exit", "detail": {"pid": 123}},)
    completion = ProcessQueueCompletionResult(merged=merged, had_error=False, worker_exit_evidence=exit_evidence)
    merge_output = ProcessQueueResultMergeOutput(merged=merged, had_error=False)
    child_output = ProcessQueueChildModeResult(results=merged)

    merged["file.exe"]["tags"].append("mutated")
    exit_evidence[0]["detail"]["pid"] = 999

    assert tuple(completion.merged["file.exe"]["tags"]) == ("a",)
    assert completion.worker_exit_evidence[0]["detail"]["pid"] == 123
    assert tuple(merge_output.merged["file.exe"]["tags"]) == ("a",)
    assert tuple(child_output.results["file.exe"]["tags"]) == ("a",)
    with pytest.raises(TypeError):
        cast(dict[str, Any], completion.merged)["file.exe"] = {}


def test_phase9_dynamic_feed_and_stale_recovery_boundaries_freeze_inputs():
    env = {"UMIGE": "1"}
    io_sample = {"pressure": False, "reasons": ["initial"]}
    request = ProcessQueueDynamicFeedRequest(
        enabled=True,
        queue_dir="queue",
        ordered_queue_items=("a",),
        queue_feed_cursor=0,
        queue_total_enqueued=0,
        queue_enqueued_identities=(),
        target_workers=1,
        file_active_count=0,
        file_pending_count=0,
        io_pressure=False,
        cpu_sample=None,
        elastic_io_sample=io_sample,
        all_files_count=1,
        raw_live=0,
        current_time=0.0,
        queue_last_feed_log=0.0,
        env=env,
    )
    output = ProcessQueueDynamicFeedOutput(
        queue_feed_cursor=1,
        queue_total_enqueued=1,
        queue_enqueued_identities=("id",),
        queue_last_feed_log=0.0,
        counts={"pending": 1},
    )
    stale_request = ProcessQueueStaleRecoveryRequest(
        queue_dir="queue",
        progress_stall_sec=1.0,
        per_file_timeout_sec=2.0,
        raw_stage_progress_state={"raw": (1, 2.0)},
    )
    stale_output = ProcessQueueStaleRecoveryOutput(
        recovered={"active": 1},
        raw_stage_progress_state={"raw": (1, 2.0)},
        evidence=({"stage": "stale", "tags": ["x"]},),
    )

    env["UMIGE"] = "mutated"
    io_sample["reasons"].append("mutated")

    assert request.env["UMIGE"] == "1"
    assert tuple(request.elastic_io_sample["reasons"]) == ("initial",)
    assert output.counts["pending"] == 1
    assert stale_request.raw_stage_progress_state["raw"] == (1, 2.0)
    assert stale_output.recovered["active"] == 1
    assert tuple(stale_output.evidence[0]["tags"]) == ("x",)
    with pytest.raises(TypeError):
        cast(dict[str, int], output.counts)["pending"] = 2


def test_phase9_inmemory_runtime_config_freezes_scalar_snapshot_mappings_but_preserves_ipc_tables():
    cancel_table = {"cancel": False}
    heartbeat_table = {"worker": "live"}
    stage_limits = {"raw": 3}
    semaphores = {"raw": object()}
    snapshot = InMemoryRuntimeConfigSnapshot(
        strict=True,
        yara_enabled=False,
        scan_cache_enabled=False,
        yara_runtime_descriptor=_disabled_yara_descriptor(),
        per_file_timeout_sec=30,
        slow_file_warn_sec=5.0,
        deep_scan_mode="fast",
        worker_threads=1,
        worker_threads_base=1,
        worker_threads_max=2,
        cancel_table=cancel_table,
        heartbeat_table=heartbeat_table,
        heartbeat_interval_sec=1.0,
        stage_semaphores=semaphores,
        stage_limits=stage_limits,
        max_jobs_per_worker=4,
        worker_rss_limit_mb=1024.0,
        heartbeat_flags=build_inmemory_heartbeat_flags(lambda name, default=None: default),
        timeout_budget_factory=lambda *a, **k: 1.0,
        timeout_result_annotator=lambda result, **k: result,
        timeout_error_type=TimeoutError,
        mitre_initializer=lambda **_kwargs: None,
        mitre_root="/tmp/mitre",
        mitre_enabled=False,
        mitre_available=False,
        mitre_repository_digest="",
        mitre_dataset_version="",
        mitre_unavailable_reason="mitre_disabled",

        scan_session_snapshot=scan_session_snapshot_fixture(),
        routing_evidence_context=RoutingEvidenceContext.build("/tmp"),
    )
    stage_limits["raw"] = 99
    semaphores["extra"] = object()

    assert snapshot.stage_limits["raw"] == 3
    assert "extra" not in snapshot.stage_semaphores
    payload = snapshot.as_worker_config()
    assert payload["scan_cache_enabled"] is False
    assert payload["cancel_table"] is cancel_table
    assert payload["heartbeat_table"] is heartbeat_table
    assert payload["stage_limits"] == {"raw": 3}
