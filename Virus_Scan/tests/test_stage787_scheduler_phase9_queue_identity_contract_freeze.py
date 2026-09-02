from pathlib import Path
from typing import Any, cast

import pytest

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.scheduler.execution.process_queue_setup import ProcessQueueSetupOutput, ProcessQueueSetupRequest
from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping
from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import (
    ProcessQueueMonitorLoopRequest,
    ProcessQueueMonitorLoopResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_iteration_start import (
    MonitorIterationStartRequest,
    MonitorIterationStartResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_monitor_scaling_feed import (
    MonitorScalingFeedRequest,
    MonitorScalingFeedResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup import ProcessQueueStartupRequest, ProcessQueueStartupState
from Virus_Scan.scheduler.orchestration.process_queue_startup_admission import (
    ProcessQueueStartupAdmissionRequest,
    ProcessQueueStartupAdmissionResult,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_workers import ProcessQueueStartupWorkerResult
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState


class DummyWorkerPool:
    pass


def test_process_queue_setup_and_startup_outputs_freeze_dynamic_identity_sets():
    all_files: list[str] = ["a.bin"]
    ordered: list[list[Any]] = [[1, 0, {"file": "a.bin"}]]
    identities = {"job-a"}

    request = cast(Any, ProcessQueueSetupRequest)(
        all_files=all_files,
        process_count="2",
        requested_process_count="3",
        dynamic_queue_feed=1,
        env=None,
    )
    setup_output = cast(Any, ProcessQueueSetupOutput)(
        ordered_queue_items=ordered,
        queue_feed_cursor="1",
        queue_enqueued_identities=identities,
        queue_total_enqueued="1",
    )
    startup_request = cast(Any, ProcessQueueStartupRequest)(
        root=".",
        all_files=all_files,
        process_count="2",
        strict=0,
        progress_every="5",
        throttle_sec="0.1",
        partial_output_every="4",
        slow_file_warn_sec="6.0",
        per_file_timeout_sec="7.0",
        scan_session_snapshot=scan_session_snapshot_fixture(),
    )
    startup_state = cast(Any, ProcessQueueStartupState)(
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        runtime_dir=Path("runtime"),
        worker_pool=DummyWorkerPool(),
        ordered_queue_items=ordered,
        queue_feed_cursor="1",
        queue_enqueued_identities=identities,
        queue_total_enqueued="1",
        queue_last_feed_log="0.5",
        raw_stage_progress_state={"counts": {"pending": 1}},
        process_count="2",
        requested_process_count="3",
        dynamic_queue_feed=1,
        elastic_scheduler=0,
        elastic_min_workers="1",
        next_worker_spawn_id="8",
    )
    admission_request = cast(Any, ProcessQueueStartupAdmissionRequest)(
        queue_dir=Path("queue"),
        all_files=all_files,
        process_count="2",
        requested_process_count="3",
        dynamic_queue_feed=1,
    )
    admission_result = cast(Any, ProcessQueueStartupAdmissionResult)(
        ordered_queue_items=ordered,
        queue_feed_cursor="1",
        queue_enqueued_identities=identities,
        queue_total_enqueued="1",
    )

    all_files.append("b.bin")
    ordered[0][2]["file"] = "mutated.bin"
    identities.add("job-b")

    assert request.all_files == ("a.bin",)
    assert setup_output.ordered_queue_items[0][2]["file"] == "a.bin"
    assert setup_output.queue_enqueued_identities == frozenset({"job-a"})
    assert startup_request.all_files == ("a.bin",)
    assert startup_state.ordered_queue_items[0][2]["file"] == "a.bin"
    assert startup_state.queue_enqueued_identities == frozenset({"job-a"})
    assert isinstance(startup_state.raw_stage_progress_state, FrozenSchedulerMapping)
    assert admission_request.all_files == ("a.bin",)
    assert admission_result.ordered_queue_items[0][2]["file"] == "a.bin"
    assert admission_result.queue_enqueued_identities == frozenset({"job-a"})


def test_monitor_loop_iteration_and_scaling_contracts_freeze_identity_and_evidence():
    ordered: list[list[Any]] = [[1, 0, {"file": "a.bin"}]]
    identities = {"job-a"}
    evidence: list[dict[str, Any]] = [{"kind": ["timeout"]}]

    loop_request = cast(Any, ProcessQueueMonitorLoopRequest)(
        queue_dir=Path("queue"),
        outputs_dir=Path("outputs"),
        worker_pool=DummyWorkerPool(),
        all_files=["a.bin"],
        ordered_queue_items=ordered,
        queue_feed_cursor="1",
        queue_enqueued_identities=identities,
        queue_total_enqueued="1",
        queue_last_feed_log="0.5",
        raw_stage_progress_state=None,
        process_count="2",
        requested_process_count="3",
        dynamic_queue_feed=1,
        elastic_scheduler=0,
        next_worker_spawn_id="4",
        progress_every="5",
        partial_output_path=None,
        per_file_timeout_sec="6.0",
    )
    loop_result = cast(Any, ProcessQueueMonitorLoopResult)(had_error=0, timeout_retry_evidence=evidence)
    iteration_request = cast(Any, MonitorIterationStartRequest)(
        worker_pool=DummyWorkerPool(),
        queue_dir=Path("queue"),
        all_files=["a.bin"],
        ordered_queue_items=ordered,
        raw_stage_progress_state=None,
        progress_stall_sec="1.0",
        per_file_timeout_sec="2.0",
        last_integrity_repair_time="3.0",
        elastic_scheduler=1,
        process_count="2",
        requested_process_count="3",
        queue_feed_cursor="1",
        next_worker_spawn_id="4",
        dynamic_queue_feed=1,
        queue_total_enqueued="1",
        queue_enqueued_identities=identities,
        queue_last_feed_log="0.5",
        recoverable_exceptions=(RuntimeError,),
    )
    iteration_result = cast(Any, MonitorIterationStartResult)(
        live_workers="2",
        raw_stage_progress_state=None,
        last_integrity_repair_time="3.0",
        counts=None,
        file_done_count="1",
        file_failed_count="0",
        file_active_count="0",
        file_pending_count="0",
        raw_live="0",
        queue_feed_cursor="1",
        queue_total_enqueued="1",
        queue_enqueued_identities=identities,
        queue_last_feed_log="0.5",
        next_worker_spawn_id="4",
        elastic_cpu_sample=None,
        stale_recovery_evidence=evidence,
    )
    scaling_request = cast(Any, MonitorScalingFeedRequest)(
        worker_pool=DummyWorkerPool(),
        enabled_elastic_scheduler=1,
        process_count="2",
        requested_process_count="3",
        queue_dir=Path("queue"),
        ordered_queue_items=ordered,
        queue_feed_cursor="1",
        file_pending_count="0",
        file_active_count="0",
        raw_live="0",
        live_workers="2",
        next_worker_spawn_id="4",
        dynamic_queue_feed=1,
        queue_total_enqueued="1",
        queue_enqueued_identities=identities,
        elastic_io_sample={"pressure": [False]},
        all_files_count="1",
        queue_last_feed_log="0.5",
        recoverable_exceptions=(RuntimeError,),
    )
    scaling_result = cast(Any, MonitorScalingFeedResult)(
        live_workers="2",
        next_worker_spawn_id="4",
        elastic_target_workers="2",
        elastic_cpu_sample=None,
        elastic_io_sample={"pressure": [False]},
        queue_feed_cursor="1",
        queue_total_enqueued="1",
        queue_enqueued_identities=identities,
        queue_last_feed_log="0.5",
        counts=None,
        worker_spawn_failures=evidence,
    )

    ordered[0][2]["file"] = "mutated.bin"
    identities.add("job-b")
    evidence[0]["kind"].append("mutated")

    assert loop_request.ordered_queue_items[0][2]["file"] == "a.bin"
    assert loop_request.queue_enqueued_identities == frozenset({"job-a"})
    assert loop_result.timeout_retry_evidence[0]["kind"] == ("timeout",)
    assert iteration_request.ordered_queue_items[0][2]["file"] == "a.bin"
    assert iteration_request.queue_enqueued_identities == frozenset({"job-a"})
    assert iteration_result.queue_enqueued_identities == frozenset({"job-a"})
    assert iteration_result.stale_recovery_evidence[0]["kind"] == ("timeout",)
    assert scaling_request.ordered_queue_items[0][2]["file"] == "a.bin"
    assert scaling_request.queue_enqueued_identities == frozenset({"job-a"})
    assert scaling_request.elastic_io_sample["pressure"] == (False,)
    assert scaling_result.queue_enqueued_identities == frozenset({"job-a"})
    assert scaling_result.elastic_io_sample["pressure"] == (False,)
    assert scaling_result.worker_spawn_failures[0]["kind"] == ("timeout",)


def test_publication_and_worker_startup_state_freeze_direct_construction_inputs():
    jobs = {"job-a"}
    files = {"file-a"}
    failures: list[dict[str, Any]] = [{"worker": ["failed"]}]

    publication = cast(Any, QueuePublicationState)(job_identities=jobs, file_identities=files)
    worker_result = cast(Any, ProcessQueueStartupWorkerResult)(
        elastic_scheduler=1,
        elastic_min_workers="1",
        next_worker_spawn_id="2",
        worker_spawn_failures=failures,
    )

    jobs.add("job-b")
    files.add("file-b")
    failures[0]["worker"].append("mutated")

    assert publication.job_identities == frozenset({"job-a"})
    assert publication.file_identities == frozenset({"file-a"})
    with pytest.raises(AttributeError):
        publication.job_identities.add("blocked")  # type: ignore[attr-defined]
    assert worker_result.worker_spawn_failures[0]["worker"] == ("failed",)
