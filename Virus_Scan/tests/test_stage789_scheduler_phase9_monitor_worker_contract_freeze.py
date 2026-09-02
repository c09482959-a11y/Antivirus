from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from pathlib import Path

from Virus_Scan.scheduler.evidence.process_queue_monitor_progress import ProcessQueueMonitorProgressRequest
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.orchestration.process_queue_completion import ProcessQueueCompletionRequest
from Virus_Scan.scheduler.orchestration.process_queue_monitor_progress_publish import MonitorProgressPublicationRequest
from Virus_Scan.scheduler.orchestration.process_queue_monitor_runtime import ProcessQueueMonitorRuntimeState
from Virus_Scan.scheduler.orchestration.process_queue_monitor_stall import MonitorStallRequest, MonitorStallResult
from Virus_Scan.scheduler.orchestration.process_queue_startup_integrity import ProcessQueueStartupIntegrityRequest
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import SchedulerModeDispatchRequest
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import SchedulerTargetPlanningResult
from Virus_Scan.scheduler.workers.cleanup import WorkerExitWaitResult
from Virus_Scan.scheduler.workers.initial_spawn import ProcessQueueInitialSpawnOutput


class _WorkerPool:
    pass


def test_stage789_monitor_runtime_and_stall_contracts_freeze_direct_inputs():
    evidence = [{"stage": "timeout", "details": ["a"]}]
    runtime_state = ProcessQueueMonitorRuntimeState(
        monitor_policy=object(),
        monitor_sleep_sec=0.1,
        per_file_timeout_sec=1.0,
        queue_progress_stall_sec=2.0,
        last_accounted_total=0,
        last_accounted_change_time=1.0,
        idle_done_since=None,
        last_integrity_repair_time=0.0,
        last_monitor_heartbeat_time=1.0,
        idle_grace_sec=2.0,
        idle_notice_sec=2.0,
        progress_interval_sec=15.0,
        timeout_config_evidence=evidence,
    )
    evidence[0]["details"].append("mutated")
    assert materialize_scheduler_mapping(runtime_state.timeout_config_evidence) == [
        {"stage": "timeout", "details": ["a"]}
    ]

    progress = {"raw": {"done": 1}}
    request = MonitorStallRequest(
        worker_pool=_WorkerPool(),
        live_workers=1,
        file_active_count=1,
        file_pending_count=0,
        raw_live=0,
        accounted_total=1,
        last_accounted_total=1,
        last_accounted_change_time=1.0,
        now=2.0,
        queue_progress_stall_sec=30.0,
        queue_dir=Path("queue"),
        raw_stage_progress_state=progress,
        recoverable_exceptions=[RuntimeError],
    )
    progress["raw"]["done"] = 99
    assert materialize_scheduler_mapping(request.raw_stage_progress_state) == {"raw": {"done": 1}}
    assert request.recoverable_exceptions == (RuntimeError,)

    result_evidence = [{"stall": ["initial"]}]
    result = MonitorStallResult(
        last_accounted_total=1,
        last_accounted_change_time=2.0,
        raw_stage_progress_state={"state": {"a": 1}},
        stall_escalation_evidence=result_evidence,
    )
    result_evidence[0]["stall"].append("mutated")
    assert materialize_scheduler_mapping(result.raw_stage_progress_state) == {"state": {"a": 1}}
    assert materialize_scheduler_mapping(result.stall_escalation_evidence) == [
        {"stall": ["initial"]}
    ]


def test_stage789_monitor_progress_completion_startup_and_mode_contracts_freeze_inputs():
    outputs = [["worker-output.json"]]
    progress_request = ProcessQueueMonitorProgressRequest(
        outputs=outputs,
        partial_output_path="partial.json",
        file_done_count=0,
        file_failed_count=0,
        file_active_count=0,
        file_pending_count=1,
        raw_live=0,
        raw_done=0,
        raw_failed=0,
        live_workers=1,
        total_files=1,
        progress_every=10,
        last_done_count=0,
        last_progress_time=1.0,
        progress_interval_sec=15.0,
        last_monitor_heartbeat_time=1.0,
        monitor_heartbeat_sec=30.0,
        accounted_total=0,
        elastic_cpu_sample=None,
        now=1.0,
    )
    outputs[0].append("mutated.json")
    assert materialize_scheduler_mapping(progress_request.outputs) == [["worker-output.json"]]

    completion_files = ["a.bin"]
    completion = ProcessQueueCompletionRequest(
        queue_dir=Path("queue"),
        runtime_dir=Path("runtime"),
        worker_pool=_WorkerPool(),
        all_files=completion_files,
        partial_output_path=None,
        strict=False,
        had_error=False,
    )
    completion_files.append("b.bin")
    assert completion.all_files == ("a.bin",)

    startup_files = ["first"]
    startup = ProcessQueueStartupIntegrityRequest(Path("queue"), startup_files)
    startup_files.append("second")
    assert startup.all_files == ("first",)

    dispatch_files = ["one"]
    dispatch = SchedulerModeDispatchRequest(
        scheduler="serial",
        workers=1,
        root=Path("root"),
        all_files=dispatch_files,
        total_files=1,
        scan_started_at=1.0,
        strict=False,
        yara_enabled=False,
        progress_every=10,
        throttle_sec=0.0,
        partial_output_path=None,
        partial_output_every=10,
        slow_file_warn_sec=2.0,
        per_file_timeout_sec=20.0,
        work_queue_dir=None,
        worker_output_path=None,

        scan_session_snapshot=scan_session_snapshot_fixture(),    )
    dispatch_files.append("two")
    assert dispatch.all_files == ("one",)

    exceptions = [RuntimeError]
    publication = MonitorProgressPublicationRequest(
        worker_pool=_WorkerPool(),
        partial_output_path=None,
        file_done_count=0,
        file_failed_count=0,
        file_active_count=0,
        file_pending_count=1,
        raw_live=0,
        raw_done=0,
        raw_failed=0,
        live_workers=1,
        total_files=1,
        progress_every=10,
        last_done_count=0,
        last_progress_time=1.0,
        progress_interval_sec=15.0,
        last_monitor_heartbeat_time=1.0,
        monitor_heartbeat_sec=30.0,
        accounted_total=0,
        elastic_cpu_sample=None,
        now=1.0,
        recoverable_exceptions=exceptions,
    )
    exceptions.append(ValueError)
    assert publication.recoverable_exceptions == (RuntimeError,)


def test_stage789_worker_cleanup_initial_spawn_and_target_plan_freeze_inputs():
    cleanup_actions = ["terminate"]
    failure_markers = ["timeout"]
    wait_result = WorkerExitWaitResult(
        worker_idx=1,
        pid=123,
        output="worker.json",
        status=4,
        timed_out=True,
        cleanup_actions=cleanup_actions,
        failure_markers=failure_markers,
    )
    cleanup_actions.append("kill")
    failure_markers.append("mutated")
    assert wait_result.cleanup_actions == ("terminate",)
    assert wait_result.failure_markers == ("timeout",)

    io_sample = {"pressure": [False]}
    spawn_failures = [{"worker": [1]}]
    spawn_output = ProcessQueueInitialSpawnOutput(
        next_worker_spawn_id=2,
        initial_cpu_sample=12.5,
        initial_io_sample=io_sample,
        initial_spawn_target=1,
        worker_spawn_failures=spawn_failures,
    )
    io_sample["pressure"].append(True)
    spawn_failures[0]["worker"].append(2)
    assert materialize_scheduler_mapping(spawn_output.initial_io_sample) == {"pressure": [False]}
    assert materialize_scheduler_mapping(spawn_output.worker_spawn_failures) == [{"worker": [1]}]

    plan = {"limits": {"raw": 2}}
    target_result = SchedulerTargetPlanningResult(files=["a", "b"], total_files=2, workload_plan=plan)
    plan["limits"]["raw"] = 99
    assert target_result.files == ("a", "b")
    assert materialize_scheduler_mapping(target_result.workload_plan) == {"limits": {"raw": 2}}
