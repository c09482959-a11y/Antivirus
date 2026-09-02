from pathlib import Path

from Virus_Scan.scheduler.api.runner import run_pipeline_safe
from Virus_Scan.scheduler.orchestration.process_queue_startup import ProcessQueueStartupRequest
from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import SchedulerModeDispatchRequest
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.process_scheduler_capacity import (
    process_scheduler_test_capacity,
)


def _dispatch_request(tmp_path: Path) -> SchedulerModeDispatchRequest:
    return SchedulerModeDispatchRequest(
        scheduler="process",
        workers=2,
        root=tmp_path,
        all_files=(),
        total_files=0,
        scan_started_at=0.0,
        strict=False,
        yara_enabled=False,
        progress_every=1,
        throttle_sec=0.0,
        partial_output_path=tmp_path / "results.json",
        partial_output_every=0,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=20.0,
        work_queue_dir=tmp_path / "queue",
        worker_output_path=tmp_path / "worker.json",
        scan_session_snapshot=scan_session_snapshot_fixture(),
    )


def _worker_pool(tmp_path: Path) -> ProcessQueueParentWorkerPool:
    return ProcessQueueParentWorkerPool(
        root=tmp_path,
        queue_dir=tmp_path / "queue",
        outputs_dir=tmp_path / "outputs",
        script_path="child.py",
        python_executable="python",
        env_base={},
        progress_every=1,
        partial_output_every=0,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=20.0,
        throttle_sec=0.0,
        strict=False,
        subprocess_stdin=lambda: None,
        windows_creationflags=lambda: 0,
        log_error=lambda _message: None,
        recoverable_exceptions=(Exception,),
        scan_session_manifest_path=tmp_path / "scan-session.json",
    )


def test_zero_partial_interval_survives_all_scheduler_contracts(tmp_path: Path) -> None:
    dispatch = _dispatch_request(tmp_path)
    startup = ProcessQueueStartupRequest(
        root=tmp_path,
        all_files=(),
        process_count=1,
        strict=False,
        progress_every=1,
        throttle_sec=0.0,
        partial_output_every=0,
        slow_file_warn_sec=0.0,
        per_file_timeout_sec=20.0,
        scan_session_snapshot=scan_session_snapshot_fixture(),
    )
    pool = _worker_pool(tmp_path)

    assert dispatch.partial_output_every == 0
    assert startup.partial_output_every == 0
    assert pool.partial_output_every == 0


def test_process_scheduler_zero_interval_creates_no_partial_checkpoint(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.write_text("benign documentation only", encoding="utf-8")
    output = tmp_path / "results.json"

    with process_scheduler_test_capacity():
        results = run_pipeline_safe(
            str(tmp_path),
            scheduler="process",
            max_workers=2,
            yara_enabled=False,
            freeze_existing_baselines=False,
            per_file_timeout_sec=20,
            partial_output_path=str(output),
            partial_output_every=0,
        )

    assert str(target) in results
    assert not Path(str(output) + ".partial").exists()
    assert not Path(str(output) + ".partial.checkpoint.json").exists()
