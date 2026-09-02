from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.process_scheduler_capacity import (
    process_scheduler_test_capacity,
)
from pathlib import Path
import inspect

from Virus_Scan.scheduler.api.runner import run_pipeline_safe
from Virus_Scan.scheduler.orchestration import scheduler_runner
from Virus_Scan.scheduler.orchestration import scheduler_mode_dispatch
from Virus_Scan.scheduler.orchestration import scheduler_mode_recovery
from Virus_Scan.scheduler.orchestration.scheduler_mode_dispatch import run_scheduler_mode
from Virus_Scan.scheduler.orchestration.scheduler_mode_contracts import (
    SchedulerModeDispatchDependencies,
    SchedulerModeDispatchRequest,
)


def _write_png(path: Path) -> None:
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR"
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        b"\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc```\x00\x00\x00\x04\x00\x01"
        b"\x0b\xe7\x02\x9d"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def test_process_scheduler_ignores_threaded_transport_escape(tmp_path):
    assert "UMIGE_PROCESS_TRANSPORT" not in inspect.getsource(scheduler_runner.run_scheduler_pipeline)
    target = tmp_path / "img.png"
    _write_png(target)
    with process_scheduler_test_capacity():
        results = run_pipeline_safe(
            str(tmp_path),
            scheduler="process",
            max_workers=2,
            yara_enabled=False,
            freeze_existing_baselines=False,
            per_file_timeout_sec=20,
            partial_output_path=str(tmp_path / "partial.json"),
            partial_output_every=0,
        )
    assert str(target) in results
    result = results[str(target)]
    assert result.get("timeout_evidence")
    assert result.get("timeout_evidence", {}).get("scheduler_mode") != "process-deterministic-threaded"
    assert result.get("timeout_evidence", {}).get("worker_state") in {"queue_worker_alive_progressing", "queue_worker_alive"}


def test_process_scheduler_permission_denied_setup_recovers_without_threaded_transport(tmp_path):
    target = tmp_path / "img.png"
    _write_png(target)

    def denied_setup(*_args, **_kwargs):
        raise PermissionError("multiprocessing pipe denied")

    def worker(path, _previous_stage, _is_final):
        return path, {"effective_stage": "image", "tags": ["image"]}

    original_runner = scheduler_mode_dispatch._run_longlived_process_queue
    original_maintenance = scheduler_mode_recovery.bulk_scan_maintenance
    original_progress = scheduler_mode_recovery.log_bulk_progress
    scheduler_mode_dispatch._run_longlived_process_queue = denied_setup
    scheduler_mode_recovery.bulk_scan_maintenance = lambda _count: None
    scheduler_mode_recovery.log_bulk_progress = lambda *_args, **_kwargs: None
    try:
        results = scheduler_mode_dispatch.run_scheduler_mode(
            SchedulerModeDispatchRequest(
                scheduler="process",
                workers=2,
                root=tmp_path,
                all_files=(str(target),),
                total_files=1,
                scan_started_at=0.0,
                strict=False,
                yara_enabled=False,
                progress_every=10,
                throttle_sec=0.0,
                partial_output_path=tmp_path / "partial.json",
                partial_output_every=0,
                slow_file_warn_sec=2.0,
                per_file_timeout_sec=20.0,
                work_queue_dir=tmp_path / "queue",
                worker_output_path=tmp_path / "worker.json",

                scan_session_snapshot=scan_session_snapshot_fixture(),            ),
            SchedulerModeDispatchDependencies(
                worker=worker,
                write_partial=lambda _final: None,
                result_retainer=lambda _path, result: result,
                derived_cache_writer=lambda _result: False,
            ),
        )

        result = results[str(target)]
        assert result["timeout_evidence"]["scheduler_mode"] == "process-setup-recovery"
        assert result["timeout_evidence"]["worker_state"] == "queue_worker_alive"
    finally:
        scheduler_mode_dispatch._run_longlived_process_queue = original_runner
        scheduler_mode_recovery.bulk_scan_maintenance = original_maintenance
        scheduler_mode_recovery.log_bulk_progress = original_progress
