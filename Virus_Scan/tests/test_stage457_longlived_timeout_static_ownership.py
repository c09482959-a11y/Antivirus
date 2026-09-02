from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.detection.enrichment.prefilter.scan import strict_fast_prefilter
from Virus_Scan.scheduler.workers.heartbeat import cooperative_cancel_requested
from Virus_Scan.scheduler.orchestration import inmemory_parent_loop
from Virus_Scan.scheduler.orchestration import inmemory_parent_setup_recovery
from Virus_Scan.scheduler.orchestration.inmemory_parent_loop import _run_longlived_process_queue
from Virus_Scan.scheduler.runtime.stage_budget import record_stage_cost_observation
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.process_scheduler_capacity import (
    process_scheduler_test_environment,
)


def test_strict_fast_prefilter_owns_static_constants(tmp_path):
    target = tmp_path / "boring.txt"
    target.write_text("ordinary notes\n", encoding="utf-8")
    info = strict_fast_prefilter(str(target), compiled_rules=None, artifact_read_snapshot=artifact_read_snapshot_fixture(target))
    assert isinstance(info, dict)
    assert "force_full" in info


def test_shared_memory_cancel_uses_owned_heartbeat_constants():
    table = {"generation": [0], "flags": [0]}
    assert cooperative_cancel_requested(table, 0, 0) is False


def test_stage_cost_observation_has_static_extension_owner(tmp_path):
    target = tmp_path / "image.png"
    target.write_bytes(b"not-a-real-png")
    assert record_stage_cost_observation(path=str(target), cost={"stage": "image"}, duration_sec=0.01) is not None


def test_longlived_process_queue_attaches_routing_evidence(tmp_path):
    files = []
    for idx in range(4):
        p = tmp_path / f"img_{idx}.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes([idx]) * 64)
        files.append(str(p))
    results = _run_longlived_process_queue(
        str(tmp_path),
        files,
        process_count=1,
        progress_every=1,
        slow_file_warn_sec=999.0,
        per_file_timeout_sec=20,
        result_retainer=lambda _path, result: result,
        derived_cache_writer=lambda _result: False,
        scan_session_snapshot=scan_session_snapshot_fixture(scan_mode="process"),
        environ=process_scheduler_test_environment({"UMIGE_INMEMORY_MAX_JOBS_PER_WORKER": "25"}),
    )
    assert set(results) == set(files)
    required = {"container_engine", "artifact_engine", "baseline_key", "sniffed_type", "effective_analysis_engine"}
    assert all(required.issubset(set(record)) for record in results.values())


def test_longlived_process_queue_permission_denied_setup_uses_direct_recovery(tmp_path):
    target = tmp_path / "direct_recovery.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"r" * 64)

    def denied_setup(*_args, **_kwargs):
        raise PermissionError("named pipe unavailable")

    def fake_scan(path, cfg):
        assert cfg is not None
        return path, {
            "tags": ["image"],
            "effective_stage": "image",
            "timeout_evidence": {},
            "container_engine": "image",
            "artifact_engine": "image",
            "baseline_key": "image",
            "sniffed_type": "png",
            "effective_analysis_engine": "image",
        }

    original_setup = inmemory_parent_loop._build_longlived_parent_runtime
    original_scan = inmemory_parent_setup_recovery.execute_inmemory_scan_one_file
    inmemory_parent_loop._build_longlived_parent_runtime = denied_setup
    inmemory_parent_setup_recovery.execute_inmemory_scan_one_file = fake_scan
    try:
        results = _run_longlived_process_queue(
            str(tmp_path),
            [str(target)],
            process_count=1,
            progress_every=1,
            slow_file_warn_sec=999.0,
            per_file_timeout_sec=20,
            result_retainer=lambda _path, result: result,
            derived_cache_writer=lambda _result: False,
            scan_session_snapshot=scan_session_snapshot_fixture(scan_mode="process"),
        )

        result = results[str(target)]
        assert result["timeout_evidence"]["scheduler_mode"] == "process-setup-recovery"
        assert result["timeout_evidence"]["worker_state"] == "queue_worker_alive"
    finally:
        inmemory_parent_loop._build_longlived_parent_runtime = original_setup
        inmemory_parent_setup_recovery.execute_inmemory_scan_one_file = original_scan
