import Virus_Scan.scheduler.queue.orphan_recovery as orphan_recovery
import Virus_Scan.scheduler.queue.orphan_recovery_gates as gates
import Virus_Scan.scheduler.queue.orphan_recovery_timeout as timeout

from pathlib import Path
import inspect

from Virus_Scan.scheduler.queue import diagnostics, integrity_pipeline, issue_reporting, progress, quarantine, results


def test_process_queue_support_surface_removed_and_split_to_queue_owners():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "scheduler" / "queue" / "process_queue_support.py").exists()
    for module in (diagnostics, integrity_pipeline, issue_reporting, progress, quarantine, results):
        assert Path(module.__file__).parts[-3:-1] == ("scheduler", "queue")


def test_split_queue_support_modules_expose_canonical_behaviors():
    assert hasattr(issue_reporting, "record_raw_queue_issue")
    assert not hasattr(issue_reporting, "_stage122_record_raw_queue_issue")
    assert hasattr(diagnostics, "queue_cleanup_diagnostic_tmp_files")
    assert not hasattr(diagnostics, "_queue_cleanup_diagnostic_tmp_files")
    assert hasattr(integrity_pipeline, "queue_integrity_verify_and_repair")
    assert not hasattr(integrity_pipeline, "_queue_integrity_verify_and_repair")
    assert hasattr(progress, "queue_progress_counts_global")
    assert not hasattr(progress, "_queue_progress_counts_global")
    assert hasattr(quarantine, "_queue_quarantine_job")
    assert hasattr(results, "load_queue_file_results")
    assert not hasattr(results, "_load_queue_file_results")


def test_orphan_recovery_delegates_raw_and_timeout_policy_to_bounded_modules():

    source = inspect.getsource(orphan_recovery)
    assert "apply_raw_stage_reclaim_gate" in source
    assert "apply_raw_owner_reclaim_gate" in source
    assert "classify_reclaim_timeout" in source
    assert hasattr(gates, "apply_raw_stage_reclaim_gate")
    assert hasattr(timeout, "build_reclaim_failure_info")
