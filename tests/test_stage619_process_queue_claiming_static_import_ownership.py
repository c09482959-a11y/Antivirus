from pathlib import Path

from Virus_Scan.scheduler.queue import claim as process_queue_claiming


def test_process_queue_claiming_exports_only_claim_authority_api():
    assert process_queue_claiming.__all__ == (
        "claim_process_queue_file_job",
        "claim_process_queue_job",
        "claim_process_queue_job_matching",
    )
    assert not hasattr(process_queue_claiming, "_ensure_process_queue_dirs") or "_ensure_process_queue_dirs" not in process_queue_claiming.__all__
    assert not hasattr(process_queue_claiming, "_claim_process_queue_job")
    assert not hasattr(process_queue_claiming, "_claim_process_queue_file_job")
    assert not hasattr(process_queue_claiming, "_claim_process_queue_job_matching")


def test_process_queue_claiming_has_no_dead_runtime_or_queue_authority_imports():
    source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    forbidden = [
        "compute_timeout_budget",
        "reset_queue_retry_runtime_metadata",
        "classify_workload",
        "_process_weight_for_path",
        "_queue_file_identity_for_path",
        "_queue_retire_dir",
        "_queue_claim_meta_path",
        "_queue_failure_diagnostics_dir",
        "_queue_write_json_replace",
        "_record_process_queue_failure",
        "validate_persistent_record_semantics",
        "verify_persistent_json_file",
        "_queue_identity_index_note",
        "_queue_acquire_identity_lock",
        "_queue_identity_index_invalidate",
        "_queue_release_identity_lock",
        "_umige_terminate_queue_worker_pid",
        "_process_queue_pid_is_alive",
        "_process_queue_cleanup_diagnostic_tmp_files",
        "_process_queue_env_float_value",
        "_process_queue_env_int_value",
        "_process_queue_log_error",
        "_process_queue_record_suppressed",
        "from Virus_Scan.scheduler.queue.process_queue_finalization import _finish_process_queue_job\n\n__all__",
    ]
    for text in forbidden:
        assert text not in source


def test_process_queue_claiming_handles_claim_exception_without_terminal_reconciliation_import():
    source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    assert "from Virus_Scan.scheduler.queue.process_queue_finalization import _finish_process_queue_job" not in source
    assert "process_queue_finish_claim_failure" not in source
    assert "_queue_finish_claim_failure" not in source
    assert "_queue_quarantine_invalid_claim" in source
    assert "queue_claim_matching_exception_quarantine_failed" in source
    assert "def _queue_return_active_claim_to_pending" not in source
