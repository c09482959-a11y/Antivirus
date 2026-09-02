from pathlib import Path

from Virus_Scan.scheduler.queue import dirs as process_queue_dirs


def test_stage625_diagnostic_tmp_cleanup_owned_by_process_queue_dirs():
    authority_source = Path(process_queue_dirs.__file__).read_text(encoding="utf-8")
    assert hasattr(process_queue_dirs, "cleanup_diagnostic_tmp_files")
    assert "def cleanup_diagnostic_tmp_files" in authority_source
    assert "process_queue_diagnostic_tmp_cleanup" in authority_source


def test_stage625_reconciliation_process_queue_cleanup_module_deleted():
    old_path = Path("Virus_Scan/scheduler/reconciliation/process_queue_cleanup.py")
    orphan_cleanup = Path("Virus_Scan/scheduler/reconciliation/orphan_cleanup.py")
    assert not old_path.exists()
    assert not orphan_cleanup.exists()
