from pathlib import Path

from Virus_Scan.scheduler.queue import dirs as process_queue_dirs


def test_stage625_quarantine_transition_owned_by_process_queue_dirs():
    authority_source = Path(process_queue_dirs.__file__).read_text(encoding="utf-8")
    assert hasattr(process_queue_dirs, "process_queue_quarantine_job")
    assert "def process_queue_quarantine_job" in authority_source
    assert "queue_write_json_replace" in authority_source
    assert "process_queue_quarantine_failed" in authority_source


def test_stage625_reconciliation_quarantine_module_deleted_and_callers_rewritten():
    old_path = Path("Virus_Scan/scheduler/reconciliation/process_queue_quarantine.py")
    orphan_cleanup = Path("Virus_Scan/scheduler/reconciliation/orphan_cleanup.py")
    assert not old_path.exists()
    assert not orphan_cleanup.exists()
