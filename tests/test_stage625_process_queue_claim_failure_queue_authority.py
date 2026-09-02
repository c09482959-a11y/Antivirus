from pathlib import Path

from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue import dirs as process_queue_dirs


def test_stage625_claiming_does_not_import_reconciliation_finalization_directly():
    claiming_source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    assert "process_queue_finalization" not in claiming_source
    assert "_finish_process_queue_job" not in claiming_source
    assert "process_queue_finish_claim_failure" not in claiming_source


def test_stage625_process_queue_dirs_does_not_own_terminal_reconciliation():
    authority_source = Path(process_queue_dirs.__file__).read_text(encoding="utf-8")
    assert not hasattr(process_queue_dirs, "process_queue_finish_claim_failure")
    assert "def process_queue_finish_claim_failure" not in authority_source
    assert "_queue_finish_process_queue_job" not in authority_source
    assert "queue_claim_failure_finalization_failed" not in authority_source


def test_stage625_claim_exception_uses_queue_quarantine_not_terminal_finalization():
    claiming_source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    assert "queue_claim_matching_exception" in claiming_source
    assert "_queue_quarantine_invalid_claim" in claiming_source
    assert "queue_claim_matching_exception_quarantine_failed" in claiming_source
