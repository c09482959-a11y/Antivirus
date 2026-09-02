from pathlib import Path

from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue import dirs as process_queue_dirs


def test_stage622_invalid_claim_quarantine_owned_by_process_queue_dirs():
    claiming_source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    authority_source = Path(process_queue_dirs.__file__).read_text(encoding="utf-8")

    assert "_queue_quarantine_invalid_claim" not in process_queue_claiming.__all__
    assert "def _queue_quarantine_invalid_claim" not in claiming_source
    assert "process_queue_quarantine_invalid_claim as _queue_quarantine_invalid_claim" in claiming_source
    assert "process_queue_quarantine_job as _queue_quarantine_job" not in claiming_source
    assert "_queue_safe_remove_claim_meta" not in claiming_source

    assert hasattr(process_queue_dirs, "process_queue_quarantine_invalid_claim")
    assert "def process_queue_quarantine_invalid_claim" in authority_source
    assert "_queue_safe_remove_claim_meta" in authority_source
