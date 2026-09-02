from pathlib import Path

from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue import claim_failures


def test_stage621_process_queue_claiming_uses_canonical_failure_info_owner():
    claim_source = Path(process_queue_claiming.__file__).read_text(encoding="utf-8")
    failure_source = Path(claim_failures.__file__).read_text(encoding="utf-8")

    assert "process_queue_default_failure_info(" not in claim_source
    assert "queue_default_failure_info(" not in claim_source
    assert "claim_failure_info(" in claim_source
    assert "processqueue_default_failure_info(" in failure_source
    assert "from Virus_Scan.scheduler.queue.claim_failures import" in claim_source


def test_stage621_process_queue_claiming_exports_only_claim_functions():
    assert process_queue_claiming.__all__ == (
        "claim_process_queue_file_job",
        "claim_process_queue_job",
        "claim_process_queue_job_matching",
    )
