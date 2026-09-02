from pathlib import Path

from Virus_Scan.scheduler.queue import claim as process_queue_claiming
from Virus_Scan.scheduler.queue.claim import claim_process_queue_job_matching


def test_process_queue_claiming_is_owned_by_queue_authority_area():
    path = Path(process_queue_claiming.__file__).as_posix()
    assert "/scheduler/queue/claim.py" in path
    assert "/scheduler/execution/process_queue_claiming.py" not in path


def test_execution_process_queue_claiming_obsolete_path_deleted():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "scheduler" / "execution" / "process_queue_claiming.py").exists()


def test_claim_matching_public_caller_uses_canonical_ownership_module():
    assert claim_process_queue_job_matching.__module__ == "Virus_Scan.scheduler.queue.claim"
    assert not hasattr(process_queue_claiming, "_claim_process_queue_job_matching")
