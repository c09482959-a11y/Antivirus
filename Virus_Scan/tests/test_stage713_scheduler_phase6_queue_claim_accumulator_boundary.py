from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scheduler.queue import authority, claim, raw_accumulator_records, raw_queue_accumulator



def test_stage713_claim_matching_and_accumulator_are_bounded_queue_owners():
    assert claim.claim_process_queue_job.__module__ == "Virus_Scan.scheduler.queue.claim"
    assert claim.claim_process_queue_job_matching.__module__ == "Virus_Scan.scheduler.queue.claim"
    assert not hasattr(claim, "_claim_process_queue_job")
    assert not hasattr(claim, "_claim_process_queue_job_matching")
    assert raw_queue_accumulator.RawAccumulatorStore.__module__ == "Virus_Scan.scheduler.queue.raw_queue_accumulator"
    assert raw_accumulator_records.append_result_record.__module__ == "Virus_Scan.scheduler.queue.raw_accumulator_records"


def test_stage713_old_queue_ownership_surfaces_removed():
    assert not Path("Virus_Scan/scheduler/ownership/claim_meta.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/claim_sidecar.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/raw_queue_directory.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/raw_queue_feed.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/process_queue_identity_lock.py").exists()
    assert not Path("Virus_Scan/scheduler/ownership/raw_queue_claims.py").exists()
    assert not Path("Virus_Scan/scheduler/queue/raw_queue_claims.py").exists()
    assert not Path("Virus_Scan/scheduler/reconciliation/process_queue_result_merge.py").exists()
    assert Path("Virus_Scan/scheduler/queue/process_queue_result_merge.py").exists()


def test_stage713_queue_authority_is_thin_and_delegates_to_queue_owned_modules():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/authority.py"))
    assert "Virus_Scan.scheduler.queue.claim_protection" in source
    assert "Virus_Scan.scheduler.queue.duplicate_guard" in source
    assert "Virus_Scan.scheduler.queue.raw_queue_directory" in source
    assert "Virus_Scan.scheduler.ownership.claim_sidecar" not in source
    assert authority.queue_duplicate_live_guard.__module__ == "Virus_Scan.scheduler.queue.authority"
