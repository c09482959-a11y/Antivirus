from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scheduler.queue.authority import process_queue_merge_claim_meta_into_job
from Virus_Scan.scheduler.queue.authority import acquire_identity_lock_decision, release_identity_lock_decision



def test_stage615_identity_lock_imports_canonical_owner(tmp_path):
    acquired = acquire_identity_lock_decision(tmp_path, "stage615-file")
    assert acquired.acquired is True
    assert acquired.lock_path is not None
    assert acquire_identity_lock_decision(tmp_path, "stage615-file").reason == "process_queue_identity_lock_already_locked"
    assert release_identity_lock_decision(acquired.lock_path).released is True


def test_stage615_process_queue_claiming_no_longer_owns_claim_meta_or_identity_aliases():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert "def _queue_merge_claim_meta_into_job" not in source
    assert "from Virus_Scan.scheduler.queue.claim import _queue_acquire_identity_lock" not in source
    assert "from Virus_Scan.scheduler.queue.claim import _queue_release_identity_lock" not in source


def test_stage615_claim_meta_merge_is_queue_authority_owned():
    job = {"file": "sample.bin"}
    merged = process_queue_merge_claim_meta_into_job("missing.claim", job)
    assert merged == job
    assert merged is not job
