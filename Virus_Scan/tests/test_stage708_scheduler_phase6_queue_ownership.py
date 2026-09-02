from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scheduler.queue import admission, authority, claim, feed_marker, feed_policy, integrity, orphan_recovery
from Virus_Scan.scheduler.queue.admission_fairness import interleave_workloads, weighted_fair_interleave
from Virus_Scan.scheduler.queue.file_job_predicate import process_queue_is_file_job
from Virus_Scan.scheduler.queue.workload_identity import _sniff_workload_identity



def test_stage708_phase6_queue_modules_are_canonical():
    assert authority.__name__ == "Virus_Scan.scheduler.queue.authority"
    assert claim.__name__ == "Virus_Scan.scheduler.queue.claim"
    assert admission.__name__ == "Virus_Scan.scheduler.queue.admission"
    assert feed_marker.__name__ == "Virus_Scan.scheduler.queue.feed_marker"
    assert feed_policy.__name__ == "Virus_Scan.scheduler.queue.feed_policy"
    assert integrity.__name__ == "Virus_Scan.scheduler.queue.integrity"
    assert orphan_recovery.__name__ == "Virus_Scan.scheduler.queue.orphan_recovery"


def test_stage708_legacy_queue_ownership_surfaces_deleted():
    deleted = (
        "Virus_Scan/scheduler/ownership/queue_authority.py",
        "Virus_Scan/scheduler/ownership/process_queue_claiming.py",
        "Virus_Scan/scheduler/ownership/workload_queues.py",
        "Virus_Scan/scheduler/ownership/queue_feed_policy.py",
        "Virus_Scan/scheduler/reconciliation/process_queue_recovery.py",
        "Virus_Scan/scheduler/reconciliation/raw_queue_integrity.py",
        "Virus_Scan/scheduler/reconciliation/raw_queue_cleanup.py",
        "Virus_Scan/scheduler/reconciliation/raw_queue_counts.py",
    )
    for rel in deleted:
        assert not Path(rel).exists(), rel


def test_stage708_queue_split_functions_have_single_owner_modules():
    assert _sniff_workload_identity.__module__ == "Virus_Scan.scheduler.queue.workload_identity"
    assert interleave_workloads.__module__ == "Virus_Scan.scheduler.queue.admission_fairness"
    assert weighted_fair_interleave.__module__ == "Virus_Scan.scheduler.queue.admission_fairness"
    assert process_queue_is_file_job.__module__ == "Virus_Scan.scheduler.queue.file_job_predicate"
    assert feed_marker.mark_process_queue_feed_complete.__module__ == "Virus_Scan.scheduler.queue.feed_marker"
    assert feed_policy.build_process_queue_feed_policy.__module__ == "Virus_Scan.scheduler.queue.feed_policy"


def test_stage708_queue_claim_uses_queue_owned_dependencies():
    source = read_python_file(Path("Virus_Scan/scheduler/queue/claim.py"))
    assert "scheduler.ownership.process_queue_claiming" not in source
    assert "scheduler.ownership.queue_authority" not in source
    assert "scheduler.queue.authority" in source
    assert "scheduler.queue.file_job_predicate" in source
