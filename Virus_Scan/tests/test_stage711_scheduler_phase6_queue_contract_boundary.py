from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, QueuePhaseLedger
from Virus_Scan.scheduler.queue.recovery_contracts import QueueRecoveryDecision, QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState, QueueRunFinalizationState
from Virus_Scan.scheduler.queue.phase_validation import _validate_queue_integrity

from pathlib import Path


def test_queue_contracts_are_owned_by_queue_domain():

    planning = QueueBehaviorSnapshot.from_counts("planning", {"pending": 1, "total": 1})
    ledger = QueuePhaseLedger(()).with_snapshot(planning)
    publication = QueuePublicationState.empty()
    failure = QueueWorkerFailureAccounting(
        worker_id="worker-1",
        job_id="job-1",
        file_path="sample.bin",
        failure_reason="worker_exit",
        requeued=True,
        failed=False,
        attempt_count=0,
        final_scheduler_action="requeue",
    )
    failure.assert_valid()
    decision = QueueRecoveryDecision(
        job_id="job-1",
        worker_id="worker-1",
        file_path="sample.bin",
        failure_reason="worker_exit",
        final_action="requeue",
        reason_text="requeue:worker_exit",
        attempt_count=0,
        source_event="stage711",
    )
    decision.assert_valid()
    _validate_queue_integrity(None, planning)
    assert isinstance(QueueRunFinalizationState, type)
    assert ledger.as_dict()["snapshots"][0]["phase"] == "planning"
    assert publication.as_dict() == {"job_identities": [], "file_identities": []}


def test_old_reconciliation_contract_surfaces_are_deleted():
    scheduler = Path(__file__).resolve().parents[1] / "scheduler"
    assert not (scheduler / "reconciliation" / "phase_output_contracts.py").exists()
    assert not (scheduler / "reconciliation" / "phase_validation.py").exists()
    assert not (scheduler / "reconciliation" / "phase_ledger.py").exists()
    assert not (scheduler / "reconciliation" / "scheduler_audit.py").exists()
    assert not (scheduler / "ownership" / "queue_identity.py").exists()
    assert not (scheduler / "ownership" / "queue_identity_index.py").exists()
    assert not (scheduler / "ownership" / "process_queue_claim_sidecar.py").exists()
    assert not (scheduler / "ownership" / "process_queue_claims.py").exists()
