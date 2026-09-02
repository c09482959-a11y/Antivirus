from Virus_Scan.scheduler.workers.process_queue_worker_exit import (
    ProcessQueueWorkerExitDependencies,
    ProcessQueueWorkerExitRequest,
    reconcile_process_queue_worker_exits,
)
from Virus_Scan.scheduler.workers.cleanup import WorkerExitWaitResult
from Virus_Scan.scheduler.orchestration.process_queue_completion import _attach_worker_exit_evidence_to_merged_results


def test_stage734_worker_exit_reconciliation_returns_immutable_exit_evidence():
    observed = []

    def wait_for_worker_exit(*args, **kwargs):
        return WorkerExitWaitResult(
            worker_idx=7,
            pid=1234,
            output="worker.out",
            status=-1,
            timed_out=True,
            cleanup_actions=("terminate", "kill"),
            failure_markers=("queue_worker_final_wait_timeout",),
            reason="worker_final_wait_timeout",
        )

    output = reconcile_process_queue_worker_exits(
        ProcessQueueWorkerExitRequest(procs=((7, object(), "worker.out", ()),), strict=False, had_error=False),
        ProcessQueueWorkerExitDependencies(
            wait_for_worker_exit=wait_for_worker_exit,
            record_issue=lambda *a, **k: observed.append((a, k)),
            log_error=lambda msg: observed.append((msg,)),
        ),
    )

    assert output.had_error is True
    assert output.exit_evidence
    assert output.exit_evidence[0]["worker_wait_timed_out"] is True
    assert tuple(output.exit_evidence[0]["worker_failure_markers"]) == ("queue_worker_final_wait_timeout",)


def test_stage734_nonclean_worker_exit_evidence_reaches_merged_scan_integrity():
    merged = {"sample.bin": {"class": "ERROR", "scan_integrity": {}}}
    evidence = (
        {
            "worker_idx": 7,
            "worker_pid": 1234,
            "worker_output": "worker.out",
            "worker_exit_status": -1,
            "worker_wait_timed_out": True,
            "worker_cleanup_actions": ["terminate"],
            "worker_failure_markers": ["queue_worker_final_wait_timeout"],
            "worker_cleanup_reason": "worker_final_wait_timeout",
        },
    )

    _attach_worker_exit_evidence_to_merged_results(merged, evidence)

    integrity = merged["sample.bin"]["scan_integrity"]
    assert integrity["process_queue_worker_exit_evidence"]
    assert integrity["process_queue_worker_exit_evidence"][0]["worker_exit_status"] == -1
