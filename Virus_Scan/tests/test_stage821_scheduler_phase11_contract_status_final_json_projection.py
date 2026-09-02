from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.scheduler.api.final_json import attach_scheduler_final_json_fields
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision, RetryExhaustionResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerIdentity, WorkerResult
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section


def test_stage821_timeout_result_contract_cannot_remain_clean_final_json():
    compact = compact_result_record(attach_scheduler_final_json_fields(
        {
            "path": "timeout-contract.bin",
            "timeout_result": TimeoutResult(
                timed_out=True,
                elapsed_sec=12.5,
                budget_sec=10.0,
                stage="worker_timeout",
            ),
        }
    ))

    assert compact["scheduler_status"] == "degraded"
    evidence = compact["scheduler_failure_evidence"]
    assert evidence[0]["stage"] == "worker_timeout"
    assert evidence[0]["error_category"] == "timeout_result_timed_out"
    assert evidence[0]["timeout_state_affected"] is True
    assert compact["scheduler"]["timeout_decisions"][0]["context"]["timeout_result"]["timed_out"] is True


def test_stage821_retry_exhaustion_contract_projects_to_retry_evidence():
    section = build_final_json_scheduler_section(
        {
            "path": "retry-contract.bin",
            "queue_claim_id": "claim-retry-821",
            "retry_decision": RetryDecision(
                retry_allowed=False,
                exhausted=True,
                attempt=3,
                max_attempts=3,
                reason="retry_exhausted_after_worker_timeout",
            ),
            "retry_exhaustion_result": RetryExhaustionResult(
                exhausted=True,
                job_id="job-retry-821",
                reason="retry_exhausted_after_worker_timeout",
            ),
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert any(item["stage"] == "retry_exhaustion" for item in section["retry_exhaustion"])
    assert any(item["retry_state_affected"] is True for item in section["retry_decisions"])
    assert section["evidence"][0]["final_json_must_record"] is True
    assert section["evidence"][0]["checkpoint_must_record"] is True
    assert section["evidence"][0]["replay_must_record"] is True


def test_stage821_worker_result_contract_failures_project_to_worker_evidence():
    section = build_final_json_scheduler_section(
        {
            "path": "worker-contract.bin",
            "worker_result": WorkerResult(
                WorkerIdentity("worker-821", pid=821),
                success=False,
                failures=(
                    {
                        "stage": "worker_lifecycle",
                        "state": "failure",
                        "error_category": "worker_exited_after_claim",
                        "error_source": "scheduler.workers.lifecycle",
                        "message": "worker exited after claiming work",
                        "final_json_must_record": True,
                        "checkpoint_must_record": True,
                        "replay_must_reproduce": True,
                    },
                ),
            ),
        }
    )

    assert section is not None
    assert section["scheduler_status"] == "degraded"
    assert any(item["error_category"] == "worker_exited_after_claim" for item in section["worker_lifecycle_events"])
    assert any(item["worker_id"] == "worker-821" for item in section["worker_failures"])


def test_stage821_clean_passive_contracts_do_not_create_scheduler_section():
    section = build_final_json_scheduler_section(
        {
            "path": "clean-contract.bin",
            "timeout_result": TimeoutResult(timed_out=False, elapsed_sec=1.0, budget_sec=10.0),
            "retry_decision": RetryDecision(retry_allowed=True, exhausted=False, attempt=0, max_attempts=3),
        }
    )

    assert section is None
