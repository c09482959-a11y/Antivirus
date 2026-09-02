from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import (
    safe_stage_is_pre_execution,
    safe_start_wait_budget,
)

TARGET = Path("Virus_Scan/scheduler/timeout/inmemory_timeout_policy_callbacks.py")
CONTRACTS = Path("Virus_Scan/scheduler/timeout/inmemory_timeout_policy_callback_contracts.py")


def test_stage2202_timeout_policy_callbacks_have_no_any_boundary_annotations() -> None:
    target_source = TARGET.read_text(encoding="utf-8")
    contracts_source = CONTRACTS.read_text(encoding="utf-8")

    assert "Any" not in target_source
    assert "Any" not in contracts_source
    assert "QueuedUnstartedCounter" not in target_source
    assert "TimeoutPolicyJobRecords" not in target_source
    assert "StartWaitBudget" in target_source
    assert "StagePreExecutionClassifier" in target_source


def test_stage2202_timeout_policy_callback_failures_remain_replayable_evidence() -> None:
    failures: list[object] = []
    suppressed: list[tuple[str, str]] = []

    def _suppressed(name: str, exc: BaseException) -> object:
        suppressed.append((name, type(exc).__name__))
        return None

    budget = safe_start_wait_budget(
        start_wait_budget=lambda _record, _default: "bad-budget",  # type: ignore[return-value]
        job_id="job-1",
        record={"attempt": 1, "timeout_budget": {"timeout_budget": 3.0}},
        default_budget=4.0,
        reason="queued_start_wait_budget_failed",
        failures=failures,  # type: ignore[arg-type]
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=(Exception,),
    )
    assert budget == 4.0
    assert failures[-1]["reason"] == "start_wait_budget_return_rejected"  # type: ignore[index]

    assert safe_stage_is_pre_execution(
        classifier=lambda _stage: "truthy-but-not-bool",  # type: ignore[return-value]
        stage="queued",
        job_id="job-1",
        record={"attempt": 1, "timeout_budget": {"timeout_budget": 3.0}},
        pid=None,
        failures=failures,  # type: ignore[arg-type]
        record_scheduler_suppressed=_suppressed,
        recoverable_exceptions=(Exception,),
    ) is False
    assert failures[-1]["reason"] == "stage_pre_execution_classification_return_rejected"  # type: ignore[index]
