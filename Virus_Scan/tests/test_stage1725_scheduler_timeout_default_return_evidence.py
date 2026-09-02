from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.scheduler.evidence.inmemory_result_timeout_support import timeout_mapping
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_budget_values import timeout_budget_mapping_for_record


class HostileSchedulerMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("mapping iteration must not run")

    def __len__(self):
        type(self).touched += 1
        raise AssertionError("mapping length must not run")

    def __getitem__(self, key):
        type(self).touched += 1
        raise AssertionError("mapping lookup must not run")

    def items(self):
        type(self).touched += 1
        raise AssertionError("mapping items must not run")


class HostileTimeoutBudget:
    touched = 0

    def __eq__(self, other):
        type(self).touched += 1
        raise AssertionError("timeout budget equality must not run")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("timeout budget truthiness must not run")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("timeout budget repr must not run")


def test_safe_mapping_rejects_hostile_timeout_evidence_without_empty_default() -> None:
    HostileSchedulerMapping.touched = 0
    rejections: list[dict[str, object]] = []

    result = timeout_mapping(HostileSchedulerMapping(), field="timeout_evidence", rejections=rejections)

    assert HostileSchedulerMapping.touched == 0
    assert result["timeout_evidence_unavailable"] is True
    assert result["timeout_evidence_unavailable_reason"] == "unsafe_scheduler_mapping_rejected"
    assert result["timeout_evidence_failure"]["unsupported_scheduler_value"] is True
    assert result["final_json_must_record"] is True
    assert rejections == [{"field": "timeout_evidence", "reason": "unsafe_scheduler_mapping_rejected"}]


def test_timeout_budget_malformed_container_returns_explicit_evidence_without_hooks() -> None:
    HostileTimeoutBudget.touched = 0
    failures = []
    suppressed = []
    hostile = HostileTimeoutBudget()

    result = timeout_budget_mapping_for_record(
        jid="job-1725",
        rec={"pid": 123, "attempt": 2, "timeout_budget": hostile},
        pid=123,
        timeout_retry_evidence=failures,
        record_scheduler_suppressed=lambda stage, exc: suppressed.append((stage, type(exc).__name__)),
        recoverable_exceptions=(Exception,),
    )

    assert HostileTimeoutBudget.touched == 0
    assert result["timeout_budget_unavailable"] is True
    assert result["timeout_budget_unavailable_reason"] == "timeout_budget_container_malformed"
    assert result["timeout_budget_failure"]["unsupported_scheduler_value"] is True
    assert result["final_json_must_record"] is True
    assert failures
    assert failures[0]["timeout_budget"]["timeout_budget_unavailable"] is True
    assert failures[0]["final_json_must_record"] is True
    assert suppressed == [("suppressed_exception", "TypeError")]


def test_timeout_budget_missing_records_explicit_unavailable_state() -> None:
    failures = []

    result = timeout_budget_mapping_for_record(
        jid="job-1725-missing",
        rec={"pid": 456},
        pid=456,
        timeout_retry_evidence=failures,
        record_scheduler_suppressed=lambda stage, exc: None,
        recoverable_exceptions=(Exception,),
    )

    assert result["timeout_budget_unavailable"] is True
    assert result["timeout_budget_unavailable_reason"] == "missing_timeout_budget"
    assert result["final_json_must_record"] is True
    assert failures == []

from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_numbers import safe_timeout_budget_number, timeout_budget_for_record


def test_safe_timeout_budget_number_rejects_hostile_numeric_without_equality_or_float_hooks() -> None:
    class HostileNumber:
        touched = 0

        def __eq__(self, other):
            type(self).touched += 1
            raise AssertionError("numeric equality must not run")

        def __float__(self):
            type(self).touched += 1
            raise AssertionError("numeric float must not run before evidence")

        def __repr__(self):
            type(self).touched += 1
            raise AssertionError("numeric repr must not run")

    failures = []
    hostile = HostileNumber()

    result = safe_timeout_budget_number(
        record={"attempt": 3},
        budget={"timeout_budget": hostile},
        field="timeout_budget",
        default=7.0,
        job_id="job-unsafe-number",
        pid=789,
        failures=failures,
        record_scheduler_suppressed=lambda stage, exc: None,
        recoverable_exceptions=(Exception,),
    )

    assert HostileNumber.touched == 0
    assert result == 7.0
    assert failures
    assert failures[0]["reason"] == "timeout_budget_timeout_budget_malformed"
    assert failures[0]["timeout_budget"]["timeout_budget_unavailable"] is True


def test_timeout_budget_for_record_does_not_collapse_malformed_budget_to_empty_mapping() -> None:
    HostileTimeoutBudget.touched = 0
    hostile = HostileTimeoutBudget()

    result = timeout_budget_for_record({"timeout_budget": hostile})

    assert HostileTimeoutBudget.touched == 0
    assert result["timeout_budget_unavailable"] is True
    assert result["timeout_budget_unavailable_reason"] == "timeout_budget_container_malformed"
    assert result["timeout_budget_failure"]["unsupported_scheduler_value"] is True
    assert result["final_json_must_record"] is True
