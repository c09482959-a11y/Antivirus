from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.evidence.final_json_contract_projection import (
    failure_records_from_scheduler_contract_status,
)
from Virus_Scan.scheduler.evidence.final_json_exact_fields import exact_int_with_rejection
from Virus_Scan.scheduler.evidence.final_json_queue_projection import failure_records_from_queue_status


class HostileNumeric:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    int_calls = 0
    float_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.int_calls = 0
        cls.float_calls = 0

    def __str__(self):
        type(self).str_calls += 1
        raise RuntimeError("must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise RuntimeError("must not execute")

    def __format__(self, spec):
        type(self).format_calls += 1
        raise RuntimeError("must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise RuntimeError("must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise RuntimeError("must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise RuntimeError("must not execute")


def _hostile_counters() -> tuple[int, int, int, int, int, int]:
    return (
        HostileNumeric.str_calls,
        HostileNumeric.repr_calls,
        HostileNumeric.format_calls,
        HostileNumeric.bool_calls,
        HostileNumeric.int_calls,
        HostileNumeric.float_calls,
    )


def test_stage1814_exact_int_reports_rejection_without_numeric_or_text_hooks() -> None:
    HostileNumeric.reset()
    value, rejected = exact_int_with_rejection({"attempt": HostileNumeric()}, "attempt", default=0)

    assert value == 0
    assert rejected is True
    assert _hostile_counters() == (0, 0, 0, 0, 0, 0)


def test_stage1814_retry_invalid_numeric_text_becomes_final_json_evidence() -> None:
    records = failure_records_from_scheduler_contract_status(
        {
            "retry_decision": {
                "retry_allowed": False,
                "attempt": "not-an-int",
                "max_attempts": "3",
                "job_id": "job-1",
            }
        }
    )

    assert records
    record = records[0]
    assert record.stage == "retry"
    assert record.error_category == "retry_decision_failure"
    assert record.retry_state_affected is True
    assert record.final_json_must_record is True
    assert record.context["retry_decision"]["attempt"] == "not-an-int"


def test_stage1814_retry_hostile_numeric_becomes_evidence_without_hooks() -> None:
    HostileNumeric.reset()
    records = failure_records_from_scheduler_contract_status(
        {
            "retry_result": {
                "retry_allowed": False,
                "attempt": HostileNumeric(),
                "max_attempts": 2,
            }
        }
    )

    assert records
    assert records[0].stage == "retry"
    assert records[0].retry_state_affected is True
    assert _hostile_counters() == (0, 0, 0, 0, 0, 0)


def test_stage1814_orphan_recovery_invalid_count_becomes_queue_evidence() -> None:
    records = failure_records_from_queue_status(
        {
            "orphan_recovery_result": {
                "orphaned": "not-an-int",
                "queue_id": "queue-1",
            }
        }
    )

    assert records
    record = records[0]
    assert record.stage == "orphan_recovery"
    assert record.error_category == "orphan_recovery_failure"
    assert record.final_json_must_record is True
    assert record.context["orphan_recovery_result"]["orphaned"] == "not-an-int"


def test_stage1814_scheduler_numeric_status_projections_do_not_use_silent_exact_int_default() -> None:
    files = [
        Path("Virus_Scan/scheduler/evidence/final_json_contract_projection.py"),
        Path("Virus_Scan/scheduler/evidence/final_json_queue_projection.py"),
    ]
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exact_int"
        ]
        assert calls == [], f"{path} must use exact_int_with_rejection for status counts"
