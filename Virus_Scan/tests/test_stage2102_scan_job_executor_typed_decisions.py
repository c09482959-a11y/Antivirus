"""Stage2102 raw-stage scan job typed decision regressions."""
from __future__ import annotations

from typing import Any

from Virus_Scan.scheduler.execution.scan_job_executor import RawQueueJobExecutionDependencies, process_one_raw_stage_job
from Virus_Scan.scheduler.execution.scan_job_executor_decisions import (
    raw_recovery_text_decision,
    raw_stage_job_predicate_decision,
    raw_stage_job_unclaimed_decision,
)


class HostileValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not repr")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("must not bool")


def test_stage2102_recovery_text_decision_records_missing_instance_without_empty_sentinel() -> None:
    outcome = raw_recovery_text_decision(object(), field_name="action")

    assert outcome.text == ""
    assert outcome.accepted is False
    assert outcome.reason == "raw_recovery_action_decision_unavailable"


def test_stage2102_recovery_text_decision_rejects_hostile_field_without_hooks() -> None:
    HostileValue.reset()
    class Decision:
        def __init__(self) -> None:
            self.action = HostileValue()

    outcome = raw_recovery_text_decision(Decision(), field_name="action")

    assert HostileValue.touched == 0
    assert outcome.text == ""
    assert outcome.accepted is False
    assert outcome.reason == "raw_job_recovery_action_rejected"


def test_stage2102_raw_stage_predicate_returns_replayable_rejection_reasons() -> None:
    wrong_type = raw_stage_job_predicate_decision({"job_type": "other", "file_id": "a"})
    wrong_file = raw_stage_job_predicate_decision({"job_type": "raw_stage", "file_id": "a"}, only_file_id="b")
    accepted = raw_stage_job_predicate_decision({"job_type": "raw_stage", "file_id": "b"}, only_file_id="b")

    assert wrong_type.eligible is False
    assert wrong_type.reason == "raw_stage_job_type_not_raw_stage"
    assert wrong_file.eligible is False
    assert wrong_file.reason == "raw_stage_job_file_id_mismatch"
    assert accepted.eligible is True
    assert accepted.reason == ""


def test_stage2102_process_one_raw_stage_job_preserves_legacy_projection_from_typed_unclaimed_decision(tmp_path) -> None:
    finish_calls: list[Any] = []
    deps = RawQueueJobExecutionDependencies(
        claim_matching=lambda *args, **kwargs: (None, None),
        execute_stage_job=lambda raw_job: {},
        envelope_from_raw_result=lambda raw_job, result: None,
        result_has_infra_error=lambda value: False,
        classify_recovery=lambda *args, **kwargs: object(),
        default_failure_info=lambda **kwargs: kwargs,
        prepare_raw_retry=lambda *args, **kwargs: False,
        accumulator_store=lambda *args, **kwargs: None,
        record_suppressed=lambda where, exc: None,
        safe_exception_info=lambda *args, **kwargs: {},
        finish_job=lambda *args, **kwargs: finish_calls.append((args, kwargs)),
        recoverable_exceptions=(RuntimeError,),
    )

    typed = raw_stage_job_unclaimed_decision()

    assert typed.processed is False
    assert typed.reason == "raw_stage_job_not_claimed"
    assert process_one_raw_stage_job(tmp_path, deps=deps) is typed.processed
    assert finish_calls == []
