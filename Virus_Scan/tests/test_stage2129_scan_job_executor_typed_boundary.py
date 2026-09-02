"""Stage2129 raw-stage scan job executor typed boundary regressions."""
from __future__ import annotations

import inspect

from Virus_Scan.scheduler.execution import scan_job_executor
from Virus_Scan.scheduler.execution.scan_job_executor import RawQueueJobExecutionDependencies, process_one_raw_stage_job
from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.reporting.result_schema import _umige_raw_result_has_infra_error


class HostileDecision:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    @property
    def action(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not read action property")

    @property
    def reason(self) -> str:
        type(self).touched += 1
        raise RuntimeError("must not read reason property")


class Accumulator:
    def __init__(self) -> None:
        self.records: list[object] = []

    def append(self, payload: object) -> object:
        self.records.append(payload)
        return payload


def test_stage2129_scan_job_executor_source_has_typed_boundary_no_any_or_local_projection_wrappers() -> None:
    source = inspect.getsource(scan_job_executor)

    assert "typing import Any" not in source
    assert "Any" not in source
    assert "def _raw_job_text" not in source
    assert "def _raw_job_attempt" not in source
    assert "def _safe_decision_action" not in source
    assert "def _safe_decision_reason" not in source


def test_stage2129_scan_job_executor_inlines_recovery_decisions_without_descriptor_hooks(tmp_path) -> None:
    HostileDecision.reset()
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir(parents=True)
    claim.write_text("{}", encoding="utf-8")
    finish_calls: list[tuple[bool, object, object]] = []
    accumulator = Accumulator()
    job = {
        "job_type": "raw_stage",
        "file": "sample.bin",
        "collector": "identity",
        "file_id": "fid-stage2129",
        "seq": 1,
        "attempt": 0,
    }

    deps = RawQueueJobExecutionDependencies(
        claim_matching=lambda *args, **kwargs: (job, claim),
        execute_stage_job=lambda raw_job: {"error": "infra", "tags": ["scanner_failure"]},
        envelope_from_raw_result=envelope_from_raw_result,
        result_has_infra_error=_umige_raw_result_has_infra_error,
        classify_recovery=lambda *args, **kwargs: HostileDecision(),
        default_failure_info=lambda **kwargs: dict(kwargs),
        prepare_raw_retry=lambda *args, **kwargs: False,
        accumulator_store=lambda *args, **kwargs: accumulator,
        record_suppressed=lambda where, exc: None,
        safe_exception_info=lambda *args, **kwargs: {},
        finish_job=lambda queue_dir, claim_path, ok=True, error_info=None, job=None: finish_calls.append((ok, error_info, job)),
        recoverable_exceptions=(RuntimeError,),
    )

    assert process_one_raw_stage_job(tmp_path, deps=deps) is True

    assert HostileDecision.touched == 0
    assert finish_calls and finish_calls[0][0] is True
    failure_info = finish_calls[0][1]
    assert isinstance(failure_info, dict)
    assert failure_info["exception_type"] == "RawStageInfrastructureError"
    assert failure_info["error"] == "infra"
    assert failure_info["extra"]["recovery_action"] == ""
    assert accumulator.records
