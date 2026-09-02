from pathlib import Path

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.context.inmemory_raw_stage_dependencies import (
    RawStageExecutionDependencyRequest,
    raw_stage_execution_dependencies_from_request,
)
from Virus_Scan.scheduler.execution.raw_stage_executor import execute_global_raw_stage_job
from Virus_Scan.scheduler.execution.scan_job_executor import RawQueueJobExecutionDependencies, process_one_raw_stage_job
from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.scheduler.evidence.raw_queue_failure import default_failure_info
from Virus_Scan.scheduler.workers.child_result_publication import build_safe_exception_info
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.reporting.result_schema import _umige_raw_result_has_infra_error



def test_stage118_unknown_raw_collector_is_degraded_infra_error(tmp_path):
    job = {
        "file": str(tmp_path / "x.bin"),
        "collector": "not_a_collector",
        "file_id": "fid-stage118",
        "seq": 1,
        "attempt": 0,
    }
    out = raw_deps.execute_inmemory_raw_stage_job(job)
    assert out.get("error")
    assert out.get("failure_stage") == "raw_stage_unknown_collector"
    assert _umige_raw_result_has_infra_error(out) is True
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete"} <= set(out.get("tags") or [])


def test_stage118_yara_collector_failure_is_not_clean_diagnostic(tmp_path):
    calls = []
    job = {
        "file": str(tmp_path / "x.bin"),
        "collector": "yara",
        "file_id": "fid-stage118-yara",
        "seq": 2,
        "attempt": 0,
    }
    deps = raw_stage_execution_dependencies_from_request(
        RawStageExecutionDependencyRequest(
            yara_scan_with_optional_zip_func=lambda *a, **k: (
                _ for _ in ()
            ).throw(RuntimeError("bad rules")),
            record_issue_func=lambda where, exc: calls.append(
                (where, type(exc).__name__)
            ),
        )
    )
    out = execute_global_raw_stage_job(job, deps=deps)
    assert out.get("error") and "bad rules" in out.get("error")
    assert out.get("failure_stage") == "raw_stage_yara"
    assert _umige_raw_result_has_infra_error(out) is True
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete"} <= set(out.get("tags") or [])


def test_stage118_process_one_job_accumulator_failure_finalizes_failed(tmp_path):
    job = {"job_type": "raw_stage", "file": "x.bin", "collector": "identity", "file_id": "fid-stage118-proc", "seq": 3, "attempt": 0}
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir(parents=True)
    claim.write_text("{}", encoding="utf-8")
    finish_calls = []
    telemetry = []

    class BadAccumulator:
        def __init__(self, *a, **k):
            pass
        def append(self, payload):
            raise RuntimeError("accumulator denied")

    deps = RawQueueJobExecutionDependencies(
        claim_matching=lambda *a, **k: (job, claim),
        execute_stage_job=lambda j: {"tags": ["identity"], "collector": j["collector"], "file_id": j["file_id"], "seq": j["seq"]},
        envelope_from_raw_result=envelope_from_raw_result,
        result_has_infra_error=_umige_raw_result_has_infra_error,
        classify_recovery=lambda *a, **k: type("Decision", (), {"action": "fail", "reason": ""})(),
        default_failure_info=default_failure_info,
        prepare_raw_retry=lambda *a, **k: False,
        accumulator_store=BadAccumulator,
        record_suppressed=lambda where, exc: telemetry.append((where, type(exc).__name__, str(exc))),
        safe_exception_info=build_safe_exception_info,
        finish_job=lambda q, c, ok=True, error_info=None, job=None: _append_and_return_true(finish_calls, (ok, error_info, job)),
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )

    assert process_one_raw_stage_job(tmp_path, deps=deps) is True
    assert finish_calls and finish_calls[0][0] is False
    assert finish_calls[0][1]["exception_type"] == "RuntimeError"
    assert finish_calls[0][1]["stage"] == "identity"
    assert any(where == "raw_process_one_job_failed_closed" for where, _, _ in telemetry)


def test_stage118_process_one_job_retry_prepare_path_marks_done(tmp_path):
    job = {"job_type": "raw_stage", "file": "x.bin", "collector": "binary_context", "file_id": "fid-stage118-retry", "seq": 4, "attempt": 0}
    claim = tmp_path / "active" / "claim.json"
    claim.parent.mkdir(parents=True)
    claim.write_text("{}", encoding="utf-8")
    finish_calls = []

    deps = RawQueueJobExecutionDependencies(
        claim_matching=lambda *a, **k: (job, claim),
        execute_stage_job=lambda j: {"error": "binary_context:denied", "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete"], "collector": j["collector"], "file_id": j["file_id"], "seq": j["seq"]},
        envelope_from_raw_result=envelope_from_raw_result,
        result_has_infra_error=_umige_raw_result_has_infra_error,
        classify_recovery=lambda *a, **k: type("Decision", (), {"action": "retry", "reason": "denied"})(),
        default_failure_info=default_failure_info,
        prepare_raw_retry=lambda *a, **k: True,
        accumulator_store=lambda *a, **k: None,
        record_suppressed=lambda where, exc: None,
        safe_exception_info=build_safe_exception_info,
        finish_job=lambda q, c, ok=True, error_info=None, job=None: _append_and_return_true(finish_calls, (ok, error_info, job)),
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )

    assert process_one_raw_stage_job(tmp_path, deps=deps) is True
    assert finish_calls and finish_calls[0][0] is True
    assert finish_calls[0][1]["exception_type"] == "RawStageInfrastructureError"
