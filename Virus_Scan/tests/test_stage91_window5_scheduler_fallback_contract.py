from pathlib import Path
import inspect

from Virus_Scan.contracts.result_record import INCOMPLETE_SCAN_TAGS
from Virus_Scan.reporting.result_schema import _umige_cancel_result
from Virus_Scan.scheduler.api import runner
from Virus_Scan.scheduler.orchestration import scheduler_runner as scheduler_pipeline
from Virus_Scan.scheduler.execution import scan_job_executor
from Virus_Scan.scheduler.orchestration.scheduler_file_execution_context import build_scheduler_file_execution_dependencies
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result


def _assert_failure_record(res):
    tags = set(res.get("tags") or [])
    assert set(INCOMPLETE_SCAN_TAGS).issubset(tags)
    assert res.get("learn_eligible") is False
    assert res.get("scan_integrity", {}).get("allow_learning") is False
    assert str(res.get("class") or res.get("classification")).lower() in {"error", "timeout"}


def test_cancel_result_uses_canonical_failure_contract():
    path, res = _umige_cancel_result("cancelled.bin", "unit cancel")
    assert path == "cancelled.bin"
    assert res["queue_failure"] is True
    assert res["cancelled_generation"] is True
    _assert_failure_record(res)


def test_scheduler_modules_do_not_keep_empty_worker_error_fallback_dicts():
    for module in (runner, scheduler_pipeline, scan_job_executor):
        src = inspect.getsource(module)
        assert 'if "_make_worker_error_result" in globals() else' not in src
        assert '{"file": str(path), "error": str(e), "class": "ERROR", "score": 0, "tags": []}' not in src
        assert '{"file": str(f), "error": str(e), "score": 0, "class": "error", "tags": []}' not in src


def test_scheduler_contract_constructor_is_worker_owned_not_orchestration_owned():
    for module in (runner, scheduler_pipeline, scan_job_executor):
        assert not hasattr(module, "_contract_worker_error_result")
        assert "make_worker_error_result as _contract_worker_error_result" not in inspect.getsource(module)
    deps = build_scheduler_file_execution_dependencies()
    assert deps.make_worker_error_result is make_scheduler_worker_error_result
    res = deps.make_worker_error_result("x.bin", RuntimeError("boom"))
    _assert_failure_record(res)
