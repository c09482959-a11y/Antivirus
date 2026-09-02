from Virus_Scan.tests.support.static_inventory import read_python_file

from dataclasses import FrozenInstanceError
from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_result_publication import (
    InMemoryWorkerResultPublication,
    publish_completed_inmemory_worker_result,
)



class _Future:
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


class _ResultQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


def _worker_error(path, exc):
    return {"file": str(path), "error": str(exc), "scan_integrity": {"worker_error": True}}


def test_inmemory_worker_modules_do_not_import_timeout_ownership_directly():
    worker_root = Path("Virus_Scan/scheduler/workers")
    offenders = []
    for path in worker_root.glob("*.py"):
        text = path.read_text()
        if "Virus_Scan.scheduler.timeout" in text or "Virus_Scan.scheduler.timeouts" in text:
            offenders.append(path.name)
    assert offenders == []


def test_inmemory_file_scan_uses_injected_timeout_dependencies():
    text = read_python_file(Path("Virus_Scan/scheduler/workers/inmemory_file_scan.py"))
    assert "FileScanTimeoutError" not in text
    assert "compute_timeout_budget" not in text
    assert "annotate_timeout_result" not in text
    assert "cfg = owned_cfg_snapshot(cfg)" in text
    assert "timeout_budget_factory = cfg_value(cfg, 'timeout_budget_factory')" in text
    assert "timeout_result_annotator = cfg_value(cfg, 'timeout_result_annotator')" in text
    assert "timeout_error_type = cfg_value(cfg, 'timeout_error_type')" in text
    assert ".get('timeout_budget_factory')" not in text


def test_inmemory_worker_publication_returns_immutable_evidence():
    future = _Future(("a.bin", ["not", "a", "dict"]))
    active = {future: {"job_id": 9, "path": "a.bin", "attempt": 3}}
    result_q = _ResultQueue()

    result = publish_completed_inmemory_worker_result(
        future=future,
        active=active,
        result_q=result_q,
        max_jobs_per_worker=5,
        processed_jobs=1,
        worker_error_result=_worker_error,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert isinstance(result, InMemoryWorkerResultPublication)
    assert result.processed_jobs == 2
    assert result.stop_requested is False
    assert result.job_id == 9
    assert result.attempt == 3
    assert result.schema_normalized is True
    assert active == {}
    assert result_q.items[0][3]["scan_integrity"]["worker_result_schema_invalid"] is True
    try:
        result.processed_jobs = 99
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("publication evidence must be immutable")
