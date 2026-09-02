from Virus_Scan.scheduler.workers.inmemory_result_publication import InMemoryWorkerResultPublication, publish_completed_inmemory_worker_result
from Virus_Scan.scheduler.workers.result_contracts import normalize_scheduler_worker_result


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


def _worker_error_result(path, exc):
    return {"file": str(path), "tags": [], "error": str(exc), "scan_integrity": {}}


def test_stage722_worker_result_contract_rejects_non_mapping_result():
    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        ["not", "a", "result"],
        worker_error_result=_worker_error_result,
        recoverable_exceptions=(Exception,),
    )
    assert normalized["queue_failure"] is True
    assert normalized["scan_integrity"]["worker_result_schema_invalid"] is True
    assert normalized["scan_integrity"]["allow_learning"] is False


def test_stage722_inmemory_result_publication_validates_before_queue_merge():
    future = _Future(("sample.bin", ["bad", "result"]))
    active = {future: {"job_id": 7, "path": "sample.bin", "attempt": 2}}
    result_q = _ResultQueue()
    publication = publish_completed_inmemory_worker_result(
        future=future,
        active=active,
        result_q=result_q,
        max_jobs_per_worker=10,
        processed_jobs=0,
        worker_error_result=_worker_error_result,
        recoverable_exceptions=(Exception,),
        record_suppressed=lambda _context, _exc: None,
    )
    assert isinstance(publication, InMemoryWorkerResultPublication)
    assert publication.processed_jobs == 1
    assert publication.stop_requested is False
    assert publication.schema_normalized is True
    assert active == {}
    kind, job_id, path, result, _pid, _time, attempt = result_q.items[0]
    assert (kind, job_id, path, attempt) == ("result", 7, "sample.bin", 2)
    assert isinstance(result, dict)
    assert result["scan_integrity"]["worker_result_schema_invalid"] is True


def test_stage722_worker_result_contract_preserves_valid_result_but_records_malformed_optional_integrity():
    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        {"file": "sample.bin", "scan_integrity": ["not", "mapping"]},
        worker_error_result=_worker_error_result,
        recoverable_exceptions=(Exception,),
    )
    assert normalized["scan_integrity"]["worker_result_integrity_unavailable"] is True
    assert normalized["scan_integrity"]["worker_result_integrity_unavailable_reason"] == "non_materializable_worker_result_integrity"
    assert normalized["scan_integrity"]["allow_learning"] is False
    assert "queue_failure" not in normalized
