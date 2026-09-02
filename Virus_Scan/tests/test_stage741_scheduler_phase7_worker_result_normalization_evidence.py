from Virus_Scan.scheduler.workers.result_contracts import (
    WorkerResultNormalizationEvidence,
    build_worker_result_schema_failure,
    normalize_scheduler_worker_result,
)


RECOVERABLE = (RuntimeError, ValueError, TypeError)


def test_worker_result_normalization_evidence_is_immutable_and_explicit():
    evidence = WorkerResultNormalizationEvidence(
        path="sample.bin",
        reason="invalid_worker_result_schema",
        original_type="list",
        error_result_failed=True,
        error="constructor boom",
    )

    integrity = evidence.as_scan_integrity()
    assert integrity["worker_result_schema_invalid"] is True
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_result_original_type"] == "list"
    assert integrity["allow_learning"] is False


def test_invalid_worker_result_uses_immutable_schema_failure_evidence():
    def fail_error_result(path, exc):
        raise RuntimeError("constructor failed")

    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        ["not", "a", "dict"],
        worker_error_result=fail_error_result,
        recoverable_exceptions=RECOVERABLE,
    )

    integrity = normalized["scan_integrity"]
    assert normalized["queue_failure"] is True
    assert normalized["scheduler_failure_reason"] == "invalid_worker_result_schema"
    assert integrity["worker_result_schema_invalid"] is True
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_result_original_type"] == "list"


def test_schema_failure_builder_normalizes_non_dict_error_result():
    def non_dict_error_result(path, exc):
        return "bad-constructor-result"

    normalized = build_worker_result_schema_failure(
        "sample.bin",
        object(),
        worker_error_result=non_dict_error_result,
        recoverable_exceptions=RECOVERABLE,
        reason="bad-schema",
    )

    integrity = normalized["scan_integrity"]
    assert normalized["queue_failure"] is True
    assert integrity["worker_result_schema_invalid"] is True
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_result_schema_reason"] == "bad-schema"
