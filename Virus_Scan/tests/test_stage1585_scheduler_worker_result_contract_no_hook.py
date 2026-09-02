from __future__ import annotations

from Virus_Scan.scheduler.workers.result_contracts import (
    build_worker_result_schema_failure,
    make_scheduler_cancel_result,
    normalize_scheduler_worker_result,
)
from Virus_Scan.contracts.result_record import make_worker_error_result


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("__str__ must not be called")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("__repr__ must not be called")

    def __format__(self, spec):
        type(self).touched += 1
        raise AssertionError("__format__ must not be called")


class HostileMapping(dict):
    touched = 0

    def get(self, key, default=None):
        type(self).touched += 1
        raise AssertionError("get must not be called")

    def items(self):
        type(self).touched += 1
        raise AssertionError("items must not be called")

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("iter must not be called")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("exception __str__ must not be called")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("exception __repr__ must not be called")


def test_worker_result_schema_failure_rejects_hostile_path_reason_without_hooks():
    HostileText.touched = 0
    hostile_path = HostileText()
    hostile_reason = HostileText()

    def failing_worker_error_result(path, exc):
        raise HostileError("hidden")

    normalized = build_worker_result_schema_failure(
        hostile_path,
        object(),
        worker_error_result=failing_worker_error_result,
        recoverable_exceptions=(HostileError,),
        reason=hostile_reason,  # type: ignore[arg-type]
    )

    assert HostileText.touched == 0
    assert HostileError.touched == 0
    assert normalized["queue_failure"] is True
    assert normalized["scheduler_failure_reason"] == "scheduler_worker_result_schema_failure"
    integrity = normalized["scan_integrity"]
    assert integrity["worker_result_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_result_reason_unavailable_reason"] == "unsafe_scheduler_worker_reason_rejected"
    assert integrity["worker_error_result_error"] == "HostileError"


def test_normalize_scheduler_worker_result_rejects_mapping_subclass_without_iterating():
    HostileMapping.touched = 0
    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        HostileMapping({"file": "sample.bin"}),
        worker_error_result=make_worker_error_result,
        recoverable_exceptions=(Exception,),
    )

    assert HostileMapping.touched == 0
    assert normalized["queue_failure"] is True
    assert normalized["scan_integrity"]["worker_result_schema_invalid"] is True
    assert normalized["scan_integrity"]["worker_result_original_type"] == "HostileMapping"


def test_normalize_scheduler_worker_result_rejects_hostile_integrity_without_hooks():
    HostileMapping.touched = 0
    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        {"file": "sample.bin", "scan_integrity": HostileMapping({"allow_learning": True})},
        worker_error_result=make_worker_error_result,
        recoverable_exceptions=(Exception,),
    )

    assert HostileMapping.touched == 0
    integrity = normalized["scan_integrity"]
    assert integrity["worker_result_integrity_unavailable"] is True
    assert integrity["worker_result_integrity_unavailable_reason"] == "non_materializable_worker_result_integrity"
    assert integrity["allow_learning"] is False


def test_make_scheduler_cancel_result_rejects_hostile_path_reason_without_hooks():
    HostileText.touched = 0
    path, result = make_scheduler_cancel_result(HostileText(), HostileText())  # type: ignore[arg-type]

    assert HostileText.touched == 0
    assert path == ""
    assert result["queue_failure"] is True
    assert result["cancelled_generation"] is True
    assert result["scheduler_failure_reason"] == "cancelled_generation"
    assert result["scan_integrity"]["file_failed"] is True
