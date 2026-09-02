from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.scheduler.workers.child_failure_metadata import safe_exception_info
from Virus_Scan.scheduler.workers.child_output_evidence import (
    ChildWorkerOutputPublicationRequest,
    record_worker_output_publication_failure,
)


class HostileBuilder:
    called = 0

    def __call__(self, *_args, **_kwargs):
        type(self).called += 1
        raise RuntimeError("builder must not run")


class HostileReason(Exception):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("no str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("no repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("no format")


def _reset() -> None:
    HostileBuilder.called = 0
    HostileReason.touched = 0


def test_stage1946_safe_exception_info_rejects_caller_owned_builder_without_calling_it() -> None:
    _reset()
    reports: list[tuple[str, str]] = []
    info = safe_exception_info(
        RuntimeError("root"),
        stage="stage1946",
        job={"attempt": 4},
        exception_info_builder=HostileBuilder(),
        report=lambda where, exc: reports.append((where, type(exc).__name__)),
        recoverable_exceptions=(Exception,),
    )

    assert info["stage"] == "stage1946"
    assert info["attempt"] == 4
    assert info["exception_info_builder_unavailable_reason"] == "caller_owned_exception_info_builder_rejected"
    assert HostileBuilder.called == 0
    assert reports == []


def test_stage1946_worker_output_publication_uses_owned_sentinel_without_format_hooks() -> None:
    _reset()
    child_results = {"__scheduler_worker_output_publication_failure__": "occupied"}

    evidence = record_worker_output_publication_failure(
        ChildWorkerOutputPublicationRequest(
            child_results=child_results,
            file_path=None,
            worker_output_path=None,
            context="ctx",
            failure_stage="stage",
            reason=HostileReason("secret"),
        )
    )

    assert evidence.child_result_count == 1
    assert "__scheduler_worker_output_publication_failure___1" in child_results
    assert child_results["__scheduler_worker_output_publication_failure___1"]["queue_failure"] is True
    assert HostileReason.touched == 0


def test_stage1946_worker_child_sources_have_no_legacy_fallback_or_sentinel_fstring() -> None:
    failure_source = read_python_file(Path("Virus_Scan/scheduler/workers/child_failure_metadata.py"))
    output_source = read_python_file(Path("Virus_Scan/scheduler/workers/child_output_evidence.py"))

    assert "fallback=" not in failure_source
    assert "return fallback" not in failure_source
    assert "safe_exception_info_failed" not in failure_source or "f\"" not in failure_source
    assert "fallback=" not in output_source
    assert "return fallback" not in output_source
    assert "f\"{sentinel}_{evidence.child_result_count}" not in output_source
    assert "child_result_count=safe_child_result_count(child_results)" not in output_source
