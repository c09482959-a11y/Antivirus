from types import SimpleNamespace
from collections.abc import Mapping

from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    InMemoryWorkerLifecyclePublicationEvidence,
    annotate_worker_lifecycle_publication_failure,
    build_worker_error_result_evidence,
)
from Virus_Scan.scheduler.workers.inmemory_worker_job_publication import running_publication_evidence
from Virus_Scan.scheduler.workers.inmemory_worker_submission import submit_inmemory_worker_task


class HostilePath:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify path")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr path")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format path")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test path")


class HostileRuntimeError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify exception")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr exception")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("do not format exception")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping")

    def __getitem__(self, _key):
        type(self).touched += 1
        raise RuntimeError("do not read mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len mapping")

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("do not get mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items mapping")


def _reset():
    HostilePath.touched = 0
    HostileRuntimeError.touched = 0
    HostileMapping.touched = 0


def test_stage1587_worker_lifecycle_fallback_rejects_hostile_path_and_exception_without_hooks():
    _reset()
    result = build_worker_error_result_evidence(
        HostilePath(),
        HostileRuntimeError("scan exploded"),
        error_result_exc=HostileRuntimeError("constructor exploded"),
    )

    assert HostilePath.touched == 0
    assert HostileRuntimeError.touched == 0
    assert result["queue_failure"] is True
    assert result["file"] == ""
    integrity = result["scan_integrity"]
    assert integrity["worker_error_result_construction_failed"] is True
    assert integrity["worker_error_result_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_failure_error"] == "HostileRuntimeError"
    assert integrity["worker_error_result_error"] == "HostileRuntimeError"


def test_stage1587_lifecycle_publication_evidence_rejects_hostile_path_reason_and_report_without_hooks():
    _reset()
    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation="running",
        job_id=3,
        path=HostilePath(),
        generation=2,
        reason=HostileRuntimeError("queue unavailable"),
        report_failed=True,
        report_error=HostileRuntimeError("report unavailable"),
    )
    integrity = evidence.as_scan_integrity()

    assert HostilePath.touched == 0
    assert HostileRuntimeError.touched == 0
    assert integrity["worker_lifecycle_publication_path"] == ""
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_lifecycle_publication_reason_unavailable_reason"] == "unsafe_worker_lifecycle_publication_reason_rejected"
    assert integrity["worker_lifecycle_publication_report_error_unavailable_reason"] == "unsafe_worker_lifecycle_publication_report_error_rejected"


def test_stage1587_annotate_worker_lifecycle_rejects_hostile_mapping_without_hooks():
    _reset()
    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation="running",
        job_id=4,
        path="life.bin",
        generation=1,
        reason="RuntimeError: queue unavailable",
    )

    output = annotate_worker_lifecycle_publication_failure((HostilePath(), HostileMapping()), evidence)

    assert HostilePath.touched == 0
    assert HostileMapping.touched == 0
    assert output[0] is not None
    result = output[1]
    assert result["worker_lifecycle_publication_failed"] is True
    integrity = result["scan_integrity"]
    assert integrity["worker_lifecycle_publication_output_unavailable_reason"] == "non_materializable_worker_lifecycle_output"


def test_stage1587_running_publication_evidence_avoids_hostile_request_path_and_exception_hooks():
    _reset()
    request = SimpleNamespace(job_id=9, path=HostilePath(), generation=7)

    evidence = running_publication_evidence(request, HostileRuntimeError("running failed"), report_exc=HostileRuntimeError("report failed"))
    integrity = evidence.as_scan_integrity()

    assert HostilePath.touched == 0
    assert HostileRuntimeError.touched == 0
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_lifecycle_publication_failure_reason"] == "HostileRuntimeError: HostileRuntimeError"
    assert integrity["worker_lifecycle_publication_report_error"] == "HostileRuntimeError: HostileRuntimeError"


class _FailingThreadPool:
    def submit(self, *_args, **_kwargs):
        raise HostileRuntimeError("thread pool unavailable")


def test_stage1587_submission_failure_fallback_publishes_safe_path_without_hostile_hooks():
    _reset()
    result_items = []
    task = SimpleNamespace(job_id=41, path=HostilePath(), attempt=6)

    def broken_error_result(_path, _exc):
        raise HostileRuntimeError("constructor unavailable")

    worker_deps = SimpleNamespace(
        result_put=lambda item: result_items.append(item),
        worker_error_result=broken_error_result,
    )

    submission = submit_inmemory_worker_task(
        task=task,
        tpool=_FailingThreadPool(),
        active={},
        execute_job=lambda *_args, **_kwargs: None,
        worker_execution_deps=worker_deps,
        worker_config={},
        cancel_table={},
        heartbeat_table={},
        heartbeat_flags={},
        completed_jobs=0,
        recoverable_exceptions=(HostileRuntimeError,),
        record_suppressed=lambda _stage, _exc: None,
    )

    assert submission.submitted is False
    assert HostilePath.touched == 0
    assert HostileRuntimeError.touched == 0
    assert result_items[0][2] == ""
    result = result_items[0][3]
    integrity = result["scan_integrity"]
    assert integrity["worker_error_result_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
