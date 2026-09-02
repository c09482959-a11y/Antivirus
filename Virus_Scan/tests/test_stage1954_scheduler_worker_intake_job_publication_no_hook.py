from __future__ import annotations

from pathlib import Path
from queue import Empty

from Virus_Scan.scheduler.workers.inmemory_worker_intake import (
    InMemoryWorkerTaskIntakeDependencies,
    receive_inmemory_worker_task,
)
from Virus_Scan.scheduler.workers.inmemory_worker_job import InMemoryWorkerJobExecutionRequest
from Virus_Scan.scheduler.workers.inmemory_worker_job_publication import running_publication_evidence


class HostileScalar:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    class_getattribute_calls = 0
    property_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.class_getattribute_calls = 0
        cls.property_calls = 0

    def __getattribute__(self, name):
        if name == "__class__":
            type(self).class_getattribute_calls += 1
            raise AssertionError("caller-owned __class__ lookup must not execute")
        return object.__getattribute__(self, name)

    def __str__(self):
        type(self).str_calls += 1
        raise AssertionError("caller-owned __str__ must not execute")

    def __repr__(self):
        type(self).repr_calls += 1
        raise AssertionError("caller-owned __repr__ must not execute")

    def __format__(self, _spec):
        type(self).format_calls += 1
        raise AssertionError("caller-owned __format__ must not execute")

    def __bool__(self):
        type(self).bool_calls += 1
        raise AssertionError("caller-owned __bool__ must not execute")

    def __iter__(self):
        type(self).iter_calls += 1
        raise AssertionError("caller-owned __iter__ must not execute")

    def __float__(self):
        type(self).float_calls += 1
        raise AssertionError("caller-owned __float__ must not execute")

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("caller-owned __int__ must not execute")


class HostileRequest:
    @property
    def job_id(self):
        HostileScalar.property_calls += 1
        raise AssertionError("request.job_id property must not execute")

    @property
    def generation(self):
        HostileScalar.property_calls += 1
        raise AssertionError("request.generation property must not execute")

    @property
    def path(self):
        HostileScalar.property_calls += 1
        raise AssertionError("request.path property must not execute")


class FakeTaskQueue:
    def __init__(self, item=None, *, empty=False):
        self.item = item
        self.empty = empty
        self.timeouts = []

    def get(self, timeout=0.0):
        self.timeouts.append(timeout)
        if self.empty:
            raise Empty()
        return self.item


def _assert_hostile_untouched() -> None:
    assert HostileScalar.str_calls == 0
    assert HostileScalar.repr_calls == 0
    assert HostileScalar.format_calls == 0
    assert HostileScalar.bool_calls == 0
    assert HostileScalar.iter_calls == 0
    assert HostileScalar.float_calls == 0
    assert HostileScalar.int_calls == 0
    assert HostileScalar.class_getattribute_calls == 0
    assert HostileScalar.property_calls == 0


def test_stage1954_running_publication_rejects_caller_owned_request_properties_without_hooks():
    HostileScalar.reset()

    evidence = running_publication_evidence(HostileRequest(), RuntimeError("queue unavailable"))
    integrity = evidence.as_scan_integrity()

    assert evidence.job_id == 0
    assert evidence.generation == 0
    assert evidence.path == ""
    assert integrity["worker_lifecycle_publication_job_id"] == 0
    assert integrity["worker_lifecycle_publication_generation"] == 0
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsupported_inmemory_worker_request_type"
    assert integrity["worker_lifecycle_publication_job_id_unavailable_reason"] == "unsupported_inmemory_worker_request_type"
    assert integrity["worker_lifecycle_publication_generation_unavailable_reason"] == "unsupported_inmemory_worker_request_type"
    _assert_hostile_untouched()


def test_stage1954_worker_request_rejects_hostile_job_generation_completed_values_without_hooks():
    HostileScalar.reset()

    request = InMemoryWorkerJobExecutionRequest(
        job_id=HostileScalar(),
        path=HostileScalar(),
        generation=HostileScalar(),
        worker_config={},
        cancel_table=None,
        heartbeat_table=None,
        heartbeat_flags=None,
        completed_jobs=HostileScalar(),
        task_meta=None,
    )
    evidence = running_publication_evidence(request, RuntimeError("running unavailable"))
    integrity = evidence.as_scan_integrity()

    assert request.job_id == 0
    assert request.generation == 0
    assert request.completed_jobs == 0
    assert evidence.job_id == 0
    assert evidence.generation == 0
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert "worker_lifecycle_publication_job_id_unavailable_reason" not in integrity
    assert "worker_lifecycle_publication_generation_unavailable_reason" not in integrity
    _assert_hostile_untouched()


def test_stage1954_intake_uses_owned_timeout_after_hostile_float_rejection_without_hooks():
    HostileScalar.reset()
    task_q = FakeTaskQueue(empty=True)

    result = receive_inmemory_worker_task(
        task_q=task_q,
        intake=InMemoryWorkerTaskIntakeDependencies(
            result_put=lambda _item: None,
            queue_empty_type=Empty,
            recoverable_exceptions=(RuntimeError, TypeError, ValueError),
            record_suppressed=lambda _stage, _exc: None,
        ),
        timeout_sec=HostileScalar(),
    )

    assert result.queue_empty is True
    assert task_q.timeouts == [0.05]
    _assert_hostile_untouched()


def test_stage1954_worker_intake_job_publication_source_keeps_closed_rows_removed():
    root = Path(__file__).resolve().parents[1]
    intake = (root / "scheduler" / "workers" / "inmemory_worker_intake.py").read_text()
    job = (root / "scheduler" / "workers" / "inmemory_worker_job.py").read_text()
    publication = (root / "scheduler" / "workers" / "inmemory_worker_job_publication.py").read_text()
    lifecycle_evidence = (root / "scheduler" / "workers" / "inmemory_worker_lifecycle_evidence.py").read_text()
    submission = (root / "scheduler" / "workers" / "inmemory_worker_submission.py").read_text()

    assert "fallback=0.05" not in intake
    assert "default=0," not in intake
    assert "default=0," not in job
    assert "build_worker_error_result_fallback" not in job
    assert "safe_lifecycle_int(request.job_id" not in publication
    assert "safe_lifecycle_int(request.generation" not in publication
    assert "return None" not in publication
    assert "InMemoryWorkerRequestField" in publication
    assert "worker_lifecycle_publication_job_id_unavailable_reason" in lifecycle_evidence
    assert "build_worker_error_result_fallback" not in lifecycle_evidence
    assert "build_worker_error_result_fallback" not in submission
