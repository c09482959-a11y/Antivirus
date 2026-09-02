from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    safe_lifecycle_int,
    safe_lifecycle_text,
    safe_parent_worker_message_identity,
    safe_worker_evidence_label,
    safe_worker_message_preview,
    safe_worker_thread_progress_evidence_inputs,
    worker_lifecycle_exception_reason,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import InMemoryWorkerLifecyclePublicationEvidence


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    int_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.int_calls = 0
        cls.getattribute_calls = 0

    def __getattribute__(self, name):
        if name in {"__class__", "__dict__"}:
            type(self).getattribute_calls += 1
            raise AssertionError(f"caller-owned {name} lookup must not execute")
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

    def __int__(self):
        type(self).int_calls += 1
        raise AssertionError("caller-owned __int__ must not execute")


def _assert_hostile_untouched() -> None:
    assert HostileValue.str_calls == 0
    assert HostileValue.repr_calls == 0
    assert HostileValue.format_calls == 0
    assert HostileValue.bool_calls == 0
    assert HostileValue.iter_calls == 0
    assert HostileValue.int_calls == 0
    assert HostileValue.getattribute_calls == 0


def test_stage1955_lifecycle_scalar_and_text_boundaries_reject_hostile_values_without_hooks():
    HostileValue.reset()

    number = safe_lifecycle_int(HostileValue())
    text, reason = safe_lifecycle_text(
        HostileValue(),
        replacement_text="worker_lifecycle_publication",
        missing_reason="missing_stage1955_text",
        unsupported_reason="unsupported_stage1955_text",
    )
    label = safe_worker_evidence_label(HostileValue(), replacement_text="worker_message")

    assert number == 0
    assert text == "worker_lifecycle_publication"
    assert reason == "unsupported_stage1955_text"
    assert label == "worker_message"
    _assert_hostile_untouched()


def test_stage1955_thread_progress_inputs_reject_hostile_fields_without_hooks():
    HostileValue.reset()

    job_text, attempt, stage_text, counter, reason_text = safe_worker_thread_progress_evidence_inputs(
        job_id=HostileValue(),
        generation=HostileValue(),
        stage_name=HostileValue(),
        reason=HostileValue(),
        progress_counter=HostileValue(),
    )

    assert job_text == "worker"
    assert attempt == 0
    assert stage_text == "scan"
    assert counter == 0
    assert reason_text == "shared heartbeat publication failed"
    _assert_hostile_untouched()


def test_stage1955_lifecycle_publication_evidence_rejects_hostile_fields_without_hooks():
    HostileValue.reset()

    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation=HostileValue(),
        job_id=HostileValue(),
        path=HostileValue(),
        generation=HostileValue(),
        reason=HostileValue(),
        report_failed=HostileValue(),
        report_error=HostileValue(),
    )
    integrity = evidence.as_scan_integrity()

    assert evidence.operation == "worker_lifecycle_publication"
    assert evidence.job_id == 0
    assert evidence.path == ""
    assert evidence.generation == 0
    assert evidence.reason == "worker_lifecycle_publication_failed"
    assert evidence.report_failed is False
    assert evidence.report_error == ""
    assert integrity["worker_lifecycle_publication_path_unavailable_reason"] == "unsafe_scheduler_worker_path_rejected"
    assert integrity["worker_lifecycle_publication_reason_unavailable_reason"] == "unsafe_worker_lifecycle_publication_reason_rejected"
    assert integrity["worker_lifecycle_publication_report_error_unavailable_reason"] == "unsafe_worker_lifecycle_publication_report_error_rejected"
    _assert_hostile_untouched()




def test_stage1955_parent_worker_message_identity_rejects_hostile_message_values_without_hooks():
    HostileValue.reset()

    hostile_kind, hostile_preview = safe_parent_worker_message_identity([HostileValue()])
    dict_preview = safe_worker_message_preview({HostileValue(): "value"})
    unsupported_preview = safe_worker_message_preview(HostileValue())

    assert hostile_kind == "unsupported_parent_worker_message_kind"
    assert hostile_preview == "list[len=1, kind=unsupported_parent_worker_message_kind]"
    assert dict_preview == "dict[len=1]"
    assert unsupported_preview == "unsupported_message_type:HostileValue"
    _assert_hostile_untouched()

def test_stage1955_exception_reason_and_source_guards_keep_fallback_routes_removed():
    HostileValue.reset()

    reason = worker_lifecycle_exception_reason(HostileValue())

    assert reason == "HostileValue: HostileValue"
    _assert_hostile_untouched()

    root = Path(__file__).resolve().parents[1]
    boundary = (root / "scheduler" / "workers" / "inmemory_worker_lifecycle_boundary.py").read_text()
    evidence = (root / "scheduler" / "workers" / "inmemory_worker_lifecycle_evidence.py").read_text()
    submission = (root / "scheduler" / "workers" / "inmemory_worker_submission.py").read_text()
    pool = (root / "scheduler" / "workers" / "inmemory_worker_pool.py").read_text()

    assert "fallback" not in boundary
    assert "default=0" not in boundary
    assert "default=0" not in evidence
    assert "default=0" not in submission
    assert "default=0" not in pool
    assert "name=f" not in pool
    assert "format(index" not in pool
    assert "safe_lifecycle_int(value: Any, *," not in boundary
    assert "safe_lifecycle_int(self.job_id," not in evidence
    assert "safe_lifecycle_int(self.generation," not in evidence
