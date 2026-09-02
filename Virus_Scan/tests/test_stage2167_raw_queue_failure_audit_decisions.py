from __future__ import annotations

from Virus_Scan.scheduler.queue.raw_queue_failure_audit import collect_failed_queue_report, summarize_failed_queue_report
from Virus_Scan.scheduler.queue.raw_queue_failure_audit_decisions import (
    failed_queue_mapping_decision,
    failed_queue_name_decision,
)


class HostileFailureAuditValue:
    touched = 0

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failure audit called __bool__")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failure audit called __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failure audit called __repr__")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("failure audit called __iter__")


def test_stage2167_failed_queue_name_decision_replays_rejection_without_hooks() -> None:
    HostileFailureAuditValue.touched = 0

    decision = failed_queue_name_decision(HostileFailureAuditValue())

    assert decision.accepted is False
    assert decision.text == ""
    assert decision.reason == "unsafe_failed_queue_name_rejected"
    assert decision.value_type == "HostileFailureAuditValue"
    assert HostileFailureAuditValue.touched == 0


def test_stage2167_failed_queue_mapping_decision_replays_unavailable_mapping_without_hooks() -> None:
    HostileFailureAuditValue.touched = 0

    decision = failed_queue_mapping_decision(HostileFailureAuditValue())

    assert decision.accepted is False
    assert decision.reason == "failed_queue_mapping_unsupported"
    assert decision.value_type == "HostileFailureAuditValue"
    assert decision.as_mapping() == {}
    assert HostileFailureAuditValue.touched == 0


def test_stage2167_failed_queue_audit_preserves_canonical_projection_shapes() -> None:
    HostileFailureAuditValue.touched = 0
    messages: list[str] = []

    report = collect_failed_queue_report(
        HostileFailureAuditValue(),
        queue_job_dirs=lambda _queue_dir: (_ for _ in ()).throw(ValueError("blocked")),
        safe_queue_listdir=lambda _path: [],
        is_job_json_name=lambda _name: True,
        read_json_file=lambda _path, default=None: {},
        recoverable_exceptions=(ValueError,),
        log_error=lambda msg: messages.append(msg),
    )
    summary = summarize_failed_queue_report(
        [{"job_type": HostileFailureAuditValue(), "stage": HostileFailureAuditValue()}],
        limit=HostileFailureAuditValue(),
    )

    assert report == []
    assert messages == ["process queue failed-job report collection failed: blocked"]
    assert summary == [(("file", "unknown", "unknown", ""), 1)]
    assert HostileFailureAuditValue.touched == 0
