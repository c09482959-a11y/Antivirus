from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity import enforce_worker_memory_toxicity
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_actions import cancel_memory_toxic_active_jobs
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import (
    InMemoryMemoryToxicityEvidence,
    memory_toxicity_evidence,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_policy import (
    coerce_memory_toxicity_float,
    record_memory_toxicity_suppression,
)
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_records import (
    memory_toxicity_owned_jobs,
    memory_toxicity_owned_pid_decision,
)


class HostileValue:
    def __bool__(self):  # pragma: no cover - hook execution proves the defect
        raise AssertionError("memory toxicity called __bool__")

    def __float__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called __float__")

    def __int__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called __int__")

    def __str__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called __str__")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called __repr__")


class HostileMapping:
    def items(self):  # pragma: no cover
        raise AssertionError("memory toxicity called mapping items")

    def get(self, _name, _default=None):  # pragma: no cover
        raise AssertionError("memory toxicity called mapping get")

    def __iter__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called mapping iter")

    def __len__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called mapping len")

    def __bool__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called mapping bool")


class HostileError(RuntimeError):
    def __str__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called exception __str__")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("memory toxicity called exception __repr__")


def test_stage1940_memory_toxicity_policy_and_metric_values_reject_without_hooks():
    worker_metrics = {77: {"rss_mb": HostileValue()}}
    active = {5: {"pid": 77}}
    suppressed: list[tuple[str, str]] = []

    result = enforce_worker_memory_toxicity(
        procs=(),
        active=active,
        terminal=set(),
        worker_metrics=worker_metrics,
        rss_limit_mb=10.0,
        cancel_job=lambda *_args, **_kwargs: True,
        idle_worker_terminator=lambda **_kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
        record_suppressed=lambda name, exc: suppressed.append((name, type(exc).__name__)),
        job_records={5: {"state": "running"}},
    )

    assert result == 0
    record = worker_metrics[77]["memory_toxicity_evidence"][0]
    assert record["reason"] == "worker_memory_toxic_rss_metric_malformed"
    assert "memory_toxicity_float_rejected" in record["detail"]
    assert suppressed == [("suppressed_exception", "ValueError")]


def test_stage1940_memory_toxicity_non_owned_mappings_are_not_materialized():
    result = enforce_worker_memory_toxicity(
        procs=(),
        active=HostileMapping(),
        terminal=set(),
        worker_metrics=HostileMapping(),
        rss_limit_mb=10.0,
        cancel_job=lambda *_args, **_kwargs: True,
        idle_worker_terminator=lambda **_kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
        record_suppressed=lambda *_args, **_kwargs: None,
        job_records={},
    )

    assert result == 0
    assert memory_toxicity_owned_jobs(active=HostileMapping(), pid=HostileValue()) == ()
    assert (
        cancel_memory_toxic_active_jobs(
            active=HostileMapping(),
            terminal=set(),
            pid=HostileValue(),
            rss_mb=10.0,
            cancel_job=lambda *_args, **_kwargs: True,
            recoverable_exceptions=(RuntimeError,),
            record_suppressed=lambda *_args, **_kwargs: None,
        )
        == 0
    )


def test_stage2183_memory_toxicity_missing_active_pid_records_replayable_evidence():
    active = {8: {"state": "running"}}
    job_records = {8: {}}
    worker_metrics = {77: {}}
    suppressed: list[tuple[str, str]] = []

    decision = memory_toxicity_owned_pid_decision(active[8])
    assert decision.status == "missing_active_pid"
    assert decision.reason == "missing_active_job_pid"

    cancelled = cancel_memory_toxic_active_jobs(
        active=active,
        terminal=set(),
        pid=77,
        rss_mb=12.5,
        cancel_job=lambda *_args, **_kwargs: True,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
        record_suppressed=lambda event, error, **_kwargs: suppressed.append((event, type(error).__name__)),
        job_records=job_records,
        worker_metrics=worker_metrics,
    )

    assert cancelled == 0
    assert suppressed == [("suppressed_exception", "ValueError")]
    active_record = active[8]["memory_toxicity_evidence"][0]
    assert active_record["reason"] == "worker_memory_toxic_active_job_pid_unavailable"
    assert active_record["error_source"] == "active_job_pid"
    assert "missing_active_job_pid" in active_record["detail"]
    assert active[8]["memory_toxicity_failed"] is True
    assert job_records[8]["scan_integrity"]["memory_toxicity_reason"] == "worker_memory_toxic_active_job_pid_unavailable"
    metric_record = worker_metrics[77]["memory_toxicity_evidence"][0]
    assert metric_record["reason"] == "worker_memory_toxic_active_job_pid_unavailable"


def test_stage1940_memory_toxicity_evidence_projection_rejects_hostile_fields():
    evidence = InMemoryMemoryToxicityEvidence(
        pid=HostileValue(),
        job_id=HostileValue(),
        reason=HostileValue(),
        action=HostileValue(),
        error_category=HostileValue(),
        error_source=HostileValue(),
        detail=HostileValue(),
        rss_mb=HostileValue(),
        final_json_must_record=HostileValue(),
        checkpoint_must_record=HostileValue(),
        replay_must_reproduce=HostileValue(),
    )

    record = evidence.as_record()
    integrity = evidence.as_scan_integrity()

    assert record["pid"] == 0
    assert record["job_id"] == 0
    assert record["rss_mb"] == 0.0
    assert record["final_json_must_record"] is True
    assert integrity["memory_toxicity_pid"] == 0
    assert integrity["memory_toxicity_escalation_failed"] is True

    derived = memory_toxicity_evidence(
        pid=HostileValue(),
        job_id=HostileValue(),
        reason=HostileValue(),
        action=HostileValue(),
        rss_mb=HostileValue(),
        error=HostileError(),
        source=HostileValue(),
    ).as_record()
    assert derived["pid"] == 0
    assert derived["error_category"] == "HostileError"
    assert "input_rejections" in derived["detail"]


def test_stage1940_memory_toxicity_policy_errors_do_not_format_hostile_objects():
    with pytest.raises(ValueError) as excinfo:
        coerce_memory_toxicity_float(value=HostileValue(), field=HostileValue())
    assert "memory_toxicity_float_rejected" in str(excinfo.value)

    returned = record_memory_toxicity_suppression(
        error=HostileError(),
        recoverable_exceptions=(HostileError,),
        record_suppressed=lambda *_args, **_kwargs: (_ for _ in ()).throw(HostileError()),
    )
    assert isinstance(returned, RuntimeError)
    assert "suppression_record_failed" in returned.args[0]


def test_stage1940_memory_toxicity_source_guards_block_regression():
    source_expectations = {
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity.py": (
            "return 0",
            "tuple(worker_metrics.items())",
        ),
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_actions.py": (
            "tuple(active.items())",
        ),
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_evidence.py": (
            "float(self.rss_mb or 0.0)",
            "detail = f\"{detail}; input_rejections=",
        ),
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_policy.py": (
            "parsed = float(value or 0.0)",
            "raise ValueError(f\"{field} must be finite\")",
            "return RuntimeError(f\"{error}; suppression_record_failed={record_exc}\")",
        ),
        "Virus_Scan/scheduler/timeout/inmemory_memory_toxicity_records.py": (
            "active.items() if isinstance(info, Mapping) and info.get(\"pid\") == pid",
            "dict(info_items).get(\"pid\")",
        ),
    }
    for relpath, forbidden in source_expectations.items():
        source = Path(relpath).read_text(encoding="utf-8")
        for snippet in forbidden:
            assert snippet not in source
