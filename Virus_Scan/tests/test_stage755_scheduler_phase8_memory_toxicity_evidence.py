from __future__ import annotations

from dataclasses import dataclass

import pytest

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity import enforce_worker_memory_toxicity
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import InMemoryMemoryToxicityEvidence


@dataclass(frozen=True)
class _TerminationResult:
    requested: bool
    terminated: bool
    error: str = ""


def test_stage755_memory_toxicity_cancel_failure_records_job_evidence():
    active = {7: {"pid": 55, "state": "running"}}
    job_records = {7: {"attempt": 0}}
    metrics = {55: {"rss_mb": 512.0}}
    suppressed: list[str] = []

    def cancel_job(job_id, reason, *, pid):
        raise RuntimeError(f"cancel failed {job_id} {reason} {pid}")

    cancelled = enforce_worker_memory_toxicity(
        procs=(),
        active=active,
        terminal=set(),
        worker_metrics=metrics,
        rss_limit_mb=128.0,
        cancel_job=cancel_job,
        idle_worker_terminator=lambda **_: _TerminationResult(False, False),
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _kind, exc: suppressed.append(str(exc)),
        job_records=job_records,
    )

    assert cancelled == 0
    assert suppressed and "cancel failed" in suppressed[0]
    integrity = job_records[7]["scan_integrity"]
    assert integrity["memory_toxicity_escalation_failed"] is True
    assert integrity["memory_toxicity_action"] == "cancel_active_job"
    evidence = job_records[7]["timeout_retry_evidence"][0]
    assert evidence["stage"] == "inmemory_worker_memory_toxicity_escalation"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_stage755_memory_toxicity_cancel_rejection_records_job_evidence():
    active = {8: {"pid": 56, "state": "running"}}
    job_records = {8: {"attempt": 0}}
    metrics = {56: {"rss_mb": 384.0}}

    cancelled = enforce_worker_memory_toxicity(
        procs=(),
        active=active,
        terminal=set(),
        worker_metrics=metrics,
        rss_limit_mb=128.0,
        cancel_job=lambda *_args, **_kwargs: False,
        idle_worker_terminator=lambda **_: _TerminationResult(False, False),
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args, **_kwargs: None,
        job_records=job_records,
    )

    assert cancelled == 0
    integrity = job_records[8]["scan_integrity"]
    assert integrity["memory_toxicity_reason"] == "worker_memory_toxic_cancel_rejected"
    assert active[8]["memory_toxicity_failed"] is True


def test_stage755_memory_toxicity_termination_failure_records_worker_metric_evidence():
    metrics = {57: {"rss_mb": 640.0}}

    evidence_recorded = enforce_worker_memory_toxicity(
        procs=(object(),),
        active={},
        terminal=set(),
        worker_metrics=metrics,
        rss_limit_mb=128.0,
        cancel_job=lambda *_args, **_kwargs: True,
        idle_worker_terminator=lambda **_: _TerminationResult(True, False, "terminate denied"),
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda *_args, **_kwargs: None,
        job_records={},
    )

    assert evidence_recorded == 0
    evidence = metrics[57]["memory_toxicity_evidence"][0]
    assert evidence["reason"] == "worker_memory_toxic_termination_failed"
    assert evidence["error_source"] == "idle_worker_terminator"


def test_stage755_memory_toxicity_evidence_is_immutable():
    evidence = InMemoryMemoryToxicityEvidence(
        pid=1,
        job_id=2,
        reason="unit",
        action="cancel_active_job",
        error_category="RuntimeError",
        error_source="unit",
        detail="boom",
    )
    record = evidence.as_record()
    with pytest.raises(TypeError):
        record["stage"] = "mutated"


def test_stage757_memory_toxicity_terminator_exception_records_evidence():
    active = {9: {"pid": 58, "state": "running"}}
    job_records = {9: {"attempt": 0}}
    metrics = {58: {"rss_mb": 768.0}}
    suppressed: list[str] = []

    def idle_worker_terminator(**_kwargs):
        raise RuntimeError("terminator exploded")

    cancelled = enforce_worker_memory_toxicity(
        procs=(object(),),
        active=active,
        terminal=set(),
        worker_metrics=metrics,
        rss_limit_mb=128.0,
        cancel_job=lambda *_args, **_kwargs: True,
        idle_worker_terminator=idle_worker_terminator,
        recoverable_exceptions=(RuntimeError,),
        record_suppressed=lambda _kind, exc: suppressed.append(str(exc)),
        job_records=job_records,
    )

    assert cancelled == 1
    assert suppressed and "terminator exploded" in suppressed[0]
    evidence = job_records[9]["timeout_retry_evidence"][0]
    assert evidence["reason"] == "worker_memory_toxic_termination_exception"
    assert evidence["error_source"] == "idle_worker_terminator"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
    assert metrics[58]["memory_toxicity_failed"] is True
