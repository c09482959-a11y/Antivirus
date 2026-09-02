from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity import enforce_worker_memory_toxicity


def test_stage765_memory_toxicity_invalid_limit_records_timeout_evidence():
    worker_metrics = {44: {"rss_mb": 999.0}}
    suppressed = []

    result = enforce_worker_memory_toxicity(
        procs=(),
        active={1: {"pid": 44}},
        terminal=set(),
        worker_metrics=worker_metrics,
        rss_limit_mb="not-a-limit",
        cancel_job=lambda *args, **kwargs: True,
        idle_worker_terminator=lambda **kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
        record_suppressed=lambda name, exc: suppressed.append((name, type(exc).__name__, str(exc))),
        job_records={1: {"state": "running"}},
    )

    assert result == 0
    evidence = worker_metrics["memory_toxicity_policy_evidence"]
    assert evidence
    record = evidence[0]
    assert record["stage"] == "inmemory_worker_memory_toxicity_escalation"
    assert record["reason"] == "worker_memory_toxic_limit_malformed"
    assert record["final_json_must_record"] is True
    assert record["checkpoint_must_record"] is True
    assert record["replay_must_reproduce"] is True


def test_stage765_memory_toxicity_invalid_worker_rss_records_timeout_evidence():
    active = {1: {"pid": 44}}
    job_records = {1: {"state": "running"}}
    worker_metrics = {44: {"rss_mb": "not-rss"}}
    suppressed = []

    result = enforce_worker_memory_toxicity(
        procs=(),
        active=active,
        terminal=set(),
        worker_metrics=worker_metrics,
        rss_limit_mb=10.0,
        cancel_job=lambda *args, **kwargs: True,
        idle_worker_terminator=lambda **kwargs: None,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
        record_suppressed=lambda name, exc: suppressed.append((name, type(exc).__name__, str(exc))),
        job_records=job_records,
    )

    assert result == 0
    record = worker_metrics[44]["memory_toxicity_evidence"][0]
    assert record["reason"] == "worker_memory_toxic_rss_metric_malformed"
    assert record["final_json_must_record"] is True
    assert job_records[1]["scan_integrity"]["timeout_failure"] is True
    assert job_records[1]["scan_integrity"]["allow_learning"] is False
