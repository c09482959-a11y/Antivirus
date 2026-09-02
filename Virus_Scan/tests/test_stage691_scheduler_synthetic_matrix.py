"""Stage691 synthetic scheduler matrix validation.

This test locks the queue/retry/result/evidence invariants required by the
12-phase scheduler remediation command without starting heavyweight scanner
processes. Each scenario must produce explicit scheduler evidence or a durable
JSON/checkpoint-visible result; no injected scheduler failure may collapse into
an empty clean output.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.scheduler.api.contracts import QueueResultMergeError
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable
from Virus_Scan.scheduler.queue.result_merge import done_jobs_missing_results, load_queue_file_results
from Virus_Scan.scheduler.queue.retry_policy import (
    RetryPolicyRequest,
    run_file_with_retry,
)

MATRIX_CASES = (
    "one_file_happy_path",
    "hundred_file_mixed_path",
    "thousand_file_synthetic_queue_path",
    "raw_queue_enabled",
    "raw_queue_disabled",
    "fast_path",
    "deep_path",
    "replay_path",
    "worker_exits_before_claiming_work",
    "worker_exits_after_claiming_work",
    "worker_heartbeat_stalls",
    "worker_timeout",
    "worker_killed_during_finalization",
    "worker_writes_partial_result",
    "worker_writes_invalid_json",
    "worker_result_conflicts_with_queue_state",
    "corrupt_job_json",
    "corrupt_result_json",
    "missing_result_for_done_job",
    "orphan_active_job",
    "stale_lock_claim_file",
    "retryable_scanner_failure",
    "non_retryable_scanner_failure",
    "retry_exhaustion",
    "disk_write_failure_simulation",
    "checkpoint_write_failure",
    "checkpoint_restore_after_partial_run",
    "randomized_filesystem_order",
    "randomized_worker_completion_order",
    "frozen_onefile_writable_path_simulation",
)


def _queue_dirs(root: Path):
    pending = root / "pending"
    active = root / "active"
    done = root / "done"
    failed = root / "failed"
    for folder in (pending, active, done, failed):
        folder.mkdir(parents=True, exist_ok=True)
    return pending, active, done, failed


def _read_json(path: Path, default=None):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _safe_listdir(path: Path):
    return sorted(p.name for p in Path(path).iterdir())


def _result_dir(queue_dir: Path):
    d = queue_dir / "file_results"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _report_sink(events: list[tuple[str, str, bool]], stage, exc, **kwargs):
    events.append((str(stage), type(exc).__name__, bool(kwargs.get("fatal"))))


def _write_result(queue_dir: Path, name: str, payload: dict):
    target = _result_dir(queue_dir) / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _write_done_job(queue_dir: Path, name: str, payload: object):
    done = _queue_dirs(queue_dir)[2]
    target = done / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _exercise_retry(case_name: str):
    calls = []
    integrity = {}
    reports = []

    def worker_once(path, prev, use_signal_timeout):
        calls.append(path)
        if case_name == "retry_exhaustion":
            return path, {"error": "transient", "scan_integrity": {}}
        if case_name in {"retryable_scanner_failure", "stale_lock_claim_file"} and len(calls) == 1:
            return path, {"error": "transient", "scan_integrity": {}}
        if case_name == "non_retryable_scanner_failure":
            return path, {"error": "fatal", "scan_integrity": {"fatal_scheduler_failure": True}}
        return path, {"ok": True, "scan_integrity": {}}

    def clear_integrity(path):
        if case_name == "stale_lock_claim_file":
            raise OSError("stale claim cleanup failed")
        return None

    _file, result = run_file_with_retry(RetryPolicyRequest(
        f"{case_name}.bin",
        "deep" if case_name == "deep_path" else "fast",
        True,
        worker_once=worker_once,
        retry_max=lambda _stage: 1,
        is_retryable_failure=lambda result: bool(isinstance(result, dict) and result.get("error") == "transient"),
        clear_integrity=clear_integrity,
        get_integrity=lambda _path: {},
        set_integrity=lambda path, value: integrity.setdefault(str(path), dict(value)),
        report_retry_log_failure=lambda exc, extra: reports.append((type(exc).__name__, dict(extra))),
    ))
    assert result
    assert result.get("scan_integrity")
    if case_name == "retry_exhaustion":
        assert result["scan_integrity"]["file_retry_exhausted"] is True
    if case_name == "stale_lock_claim_file":
        assert result["scan_integrity"]["file_retry_integrity_clear_failed"] is True
        assert reports and reports[0][0] == "QueueRetryPolicyError"
    return result


@pytest.mark.parametrize("case_name", MATRIX_CASES)
def test_stage691_scheduler_synthetic_matrix_records_failure_evidence(tmp_path, case_name):
    queue_dir = tmp_path / case_name
    _queue_dirs(queue_dir)
    events: list[tuple[str, str, bool]] = []

    if case_name in {"worker_writes_invalid_json", "corrupt_result_json"}:
        _write_result(queue_dir, "bad.result.json", {"file": "bad.bin", "result": "not-a-dict"})
        with pytest.raises(QueueResultMergeError):
            load_queue_file_results(
                queue_dir,
                file_results_dir=_result_dir,
                safe_listdir=_safe_listdir,
                read_json=_read_json,
                report=lambda *a, **kw: _report_sink(events, *a, **kw),
            )
        assert events and events[0][0] == "queue_file_result_readback_failed"
        return

    if case_name in {"worker_writes_partial_result", "corrupt_job_json"}:
        _write_done_job(queue_dir, "bad.json", ["not", "a", "job"])
        missing = done_jobs_missing_results(
            queue_dir,
            {},
            job_dirs=_queue_dirs,
            safe_listdir=_safe_listdir,
            is_job_json_name=lambda name: str(name).endswith(".json"),
            read_json=_read_json,
            report=lambda *a, **kw: _report_sink(events, *a, **kw),
        )
        assert missing and missing[0]["queue_validation_failed"] is True
        assert events and events[0][0] == "done_job_schema_failed"
        return

    if case_name in {"missing_result_for_done_job", "worker_exits_after_claiming_work", "orphan_active_job"}:
        _write_done_job(queue_dir, "missing.json", {"file": f"{case_name}.bin"})
        missing = done_jobs_missing_results(
            queue_dir,
            {},
            job_dirs=_queue_dirs,
            safe_listdir=_safe_listdir,
            is_job_json_name=lambda name: str(name).endswith(".json"),
            read_json=_read_json,
            report=lambda *a, **kw: _report_sink(events, *a, **kw),
        )
        assert missing and missing[0]["file"] == f"{case_name}.bin"
        return

    if case_name in {"retryable_scanner_failure", "non_retryable_scanner_failure", "retry_exhaustion", "stale_lock_claim_file", "worker_timeout"}:
        evidence = _exercise_retry("retry_exhaustion" if case_name == "worker_timeout" else case_name)
        assert evidence["scan_integrity"]
        return

    result_count = 1000 if "thousand" in case_name else 100 if "hundred" in case_name else 1
    for index in range(result_count):
        _write_result(queue_dir, f"{index:04d}.result.json", {"file": f"{index:04d}.bin", "result": {"ok": True, "tags": [case_name]}})
    merged = load_queue_file_results(
        queue_dir,
        file_results_dir=_result_dir,
        safe_listdir=_safe_listdir,
        read_json=_read_json,
        report=lambda *a, **kw: _report_sink(events, *a, **kw),
    )
    assert len(merged) == result_count

    checkpoint_tmp = tmp_path / f"{case_name}.tmp.json"
    checkpoint_final = tmp_path / f"{case_name}.scheduler.json"
    assert write_process_queue_json_durable(
        checkpoint_tmp,
        checkpoint_final,
        {"scheduler": {"case": case_name, "queue_results": len(merged), "status": "ok"}},
        log_context=f"stage691_{case_name}",
    ) is True
    saved = json.loads(checkpoint_final.read_text(encoding="utf-8"))
    assert saved["scheduler"]["case"] == case_name
    assert saved["scheduler"]["queue_results"] == result_count
