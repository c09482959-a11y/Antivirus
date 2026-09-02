from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from dataclasses import replace
import inspect
import json

import pytest

from Virus_Scan.scheduler.api.contracts import QueueResultMergeError
from Virus_Scan.core.paths import _queue_job_dirs
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.reporting.output import _queue_file_results_dir
from Virus_Scan.scheduler.queue import results as queue_results
from Virus_Scan.scheduler.queue import quarantine as queue_quarantine
from Virus_Scan.scheduler.queue import issue_reporting as queue_issue_reporting
from Virus_Scan.scheduler.queue.claim_heartbeat import _umige_update_claim_heartbeat

load_queue_file_results = queue_results.load_queue_file_results
queue_done_jobs_missing_results = queue_results.queue_done_jobs_missing_results
_queue_quarantine_job = queue_quarantine._queue_quarantine_job
record_raw_queue_issue = queue_issue_reporting.record_raw_queue_issue
from Virus_Scan.scheduler.workers import process_liveness as worker_authority
from Virus_Scan.scheduler.evidence import raw_queue_monitor as rqmon
from Virus_Scan.scheduler.workers import inmemory_raw_scan as imrs
from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.context.inmemory_raw_dependency_factory import inmemory_raw_scan_dependencies


def test_stage123_load_queue_file_results_fails_closed_on_invalid_record(tmp_path):
    q = tmp_path / "q"
    d = _queue_file_results_dir(q)
    d.mkdir(parents=True, exist_ok=True)
    bad = d / "bad.result.json"
    bad.write_text(json.dumps({"file": "x.bin", "result": "not-a-dict"}), encoding="utf-8")
    calls = []
    report = lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal")))
    with pytest.raises(QueueResultMergeError):
        load_queue_file_results(q, report=report)

    assert ("queue_file_result_readback_failed", "QueueResultSchemaError", True) in calls


def test_stage123_load_queue_file_results_accepts_complete_records(tmp_path):
    q = tmp_path / "q"
    d = _queue_file_results_dir(q)
    d.mkdir(parents=True, exist_ok=True)
    (d / "good.result.json").write_text(json.dumps({"file": "x.bin", "result": {"tags": ["ok"]}}), encoding="utf-8")

    merged = load_queue_file_results(q)

    assert merged == {"x.bin": {"tags": ["ok"]}}


def test_stage123_done_jobs_missing_results_returns_validation_marker(tmp_path):
    q = tmp_path / "q"
    pending, active, done, failed = _queue_job_dirs(q)
    for folder in (pending, active, done, failed):
        folder.mkdir(parents=True, exist_ok=True)
    calls = []
    report = lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal")))
    missing = queue_done_jobs_missing_results(
        queue_results.QueueDoneJobsMissingResultsRequest(
            q,
            {},
            safe_listdir=lambda path: (_ for _ in ()).throw(OSError("list failed")),
            report=report,
        )
    )

    assert missing and missing[0].get("queue_validation_failed") is True
    assert ("queue_done_result_validation_failed", "QueueResultReadError", True) in calls


def test_stage123_inmemory_raw_future_failure_is_degraded(tmp_path):
    # Validate the exact failure-shape used for raw future errors without invoking scanner-heavy collectors.
    calls = []
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    deps = replace(
        inmemory_raw_scan_dependencies(),
        record_issue=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
        build_raw_stage_jobs=lambda *a, **k: [{"collector": "identity", "file_id": "fid", "seq": 0}, {"collector": "decode", "file_id": "fid", "seq": 1}],
        execute_stage_job=lambda j: (_ for _ in ()).throw(RuntimeError("boom")),
        set_scan_integrity=lambda *a, **k: None,
        remember_scan_evidence=lambda *a, **k: None,
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        normalize_yara_hits=lambda hits: list(hits or []),
        sniff_file_identity=lambda path: {"tags": []},
        get_scan_extension=lambda path: ".bin",
        choose_effective_stage=lambda ext_stage, identity: "binary",
        global_raw_eligible=lambda *a, **k: True,
        global_raw_file_id=lambda path: "fid",
    )
    result = imrs.scan_file_inmemory_raw(sample, timeout_sec=1, pretriage_tags=["force"], pretriage_suspicious=True, pretriage_stage="binary", deps=deps)

    assert result is not None
    assert "scanner_failure" in result["tags"]
    assert any("boom" in e for e in result.get("errors") or [])
    assert ("inmemory_raw_future_failed", "RuntimeError", False) in calls


def test_stage123_targeted_functions_do_not_use_unattributed_broad_handlers():
    for fn in (
        load_queue_file_results,
        queue_done_jobs_missing_results,
        _queue_quarantine_job,
        rqmon.queue_io_pressure_sample,
        worker_authority.check_process_queue_worker_liveness,
        _umige_update_claim_heartbeat,
    ):
        src = inspect.getsource(fn)
        assert "except Exception" not in src
