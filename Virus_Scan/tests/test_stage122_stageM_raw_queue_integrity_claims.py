import inspect
import json

from Virus_Scan.scheduler.queue import raw_queue_identity as rqi
from Virus_Scan.scheduler.queue import identity_lock as queue_identity_lock
from Virus_Scan.core.paths import _queue_job_dirs, _queue_claim_meta_path
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.queue.dirs import _ensure_process_queue_dirs
from Virus_Scan.scheduler.queue.diagnostics import queue_cleanup_diagnostic_tmp_files
from Virus_Scan.scheduler.queue.integrity_pipeline import queue_collect_jobs_by_identity
from Virus_Scan.scheduler.queue.issue_reporting import record_raw_queue_issue
from Virus_Scan.scheduler.queue.quarantine import _queue_quarantine_job
from Virus_Scan.scheduler.queue import authority as queue_authority
from Virus_Scan.scheduler.queue.integrity import (
    QueueIntegrityVerificationRequest,
    verify_and_repair_queue_integrity,
)
from Virus_Scan.scheduler.queue.claim_meta import read_claim_meta
def queue_integrity_verify_and_repair_for_test(
    queue_dir,
    *,
    all_files=None,
    phase="startup",
    repair=True,
    ensure_dirs=_ensure_process_queue_dirs,
    cleanup_diagnostic_tmp_files=queue_cleanup_diagnostic_tmp_files,
    identity_collector=queue_collect_jobs_by_identity,
    quarantine_job=_queue_quarantine_job,
    report=record_raw_queue_issue,
):
    return verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        queue_dir,
        all_files=all_files,
        phase=phase,
        repair=repair,
        ensure_dirs=ensure_dirs,
        cleanup_diagnostic_tmp_files=cleanup_diagnostic_tmp_files,
        identity_collector=identity_collector,
        active_claim_is_protected=queue_authority.process_queue_active_claim_is_protected,
        quarantine_job=quarantine_job,
        queue_now=queue_authority.queue_now,
        report=report,
    ))
def _queue_read_claim_meta(claim_path, *, report=record_raw_queue_issue):
    return read_claim_meta(
        claim_path,
        claim_meta_path=_queue_claim_meta_path,
        now=queue_authority.queue_now,
        report=report,
    )
_queue_release_identity_lock_decision = queue_identity_lock.release_identity_lock_decision
from Virus_Scan.scheduler.queue.raw_queue_duplicates import duplicate_live_guard
from Virus_Scan.scheduler.ownership.raw_queue_claim_validation import repair_and_validate_claim_job


def test_stage122_duplicate_live_guard_fails_closed_on_identity_read_failure(tmp_path):
    q = tmp_path / "q"
    pending, active, done, failed = _queue_job_dirs(q)
    for d in (pending, active, done, failed):
        d.mkdir(parents=True, exist_ok=True)
    claim = active / "claim.json"
    claim.write_text(json.dumps({"file": "x.bin"}), encoding="utf-8")
    duplicate = done / "done.json"
    duplicate.write_text(json.dumps({"file": "x.bin"}), encoding="utf-8")
    calls = []
    def bad_read(path, default=None):
        if str(path).endswith("done.json"):
            return "not-object"
        return {"file": "x.bin"}

    assert duplicate_live_guard(
        q,
        claim,
        {"file": "x.bin"},
        job_identity=lambda job, name=None: "file:x.bin",
        job_dirs=_queue_job_dirs,
        safe_listdir=_safe_queue_listdir,
        is_job_json_name=_queue_is_job_json_name,
        read_json=bad_read,
        merge_claim_meta=lambda claim_path, job=None: dict(job or {}),
        quarantine_job=lambda *a, **k: True,
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
    ) is False
    assert ("queue_duplicate_live_guard_read_failed", "ValueError", True) in calls


def test_stage122_integrity_repair_marks_incomplete_on_quarantine_failure(tmp_path):
    q = tmp_path / "q"
    calls = []
    summary = queue_integrity_verify_and_repair_for_test(
        q,
        phase="stage122",
        repair=True,
        ensure_dirs=lambda queue_dir: None,
        cleanup_diagnostic_tmp_files=lambda *a, **k: None,
        identity_collector=lambda queue_dir: {"file:x": [
            {"state": "pending", "path": tmp_path / "a.json", "name": "a.json", "job": {"file": "x"}},
            {"state": "failed", "path": tmp_path / "b.json", "name": "b.json", "job": {"file": "x"}},
        ]},
        quarantine_job=lambda *a, **k: False,
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
    )

    assert summary["integrity_complete"] is False
    assert "integrity_error" in summary
    assert ("queue_integrity_verify_repair_failed", "RuntimeError", True) in calls


def test_stage122_claim_meta_invalid_shape_is_attributable(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir()
    claim.write_text("{}", encoding="utf-8")
    meta = _queue_claim_meta_path(claim)
    meta.write_text(json.dumps(["bad"]), encoding="utf-8")
    calls = []
    data = _queue_read_claim_meta(
        claim,
        report=lambda stage, exc, **kw: calls.append((stage, type(exc).__name__, kw.get("fatal"))),
    )

    qi = data.get("queue_info") or {}
    assert qi.get("claim_meta_invalid") is True
    assert qi.get("progress_marker") == "claim_meta_invalid"
    assert ("queue_claim_meta_invalid_shape", "ValueError", True) in calls


def test_stage122_claim_job_repair_has_no_broad_handlers():
    for fn in (queue_integrity_verify_and_repair_for_test, duplicate_live_guard, _queue_read_claim_meta, _queue_release_identity_lock_decision, repair_and_validate_claim_job):
        assert "except Exception" not in inspect.getsource(fn)


def test_stage122_identity_lock_release_reports_failure(tmp_path):
    calls = []
    assert _queue_release_identity_lock_decision(
        tmp_path / "lock",
        safe_unlink=lambda *a, **k: (_ for _ in ()).throw(OSError("locked")),
        report_issue=lambda stage, exc, **_kwargs: calls.append((stage, type(exc).__name__)),
    ).released is False
    assert ("process_queue_identity_lock_release_failed", "OSError") in calls
