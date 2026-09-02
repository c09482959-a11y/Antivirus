from pathlib import Path

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.queue.integrity import (
    QueueIntegrityVerificationRequest,
    collect_jobs_by_identity,
    verify_and_repair_queue_integrity,
)


def test_collect_jobs_by_identity_merges_active_claim_meta(tmp_path):
    pending = tmp_path / "pending"; active = tmp_path / "active"; done = tmp_path / "done"; failed = tmp_path / "failed"
    for d in (pending, active, done, failed):
        d.mkdir()
    (active / "job.json").write_text("{}", encoding="utf-8")
    calls = []

    groups = collect_jobs_by_identity(
        tmp_path,
        job_dirs=lambda _q: (pending, active, done, failed),
        safe_listdir=lambda d: [p.name for p in Path(d).iterdir()],
        is_job_json_name=lambda name: name.endswith(".json"),
        read_json=lambda _p, default=None: {"file": "x"},
        job_identity=lambda job, name=None: "file:" + job["file"],
        merge_claim_meta=lambda p, job: calls.append((p, job)) or {**job, "queue_info": {"claimed": True}},
        report=lambda *a, **k: None,
    )

    assert list(groups) == ["file:x"]
    assert groups["file:x"][0]["state"] == "active"
    assert groups["file:x"][0]["job"]["queue_info"]["claimed"] is True
    assert calls


def test_verify_and_repair_quarantines_duplicate_unprotected_jobs(tmp_path):
    seen = []
    groups = {
        "file:x": [
            {"state": "done", "path": tmp_path / "done.json", "name": "done.json", "job": {"file": "x"}},
            {"state": "pending", "path": tmp_path / "pending.json", "name": "pending.json", "job": {"file": "x"}},
        ]
    }

    summary = verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        tmp_path,
        all_files=None,
        phase="startup",
        repair=True,
        ensure_dirs=lambda _q: None,
        cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
        identity_collector=lambda _q: groups,
        active_claim_is_protected=lambda *a, **k: False,
        quarantine_job=lambda path, **kw: _append_and_return_true(seen, (path, kw)),
        queue_now=lambda: 123.0,
        report=lambda *a, **k: None,
    ))

    assert summary["integrity_complete"] is True
    assert summary["duplicates"] == 1
    assert summary["quarantined"] == 1
    assert seen[0][1]["reason"] == "duplicate_queue_identity_keep_done"
