import json
from pathlib import Path

def _append_and_return_true(target, value):
    target.append(value)
    return True

from Virus_Scan.scheduler.queue import claim as pqe
from Virus_Scan.scheduler.queue import claim as pqm


def _write_job(queue_dir: Path, name: str, payload: dict) -> Path:
    pending, active, done, failed = pqe._queue_job_dirs(queue_dir)
    for d in (pending, active, done, failed):
        d.mkdir(parents=True, exist_ok=True)
    p = pending / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _quarantine_entries(queue_dir: Path):
    q = queue_dir / "quarantine"
    return list(q.glob("*.json")) + list(q.glob("*.quarantine"))


def test_file_claim_duplicate_guard_exception_fails_closed_and_quarantines(tmp_path):
    q = tmp_path / "q"
    _write_job(q, "000001.json", {"file": str(tmp_path / "a.bin"), "job_type": "file", "queue_file_id": "id-a"})
    seen = []
    job, claim = pqe.claim_process_queue_job(
        q,
        worker_id="w",
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, (where, kw)),
        duplicate_live_guard=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("guard exploded")),
    )

    assert job is None and claim is None
    assert any(where == "queue_claim_duplicate_live_guard_exception_failed_closed" for where, _ in seen)
    assert _quarantine_entries(q)


def test_matching_enqueue_guard_exception_fails_closed_without_claiming(tmp_path):
    q = tmp_path / "q"
    _write_job(q, "000002.json", {"file": str(tmp_path / "raw.bin"), "job_type": "raw_stage", "collector": "strings", "queue_file_id": "id-raw"})
    seen = []
    job, claim = pqm.claim_process_queue_job_matching(
        q,
        lambda j: j.get("job_type") == "raw_stage",
        worker_id="w",
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, where),
        enqueue_guard=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("enqueue broke")),
    )

    assert job is None and claim is None
    assert "queue_claim_matching_enqueue_guard_exception_failed_closed" in seen
    assert _quarantine_entries(q)


def test_file_claim_meta_merge_failure_fails_closed(tmp_path):
    q = tmp_path / "q"
    _write_job(q, "000003.json", {"file": str(tmp_path / "b.bin"), "job_type": "file", "queue_file_id": "id-b"})
    seen = []
    job, claim = pqe.claim_process_queue_job(
        q,
        worker_id="w",
        record_suppressed=lambda where, exc, **kw: _append_and_return_true(seen, where),
        merge_claim_meta_into_job=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("merge broke")),
    )

    assert job is None and claim is None
    assert "queue_claim_meta_merge_failed_closed" in seen
    assert _quarantine_entries(q)


def test_matching_claim_sidecar_failure_returns_to_pending(tmp_path):
    q = tmp_path / "q"
    _write_job(q, "000004.json", {"file": str(tmp_path / "c.bin"), "job_type": "raw_stage", "collector": "strings", "queue_file_id": "id-c"})
    job, claim = pqm.claim_process_queue_job_matching(
        q,
        lambda j: j.get("job_type") == "raw_stage",
        worker_id="w",
        enqueue_guard=lambda *a, **k: True,
        claim_sidecar_from_job=lambda *a, **k: False,
    )

    assert job is None and claim is None
    assert (q / "pending" / "000004.json").exists()
    assert not list((q / "active").glob("*.json"))
