import json
from pathlib import Path

from Virus_Scan.core.paths import _queue_claim_meta_path
from Virus_Scan.scheduler.queue.authority import process_queue_read_claim_meta, process_queue_merge_claim_meta_into_job
from Virus_Scan.scheduler.queue.claim_heartbeat import _umige_update_claim_heartbeat


def test_corrupt_claim_meta_is_not_silent_absence(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir(parents=True)
    claim.write_text(json.dumps({"file":"x"}), encoding="utf-8")
    meta_path = _queue_claim_meta_path(claim)
    meta_path.write_text('{"queue_info": ', encoding="utf-8")

    meta = process_queue_read_claim_meta(claim)

    assert isinstance(meta, dict)
    assert meta.get("queue_info", {}).get("claim_meta_corrupt") is True
    assert meta.get("queue_info", {}).get("progress_marker") == "claim_meta_corrupt_recovery"
    assert not meta_path.exists()
    assert any(p.name.startswith(meta_path.name + ".corrupt") for p in claim.parent.iterdir())


def test_corrupt_claim_meta_merge_preserves_owner_guard(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir(parents=True)
    claim.write_text(json.dumps({"file":"x"}), encoding="utf-8")
    meta_path = _queue_claim_meta_path(claim)
    meta_path.write_text('not-json', encoding="utf-8")

    merged = process_queue_merge_claim_meta_into_job(claim, {"file":"x"})

    qi = merged.get("queue_info")
    assert isinstance(qi, dict)
    assert qi.get("claim_meta_corrupt") is True
    assert "heartbeat_time" in qi


def test_heartbeat_rewrites_after_corrupt_claim_meta(tmp_path):
    claim = tmp_path / "active" / "job.json"
    claim.parent.mkdir(parents=True)
    claim.write_text(json.dumps({"file":"x"}), encoding="utf-8")
    meta_path = _queue_claim_meta_path(claim)
    meta_path.write_text('not-json', encoding="utf-8")

    ok = _umige_update_claim_heartbeat(claim, {"file":"x"}, worker_id="w1")

    assert ok is True
    new_meta_path = _queue_claim_meta_path(claim)
    data = json.loads(new_meta_path.read_text(encoding="utf-8"))
    assert data.get("queue_info", {}).get("worker_id") == "w1"
