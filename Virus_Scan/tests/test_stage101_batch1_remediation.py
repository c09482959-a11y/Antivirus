import json
import pytest


from Virus_Scan.core.jsonio import atomic_json_save
from Virus_Scan.scheduler.runtime.queue_json import _queue_write_json_replace
from Virus_Scan.scheduler.evidence.scheduler_json_writer import write_process_queue_json_durable
from Virus_Scan.scheduler.queue.raw_accumulator_store import write_raw_json_durable

def test_atomic_json_save_rejects_semantically_truncated_queue_failure(tmp_path):
    target = tmp_path / "bad_failure.json"
    with pytest.raises(ValueError):
        atomic_json_save(str(target), {"queue_failure": True}, backups=0)
    assert not target.exists()


def test_queue_json_replace_rejects_semantically_incomplete_record(tmp_path):
    target = tmp_path / "claim.json"
    ok = _queue_write_json_replace(target, {"queue_failure": True}, verify=False, log_context="stage101_bad_claim")
    assert ok is False
    assert not target.exists()


def test_queue_json_replace_persists_complete_failure_record(tmp_path):
    target = tmp_path / "claim.json"
    payload = {
        "queue_failure": True,
        "failure_info": {"error": "boom", "exception_type": "OSError", "stage": "unit"},
        "file": "sample.bin",
    }
    assert _queue_write_json_replace(target, payload, verify=True, log_context="stage101_good_claim") is True
    data = json.loads(target.read_text())
    assert data["failure_info"]["error"] == "boom"
    assert data["schema_version"] >= 1


def test_raw_and_process_durable_writers_reject_incomplete_failure_records(tmp_path):
    bad = {"queue_failure": True}
    assert write_process_queue_json_durable(tmp_path / "p.tmp", tmp_path / "p.json", bad, log_context="stage101_pq") is False
    assert write_raw_json_durable(tmp_path / "r.tmp", tmp_path / "r.json", bad, log_context="stage101_raw") is False
    assert not (tmp_path / "p.json").exists()
    assert not (tmp_path / "r.json").exists()


def test_semantic_verifier_rejects_cache_shape_corruption(tmp_path):
    target = tmp_path / "cache.json"
    with pytest.raises(ValueError):
        atomic_json_save(str(target), {"schema_version": 1, "entries": [], "fast_entries": {}}, backups=0)
    assert not target.exists()
