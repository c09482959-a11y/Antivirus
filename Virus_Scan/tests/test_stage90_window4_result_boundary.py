from pathlib import Path
import json
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record

from Virus_Scan.contracts.result_record import normalize_result_record, result_has_scan_evidence, make_worker_error_result
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity
from Virus_Scan.reporting.result_schema import write_queue_file_result
from Virus_Scan.storage.scan_cache_result_writer.scan_cache_result_writer import ScanCacheResultWriter
from Virus_Scan.publication.json_writer import finalize_scan_results
from Virus_Scan.models.replay.api import result_learning_payload


def test_empty_clean_result_is_forced_incomplete_non_learning():
    res = normalize_result_record({"file": "sample.bin", "score": 0, "classification": "benign_clean", "tags": []})
    assert res["classification"] == "incomplete_scan"
    assert "scan_incomplete" in res["tags"]
    assert "result_contract_violation" in res["tags"]
    assert res["scan_integrity"]["allow_learning"] is False
    assert res["learn_eligible"] is False


def test_explicit_fast_clean_asset_remains_valid():
    res = normalize_result_record({"file": "img.png", "classification": "benign_clean", "fast_path": True, "tags": []})
    assert result_has_scan_evidence(res)
    assert "scan_incomplete" not in res["tags"]
    assert res["classification"] == "benign_clean"


def test_error_result_gets_incomplete_tags_before_persistence(tmp_path):
    claim = tmp_path / "claim.json"
    claim.write_text("{}")
    assert write_queue_file_result(tmp_path, claim, "bad.rpyc", {"file": "bad.rpyc", "error": "locked", "class": "error", "tags": []})
    files = list((tmp_path / "file_results").glob("*.json"))
    assert files
    payload = json.loads(files[0].read_text())
    tags = payload["result"]["tags"]
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "scan_incomplete" in tags
    assert payload["result"]["scan_integrity"]["allow_learning"] is False


def test_finalizer_normalizes_malformed_result(tmp_path):
    out = tmp_path / "scan_results.json"
    assert finalize_scan_results(out, {"x": {"file": "x.exe", "score": 0, "classification": "clean", "tags": []}})
    data = json.loads(out.read_text())
    tags = data["x"]["tags"]
    assert "scan_incomplete" in tags
    assert data["x"]["classification"] == "incomplete_scan"
    assert data["x"]["learn_eligible"] is False


def test_replay_rejects_degraded_incomplete_payload():
    res = normalize_result_record({"file": "x.dll", "error": "worker died", "class": "error", "tags": []})
    assert result_learning_payload(res) is None


def test_worker_error_boundary_is_not_cacheable(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"abc")
    res = make_worker_error_result(str(p), RuntimeError("boom"))
    attach_artifact_read_record(res, artifact_read_snapshot_fixture(p))
    assert ScanCacheResultWriter(disabled_scan_cache_identity())(res) is False
