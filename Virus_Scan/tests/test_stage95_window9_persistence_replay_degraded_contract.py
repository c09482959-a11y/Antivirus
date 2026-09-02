import json
from pathlib import Path
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.artifact_read_snapshot import attach_artifact_read_record

from Virus_Scan.contracts.result_record import (
    make_worker_error_result,
    normalize_result_record,
    result_is_cache_reusable,
    result_is_incomplete_scan,
)
from Virus_Scan.models.replay.api import result_learning_payload
from Virus_Scan.reporting.result_schema import _scan_cache_clone_result
from Virus_Scan.storage.scan_cache_result_writer.scan_cache_result_writer import ScanCacheResultWriter
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity


def test_degraded_result_identity_survives_json_roundtrip_and_blocks_replay(tmp_path):
    p = tmp_path / "bad.dll"
    res = normalize_result_record({
        "file": str(p),
        "classification": "benign_clean",
        "tags": ["scanner_degraded"],
        "scan_integrity": {"had_degraded_stage": True},
    })
    roundtrip = json.loads(json.dumps(res))
    assert result_is_incomplete_scan(roundtrip) is True
    assert roundtrip["scan_integrity"]["allow_learning"] is False
    assert result_learning_payload(roundtrip) is None


def test_prescan_cache_clone_rejects_legacy_degraded_record(tmp_path):
    p = tmp_path / "legacy.exe"
    p.write_bytes(b"MZ")
    legacy = {
        "file": "old.exe",
        "classification": "clean",
        "score": 0,
        "tags": ["scanner_failure", "pe_import_parse_scan_error"],
        "scan_integrity": {"allow_learning": False, "had_degraded_stage": True},
    }
    assert _scan_cache_clone_result(legacy, str(p), "aa" * 32) is None


def test_prescan_cache_store_rejects_degraded_result_even_if_class_clean(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"payload")
    degraded = {
        "file": str(p),
        "classification": "clean",
        "score": 0,
        "tags": ["scan_incomplete"],
    }
    assert result_is_cache_reusable(degraded) is False
    attach_artifact_read_record(degraded, artifact_read_snapshot_fixture(p))
    assert ScanCacheResultWriter(disabled_scan_cache_identity())(degraded) is False


def test_worker_error_cache_clone_never_becomes_cache_hit(tmp_path):
    p = tmp_path / "bad.rpyc"
    p.write_bytes(b"\x80\x04")
    res = make_worker_error_result(str(p), RuntimeError("worker died"))
    assert _scan_cache_clone_result(res, str(p), "cc" * 32) is None


def test_complete_evidence_record_remains_cache_reusable(tmp_path):
    p = tmp_path / "ok.txt"
    p.write_text("hello")
    res = normalize_result_record({
        "file": str(p),
        "classification": "benign_clean",
        "score": 1,
        "tags": ["text_file"],
        "scan_integrity": {"allow_learning": True},
    })
    assert result_is_incomplete_scan(res) is False
    clone = _scan_cache_clone_result(res, str(p), "dd" * 32)
    assert isinstance(clone, dict)
    assert clone["cache_hit"] is True
    assert clone["file"] == str(p)


def test_prescan_cache_clone_preserves_canonical_semantic_fields(tmp_path):
    original = tmp_path / "original.py"
    current = tmp_path / "alias.py"
    original.write_text("print('cached')", encoding="utf-8")
    current.write_text("print('cached')", encoding="utf-8")
    record = normalize_result_record({
        "file": str(original),
        "path": str(original),
        "node": str(original),
        "classification": "benign_clean",
        "score": 1,
        "tags": ["text_file"],
        "scan_integrity": {"allow_learning": True},
    })
    record.update({
        "sniffed_type": "py",
        "effective_analysis_engine": "other",
        "artifact_engine_confidence": 0.4,
        "baseline_key": "renpy::other::.py::py",
        "baseline_lookup_order": ["renpy::other::.py::py", "other/.py", "py"],
        "fingerprint_evidence": ["sniffed_type:py", "router:magic_text"],
        "artifact_read": {
            "canonical_path": str(original),
            "content_sha256": "ee" * 32,
            "size": original.stat().st_size,
        },
    })

    clone = _scan_cache_clone_result(record, str(current), "ee" * 32)

    assert isinstance(clone, dict)
    assert clone["file"] == clone["path"] == clone["node"] == str(current)
    assert clone["artifact_read"]["canonical_path"] == str(current)
    assert clone["sniffed_type"] == "py"
    assert clone["effective_analysis_engine"] == "other"
    assert clone["artifact_engine_confidence"] == 0.4
    assert clone["baseline_key"] == "renpy::other::.py::py"
    assert clone["baseline_lookup_order"] == ["renpy::other::.py::py", "other/.py", "py"]
    assert clone["fingerprint_evidence"] == ["sniffed_type:py", "router:magic_text"]
    assert clone["cache_hit"] is True
    assert clone["cache_source"] == "pre_scan_sha256"
