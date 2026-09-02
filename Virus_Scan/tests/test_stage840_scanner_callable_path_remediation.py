import base64
import json
import pickle

from Virus_Scan.scanners import archives, entropy, pickle_scan, rpgm, text
from Virus_Scan.detection.scoring.weighting.context_confidence import compute_context_confidence_amplifier
from Virus_Scan.scanners.binary_runtime_evidence import _remember_scan_evidence
from Virus_Scan.scanners.image_lsb import scan_pillow_lsb


def test_rpa_scanner_uses_static_helper_imports(tmp_path):
    sample = tmp_path / "scripts.rpa"
    sample.write_bytes(b"RPA-3.0 00000010 00000000\nrenpy pickle python exec(")

    tags, suspicious = archives.scan_rpa_file(str(sample))

    assert "rpa_archive" in tags
    assert "renpy_asset_archive" in tags
    assert isinstance(suspicious, bool)


def test_pickle_fast_prefilter_decodes_base64_pickle(tmp_path):
    sample = tmp_path / "script.rpyc"
    sample.write_text(base64.b64encode(pickle.dumps({"ok": True}, protocol=4)).decode("ascii"), encoding="ascii")

    result = pickle_scan.pickle_fast_escalation_prefilter(str(sample))

    assert result["force_full"] is True
    assert "pickle_base64_protocol_hint" in result["hits"]
    assert "pickle_fast_base64_protocol_hint" in result["tags"]


def test_entropy_anomaly_read_failure_is_degraded():
    result = entropy.detect_packer_entropy_anomaly("missing_locked_entropy_input.bin")

    assert result["score"] == 0.0
    assert "entropy_scan_error" in result["tags"]
    assert result["scan_integrity"]["had_degraded_stage"] is True


def test_detection_context_scoring_no_undefined_runtime_symbols():
    result = compute_context_confidence_amplifier(
        None,
        ["process_exec", "network_download"],
        
        {},
        pre_context_score=30.0,
    )

    assert result["version"] == "context_confidence_amplifier_v1_capped"
    assert "combined_context_max_bonus" in result["caps"]


def test_binary_evidence_publication_is_immutable(tmp_path):
    result = _remember_scan_evidence(tmp_path / "a.bin", strings_blob="x" * 10)

    assert result["ok"] is True
    assert result["cache_publication_request"]["kind"] == "scan_evidence_cache_write"


def test_rpgm_queue_json_reader_has_static_owner(tmp_path):
    payload = {"ok": True}
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert rpgm._queue_read_json_file(path, default={}) == payload


def test_pickle_fast_prefilter_reports_malformed_base64(tmp_path):
    sample = tmp_path / "script.rpyc"
    sample.write_text("base64 QUJDREVGR0hJSktMTU5PUFFSU1RV+_", encoding="ascii")

    result = pickle_scan.pickle_fast_escalation_prefilter(str(sample))

    assert result["force_full"] is True
    assert "pickle_malformed_base64_candidate" in result["hits"]
    assert "payload_decode_failed" in result["tags"]
    assert "scanner_failure_evidence_recorded" in result["tags"]


def test_text_raw_chunk_read_failure_carries_failure_evidence():
    def boom(*_args, **_kwargs):
        raise OSError("locked")

    result = text._global_raw_renpy_chunk("locked.rpyc", open_reader=boom)

    assert "global_raw_read_range_text_error" in result["tags"]
    assert "scanner_failure" in result["tags"]
    assert result["failure_evidence"][0]["scanner_stage"] == "global_raw_read_range_text"


def test_image_malformed_decode_is_degraded(tmp_path):
    sample = tmp_path / "bad.png"
    sample.write_bytes(b"not a real image")
    tags = []

    suspicious = scan_pillow_lsb(str(sample), tags)

    assert suspicious is False
    assert "image_decode_failed" in tags
    assert "malformed_image_input" in tags
    assert "scanner_failure_evidence_recorded" in tags
