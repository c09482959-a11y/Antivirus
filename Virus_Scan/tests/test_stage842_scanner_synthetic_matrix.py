import base64
import os
import pickle
import zipfile

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.scanners import archives, binary, binary_pe, entropy, image, payload_decode, pickle_scan, renpy, rpgm, text, unity
from Virus_Scan.scanners.contracts.scanner_evidence import ScannerFailureEvidence
from Virus_Scan.detection.scoring.weighting.context_confidence import compute_context_confidence_amplifier


def _tags(value):
    if isinstance(value, tuple):
        value = value[0]
    if isinstance(value, dict):
        value = value.get("tags") or value.get("hits") or []
    return {str(tag).lower() for tag in (value or [])}


def test_synthetic_payload_pickle_archive_binary_entropy_text_matrix(tmp_path):
    plain_payload = payload_decode.safe_decode_payloads("plain benign text")
    assert isinstance(plain_payload, list)

    encoded = base64.b64encode(b"powershell cmd.exe").decode("ascii")
    decoded = payload_decode.safe_decode_payloads(encoded)
    assert any("base64" in str(item.get("encoding", "")).lower() for item in decoded)

    nested = base64.b64encode(encoded.encode("ascii")).decode("ascii")
    assert isinstance(payload_decode.safe_decode_payloads(nested), list)
    assert isinstance(payload_decode.safe_decode_payloads("base64 QUJDREVGR0hJSktMTU5PUFFSU1RV+_"), list)
    assert isinstance(payload_decode.safe_decode_payloads("4142434445464748494a4b4c4d4e4f50"), list)

    benign_pickle = tmp_path / "benign.rpyc"
    benign_pickle.write_bytes(pickle.dumps({"ok": True}, protocol=4))
    benign_result = pickle_scan.pickle_fast_escalation_prefilter(str(benign_pickle))
    assert "pickle_fast_protocol_hint" in _tags(benign_result)

    base64_pickle = tmp_path / "base64.rpyc"
    base64_pickle.write_text(base64.b64encode(pickle.dumps({"ok": True}, protocol=5)).decode("ascii"), encoding="ascii")
    assert "pickle_fast_base64_protocol_hint" in _tags(pickle_scan.pickle_fast_escalation_prefilter(str(base64_pickle)))

    malformed_pickle = tmp_path / "malformed.rpyc"
    malformed_pickle.write_text("base64 QUJDREVGR0hJSktMTU5PUFFSU1RV+_", encoding="ascii")
    malformed_pickle_result = pickle_scan.pickle_fast_escalation_prefilter(str(malformed_pickle))
    assert {"payload_decode_failed", "scanner_failure_evidence_recorded"} <= _tags(malformed_pickle_result)

    opcode_summary = pickle_scan.analyze_pickle_opcode_graph(b"cos\nsystem\n(S'cmd.exe'\ntR.")
    assert isinstance(opcode_summary, dict)
    assert "errors" in opcode_summary

    simple_zip = tmp_path / "simple.zip"
    with zipfile.ZipFile(simple_zip, "w") as zf:
        zf.writestr("script.txt", "powershell cmd.exe")
    zip_tags, zip_suspicious = archives.scan_archive_file(str(simple_zip))
    assert "zip_archive" in _tags(zip_tags)
    assert zip_suspicious is True

    nested_zip = tmp_path / "nested.zip"
    inner_zip = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_zip, "w") as zf:
        zf.writestr("payload.pkl", pickle.dumps({"ok": True}))
    with zipfile.ZipFile(nested_zip, "w") as zf:
        zf.write(inner_zip, "inner.zip")
    nested_tags, _ = archives.scan_archive_file(str(nested_zip))
    assert "archive" in _tags(nested_tags)

    corrupt_zip = tmp_path / "corrupt.zip"
    corrupt_zip.write_bytes(b"PK\x03\x04bad")
    corrupt_tags, corrupt_suspicious = archives.scan_archive_file(str(corrupt_zip))
    assert corrupt_suspicious is True
    assert {"malformed_container", "failure_domain_extraction"} & _tags(corrupt_tags)

    rpa = tmp_path / "scripts.rpa"
    rpa.write_bytes(b"RPA-3.0 00000010 00000000\nrenpy pickle python exec(")
    rpa_tags, rpa_suspicious = archives.scan_rpa_file(str(rpa))
    assert {"rpa_archive", "renpy_asset_archive"} <= _tags(rpa_tags)
    assert isinstance(rpa_suspicious, bool)

    empty_binary = tmp_path / "empty.bin"
    empty_binary.write_bytes(b"")
    assert "entropy_scan_empty_input" in _tags(entropy.detect_packer_entropy_anomaly(str(empty_binary)))

    high_entropy_binary = tmp_path / "random.bin"
    high_entropy_binary.write_bytes(os.urandom(4096))
    assert "high_entropy_packed" in _tags(entropy.detect_packer_entropy_anomaly(str(high_entropy_binary)))

    tiny_pe = tmp_path / "tiny.exe"
    tiny_pe.write_bytes(b"MZ" + b"\x00" * 58 + (0x80).to_bytes(4, "little"))
    pe_tags, pe_meta = binary.scan_pure_python_pe_file(str(tiny_pe), finalize=False, include_strings=False)
    assert isinstance(pe_tags, list)
    assert isinstance(pe_meta, dict)

    confidence = compute_context_confidence_amplifier(None, ["process_exec", "network_download"], {}, pre_context_score=30.0)
    assert confidence["version"] == "context_confidence_amplifier_v1_capped"

    suspicious_text = tmp_path / "script.rpy"
    suspicious_text.write_text("eval('cmd.exe')\nbase64 " + encoded, encoding="utf-8")
    raw_text = text.global_raw_renpy_chunk(str(suspicious_text))
    assert "code_execution" in _tags(raw_text)


def test_synthetic_image_engine_malformed_and_public_evidence_matrix(tmp_path):
    malformed_png = tmp_path / "bad.png"
    malformed_png.write_bytes(b"not a real png image")
    image_tags, image_suspicious = image.scan_image_file(str(malformed_png), artifact_read_snapshot=artifact_read_snapshot_fixture(malformed_png))
    assert image_suspicious is True
    low_image_tags = _tags(image_tags)
    assert {"image_decode_failed", "malformed_image_input", "scanner_failure_evidence_recorded", "image_final_json_must_record"} <= low_image_tags
    assert "image_fast_triage_clean" not in low_image_tags
    assert "asset_fast_triage_clean" not in low_image_tags

    unity_file = tmp_path / "game.assets"
    unity_file.write_bytes(b"UnityFS Assembly-CSharp MonoBehaviour Process.Start WebClient DownloadString")
    assert "unity" in _tags(unity.scan_unity_file(str(unity_file)))

    rpgm_file = tmp_path / "Game.exe"
    rpgm_file.write_bytes(b"MZ nw.dll package.json www/js child_process eval(")
    assert "rpgm" in _tags(rpgm.scan_rpgm_file(str(rpgm_file)))

    renpy_file = tmp_path / "script.rpy"
    renpy_file.write_text("import pickle\neval('x')\n", encoding="utf-8")
    assert "renpy" in _tags(renpy.scan_renpy_file(str(renpy_file)))

    evidence = ScannerFailureEvidence.from_exception(
        scanner_name="synthetic",
        stage="final_json_publication_contract",
        error=ValueError("synthetic degraded scanner state"),
        input_path="synthetic.bin",
    )
    integrity = evidence.to_scan_integrity()
    assert integrity["had_degraded_stage"] is True
    assert integrity["scanner_failure_evidence"]["final_json_must_record"] is True


def test_binary_pe_parser_results_do_not_use_function_attribute_side_channels(tmp_path):
    sample = tmp_path / "broken.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 58 + (0x80).to_bytes(4, "little"))
    result = binary_pe._umige_parse_pe_sections(sample.read_bytes())

    assert isinstance(result, binary_pe.PESectionParseResult)
    assert not hasattr(binary_pe._umige_parse_pe_sections, "last_error_tags")
    assert not hasattr(binary_pe._umige_parse_pe_import_names, "last_error_tags")
