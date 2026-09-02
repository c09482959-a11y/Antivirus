import json

from Virus_Scan.publication.json_writer import finalize_scan_results
from Virus_Scan.orchestration.lifecycle import attach_direct_audit_fields, report_results
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record, RoutingEvidenceContext


class _Runtime:
    scan_started_at = 0.0
    parent_cli = False
    def get(self, name, default=None):
        return default


class _Args:
    output = "unused.json"
    scheduler = "serial"
    engine = "rpgm"


def test_stage303_reporting_service_attaches_direct_audit_fields(tmp_path):
    args = _Args()
    args.output = str(tmp_path / "scan.json")
    sample = tmp_path / "mislabeled.bin"
    sample.write_bytes(b"RPGMV\x00\x00canonical-test")
    record = {
        "file": str(sample),
        "score": 62,
        "class": "high_confidence",
        "classification": "high_confidence",
        "tags": ["magic_rpgm_encrypted_asset"],
        "profile_selection": {"active_profile": "rpgm"},
    }
    record = attach_routing_evidence_to_record(record, record["file"], container_root=tmp_path, evidence_context=RoutingEvidenceContext.build(tmp_path))
    report_results(_Runtime(), args, {record["file"]: record}, yara_ok=False)
    data = json.loads((tmp_path / "scan.json").read_text())
    out = data[record["file"]]
    assert out["schema_version"] == "scan_result_compact_v2"
    assert out["extension"] == "bin"
    assert out["detected_engine"] == "rpgm"
    assert out["expected_engine"] == "rpgm"
    assert out["scheduler_mode"] == "serial"
    assert out["yara_enabled"] is False
    assert "errors" in out
    assert "warnings" in out


def test_stage303_finalizer_preserves_direct_audit_fields(tmp_path):
    out = tmp_path / "direct.json"
    assert finalize_scan_results(str(out), {
        "sample.ps1": {
            "file": "sample.ps1",
            "score": 92,
            "class": "malicious",
            "classification": "malicious",
            "tags": ["powershell_exec"],
            "chains": ["download_execute_chain"],
            "extension": "ps1",
            "detected_engine": "other",
            "expected_engine": None,
            "scheduler_mode": "process",
            "worker_id": "umige-1",
            "scan_duration_seconds": 0.125,
            "yara_enabled": True,
            "errors": [],
            "warnings": ["synthetic"],
        }
    })
    data = json.loads(out.read_text())["sample.ps1"]
    for key in (
        "extension", "detected_engine", "expected_engine", "scheduler_mode",
        "worker_id", "scan_duration_seconds", "yara_enabled", "errors", "warnings", "chains"
    ):
        assert key in data


def test_stage303_reporting_service_rejects_missing_routing_evidence(tmp_path):
    args = _Args()
    args.output = str(tmp_path / "scan.json")
    record = {
        "file": str(tmp_path / "missing.bin"),
        "score": 0,
        "class": "clean",
        "classification": "clean",
        "tags": [],
    }
    try:
        report_results(_Runtime(), args, {record["file"]: record}, yara_ok=False)
    except ValueError as exc:
        assert "canonical routing evidence" in str(exc)
    else:
        raise AssertionError("reporting accepted a record without canonical routing evidence")
