from pathlib import Path

import pytest

from Virus_Scan.runtime.engine_hint_runtime import (
    detect_startup_engine_context,
    resolve_startup_scan_engine_hint,
)
from Virus_Scan.contracts.result_record import make_terminal_asset_result
from Virus_Scan.orchestration.lifecycle import attach_direct_audit_fields, report_results
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record


class _Runtime:
    scan_started_at = 0.0


class _Args:
    scheduler = "serial"
    engine = "auto"


def test_stage307_standalone_media_directory_resolves_media_engine(tmp_path):
    (tmp_path / "cover.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    (tmp_path / "music.ogg").write_bytes(b"OggS" + b"0" * 32)

    context = detect_startup_engine_context(tmp_path)
    resolved, resolved_context = resolve_startup_scan_engine_hint(tmp_path, "auto")

    assert context["media"] >= 0.8
    assert resolved == "media"
    assert resolved_context["media"] >= 0.8


def test_stage307_terminal_media_asset_records_media_profile():
    result = make_terminal_asset_result("sample.png", ["media_asset", "image_file", "asset_fast_triage_clean"])

    assert result["profile_selection"] == {"active_profile": "media"}
    assert result["engine_context"]["media"] == 1.0


def test_stage307_reporting_requires_canonical_routing_evidence():
    runtime = _Runtime()
    records = {
        "sample.png": {
            "file": "sample.png",
            "score": 3.0,
            "classification": "benign_clean",
            "tags": ["media_asset", "image_file", "asset_fast_triage_clean"],
            "profile_selection": {"active_profile": "other"},
            "engine_context": None,
        }
    }

    with pytest.raises(ValueError, match="canonical routing evidence"):
        attach_direct_audit_fields(_Args(), records, yara_ok=False)


def test_stage307_reporting_consumes_worker_owned_routing_evidence(tmp_path):
    sample = tmp_path / "sample.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    runtime = _Runtime()
    base = {
        "file": str(sample),
        "score": 3.0,
        "classification": "benign_clean",
        "tags": ["media_asset", "image_file", "asset_fast_triage_clean"],
    }
    record_with_evidence = attach_routing_evidence_to_record(base, sample, container_root=tmp_path, tags=base["tags"])

    annotated = attach_direct_audit_fields(_Args(), {str(sample): record_with_evidence}, yara_ok=False)
    record = annotated[str(sample)]

    assert record["detected_engine"] == "media"
    assert record["container_engine"] == "media"
    assert record["artifact_engine"] == "media"
    assert record["scheduler_mode"] == "serial"
    assert record["yara_enabled"] is False


def test_stage308_mislabeled_media_magic_resolves_media_engine(tmp_path):
    mislabeled = tmp_path / "cover.bin"
    mislabeled.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)

    context = detect_startup_engine_context(tmp_path)
    resolved, resolved_context = resolve_startup_scan_engine_hint(tmp_path, "auto")

    assert context["media"] >= 0.8
    assert resolved == "media"
    assert resolved_context["media"] >= 0.8


def test_stage308_reporting_rejects_magic_tag_inference_without_routing_evidence():
    runtime = _Runtime()
    records = {
        "cover.bin": {
            "file": "cover.bin",
            "score": 3.0,
            "classification": "benign_clean",
            "tags": ["filetype_image", "image_file", "magic_png", "asset_fast_triage_clean"],
            "profile_selection": {"active_profile": "other"},
            "engine_context": None,
        }
    }

    with pytest.raises(ValueError, match="canonical routing evidence"):
        attach_direct_audit_fields(_Args(), records, yara_ok=False)
