from Virus_Scan.orchestration.lifecycle import attach_direct_audit_fields, report_results
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record


class _Runtime:
    scan_started_at = 0.0


class _Args:
    scheduler = "serial"
    engine = "auto"
    dir = None


def test_contextual_media_embedded_pe_is_not_finalized_as_clean_fast_asset(tmp_path):
    sample = tmp_path / "polyglot.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\ncontentMZpayload")
    runtime = _Runtime()
    base = {
        "file": str(sample),
        "path": str(sample),
        "score": 3.0,
        "class": "benign_clean",
        "classification": "benign_clean",
        "confidence": 0.3,
        "tags": ["terminal_clean_asset_triage", "fast_path_non_learning", "image_file", "embedded_pe_payload"],
        "fast_path": True,
    }
    record = attach_routing_evidence_to_record(
        base,
        sample,
        container_root=tmp_path,
        tags=base["tags"],
        router_identity={"ext": ".png", "magic_type": "png", "tags": ["embedded_pe_signature", "filetype_image", "magic_png"]},
    )
    records = {str(sample): record}

    annotated = attach_direct_audit_fields(_Args(), records, yara_ok=False)
    record = annotated[str(sample)]

    assert record["classification"] == "low_confidence"
    assert record["class"] == "low_confidence"
    assert record["score"] >= 25.0
    assert record["exit_code"] == 1
    assert record["fast_path"] is False
    assert "embedded_pe_payload" in record["tags"]
    assert any("EmbeddedPayload: PE" in item for item in record["decoded_evidence_snippets"])
    assert any("EmbeddedPayload: PE" in item for item in record["explanation"]["reasons"])
