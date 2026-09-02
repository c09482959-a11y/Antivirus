from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import Virus_Scan.scanners.text as text
from Virus_Scan.scanners import (
    image_jpeg_segments,
    text_api_sequence,
    text_behavior,
    text_extraction,
    text_graph_enrichment,
    text_raw_chunks,
    text_validation_gates,
)



def test_text_public_surface_is_bounded_import_surface_not_oversized_mixed_owner_module():
    source = read_python_file(Path("Virus_Scan/scanners/text.py"))
    assert len(source.splitlines()) <= 200
    assert "def " not in source
    assert "from Virus_Scan.detection.profiles" not in source
    assert "from Virus_Scan.scanners.text_raw_chunks" in source
    assert "from Virus_Scan.scanners.text_api_sequence" in source
    assert "from Virus_Scan.scanners.text_graph_enrichment" in source
    assert "from Virus_Scan.scanners.text_validation_gates" in source


def test_text_facade_points_to_single_bounded_implementations():
    assert text.extract_api_calls is text_api_sequence.extract_api_calls
    assert text.enrich_with_api_and_graph is text_graph_enrichment.enrich_with_api_and_graph
    assert text._umige_build_extraction_view is text_extraction._umige_build_extraction_view
    assert text._looks_like_base64_payload_status is text_behavior._looks_like_base64_payload_status
    assert text.global_raw_renpy_chunk is text_raw_chunks.global_raw_renpy_chunk
    assert text.validate_high_risk_tag is text_validation_gates.validate_high_risk_tag
    assert text._scan_jpeg_segments is image_jpeg_segments._scan_jpeg_segments


def test_image_scanner_no_longer_imports_jpeg_helper_from_text_module():
    source = read_python_file(Path("Virus_Scan/scanners/image_stego.py"))
    assert "from Virus_Scan.scanners.text import _scan_jpeg_segments" not in source
    assert "from Virus_Scan.scanners.image_jpeg_segments import _scan_jpeg_segments" in source


def test_text_api_graph_preserves_deterministic_tag_normalization_after_split():
    first = text.infer_tags_from_api(
        ["CreateProcess", "InternetOpenUrl", "ReadFile"],
        {"credential_access", "network_activity"},
    )
    second = text.infer_tags_from_api(
        ["CreateProcess", "InternetOpenUrl", "ReadFile"],
        {"network_activity", "credential_access"},
    )
    assert first == second
    assert first == sorted(first)
