from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.analytical_evidence import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    analytical_correlation_ceiling,
    analytical_family_counts,
    analytical_format_oddity_snapshot,
)
from Virus_Scan.detection.scoring.calibration import analytical_bundle
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.runtime import analytical_calibration



def test_stage1175_runtime_and_detection_use_shared_format_oddity_contract():
    expected = analytical_format_oddity_snapshot(path="sample.exe", entropy=9.0, tags=["packed_payload"])
    assert analytical_calibration.format_oddity_snapshot(path="sample.exe", entropy=9.0, tags=["packed_payload"]) == expected
    assert analytical_bundle.format_oddity_snapshot(path="sample.exe", entropy=9.0, tags=["packed_payload"]) == expected
    assert expected["schema_version"] == ANALYTICAL_EVIDENCE_SCHEMA_VERSION
    assert expected["format"] == "exe"
    assert 0.0 <= expected["confidence"] <= 1.0


def test_stage1175_runtime_and_detection_preserve_distinct_lineage_boundaries():
    runtime_bundle = analytical_calibration.build_analytical_calibration_bundle(
        path="sample.exe",
        tags=["exec", "packed"],
        
        entropy=9.0,
        prev_stage="input",
        curr_stage="evidence",
        graph_score=25.0,
        risk=7.0,
    )
    detection_bundle = analytical_bundle.build_analytical_calibration_bundle(
        analytical_bundle.AnalyticalCalibrationBundleRequest(
            path="sample.exe",
            tags=physical_tag_evidence(
                ("exec", "packed"), source_detector="stage1175", source_stage="calibration"
            ),
            
            entropy=9.0,
            prev_stage="input",
            curr_stage="evidence",
            graph_score=25.0,
            risk=7.0,
        )
    )
    assert runtime_bundle["format_oddity"] == detection_bundle["format_oddity"]
    assert runtime_bundle["correlation_control"] == detection_bundle["correlation_control"]
    assert runtime_bundle["sequence_probability"]["reason"] == "event_native_snapshot_only"
    assert detection_bundle["sequence_probability"]["reason"] == "pure_detection_snapshot_only"
    assert str(detection_bundle["lineage_id"]).startswith("detection-calibration-")


def test_stage1175_calibration_authority_not_duplicated_in_runtime_or_detection_modules():
    runtime_source = read_python_file(Path("Virus_Scan/runtime/analytical_calibration.py"))
    detection_source = read_python_file(Path("Virus_Scan/detection/scoring/calibration/analytical_bundle.py"))
    for source in (runtime_source, detection_source):
        assert "FORMAT_ODDITY_BASELINES" not in source
        assert "ANALYTICAL_TAG_FAMILIES" not in source
        assert "def analytical_format_oddity_snapshot" not in source
        assert "def analytical_family_counts" not in source
        assert "def analytical_correlation_ceiling" not in source
        assert "yara_hits" not in source
    families = analytical_family_counts(["exec", "powershell", "packed", "url"])
    ceiling = analytical_correlation_ceiling(families)
    assert ceiling["active_families"]
    assert 0.35 <= ceiling["correlation_multiplier"] <= 1.0
