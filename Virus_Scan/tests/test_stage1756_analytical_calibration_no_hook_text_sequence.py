from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.static_inventory import read_python_file

import json

import pytest
from pathlib import Path

from Virus_Scan.contracts.analytical_evidence import analytical_text_sequence
from Virus_Scan.detection.scoring.calibration.analytical_bundle import (
    AnalyticalCalibrationBundleRequest,
    build_analytical_calibration_bundle as build_detection_analytical_bundle,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.runtime.analytical_calibration import (
    build_analytical_calibration_bundle as build_runtime_analytical_bundle,
)



class HostileAnalyticalToken:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("hostile __str__ must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("hostile __repr__ must not run")

    def __format__(self, _spec):
        type(self).touched += 1
        raise RuntimeError("hostile __format__ must not run")


class HostileAnalyticalIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("hostile __iter__ must not run")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("hostile iterable __str__ must not run")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("hostile iterable __repr__ must not run")


def _reset_hostile_state():
    HostileAnalyticalToken.touched = 0
    HostileAnalyticalIterable.touched = 0


def test_analytical_text_sequence_preserves_counts_with_explicit_rejection_without_hooks():
    _reset_hostile_state()
    rejected = analytical_text_sequence(
        ("safe-tag", HostileAnalyticalToken(), b"byte-tag"),
        unsupported_reason="unsafe_stage1756_analytical_token_rejected",
    )

    assert HostileAnalyticalToken.touched == 0
    assert rejected == (
        "safe-tag",
        "unsafe_stage1756_analytical_token_rejected:HostileAnalyticalToken",
        "byte-tag",
    )
    json.dumps(rejected, sort_keys=True, allow_nan=False)


def test_runtime_analytical_bundle_rejects_hostile_tags_and_yara_hits_without_stringifying():
    _reset_hostile_state()
    bundle = build_runtime_analytical_bundle(
        path="game/script.rpy",
        tags=(HostileAnalyticalToken(), "http"),
        
        entropy=7.1,
        prev_stage="stage-a",
        curr_stage="stage-b",
        graph_score=10.0,
        graph_features={"node": 1},
        risk=0.25,
    )

    assert HostileAnalyticalToken.touched == 0
    assert bundle["summary"]["tag_count"] == 2
    assert bundle["families"]["network"] == 1
    assert bundle["schema_version"]
    json.dumps(bundle, sort_keys=True, allow_nan=False)


def test_detection_analytical_bundle_rejects_hostile_tags_and_yara_hits_without_stringifying():
    _reset_hostile_state()
    bundle = build_detection_analytical_bundle(
        AnalyticalCalibrationBundleRequest(
            path="game/script.rpy",
            tags=physical_tag_evidence(
                ("powershell",), source_detector="stage1756", source_stage="calibration"
            ),
            
            entropy=7.1,
            prev_stage="stage-a",
            curr_stage="stage-b",
            graph_score=10.0,
            graph_features={"node": 1},
            risk=0.25,
        )
    )

    assert HostileAnalyticalToken.touched == 0
    assert bundle["summary"]["tag_count"] == 1
    assert bundle["families"]["execution"] >= 1
    assert bundle["lineage_id"].startswith("detection-calibration-")
    json.dumps(bundle, sort_keys=True, allow_nan=False)


def test_analytical_bundle_sequence_boundaries_do_not_iterate_hostile_sequence_objects():
    _reset_hostile_state()
    runtime_bundle = build_runtime_analytical_bundle(
        path="game/script.rpy",
        tags=HostileAnalyticalIterable(),
        
    )
    with pytest.raises(TypeError, match="analytical_calibration_tag_evidence_required"):
        build_detection_analytical_bundle(
            AnalyticalCalibrationBundleRequest(
                path="game/script.rpy",
                tags=HostileAnalyticalIterable(),
                
            )
        )

    assert HostileAnalyticalIterable.touched == 0
    assert runtime_bundle["summary"]["tag_count"] == 0
    json.dumps(runtime_bundle, sort_keys=True, allow_nan=False)


def test_analytical_calibration_source_no_longer_uses_raw_sequence_stringification():
    runtime_source = read_python_file(Path("Virus_Scan/runtime/analytical_calibration.py"))
    detection_source = read_python_file(Path("Virus_Scan/detection/scoring/calibration/analytical_bundle.py"))

    assert "str(tag)" not in runtime_source
    assert "str(tag)" not in detection_source
    assert "str(hit)" not in runtime_source
    assert "yara_hits" not in runtime_source
    assert "yara_hits" not in detection_source
    assert "str(hit)" not in detection_source
    assert "repr((" not in detection_source
