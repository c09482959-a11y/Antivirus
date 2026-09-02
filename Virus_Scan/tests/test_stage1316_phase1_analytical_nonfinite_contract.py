import json
import math

from Virus_Scan.contracts.analytical_evidence import analytical_format_oddity_snapshot
from Virus_Scan.detection.scoring.calibration.analytical_bundle import (
    AnalyticalCalibrationBundleRequest,
    build_analytical_calibration_bundle as build_detection_bundle,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.runtime.analytical_calibration import (
    build_analytical_calibration_bundle as build_runtime_bundle,
)


def _assert_strict_json(payload):
    encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
    assert "NaN" not in encoded
    assert "Infinity" not in encoded


def test_stage1316_format_oddity_nonfinite_entropy_is_unavailable_evidence():
    oddity = analytical_format_oddity_snapshot(
        path="asset.png",
        entropy=math.inf,
        tags=["packed_payload"],
    )

    assert oddity["entropy"] is None
    assert oddity["zscore"] is None
    assert oddity["confidence"] == 0.0
    assert oddity["ready"] is False
    assert oddity["confidence_source"] == "nonfinite_entropy_unavailable"
    assert oddity["unavailable_reason"] == "nonfinite_entropy"
    _assert_strict_json(oddity)


def test_stage1316_detection_analytical_bundle_sanitizes_nonfinite_model_inputs():
    bundle = build_detection_bundle(
        AnalyticalCalibrationBundleRequest(
            path="sample.exe",
            tags=normalize_tag_evidence(
                ("packed_payload",), source_detector="stage1316", source_stage="calibration"
            ),
            entropy=math.nan,
            graph_score=math.inf,
            risk=-math.inf,
        )
    )

    assert bundle["format_oddity"]["ready"] is False
    assert bundle["format_oddity"]["unavailable_reason"] == "nonfinite_entropy"
    assert bundle["graph_context"] == {
        "graph_score": 0.0,
        "feature_count": 0,
        "confidence": 0.0,
        "ready": False,
        "reason": "nonfinite_analytical_value",
    }
    assert bundle["summary"]["risk"] == 0.0
    assert bundle["summary"]["risk_ready"] is False
    assert bundle["summary"]["risk_reason"] == "nonfinite_analytical_value"
    _assert_strict_json(bundle)


def test_stage1316_runtime_analytical_bundle_sanitizes_nonfinite_model_inputs():
    bundle = build_runtime_bundle(
        path="runtime.exe",
        tags=["obfus"],
        entropy=-math.inf,
        graph_score=math.nan,
        risk=math.inf,
    )

    assert bundle["format_oddity"]["ready"] is False
    assert bundle["graph_context"]["graph_score"] == 0.0
    assert bundle["graph_context"]["ready"] is False
    assert bundle["graph_context"]["reason"] == "nonfinite_analytical_value"
    assert bundle["summary"]["risk"] == 0.0
    assert bundle["summary"]["risk_ready"] is False
    assert bundle["summary"]["risk_reason"] == "nonfinite_analytical_value"
    _assert_strict_json(bundle)
