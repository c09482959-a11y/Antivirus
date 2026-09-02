from Virus_Scan.detection.scoring.weighting.prefilter_risk import apply_strict_prefilter_risk_floor


def test_stage1163_prefilter_string_read_failure_is_explicit_evidence(tmp_path):
    missing_text_source = tmp_path / "missing_script.rpy"
    result = {
        "file": str(missing_text_source),
        "tags": ["renpy_official_updater"],
        "score": 80.0,
        "classification": "malicious",
        "class": "malicious",
        "explanation": {},
    }

    returned = apply_strict_prefilter_risk_floor(
        result,
        {"hits": ["prefilter"], "tags": ["renpy_official_updater"]},
    )

    failures = returned.get("detection_failures") or []
    assert failures
    assert any(item.get("stage_name") == "strict_prefilter_string_read" for item in failures)
    assert returned["scanner_degraded"] is True
    assert returned["confidence_degraded"] is True
    assert returned["explanation"]["detection_failures"]
    assert any(
        item.get("stage_name") == "strict_prefilter_string_read"
        for item in returned["explanation"]["detection_failures"]
    )
