from pathlib import Path

from Virus_Scan.detection.scoring.weighting.prefilter_risk import apply_strict_prefilter_risk_floor


def test_stage1118_prefilter_risk_no_hits_or_tags_is_noop():
    result = {"tags": ["existing"], "score": 7.0}

    returned = apply_strict_prefilter_risk_floor(result, {"hits": [], "tags": []})

    assert returned is result
    assert result == {"tags": ["existing"], "score": 7.0}


def test_stage1118_prefilter_risk_floor_preserves_raw_hits_and_tags():
    result = {"tags": [], "score": 2.0, "explanation": {}}

    returned = apply_strict_prefilter_risk_floor(
        result,
        {"hits": ["suspicious string"], "tags": ["unsafe_deserialization"]},
    )

    assert returned["score"] == 35.0
    assert returned["classification"] == "suspicious"
    assert returned["class"] == "suspicious"
    assert returned["raw_prefilter_hits"] == ["suspicious string"]
    assert returned["raw_prefilter_tags"] == ["unsafe_deserialization"]
    assert returned["explanation"]["raw_prefilter_floor"] == 35.0
    assert "strict_prefilter_risk_floor" in returned["explanation"]["reasons"]


def test_stage1118_prefilter_risk_uses_tags_without_name_only_yara_transport():
    returned = apply_strict_prefilter_risk_floor(
        {"score": 0.0, "tags": []},
        {"hits": ["hit"], "tags": ["unsafe_deserialization", "defender_disable"]},
    )
    assert returned["score"] >= 60.0
    assert "yara_light_hits" not in returned
    assert "yara_hits" not in returned


def test_stage1118_prefilter_risk_preserves_renpy_updater_cap(tmp_path: Path):
    source = tmp_path / "game.rpy"
    source.write_text("define config.name = 'Updater'\n")
    result = {
        "file": str(source),
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

    assert returned["score"] == 22.0
    assert returned["classification"] == "benign_clean"
    assert returned["class"] == "benign_clean"
    assert returned["explanation"]["caps"][-1]["name"] == "renpy_official_updater_prefilter_cap"


def test_stage1118_prefilter_risk_preserves_reference_url_cap():
    result = {
        "node": "asset.bin",
        "tags": ["reference_url_behavior_suppressed"],
        "score": 80.0,
        "classification": "malicious",
        "class": "malicious",
        "explanation": {},
    }

    returned = apply_strict_prefilter_risk_floor(
        result,
        {"hits": ["prefilter"], "tags": ["reference_url_behavior_suppressed"]},
    )

    assert returned["score"] == 18.0
    assert returned["classification"] == "benign_clean"
    assert returned["class"] == "benign_clean"
    assert returned["explanation"]["caps"][-1]["name"] == "reference_url_prefilter_cap"
