from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_record_derives_required_extension_and_declared_extension_from_path():
    record = compact_result_record({
        "path": "/corpus/RPGM/www/img/picture.rpgmvp",
        "classification": "Clean",
        "score": 0.0,
    })

    assert record["extension"] == "rpgmvp"
    assert record["declared_extension"] == ".rpgmvp"
    assert record["engine_context"]["declared_extension"] == ".rpgmvp"


def test_compact_record_always_emits_numeric_duration_fields():
    record = compact_result_record({
        "path": "/corpus/renpy/script.rpy",
        "classification": "Clean",
        "score": 0.0,
    })

    assert record["scan_duration_seconds"] == 0.0
    assert record["duration_seconds"] == 0.0
    assert record["duration"] == 0.0
    assert record["timing"]["scan_duration_seconds"] == 0.0
