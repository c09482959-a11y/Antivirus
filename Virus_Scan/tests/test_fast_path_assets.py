from Virus_Scan.contracts.result_record import (
    is_passive_fast_asset_result,
    make_terminal_asset_result,
)


def test_terminal_fast_asset_result_records_non_learning_evidence() -> None:
    result = make_terminal_asset_result(
        "game/images/title.png",
        ["image_file", "media_asset"],
        prev_stage="unknown",
        curr_stage="image",
    )

    assert result["file"] == "game/images/title.png"
    assert result["fast_path"] is True
    assert result["learn_eligible"] is False
    assert result["effective_stage"] == "image"
    assert result["profile_selection"]["active_profile"] == "media"
    assert "terminal_clean_asset_triage" in result["tags"]
    assert result["scan_integrity"]["terminal_fast_path"] is True


def test_passive_asset_detection_rejects_encoded_payload_scalar_tag() -> None:
    result = {"class": "image", "tags": "encoded_payload"}

    assert is_passive_fast_asset_result(result) is False
