from Virus_Scan.models.replay.api import result_learning_payload


def test_parent_replay_rejects_incomplete_scan_payloads() -> None:
    result = {
        "file": "game/script.rpy",
        "classification": "benign_clean",
        "score": 0.0,
        "tags": ["scanner_failure", "scan_incomplete"],
        "scan_integrity": {"file_failed": True, "allow_learning": False},
    }

    assert result_learning_payload(result) is None


def test_parent_replay_passive_fast_asset_does_not_create_behavior_flow() -> None:
    result = {
        "file": "game/audio/theme.ogg",
        "class": "media",
        "classification": "benign_clean",
        "score": 3.0,
        "tags": ["audio_file", "media_asset"],
        "yara_hits": [],
        "scan_integrity": {"allow_learning": True},
    }

    payload = result_learning_payload(result)

    assert payload is not None
    assert payload["file_path"] == "game/audio/theme.ogg"
    assert payload["flow"] == []
    assert payload["curr_stage"] == "asset"
