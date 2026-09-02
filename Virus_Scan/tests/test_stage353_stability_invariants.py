import pytest

from Virus_Scan.contracts.result_record import (
    ResultRecordCollectionSnapshot,
    validate_result_collection_invariants,
)
from Virus_Scan.core.jsonio import validate_persistent_record_semantics


def _clean_record(path):
    return {
        "file": path,
        "path": path,
        "classification": "benign_clean",
        "score": 0,
        "tags": ["terminal_clean_asset_triage"],
        "explanation": {"reason": "golden clean asset"},
    }


def test_result_collection_snapshot_rejects_duplicate_file_records():
    payload = {"schema_version": 1, "results": [_clean_record("game/script.rpy"), _clean_record("game/script.rpy")]}
    with pytest.raises(ValueError, match="duplicate result record"):
        ResultRecordCollectionSnapshot.from_payload(payload, context="stage353")


def test_persistent_json_semantics_reject_duplicate_result_records():
    payload = {"schema_version": 1, "results": [_clean_record("assets/logo.png"), _clean_record("assets/logo.png")]}
    with pytest.raises(ValueError, match="duplicate result record"):
        validate_persistent_record_semantics(payload, context="stage353_json")


def test_result_collection_snapshot_accepts_unique_replay_records():
    payload = {"schema_version": 1, "results": [_clean_record("renpy/game/script.rpy"), _clean_record("unity/Game_Data/globalgamemanagers")]}
    snapshot = ResultRecordCollectionSnapshot.from_payload(payload, context="stage353")
    assert snapshot.identities == ("renpy/game/script.rpy", "unity/Game_Data/globalgamemanagers")
    assert validate_result_collection_invariants(payload, context="stage353") is True
