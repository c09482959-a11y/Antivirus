from Virus_Scan.contracts.result_record import is_passive_fast_asset_result, normalize_result_record, result_is_incomplete_scan


def test_passive_fast_asset_scalar_danger_tags_are_not_character_split():
    for tag in ["encoded_payload", "powershell", "pickle_dangerous_global", "malware"]:
        assert is_passive_fast_asset_result({"class": "image", "tags": tag}) is False


def test_passive_fast_asset_list_danger_tags_still_block_fast_asset():
    assert is_passive_fast_asset_result({"class": "media", "tags": ["encoded_payload"]}) is False


def test_normalizer_keeps_scalar_failure_tag_identity_after_audit_fix():
    rec = normalize_result_record({"file": "x", "tags": "scanner_failure", "classification": "clean"}, file_path="x", source="stage99_audit")
    assert "scanner_failure" in rec["tags"]
    assert "s" not in rec["tags"]
    assert result_is_incomplete_scan(rec)
