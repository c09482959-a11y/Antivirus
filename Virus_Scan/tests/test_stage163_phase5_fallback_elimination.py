from Virus_Scan.reporting.result_schema import make_terminal_asset_result
from Virus_Scan.utils.stages import extract_router_stage, effective_stage_for_path


def test_terminal_asset_result_uses_canonical_router_without_hidden_asset_fallback():
    result = make_terminal_asset_result("sample.png_", ["router_stage_image", "rpgm_encrypted_asset"], curr_stage=None)
    assert result["effective_stage"] == "image"
    assert "terminal_clean_asset_triage" in result["tags"]


def test_router_stage_canonical_fallback_is_normalized():
    assert effective_stage_for_path([], 'sample.png') == "image"
