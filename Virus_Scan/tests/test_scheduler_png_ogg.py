from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.result_record import normalize_stage_from_path


def test_scheduler_extension_contract_preserves_rpgm_png_underscore_assets() -> None:
    path = "www/img/pictures/title.png_"

    assert get_scan_extension(path) == ".png"
    assert normalize_stage_from_path(path) == "image"


def test_scheduler_extension_contract_preserves_rpgm_ogg_underscore_assets() -> None:
    path = "www/audio/bgm/theme.ogg_"

    assert get_scan_extension(path) == ".ogg"
    assert normalize_stage_from_path(path) == "media"
