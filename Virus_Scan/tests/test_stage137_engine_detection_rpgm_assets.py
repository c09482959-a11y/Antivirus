import zipfile

from Virus_Scan.routing.engine_detect import detect_target_engine_context, resolve_scan_engine_hint


def test_rpgm_encrypted_asset_subtree_resolves_rpgm(tmp_path):
    # RPG Maker encrypted assets may be scanned as copied img/audio subtrees
    # without the parent www/js metadata. The engine detector must not require
    # normal .png extension or PNG magic for these RPGMV-wrapped resources.
    img = tmp_path / "img" / "characters"
    img.mkdir(parents=True)
    for i in range(25):
        (img / f"Actor{i}.png_").write_bytes(b"RPGMV\x00\x00\x00" + bytes([i]) * 64)

    ctx = detect_target_engine_context(tmp_path)
    assert ctx["rpgm"] >= 0.80
    assert ctx["rpgm"] > ctx["unknown"]
    resolved, resolved_ctx = resolve_scan_engine_hint(tmp_path, "auto")
    assert resolved == "rpgm"
    assert resolved_ctx["rpgm"] >= 0.80


def test_rpgm_archive_name_scan_detects_rpgm_without_extraction(tmp_path):
    archive = tmp_path / "rpgm_assets.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("www/js/rpg_core.js", "// RPG Maker MV core")
        zf.writestr("www/data/System.json", "{}")
        zf.writestr("www/img/characters/Hero.png_", b"RPGMV\x00\x00\x00asset")

    ctx = detect_target_engine_context(archive)
    assert ctx["rpgm"] >= 0.80
    resolved, _ = resolve_scan_engine_hint(archive, "auto")
    assert resolved == "rpgm"


def test_unity_hard_runtime_overrides_rpgm_encrypted_asset_names(tmp_path):
    (tmp_path / "Game_Data" / "Managed").mkdir(parents=True)
    (tmp_path / "UnityPlayer.dll").write_bytes(b"MZ UnityPlayer")
    (tmp_path / "Game_Data" / "globalgamemanagers").write_bytes(b"Unity")
    (tmp_path / "Game_Data" / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ Assembly-CSharp")
    (tmp_path / "img").mkdir()
    (tmp_path / "img" / "stray.png_").write_bytes(b"RPGMV\x00\x00\x00")

    ctx = detect_target_engine_context(tmp_path)
    assert ctx["unity"] >= 0.80
    assert ctx["unity"] > ctx["rpgm"]
