from pathlib import Path

from Virus_Scan.routing.engine_detect import detect_target_engine_context, resolve_scan_engine_hint


def test_rpgm_layout_wins_even_when_many_early_assets_contain_unity(tmp_path):
    # Regression: asset-heavy RPGM games can sort hundreds of PNGs before /www,
    # and generic asset text must not cause a Unity scan-root hint.
    for i in range(140):
        (tmp_path / f"Image{i:03d}.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"unity " * 8)
    (tmp_path / "www" / "data").mkdir(parents=True)
    (tmp_path / "www" / "js" / "plugins").mkdir(parents=True)
    (tmp_path / "www" / "data" / "Actors.json").write_text("{}", encoding="utf-8")
    (tmp_path / "www" / "data" / "System.json").write_text('{"gameTitle":"Example"}', encoding="utf-8")
    (tmp_path / "www" / "js" / "rpg_core.js").write_text("// RPG Maker MV core", encoding="utf-8")

    ctx = detect_target_engine_context(tmp_path)
    assert ctx["rpgm"] >= 0.80
    assert ctx["rpgm"] > ctx["unity"]
    resolved, resolved_ctx = resolve_scan_engine_hint(tmp_path, "auto")
    assert resolved == "rpgm"
    assert resolved_ctx["rpgm"] >= 0.80


def test_unity_runtime_layout_still_resolves_unity(tmp_path):
    (tmp_path / "Game_Data" / "Managed").mkdir(parents=True)
    (tmp_path / "UnityPlayer.dll").write_bytes(b"MZ UnityPlayer")
    (tmp_path / "Game_Data" / "globalgamemanagers").write_bytes(b"Unity")
    (tmp_path / "Game_Data" / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ Assembly-CSharp")

    ctx = detect_target_engine_context(tmp_path)
    assert ctx["unity"] >= 0.80
    assert ctx["unity"] > ctx["rpgm"]
    resolved, _ = resolve_scan_engine_hint(tmp_path, "auto")
    assert resolved == "unity"
