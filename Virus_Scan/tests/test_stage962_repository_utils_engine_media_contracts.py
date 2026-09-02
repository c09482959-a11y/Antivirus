import ast
from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.utils.fast_assets import (
    scan_image_file_fast_triage,
    sniff_recovered_rpgm_payload_type,
    validated_embedded_payload_hits,
)
from Virus_Scan.utils.stages import (
    effective_stage_for_path,
    normalize_game_asset_suffix_extension,
    normalize_profile_extension,
    resolve_content_evidence_stage,
    sanitize_tag_part,
)


def test_stage962_stage_helpers_promote_passive_assets_only_when_content_proves_runtime():
    assert resolve_content_evidence_stage("asset", ["encoded_powershell"]) == "runtime"
    assert resolve_content_evidence_stage("unknown", ["cmd_exec"]) == "runtime"
    assert resolve_content_evidence_stage("other", ["process_injection"]) == "runtime"

    # A concrete image/runtime route is not rewritten by passive-content promotion.
    assert resolve_content_evidence_stage("image", ["encoded_powershell"]) == "image"
    assert resolve_content_evidence_stage("binary", ["cmd_exec"]) == "binary"

    # Benign/passive tags stay passive and do not invent runtime semantics.
    assert resolve_content_evidence_stage("asset", ["image_file", "asset_fast_triage_clean"]) == "asset"


def test_stage962_stage_helpers_use_canonical_suffix_profile_and_router_ownership():
    assert normalize_game_asset_suffix_extension("Audio/BGM/theme.ogg_") == ".ogg"
    assert normalize_game_asset_suffix_extension("img/characters/Hero.PNG_") == ".png"
    assert normalize_game_asset_suffix_extension("data/System.json_") == ".json"
    assert normalize_game_asset_suffix_extension("plain.txt") is None

    assert sanitize_tag_part("PowerShell-Exec") == "powershell_exec"
    assert sanitize_tag_part("") == "unknown"
    assert normalize_profile_extension("Game.RPY") == ".rpy"

    # Router evidence is authoritative when explicit; otherwise extension routing is centralized here.
    assert effective_stage_for_path(["router_stage_asset"], "payload.exe") == "asset"
    assert effective_stage_for_path([], "payload.exe") == "binary"


def test_stage962_fast_asset_payload_detection_is_offset_aware_and_deep_scan_escalating(tmp_path: Path):
    sample = b"MZ" + (b"A" * 62) + b"PK\x03\x04" + b" powershell -enc AAAA"
    path = tmp_path / "sprite.png"
    path.write_bytes(sample)

    # Header-like signatures before min_offset are ignored; embedded signatures after the header are reported.
    assert validated_embedded_payload_hits(sample, min_offset=32) == [(64, "embedded_zip_payload")]

    tags, suspicious, returned_sample = scan_image_file_fast_triage(path, artifact_read_snapshot=artifact_read_snapshot_fixture(path), sample_bytes=128)
    tagset = {str(tag) for tag in tags}
    assert suspicious is True
    assert returned_sample.startswith(b"MZ")
    assert "embedded_zip_payload" in tagset
    assert "embedded_command_or_url" in tagset
    assert "asset_embedded_payload_signature" in tagset
    assert "asset_deep_scan_escalated" in tagset
    assert "image_fast_triage_clean" not in tagset


def test_stage962_rpgm_recovered_payload_type_uses_magic_before_unverified_extension_fallback():
    assert sniff_recovered_rpgm_payload_type(b"OggS" + b"\x00" * 16, ext=".png_") == (
        "ogg",
        ["rpgm_recovered_magic_ogg", "media_file", "audio_file"],
    )
    assert sniff_recovered_rpgm_payload_type(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8, ext=".ogg_") == (
        "png",
        ["rpgm_recovered_magic_png", "image_file", "filetype_image"],
    )
    assert sniff_recovered_rpgm_payload_type(b"", ext=".ogg_") == (
        "encrypted_audio_unverified",
        ["rpgm_encrypted_audio", "media_file", "audio_file"],
    )


def test_stage962_utils_engine_media_modules_keep_static_direct_import_boundaries():
    modules = [
        Path("Virus_Scan/utils/stages.py"),
        Path("Virus_Scan/utils/fast_assets.py"),
    ]
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child.parent = parent
        for node in ast.walk(tree):
            assert not (
                isinstance(node, (ast.Import, ast.ImportFrom)) and not isinstance(getattr(node, "parent", None), ast.Module)
            ), f"function/class-scope import found in {module}:{getattr(node, 'lineno', '?')}"
            assert not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            ), f"dynamic importlib call found in {module}:{getattr(node, 'lineno', '?')}"
            assert not (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "sys"
                and node.value.attr == "modules"
                and isinstance(getattr(node, "ctx", None), ast.Store)
            ), f"{('sys' + '.' + 'modules')} mutation found in {module}:{getattr(node, 'lineno', '?')}"
