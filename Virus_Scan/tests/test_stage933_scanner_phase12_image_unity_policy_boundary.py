from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot, load_scanner_limits_policy_snapshot
from Virus_Scan.scanners.image_asset_suffix import normalize_game_asset_suffix_extension
from Virus_Scan.scanners.image_bits import bits_to_bytes, image_is_jpeg
from Virus_Scan.scanners.image_tags import confirmed_image_payload_tags, rewrite_stego_tags, stego_tag_rewrite_map
from Virus_Scan.scanners.unity import _is_unity_container_asset_extension


def test_image_stego_policy_is_schema_validated_scanner_owned():
    policy = load_scanner_limits_policy_snapshot()
    assert "possible_lsb_stego" in policy.image_jpeg_lsb_weak_tags
    assert policy.image_stego_tag_rewrite_map["possible_lsb_stego"] == "weak_image_stego_observation"
    assert "image_payload_confirmed" in confirmed_image_payload_tags()
    assert stego_tag_rewrite_map()["url_in_image"] == "image_metadata_url_reference"


def test_image_helpers_are_scanner_owned_without_utils_media_stego_imports():
    assert bits_to_bytes([0, 1, 0, 0, 0, 0, 0, 1]) == b"A"
    assert image_is_jpeg(data=b"\xff\xd8\xffrest") is True
    assert rewrite_stego_tags(["possible_lsb_stego"], data=b"\xff\xd8\xffrest") == ["jpeg_lsb_check_suppressed"]
    assert rewrite_stego_tags(["possible_stego_payload"], data=b"notjpeg") == ["stego_candidate_observation"]


def test_image_asset_suffix_normalization_uses_scanner_policy():
    assert normalize_game_asset_suffix_extension("assets/title.png_") == ".png"
    assert normalize_game_asset_suffix_extension("data/level.bundle_") == ".bundle"
    assert normalize_game_asset_suffix_extension("plain.txt") is None


def test_unity_container_extensions_are_engine_policy_owned():
    policy = load_engine_policy_snapshot()
    assert ".bundle" in policy.unity_container_asset_extensions
    assert _is_unity_container_asset_extension(".bundle") is True
    assert _is_unity_container_asset_extension(".png") is False


def test_phase12_removed_private_media_stego_and_stage_policy_imports_from_image_unity_modules():
    checked = [
        Path("Virus_Scan/scanners/image_tags.py"),
        Path("Virus_Scan/scanners/image_lsb.py"),
        Path("Virus_Scan/scanners/image.py"),
        Path("Virus_Scan/scanners/unity.py"),
        Path("Virus_Scan/scanners/init_parts/scanner_filetype_defaults_init.py"),
    ]
    forbidden = {
        "Virus_Scan.utils.media_stego",
        "Virus_Scan.utils.stages",
    }
    for path in checked:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
            elif isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
        assert not (set(imports) & forbidden), f"{path} still imports private policy helper {set(imports) & forbidden}"
