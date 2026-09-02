from __future__ import annotations

from pathlib import Path

from Virus_Scan.routing import passive_assets
from Virus_Scan.routing.artifact_fingerprints import fingerprint_artifact
from Virus_Scan.routing.file_identity import sniff_file_identity


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def test_passive_asset_triage_accepts_only_clean_list_tags_and_known_asset_extensions() -> None:
    assert passive_assets._is_font_asset_extension(".TTF") is True
    assert passive_assets._is_font_asset_extension(".exe") is False
    assert passive_assets._is_media_asset_extension(".PNG") is True
    assert passive_assets._is_media_asset_extension(".dll") is False

    for clean_tags in (
        ["asset_fast_triage"],
        ["unity_container_fast_triage_clean"],
        ["image_fast_triage_clean"],
        ["font_fast_triage_clean"],
        ["passive_asset_fast_triage_clean"],
        ["media_asset"],
    ):
        assert passive_assets._is_terminal_clean_asset_triage(clean_tags) is True

    assert passive_assets._is_terminal_clean_asset_triage(["asset_fast_triage"], suspicious=True) is False
    assert passive_assets._is_terminal_clean_asset_triage(["asset_fast_triage", "process_exec"]) is False
    assert passive_assets._is_terminal_clean_asset_triage(["media_asset", "embedded_executable_marker"]) is False
    assert passive_assets._is_terminal_clean_asset_triage(["font_fast_triage_clean", "scan_router_error"]) is False


def test_passive_fast_asset_wrapper_uses_canonical_result_contract_for_hostile_scalar_tags() -> None:
    assert passive_assets._umige_result_is_passive_fast_asset_result({
        "classification": "media",
        "tags": ["media_asset"],
    }) is True
    assert passive_assets._umige_result_is_passive_fast_asset_result({
        "classification": "media",
        "tags": "encoded_payload",
    }) is False
    assert passive_assets._umige_result_is_passive_fast_asset_result({
        "classification": "asset",
        "suspicious_tags": ["pickle_dangerous_global"],
    }) is False


def test_artifact_fingerprint_sniffed_engine_overrides_misleading_container_context(tmp_path: Path) -> None:
    root = tmp_path / "unity_like" / "Game_Data"
    sample = _write(root / "www" / "img" / "actor.png", b"RPGMV" + b"\0" * 32)

    identity = sniff_file_identity(sample)
    artifact = fingerprint_artifact(sample, identity, container_root=root.parent)

    assert identity.declared_extension == ".png"
    assert identity.sniffed_type == "rpgm_encrypted_asset"
    assert identity.extension_mismatch is True
    assert artifact.engine == "rpgm"
    assert artifact.confidence >= 0.99
    assert "sniffed_type:rpgm_encrypted_asset" in artifact.evidence
    assert "extension_mismatch" in artifact.evidence


def test_artifact_fingerprint_uses_path_context_when_identity_is_not_decisive(tmp_path: Path) -> None:
    root = tmp_path / "unity_project"
    sample = _write(root / "Example_Data" / "Managed" / "notes.txt", b"ordinary text without engine magic")

    identity = sniff_file_identity(sample)
    artifact = fingerprint_artifact(sample, identity, container_root=root)

    assert identity.sniffed_type in {"unknown", "data"}
    assert artifact.engine == "unity"
    assert artifact.confidence >= 0.5
    assert any("path_marker:managed" in item or "path_marker:_data" in item for item in artifact.evidence)
