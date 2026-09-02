from __future__ import annotations

from pathlib import Path
from dataclasses import asdict

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.artifact_fingerprints import ArtifactFingerprint, fingerprint_artifact
from Virus_Scan.routing.context_identity import _direct_container_fingerprint
from Virus_Scan.routing.engine_fingerprints import score_direct_container_directory
from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.file_identity import sniff_file_identity


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    return path


def test_renpy_container_unity_dll_keeps_cross_engine_context(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    _write(root / "game" / "script.rpy", "label start:\n    pass\n")
    _write(root / "archive.rpa", b"RPA-3.0\n")
    dll = _write(root / "Assembly-CSharp.dll", b"MZ" + b"\0" * 64 + b"BSJB Assembly-CSharp UnityEngine")

    ctx = classify_engine_context(dll, container_root=root)

    assert ctx.container_engine == "renpy"
    assert ctx.artifact_engine == "unity"
    assert ctx.effective_analysis_engine in {"unity_dotnet", "unity"}
    assert ctx.cross_engine_artifact is True
    assert ctx.engine_mismatch is True
    assert "renpy::unity::.dll" in ctx.baseline_key
    assert ctx.learning_allowed is False


def test_rpgm_png_appended_pe_blocks_media_learning_and_records_payload_baseline(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    _write(root / "www" / "js" / "rpg_core.js", "function Game_Interpreter() {}")
    _write(root / "www" / "data" / "System.json", "{}")
    png = _write(root / "www" / "img" / "sprite.png", b"\x89PNG\r\n\x1a\n" + b"clean" + b"MZpayload")

    ctx = classify_engine_context(png, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "media"
    assert ctx.sniffed_type == "png"
    assert "pe" in ctx.sniffed_embedded_types
    assert ctx.effective_analysis_engine == "embedded_pe_payload"
    assert any(key.startswith("pe/") or "embedded_pe" in key for key in ctx.secondary_baseline_keys)
    assert ctx.learning_allowed is False


def test_unity_container_rpyc_routes_to_renpy_bytecode_without_learning(tmp_path: Path) -> None:
    root = tmp_path / "unity_game"
    _write(root / "UnityPlayer.dll", b"MZ UnityPlayer")
    _write(root / "Game_Data" / "globalgamemanagers", b"UnityFS")
    rpyc = _write(root / "Game_Data" / "script.rpyc", b"RENPY RPC2 marshal")

    ctx = classify_engine_context(rpyc, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "unity"
    assert ctx.artifact_engine == "renpy"
    assert ctx.effective_analysis_engine == "renpy_bytecode"
    assert ctx.cross_engine_artifact is True
    assert ctx.learning_allowed is False


def test_renamed_dll_dat_routes_by_sniffed_identity_not_extension(tmp_path: Path) -> None:
    sample = _write(tmp_path / "unknown" / "payload.dat", b"MZ" + b"\0" * 32 + b"BSJB Assembly-CSharp")
    ctx = classify_engine_context(sample, container_root=sample.parent, trusted_benign=True)

    assert ctx.declared_extension == ".dat"
    assert ctx.sniffed_type == "mono_dotnet_assembly"
    assert ctx.extension_mismatch is True
    assert ctx.effective_analysis_engine == "unity_dotnet"
    assert ctx.learning_allowed is False
    assert ctx.learning_baseline_key is None


def test_rpgm_encrypted_asset_renamed_png_uses_asset_identity(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    _write(root / "www" / "js" / "rpg_core.js", "function Game_Interpreter() {}")
    _write(root / "www" / "data" / "System.json", "{}")
    asset = _write(root / "www" / "img" / "actor.png", b"RPGMV" + b"\0" * 32)

    identity = sniff_file_identity(asset)
    ctx = classify_engine_context(asset, container_root=root, trusted_benign=True)

    assert identity.sniffed_type == "rpgm_encrypted_asset"
    assert ctx.declared_extension == ".png"
    assert ctx.sniffed_type == "rpgm_encrypted_asset"
    assert ctx.extension_mismatch is True
    assert ctx.effective_analysis_engine == "rpgm_encrypted_asset"
    assert ctx.learning_allowed is False


def test_unknown_folder_strong_unity_artifacts_promote_container_context(tmp_path: Path) -> None:
    root = tmp_path / "unknown_unity"
    _write(root / "UnityPlayer.dll", b"MZ UnityPlayer")
    _write(root / "Example_Data" / "globalgamemanagers", b"UnityFS")
    dll = root / "UnityPlayer.dll"

    ctx = classify_engine_context(dll, container_root=root)

    assert ctx.container_engine == "unity"
    assert ctx.container_engine_confidence >= 0.5
    assert ctx.baseline_key.startswith("unity::")


def test_compact_json_record_preserves_required_identity_and_model_fields(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    _write(root / "game" / "script.rpy", "label start:\n    pass\n")
    dll = _write(root / "Assembly-CSharp.dll", b"MZ" + b"\0" * 64 + b"BSJB Assembly-CSharp UnityEngine")
    ctx = classify_engine_context(dll, container_root=root)
    record = {
        "file": str(dll),
        "path": str(dll),
        "classification": "benign_clean",
        "score": 0.0,
        "tags": ["cross_engine_artifact"],
        "temporal_features": {"belief": 0.0},
        "markov_features": {"transition": 0.0},
        "clustering_features": {"cluster": None},
        "graph_features": {"risk": 0.0},
        "yara_hits": [],
        "entropy_signals": [],
        "archive_container_signals": [],
        "decoded_evidence_snippets": [],
        **ctx.as_record_fields(),
    }

    compact = compact_result_record(record)

    for field in (
        "container_engine", "container_engine_confidence", "artifact_engine", "artifact_engine_confidence",
        "declared_extension", "sniffed_type", "sniffed_embedded_types", "extension_mismatch",
        "cross_engine_artifact", "engine_mismatch", "effective_analysis_engine", "baseline_key",
        "extension_baseline", "contextual_baseline", "secondary_baseline_keys", "learning_allowed",
        "learning_reason", "fingerprint_evidence", "temporal_signals", "markov_sequence_signals",
        "clustering_signals", "graph_signals", "yara_signals", "entropy_signals",
        "archive_container_signals", "decoded_evidence_snippets", "errors", "warnings", "crash_traceback",
    ):
        assert field in compact
    assert compact["container_engine"] == "renpy"
    assert compact["artifact_engine"] == "unity"
    assert compact["cross_engine_artifact"] is True


def test_direct_container_directory_scoring_is_canonical_owned_module() -> None:

    scores = score_direct_container_directory("Game_Data")

    assert scores["unity"].engine == "unity"
    assert scores["unity"].evidence == ("direct_dir:game_data",)
    assert "direct_dir_markers" not in _direct_container_fingerprint.__code__.co_names


def test_artifact_fingerprinting_has_owned_canonical_module(tmp_path: Path) -> None:

    sample = _write(tmp_path / "payload.dat", b"MZ" + b"\0" * 32 + b"BSJB Assembly-CSharp UnityEngine")
    identity = sniff_file_identity(sample)
    artifact = fingerprint_artifact(sample, identity, container_root=tmp_path)
    ctx = classify_engine_context(sample, container_root=tmp_path)

    assert isinstance(artifact, ArtifactFingerprint)
    assert artifact.engine == "unity"
    assert ctx.artifact_engine == artifact.engine
    assert "_artifact_fingerprint" not in classify_engine_context.__code__.co_names
