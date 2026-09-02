from pathlib import Path

from Virus_Scan.routing.context_identity import classify_engine_context


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_game_media_artifact_is_not_cross_engine_but_embedded_payload_blocks_learning(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    _write(root / "www/js/rpg_core.js", b"function RPGMAKER(){}")
    _write(root / "www/data/System.json", b'{"gameTitle":"demo"}')
    sample = _write(root / "www/img/bad.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 64 + b"MZpayload")

    identity = classify_engine_context(sample, container_root=root, trusted_benign=True)
    record = identity.as_record_fields()

    assert record["container_engine"] == "rpgm"
    assert record["artifact_engine"] == "media"
    assert record["sniffed_type"] == "png"
    assert "pe" in record["sniffed_embedded_types"]
    assert record["cross_engine_artifact"] is False
    assert record["engine_mismatch"] is False
    assert record["effective_analysis_engine"] == "embedded_pe_payload"
    assert record["learning_allowed"] is False
    assert "polyglot" in record["learning_reason"]
    assert "rpgm::media::.png::png" == record["baseline_key"]
    assert "pe/.exe" in record["secondary_baseline_keys"]


def test_clean_game_media_can_target_artifact_baseline_when_trusted(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    _write(root / "game/script.rpy", b"label start:\n    pass")
    sample = _write(root / "game/images/logo.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 32)

    identity = classify_engine_context(sample, container_root=root, trusted_benign=True)
    record = identity.as_record_fields()

    assert record["container_engine"] == "renpy"
    assert record["artifact_engine"] == "media"
    assert record["cross_engine_artifact"] is False
    assert record["engine_mismatch"] is False
    assert record["learning_allowed"] is True
    assert record["learning_baseline_key"] == "media/.png"
    assert record["container_extension_baseline"] == "renpy/.png"


def test_mixed_scan_root_does_not_force_standalone_media_into_unrelated_game_context(tmp_path: Path) -> None:
    scan_root = tmp_path / "mixed_corpus"
    _write(scan_root / "rpgm_game/www/js/rpg_core.js", b"function RPGMAKER(){}")
    media = _write(scan_root / "standalone_media/logo.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 32)

    identity = classify_engine_context(media, container_root=scan_root, trusted_benign=True)
    record = identity.as_record_fields()

    assert record["container_engine"] == "media"
    assert record["artifact_engine"] == "media"
    assert record["cross_engine_artifact"] is False
    assert record["learning_allowed"] is True
    assert record["learning_baseline_key"] == "media/.png"
