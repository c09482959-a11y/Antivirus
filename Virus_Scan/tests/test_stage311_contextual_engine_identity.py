from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.file_identity import sniff_file_identity


def test_stage311_renpy_container_unity_dll_cross_engine(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "renpy" / "common").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = root / "game" / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"Assembly-CSharp UnityEngine" + b"\0" * 64)

    ctx = classify_engine_context(dll, container_root=root)

    assert ctx.container_engine == "renpy"
    assert ctx.artifact_engine == "unity"
    assert ctx.effective_analysis_engine == "unity_dotnet"
    assert ctx.cross_engine_artifact is True
    assert ctx.engine_mismatch is True
    assert ctx.baseline_key in {"renpy::unity::.dll::pe", "renpy::unity::.dll::mono_dotnet_assembly"}
    assert ctx.extension_baseline == "unity/.dll"
    assert ctx.contextual_baseline == "renpy::unity::.dll"
    assert ctx.learning_allowed is False
    assert "cross-engine artifact" in ctx.learning_reason


def test_stage311_polyglot_media_blocks_learning(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    png = root / "www" / "img" / "actor.png"
    png.parent.mkdir(parents=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32 + b"MZpayload")

    ctx = classify_engine_context(png, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "media"
    assert ctx.sniffed_type == "png"
    assert "pe" in ctx.sniffed_embedded_types
    assert ctx.baseline_key == "rpgm::media::.png::png"
    assert "rpgm::embedded_pe::.png" in ctx.secondary_baseline_keys
    assert ctx.learning_allowed is False
    assert "embedded-payload" in ctx.learning_reason


def test_stage311_renamed_rpa_and_dll_sniffing(tmp_path: Path) -> None:
    rpa = tmp_path / "archive.bin"
    rpa.write_bytes(b"RPA-3.0\n" + b"payload")
    dll = tmp_path / "module.dat"
    dll.write_bytes(b"MZ" + b"\0" * 32)

    assert sniff_file_identity(rpa).sniffed_type == "rpa"
    dll_id = sniff_file_identity(dll)
    assert dll_id.sniffed_type == "pe"
    assert dll_id.extension_mismatch is True


def test_stage311_compact_json_records_context_fields(tmp_path: Path) -> None:
    root = tmp_path / "unity_game"
    root.mkdir()
    (root / "UnityPlayer.dll").write_bytes(b"MZUnityPlayer")
    rpyc = root / "evil.rpyc"
    rpyc.write_bytes(b"RENPY\0pickle REDUCE exec")
    ctx = classify_engine_context(rpyc, container_root=root)
    record = {
        "file": str(rpyc),
        "path": str(rpyc),
        "score": 85,
        "classification": "malicious",
        "tags": ["renpy_bytecode", "pickle_reduce"],
        "explanation": {"reasons": ["Pickle: REDUCE exec chain"], "exit_code": 3},
        **ctx.as_record_fields(),
    }

    compact = compact_result_record(record)
    json.dumps(compact)

    assert compact["container_engine"] == "unity"
    assert compact["artifact_engine"] == "renpy"
    assert compact["effective_analysis_engine"] == "renpy_bytecode"
    assert compact["cross_engine_artifact"] is True
    assert compact["baseline_key"] == "unity::renpy::.rpyc::renpy_bytecode"
    assert compact["learning_allowed"] is False
