from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.engine_fingerprints import fingerprint_container
from Virus_Scan.routing.file_identity import sniff_file_identity


def test_stage312_unity_container_with_renpy_bytecode_cross_engine(tmp_path: Path) -> None:
    root = tmp_path / "unity_game"
    (root / "Game_Data" / "Managed").mkdir(parents=True)
    (root / "UnityPlayer.dll").write_bytes(b"MZUnityPlayer")
    (root / "Game_Data" / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZAssembly-CSharp UnityEngine")
    (root / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa" + b"0" * 16)
    rpyc = root / "mods" / "payload.rpyc"
    rpyc.parent.mkdir()
    rpyc.write_bytes(b"RENPY\x00GLOBAL\nREDUCE\nbuiltins\nexec")

    ctx = classify_engine_context(rpyc, container_root=root)

    assert ctx.container_engine == "unity"
    assert ctx.artifact_engine == "renpy"
    assert ctx.sniffed_type == "renpy_bytecode"
    assert "pickle_execution_markers" in ctx.sniffed_embedded_types
    assert ctx.effective_analysis_engine == "renpy_bytecode"
    assert ctx.cross_engine_artifact is True
    assert ctx.baseline_key == "unity::renpy::.rpyc::renpy_bytecode"
    assert ctx.learning_allowed is False


def test_stage312_rpgm_container_renamed_unity_dll(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_mv"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    dll = root / "www" / "data" / "plugin.dat"
    dll.parent.mkdir(parents=True)
    dll.write_bytes(b"MZ" + b"Assembly-CSharp UnityEngine" + b"\0" * 64)

    ctx = classify_engine_context(dll, container_root=root)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "unity"
    assert ctx.sniffed_type == "mono_dotnet_assembly"
    assert ctx.extension_mismatch is True
    assert ctx.cross_engine_artifact is True
    assert ctx.effective_analysis_engine == "unity_dotnet"
    assert ctx.baseline_key == "rpgm::unity::.dat::mono_dotnet_assembly"
    assert ctx.learning_allowed is False


def test_stage312_media_appended_pe_routes_embedded_payload_and_blocks_learning(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    png = root / "www" / "img" / "actor.png"
    png.parent.mkdir(parents=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64 + b"MZpayload")

    ctx = classify_engine_context(png, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "media"
    assert ctx.sniffed_type == "png"
    assert "pe" in ctx.sniffed_embedded_types
    assert ctx.effective_analysis_engine == "embedded_pe_payload"
    assert "pe/.exe" in ctx.secondary_baseline_keys
    assert "rpgm::embedded_pe::.png" in ctx.secondary_baseline_keys
    assert ctx.learning_allowed is False
    assert "embedded-payload" in ctx.learning_reason


def test_stage312_sniffing_matrix_core_formats(tmp_path: Path) -> None:
    samples = {
        "lib.so": (b"\x7fELF" + b"0" * 8, "elf"),
        "app.dylib": (b"\xfe\xed\xfa\xcf" + b"0" * 8, "macho"),
        "app.apk": (b"PK\x03\x04AndroidManifest.xmlclasses.dex", "apk"),
        "doc.docx": (b"PK\x03\x04[Content_Types].xmlword/document.xml", "docx_zip"),
        "data.wasm": (b"\x00asm" + b"0" * 8, "wasm"),
        "archive.bin": (b"RPA-3.0\npayload", "rpa"),
        "asset.png": (b"RPGMV" + b"0" * 16, "rpgm_encrypted_asset"),
        "bundle.dat": (b"UnityFS" + b"0" * 16, "unity_asset_bundle"),
        "global-metadata.dat": (b"\xaf\x1b\xb1\xfa" + b"0" * 16, "il2cpp_metadata"),
    }
    for filename, (data, expected) in samples.items():
        path = tmp_path / filename
        path.write_bytes(data)
        assert sniff_file_identity(path).sniffed_type == expected


def test_stage312_compact_json_includes_all_contextual_fields(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = root / "game" / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZAssembly-CSharp UnityEngine")
    ctx = classify_engine_context(dll, container_root=root)
    compact = compact_result_record({
        "file": str(dll),
        "path": str(dll),
        "score": 80,
        "classification": "high_confidence",
        "tags": ["cross_engine_artifact", "unity_dotnet"],
        "explanation": {"reasons": ["Unity DLL inside RenPy container"], "exit_code": 2},
        **ctx.as_record_fields(),
    })
    json.dumps(compact)
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
