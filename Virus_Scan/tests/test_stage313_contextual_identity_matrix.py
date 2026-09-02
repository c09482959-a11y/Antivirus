from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.baseline_routing import (
    BaselineRouteRequest,
    build_baseline_route,
)
from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.engine_fingerprints import fingerprint_container, score_engine_for_path
from Virus_Scan.routing.file_identity import sniff_file_identity


def test_stage313_rpgm_mv_container_with_renamed_unity_dll_is_cross_engine(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_mv"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    (root / "www" / "data").mkdir(parents=True)
    renamed = root / "www" / "data" / "Actors.dat"
    renamed.write_bytes(b"MZ" + b"Assembly-CSharp UnityEngine mscorlib" + b"\0" * 128)

    ctx = classify_engine_context(renamed, container_root=root)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "unity"
    assert ctx.sniffed_type == "mono_dotnet_assembly"
    assert ctx.extension_mismatch is True
    assert ctx.cross_engine_artifact is True
    assert ctx.effective_analysis_engine == "unity_dotnet"
    assert ctx.baseline_key == "rpgm::unity::.dat::mono_dotnet_assembly"
    assert ctx.extension_baseline == "unity/.dat"
    assert ctx.learning_allowed is False


def test_stage313_unity_container_has_il2cpp_webgl_and_renpy_artifact_context(tmp_path: Path) -> None:
    root = tmp_path / "unity_webgl"
    (root / "Build").mkdir(parents=True)
    (root / "Build" / "Build.wasm").write_bytes(b"\x00asm" + b"0" * 32)
    (root / "Build" / "Build.data").write_bytes(b"SerializedFile Unity default resources")
    (root / "Metadata").mkdir()
    (root / "Metadata" / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa" + b"0" * 64)
    rpyc = root / "mods" / "payload.rpyc"
    rpyc.parent.mkdir()
    rpyc.write_bytes(b"RENPY\0GLOBAL\nREDUCE\nbuiltins\nexec")

    assert fingerprint_container(root).engine == "unity"
    ctx = classify_engine_context(rpyc, container_root=root)
    assert ctx.container_engine == "unity"
    assert ctx.artifact_engine == "renpy"
    assert ctx.effective_analysis_engine == "renpy_bytecode"
    assert ctx.cross_engine_artifact is True
    assert ctx.learning_allowed is False


def test_stage313_polyglot_media_and_zip_payloads_block_learning(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    jpg = root / "game" / "image.jpg"
    jpg.write_bytes(b"\xff\xd8\xff" + b"0" * 64 + b"PK\x03\x04payload")

    ctx = classify_engine_context(jpg, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "renpy"
    assert ctx.artifact_engine == "media"
    assert ctx.sniffed_type == "jpg"
    assert "zip" in ctx.sniffed_embedded_types
    assert ctx.effective_analysis_engine == "embedded_zip_payload"
    assert "renpy::embedded_zip::.jpg" in ctx.secondary_baseline_keys
    assert ctx.learning_allowed is False
    assert "embedded-payload" in ctx.learning_reason


def test_stage313_rpgm_encrypted_asset_renamed_as_png_is_extension_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rmmz_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    asset = root / "www" / "img" / "actor.png"
    asset.parent.mkdir(parents=True)
    asset.write_bytes(b"RPGMV" + b"encrypted" * 4)

    ctx = classify_engine_context(asset, container_root=root)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "rpgm"
    assert ctx.sniffed_type == "rpgm_encrypted_asset"
    assert ctx.extension_mismatch is True
    assert ctx.cross_engine_artifact is False
    assert ctx.effective_analysis_engine == "rpgm_encrypted_asset"
    assert ctx.learning_allowed is False


def test_stage313_sniffing_extended_matrix(tmp_path: Path) -> None:
    samples = {
        "bundle.bin": (b"UnityWeb" + b"0" * 32, "unity_asset_bundle"),
        "asset.dat": (b"SerializedFile Unity default resources", "unity_serialized_asset"),
        "game.asar": ((24).to_bytes(4, "little") + b"\x00\x00\x00\x00" + b'{"files":{}}' + b"0" * 16, "asar"),
        "metadata.bin": (b"\xaf\x1b\xb1\xfa" + b"0" * 64, "il2cpp_metadata"),
        "rpg.bin": (b"RGSSAD\x00" + b"0" * 16, "rgss_archive"),
        "dotnet.dat": (b"MZ" + b"0" * 64 + b"BSJB mscorlib", "mono_dotnet_assembly"),
        "app.dylib": (b"\xcf\xfa\xed\xfe" + b"0" * 12, "macho"),
    }
    for name, (data, expected) in samples.items():
        path = tmp_path / name
        path.write_bytes(data)
        assert sniff_file_identity(path).sniffed_type == expected


def test_stage313_baseline_lookup_order_and_learning_gates() -> None:
    route = build_baseline_route(BaselineRouteRequest(
        container_engine="rpgm",
        artifact_engine="media",
        declared_extension=".png",
        sniffed_type="png",
        sniffed_embedded_types=("pe",),
        extension_mismatch=False,
        engine_mismatch=False,
        degraded=False,
        trusted_benign=True,
    ))

    assert route.baseline_key == "rpgm::media::.png::png"
    assert route.secondary_baseline_keys[:7] == (
        "rpgm::media::.png::png",
        "rpgm::media::.png",
        "media/.png",
        "png",
        "rpgm/.png",
        ".png",
        "other",
    )
    assert "pe/.exe" in route.secondary_baseline_keys
    assert route.learning_allowed is False


def test_stage313_compact_json_persists_stage313_context_fields(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = root / "game" / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZAssembly-CSharp UnityEngine")
    ctx = classify_engine_context(dll, container_root=root)
    compact = compact_result_record({
        "file": str(dll),
        "path": str(dll),
        "score": 88,
        "classification": "high_confidence",
        "tags": ["cross_engine_artifact", "unity_dotnet"],
        "temporal_signals": {"event": "cross_engine_seen"},
        "markov_sequence_signals": ["renpy_to_unity_dll"],
        "clustering_signals": ["foreign_runtime_cluster"],
        "graph_signals": ["container_artifact_mismatch"],
        "yara_signals": ["Synthetic.UnityDLL"],
        "entropy_signals": ["pe_header"],
        "archive_container_signals": ["renpy_container"],
        "decoded_evidence_snippets": ["Assembly-CSharp UnityEngine"],
        "errors": [],
        "warnings": [],
        "explanation": {"reasons": ["Unity DLL inside RenPy container"], "exit_code": 2},
        **ctx.as_record_fields(),
    })
    json.dumps(compact)
    assert compact["container_engine"] == "renpy"
    assert compact["artifact_engine"] == "unity"
    assert compact["effective_analysis_engine"] == "unity_dotnet"
    assert compact["baseline_key"] == "renpy::unity::.dll::mono_dotnet_assembly"
    assert compact["learning_allowed"] is False
    assert compact["temporal_signals"] == {"event": "cross_engine_seen"}
