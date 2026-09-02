from __future__ import annotations

import json
from pathlib import Path

from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.baseline_routing import (
    BaselineRouteRequest,
    build_baseline_route,
)
from Virus_Scan.routing.context_identity import classify_engine_context


def test_stage314_lookup_order_is_exact_and_learning_target_is_artifact_baseline() -> None:
    route = build_baseline_route(BaselineRouteRequest(
        container_engine="renpy",
        artifact_engine="renpy",
        declared_extension=".rpy",
        sniffed_type="renpy_source",
        trusted_benign=True,
    ))

    assert route.baseline_lookup_order == (
        "renpy::renpy::.rpy::renpy_source",
        "renpy::renpy::.rpy",
        "renpy/.rpy",
        "renpy_source",
        "renpy/.rpy",
        ".rpy",
        "other",
    )
    assert route.learning_allowed is True
    assert route.learning_baseline_key == "renpy/.rpy"
    assert route.blocked_baseline_keys == ("renpy/.rpy", ".rpy")


def test_stage314_cross_engine_blocks_container_and_generic_learning(tmp_path: Path) -> None:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = root / "game" / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZAssembly-CSharp UnityEngine mscorlib")

    ctx = classify_engine_context(dll, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "renpy"
    assert ctx.artifact_engine == "unity"
    assert ctx.cross_engine_artifact is True
    assert ctx.learning_allowed is False
    assert ctx.learning_baseline_key is None
    assert "renpy/.dll" in ctx.blocked_baseline_keys
    assert ".dll" in ctx.blocked_baseline_keys
    assert ctx.baseline_lookup_order[:7] == (
        "renpy::unity::.dll::mono_dotnet_assembly",
        "renpy::unity::.dll",
        "unity/.dll",
        "mono_dotnet_assembly",
        "renpy/.dll",
        ".dll",
        "other",
    )


def test_stage314_polyglot_media_blocks_embedded_container_and_generic_learning(tmp_path: Path) -> None:
    root = tmp_path / "rpgm_game"
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "js" / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    png = root / "www" / "img" / "actor.png"
    png.parent.mkdir(parents=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64 + b"MZpayload")

    ctx = classify_engine_context(png, container_root=root, trusted_benign=True)

    assert ctx.container_engine == "rpgm"
    assert ctx.artifact_engine == "media"
    assert ctx.effective_analysis_engine == "embedded_pe_payload"
    assert ctx.learning_allowed is False
    assert ctx.learning_baseline_key is None
    assert "rpgm/.png" in ctx.blocked_baseline_keys
    assert ".png" in ctx.blocked_baseline_keys
    assert "pe/.exe" in ctx.blocked_baseline_keys
    assert "rpgm::embedded_pe::.png" in ctx.blocked_baseline_keys


def test_stage314_compact_json_persists_baseline_isolation_fields(tmp_path: Path) -> None:
    root = tmp_path / "unity_game"
    (root / "Game_Data" / "Managed").mkdir(parents=True)
    (root / "UnityPlayer.dll").write_bytes(b"MZUnityPlayer")
    rpyc = root / "Game_Data" / "Managed" / "payload.rpyc"
    rpyc.write_bytes(b"RENPY\x00GLOBAL\nREDUCE\nbuiltins\nexec")
    ctx = classify_engine_context(rpyc, container_root=root)
    compact = compact_result_record({
        "file": str(rpyc),
        "path": str(rpyc),
        "score": 90,
        "classification": "high_confidence",
        "tags": ["cross_engine_artifact", "renpy_bytecode"],
        "explanation": {"reasons": ["RenPy bytecode in Unity container"], "exit_code": 2},
        **ctx.as_record_fields(),
    })
    json.dumps(compact)

    assert compact["baseline_lookup_order"][0] == "unity::renpy::.rpyc::renpy_bytecode"
    assert compact["learning_baseline_key"] is None
    assert "unity/.rpyc" in compact["blocked_baseline_keys"]
    assert compact["learning_allowed"] is False
