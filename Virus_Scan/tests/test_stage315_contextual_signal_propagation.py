from Virus_Scan.publication.json_writer import compact_result_record
from Virus_Scan.routing.context_identity import classify_engine_context


def test_contextual_json_preserves_list_shaped_subsystem_signals(tmp_path):
    root = tmp_path / "RenPyGame"
    game = root / "game"
    game.mkdir(parents=True)
    (game / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = game / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"Assembly-CSharp UnityEngine mscorlib BSJB" + b"\0" * 64)

    ctx = classify_engine_context(dll, container_root=root)
    compact = compact_result_record({
        "file": str(dll),
        "score": 72.0,
        "classification": "High confidence",
        "tags": ["unity_dll_inside_renpy", "entropy_high", "embedded_archive_marker"],
        "temporal_signals": ["late_stage_foreign_runtime"],
        "markov_sequence_signals": ["renpy_to_unity_dll_transition"],
        "clustering_signals": ["foreign_runtime_cluster"],
        "graph_signals": ["container:renpy->artifact:unity"],
        "yara_signals": ["UnityRuntimeSuspicious"],
        "entropy_signals": ["section_entropy_high"],
        "archive_container_signals": ["foreign_runtime_container_context"],
        "decoded_evidence_snippets": ["Assembly-CSharp.dll found inside RenPy game folder"],
        **ctx.as_record_fields(),
    })

    assert compact["container_engine"] == "renpy"
    assert compact["artifact_engine"] == "unity"
    assert compact["cross_engine_artifact"] is True
    assert compact["temporal_signals"] == ["late_stage_foreign_runtime"]
    assert compact["markov_sequence_signals"] == ["renpy_to_unity_dll_transition"]
    assert compact["clustering_signals"] == ["foreign_runtime_cluster"]
    assert compact["graph_signals"] == ["container:renpy->artifact:unity"]
    assert compact["yara_signals"] == ["UnityRuntimeSuspicious"]
    assert compact["entropy_signals"] == ["section_entropy_high"]
    assert compact["archive_container_signals"] == ["foreign_runtime_container_context"]
    assert compact["decoded_evidence_snippets"] == ["Assembly-CSharp.dll found inside RenPy game folder"]
    frame = compact["contextual_signal_frame"]
    assert frame["baseline_key"].startswith("renpy::unity::.dll")
    assert all(frame["signal_presence"].values())


def test_contextual_json_preserves_dict_shaped_model_signals(tmp_path):
    root = tmp_path / "RPGMGame"
    www = root / "www" / "js"
    www.mkdir(parents=True)
    (www / "rpg_core.js").write_text("function Game_Interpreter(){}", encoding="utf-8")
    png = root / "www" / "img" / "picture.png"
    png.parent.mkdir(parents=True, exist_ok=True)
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32 + b"MZpayload")

    ctx = classify_engine_context(png, container_root=root)
    compact = compact_result_record({
        "file": str(png),
        "score": 88.0,
        "classification": "Malicious",
        "temporal_features": {"stage": "post_media_load"},
        "markov_features": {"transition": "media_to_pe"},
        "cluster_features": {"cluster": "polyglot_media"},
        "graph_features": {"edge": "png_contains_pe"},
        **ctx.as_record_fields(),
    })

    assert compact["sniffed_type"] == "png"
    assert "pe" in compact["sniffed_embedded_types"]
    assert compact["effective_analysis_engine"] == "embedded_pe_payload"
    assert compact["learning_allowed"] is False
    assert compact["temporal_signals"] == {"stage": "post_media_load"}
    assert compact["markov_sequence_signals"] == {"transition": "media_to_pe"}
    assert compact["clustering_signals"] == {"cluster": "polyglot_media"}
    assert compact["graph_signals"] == {"edge": "png_contains_pe"}
    assert compact["contextual_signal_frame"]["signal_presence"]["graph_signals"] is True
