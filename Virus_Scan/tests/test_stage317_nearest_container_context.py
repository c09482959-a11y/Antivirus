from pathlib import Path

from Virus_Scan.routing.context_identity import classify_engine_context


def test_stage317_mixed_corpus_uses_nearest_game_container_for_cross_engine_artifact(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    renpy = corpus / "renpy_game"
    unity = corpus / "unity_game"
    (renpy / "game").mkdir(parents=True)
    unity.mkdir(parents=True)
    (renpy / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = renpy / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"\x00" * 32 + b"BSJB mscorlib UnityEngine Assembly-CSharp")
    (unity / "UnityPlayer.dll").write_bytes(b"MZUnityPlayer")

    context = classify_engine_context(dll, container_root=corpus, trusted_benign=False)

    assert context.container_engine == "renpy"
    assert context.artifact_engine == "unity"
    assert context.effective_analysis_engine == "unity_dotnet"
    assert context.cross_engine_artifact is True
    assert context.baseline_key.startswith("renpy::unity::.dll")
    assert context.learning_allowed is False


def test_stage317_mixed_corpus_preserves_local_native_container(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    renpy = corpus / "renpy_game"
    (renpy / "game").mkdir(parents=True)
    script = renpy / "game" / "script.rpy"
    script.write_text("label start:\n    return\n", encoding="utf-8")
    (corpus / "unity_game").mkdir(parents=True)
    (corpus / "unity_game" / "UnityPlayer.dll").write_bytes(b"MZUnityPlayer")

    context = classify_engine_context(script, container_root=corpus, trusted_benign=True)

    assert context.container_engine == "renpy"
    assert context.artifact_engine == "renpy"
    assert context.cross_engine_artifact is False
    assert context.baseline_key.startswith("renpy::renpy::.rpy")
