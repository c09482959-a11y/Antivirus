from pathlib import Path

from Virus_Scan.routing.context_identity import classify_engine_context
from Virus_Scan.routing.file_identity import sniff_file_identity


def test_mixed_scan_root_does_not_force_unrelated_direct_child_file_into_game_context(tmp_path: Path):
    renpy = tmp_path / "renpy_game"
    (renpy / "game").mkdir(parents=True)
    (renpy / "game" / "script.rpy").write_text("label start:\n    pass\n", encoding="utf-8")
    unity = tmp_path / "unity_game"
    (unity / "Game_Data").mkdir(parents=True)
    (unity / "UnityPlayer.dll").write_bytes(b"MZunity")
    loose = tmp_path / "loose.dat"
    loose.write_bytes(b"plain loose data")

    identity = classify_engine_context(loose, container_root=tmp_path)

    assert identity.container_engine == "other"
    assert identity.cross_engine_artifact is False
    assert identity.engine_mismatch is False


def test_dotnet_dll_is_pe_subtype_not_extension_mismatch(tmp_path: Path):
    dll = tmp_path / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + (b"\0" * 64) + b"BSJB mscorlib UnityEngine")

    file_identity = sniff_file_identity(dll)
    context = classify_engine_context(dll, container_root=tmp_path)

    assert file_identity.declared_extension == ".dll"
    assert file_identity.sniffed_type == "mono_dotnet_assembly"
    assert file_identity.extension_mismatch is False
    assert context.extension_mismatch is False
    assert "unity/.dll" in context.baseline_lookup_order
