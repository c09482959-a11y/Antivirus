from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.profiles import (
    get_extension_baseline,
    load_engine_profile,
    record_learning_rejection,
)
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles


def _renpy_root_with_unity_dll(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "renpy_game"
    (root / "game").mkdir(parents=True)
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    dll = root / "game" / "Assembly-CSharp.dll"
    dll.write_bytes(b"MZ" + b"\x00" * 64 + b"BSJB mscorlib UnityEngine Assembly-CSharp")
    return root, dll


def test_stage321_rejection_records_contextual_bucket_not_raw_extension(tmp_path: Path) -> None:
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()
    _root, dll = _renpy_root_with_unity_dll(tmp_path)

    recorded = record_learning_rejection(
        "renpy",
        dll,
        "cross-engine artifact requires trusted benign allowlist before learning",
    )

    profile = load_engine_profile("renpy")
    assert recorded["extension"] == "renpy::unity::.dll::mono_dotnet_assembly"
    assert "renpy::unity::.dll::mono_dotnet_assembly" in profile["extension_baselines"]
    assert ".dll" not in profile["extension_baselines"]
    assert "renpy/.dll" not in profile["extension_baselines"]


def test_stage321_profile_reads_use_contextual_namespace(tmp_path: Path) -> None:
    bind_profile_database(tmp_path)
    ensure_authoritative_engine_profiles()
    _root, dll = _renpy_root_with_unity_dll(tmp_path)
    record_learning_rejection("renpy", dll, "cross-engine artifact requires trusted benign allowlist before learning")

    baseline = get_extension_baseline("renpy", dll)

    assert baseline["extension"] == "renpy::unity::.dll::mono_dotnet_assembly"
    assert baseline["learning_gate"]["rejected"] == 1
