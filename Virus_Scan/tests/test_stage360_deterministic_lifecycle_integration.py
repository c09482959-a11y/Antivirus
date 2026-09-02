from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.routing.engine_fingerprints import fingerprint_container
from Virus_Scan.runtime.determinism import (
    deterministic_scan_path_inventory,
    deterministic_json_digest,
    validate_deterministic_result_records,
)


def test_stage360_scan_inventory_excludes_runtime_artifacts_and_is_stable(tmp_path: Path) -> None:
    (tmp_path / "Game" / "Data").mkdir(parents=True)
    (tmp_path / "Scan Logs").mkdir()
    (tmp_path / "Temp").mkdir()
    (tmp_path / "Game" / "Data" / "Assembly-CSharp.dll").write_bytes(b"MZ" + b"\0" * 16)
    (tmp_path / "Game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    (tmp_path / "Scan Logs" / "scan_results.json").write_text("{}", encoding="utf-8")
    (tmp_path / "Scan Logs" / "scanlog").write_text("log", encoding="utf-8")
    (tmp_path / "Temp" / "worker.pid").write_text("123", encoding="utf-8")

    assert deterministic_scan_path_inventory(tmp_path) == (
        "Game/Data/Assembly-CSharp.dll",
        "Game/script.rpy",
    )


def test_stage360_container_fingerprint_ignores_generated_scan_outputs(tmp_path: Path) -> None:
    (tmp_path / "game").mkdir()
    (tmp_path / "Scan Logs").mkdir()
    (tmp_path / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    before = fingerprint_container(tmp_path)

    # A generated report must not become routing evidence on the next pass.
    (tmp_path / "Scan Logs" / "scan_results.json").write_text(
        '{"fake":"UnityPlayer.dll Data/Managed Assembly-CSharp.dll"}', encoding="utf-8"
    )
    (tmp_path / "Scan Logs" / "UnityPlayer.dll").write_bytes(b"MZ" + b"\0" * 32)
    after = fingerprint_container(tmp_path)

    assert after.engine == before.engine == "renpy"
    assert deterministic_json_digest(after.__dict__) == deterministic_json_digest(before.__dict__)


def test_stage360_result_record_validation_hard_fails_duplicate_or_malformed_records() -> None:
    valid = {
        "A/file.bin": {"verdict": "Clean", "tags": ["a"]},
        "b/file.bin": {"verdict": "Low", "tags": ["b"]},
    }
    assert validate_deterministic_result_records(valid) == ("A/file.bin", "b/file.bin")

    with pytest.raises(ValueError, match="duplicate deterministic result record"):
        validate_deterministic_result_records({
            "A/file.bin": {"verdict": "Clean"},
            "a\\file.bin": {"verdict": "Clean"},
        })

    with pytest.raises(ValueError, match="missing verdict"):
        validate_deterministic_result_records({"sample.bin": {"tags": ["no_verdict"]}})

    with pytest.raises(TypeError, match="must be a mapping"):
        validate_deterministic_result_records({"sample.bin": ["not", "mapping"]})
