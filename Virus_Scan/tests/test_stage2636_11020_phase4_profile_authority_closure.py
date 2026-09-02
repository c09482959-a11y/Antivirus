from __future__ import annotations

from pathlib import Path

import Virus_Scan.scanners.text as text
from Virus_Scan.cli.args import parse_args
from Virus_Scan.detection.scoring.weighting import contextual_expected


def _production_python_text() -> str:
    chunks: list[str] = []
    for path in sorted(Path("Virus_Scan").rglob("*.py")):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks)


def test_phase4_extension_profile_json_authority_is_removed() -> None:
    production = _production_python_text()
    assert "ext_profile.json" not in production
    assert "--ext-profile" not in production
    assert "load_extension_profiles" not in production
    assert "extension_profiles_snapshot" not in production
    assert "replace_extension_profiles" not in production
    assert not Path("Virus_Scan/runtime/extension_profile_state.py").exists()


def test_phase4_scanner_does_not_own_contextual_expected_profile_signal() -> None:
    assert not hasattr(text, "ContextualExpectedBehaviorRequest")
    assert not hasattr(text, "contextual_expected_behavior_signal")
    assert callable(contextual_expected.contextual_expected_behavior_signal)


def test_phase4_cli_rejects_retired_ext_profile_option(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    try:
        parse_args(["--dir", str(target), "--ext-profile", "legacy.json"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("retired --ext-profile option was accepted")


def test_phase4_detection_owner_reads_canonical_profile_contract() -> None:
    source = Path("Virus_Scan/detection/profiles/baseline_snapshot.py").read_text(encoding="utf-8")
    assert "from Virus_Scan.models.api.profile_contracts import get_extension_baseline" in source
    assert "get_extension_baseline(" in source
