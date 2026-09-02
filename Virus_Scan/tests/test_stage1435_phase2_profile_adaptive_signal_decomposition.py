from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.api import adaptive_signals
from Virus_Scan.models.profiles import adaptive_signal, coordinated_validation, evidence, timeline
from Virus_Scan.models.profiles import api as profile_api


def _function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def _source(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_stage1435_profile_adaptive_signal_has_explicit_owner_modules() -> None:
    assert profile_api.adaptive_profile_signal is adaptive_signal.adaptive_profile_signal
    assert profile_api.extension_profile_anomaly is adaptive_signal.extension_profile_anomaly
    assert profile_api.coordinated_model_validation_signal is coordinated_validation.coordinated_model_validation_signal
    assert profile_api.extension_timeline_anomaly is timeline.extension_timeline_anomaly

    api_functions = _function_names(Path("Virus_Scan/models/profiles/api.py"))
    assert "adaptive_profile_signal" not in api_functions
    assert "extension_profile_anomaly" not in api_functions
    assert "coordinated_model_validation_signal" not in api_functions
    assert "extension_timeline_anomaly" not in api_functions


def test_stage1435_new_profile_owner_modules_do_not_import_profile_api() -> None:
    for path in (
        "Virus_Scan/models/profiles/adaptive_signal.py",
        "Virus_Scan/models/profiles/coordinated_validation.py",
        "Virus_Scan/models/profiles/evidence.py",
        "Virus_Scan/models/profiles/timeline.py",
        "Virus_Scan/models/profiles/context.py",
    ):
        source = _source(path)
        assert "Virus_Scan.models.profiles.api" not in source
        assert "from Virus_Scan.models.profiles import api" not in source


def test_stage1435_public_adaptive_contract_points_to_profile_owners() -> None:
    assert adaptive_signals.adaptive_profile_signal(
        'node:stage1435',
        ('profile_tag',),
        preliminary_risk=0.0,
        strings_blob='',
    )
    assert adaptive_signals.extension_profile_anomaly(
        'renpy',
        'sample.rpy',
        ('profile_tag',),
        0.0,
        strings_blob='',
    )
    assert adaptive_signals.coordinated_model_validation_signal(
        'renpy',
        'sample.rpy',
        ('profile_tag',),
        strings_blob='',
    )
    assert '_adaptive_profile_signal' not in adaptive_signals.__dict__
    assert '_extension_profile_anomaly' not in adaptive_signals.__dict__
    assert '_coordinated_model_validation_signal' not in adaptive_signals.__dict__


def test_stage1435_profile_adaptive_owner_files_are_bounded() -> None:
    limits = {
        "Virus_Scan/models/profiles/adaptive_signal.py": 300,
        "Virus_Scan/models/profiles/coordinated_validation.py": 250,
        "Virus_Scan/models/profiles/evidence.py": 200,
        "Virus_Scan/models/profiles/timeline.py": 200,
        "Virus_Scan/models/profiles/context.py": 120,
    }
    for path, limit in limits.items():
        assert len(Path(path).read_text(encoding="utf-8").splitlines()) <= limit
