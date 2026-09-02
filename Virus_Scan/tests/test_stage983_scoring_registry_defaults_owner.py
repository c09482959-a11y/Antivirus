from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.registries.snapshot import build_detection_registry_snapshot
from Virus_Scan.detection.scoring.registries.scoring_registry_defaults import (
    ENGINE_SPECIFIC_FILETYPE_BUCKETS,
    TAG_RISK_SCORES,
)


def test_scoring_registry_defaults_are_detection_scoring_owned() -> None:
    assert not Path("Virus_Scan/detection/registries/scoring_registry_defaults.py").exists()
    assert Path("Virus_Scan/detection/scoring/registries/scoring_registry_defaults.py").exists()
    assert "wmi_exec" in TAG_RISK_SCORES
    assert {"renpy", "rpgm", "unity"} <= set(ENGINE_SPECIFIC_FILETYPE_BUCKETS)


def test_detection_registry_snapshot_uses_scoring_owned_defaults() -> None:
    snapshot = build_detection_registry_snapshot()
    scoring_values = dict(snapshot.scoring_registry.values)
    engine_values = dict(snapshot.engine_registry.values)
    assert "TAG_RISK_SCORES" in scoring_values
    assert "ENGINE_SPECIFIC_FILETYPE_BUCKETS" in engine_values
    assert scoring_values["TAG_RISK_SCORES"].get("wmi_exec") == TAG_RISK_SCORES["wmi_exec"]
